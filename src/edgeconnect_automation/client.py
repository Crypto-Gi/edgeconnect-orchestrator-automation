import json
import random
import ssl
import sys
import time
import uuid
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Iterable, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPSHandler, Request, build_opener

from .config import Config
from .errors import AuthenticationError, ConflictError, PermissionDeniedError, RateLimitError, ResourceNotFoundError, ResponseFormatError, ServerError, TransportError, ValidationError
from .util import redact


class ApiClient:
    def __init__(
        self,
        config: Config,
        opener: Any = None,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
        verbosity: int = 0,
    ) -> None:
        self.config = config
        self.verbosity = verbosity
        context = ssl.create_default_context(cafile=config.ca_bundle)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        self._opener = opener or build_opener(HTTPSHandler(context=context))
        self._sleep = sleep
        self._jitter = jitter

    def request(
        self,
        method: str,
        path: str,
        query: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        binary_body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        expected_status: Iterable[int] = (200,),
        expect_json: bool = True,
        accept: str = "application/json",
    ) -> Any:
        method = method.upper()
        if json_body is not None and binary_body is not None:
            raise ValueError("json_body and binary_body are mutually exclusive")
        url = self._url(path, query)
        headers = {"Accept": accept, self.config.api_key_header: self.config.api_key}
        data = binary_body
        if json_body is not None:
            data = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif binary_body is not None:
            headers["Content-Type"] = content_type or "application/octet-stream"
        request = Request(url, data=data, headers=headers, method=method)
        self._log(1, "{} {}{}".format(method, path, " query=" + ",".join(sorted((query or {}).keys())) if query else ""))
        if self.verbosity >= 2 and json_body is not None:
            self._log(2, "payload=" + json.dumps(redact(json_body), sort_keys=True, separators=(",", ":")))
        elif self.verbosity >= 2 and binary_body is not None:
            self._log(2, "binary_payload_bytes={}".format(len(binary_body)))
        attempts = self.config.max_read_attempts if method == "GET" else 1
        for attempt in range(attempts):
            try:
                with self._opener.open(request, timeout=self.config.timeout) as response:
                    status = int(response.getcode())
                    body = response.read()
                    media_type = response.headers.get_content_type()
                    self._log(1, "{} {} -> {} bytes={}".format(method, path, status, len(body)))
                    if status not in set(expected_status):
                        raise ResponseFormatError("unexpected HTTP status", status, method, path)
                    return self._decode(body, media_type, expect_json, status, method, path)
            except HTTPError as error:
                status = int(error.code)
                message = self._safe_error(error)
                if method == "GET" and status in {429, 500, 502, 503, 504} and attempt + 1 < attempts:
                    self._sleep(self._delay(attempt, error.headers.get("Retry-After")))
                    continue
                self._raise_http(status, message, method, path)
            except (URLError, TimeoutError, OSError) as error:
                if method == "GET" and attempt + 1 < attempts:
                    self._sleep(self._delay(attempt, None))
                    continue
                raise TransportError("transport failure: {}".format(type(error).__name__), None, method, path) from error
        raise TransportError("read attempts exhausted", None, method, path)

    def get(self, path: str, query: Optional[Mapping[str, Any]] = None, expected_status: Iterable[int] = (200,)) -> Any:
        return self.request("GET", path, query=query, expected_status=expected_status)

    def post_json(self, path: str, value: Any, query: Optional[Mapping[str, Any]] = None, expected_status: Iterable[int] = (200, 204), accept: str = "application/json") -> Any:
        return self.request("POST", path, query=query, json_body=value, expected_status=expected_status, expect_json=False, accept=accept)

    def post_binary(self, path: str, value: bytes, query: Optional[Mapping[str, Any]] = None, expected_status: Iterable[int] = (200, 204)) -> Any:
        return self.request("POST", path, query=query, binary_body=value, content_type="application/octet-stream", expected_status=expected_status, expect_json=False)

    def post_multipart_file(
        self,
        path: str,
        field_name: str,
        filename: str,
        value: bytes,
        query: Optional[Mapping[str, Any]] = None,
        expected_status: Iterable[int] = (200,),
    ) -> Any:
        if not field_name or any(character in field_name for character in '\r\n"'):
            raise ValueError("invalid multipart field name")
        if not filename or any(character in filename for character in '\r\n"/\\'):
            raise ValueError("invalid multipart filename")
        boundary = "edgeconnect-auto-{}".format(uuid.uuid4().hex)
        disposition = 'Content-Disposition: form-data; name="{}"; filename="{}"'.format(field_name, filename)
        body = b"\r\n".join([
            ("--" + boundary).encode("ascii"),
            disposition.encode("utf-8"),
            b"Content-Type: text/csv",
            b"",
            value,
            ("--" + boundary + "--").encode("ascii"),
            b"",
        ])
        return self.request(
            "POST",
            path,
            query=query,
            binary_body=body,
            content_type="multipart/form-data; boundary={}".format(boundary),
            expected_status=expected_status,
            expect_json=True,
        )

    def _log(self, level: int, message: str) -> None:
        if self.verbosity >= level:
            print(redact(message), file=sys.stderr)

    def _url(self, path: str, query: Optional[Mapping[str, Any]]) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("API path must be absolute and host-relative")
        url = urljoin(self.config.base_url + "/", path.lstrip("/"))
        if query:
            clean = {key: value for key, value in query.items() if value is not None}
            url += "?" + urlencode(clean, doseq=True)
        return url

    @staticmethod
    def _decode(body: bytes, media_type: str, expect_json: bool, status: int, method: str, path: str) -> Any:
        if not body:
            if expect_json:
                raise ResponseFormatError("expected JSON response body", status, method, path)
            return None
        if not expect_json:
            return body
        if media_type not in {"application/json", "text/json"} and not media_type.endswith("+json"):
            raise ResponseFormatError("unexpected response media type", status, method, path)
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ResponseFormatError("invalid JSON response", status, method, path) from error
        if value is None or value is False:
            raise ResponseFormatError("invalid inventory response shape", status, method, path)
        return value

    @staticmethod
    def _safe_error(error: HTTPError) -> str:
        try:
            body = error.read(4096).decode("utf-8", "replace")
        except OSError:
            body = ""
        safe = redact(body).replace("\n", " ").strip()
        return "HTTP {}{}".format(error.code, ": " + safe if safe else "")

    @staticmethod
    def _raise_http(status: int, message: str, method: str, path: str) -> None:
        classes: Dict[int, Any] = {
            400: ValidationError,
            401: AuthenticationError,
            403: PermissionDeniedError,
            404: ResourceNotFoundError,
            409: ConflictError,
            429: RateLimitError,
        }
        error_class = classes.get(status, ServerError if status >= 500 else ResponseFormatError)
        if error_class is ValidationError:
            raise ValidationError(message)
        raise error_class(message, status, method, path)

    def _delay(self, attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return min(max(float(retry_after), 0.0), 60.0)
            except ValueError:
                try:
                    seconds = parsedate_to_datetime(retry_after).timestamp() - time.time()
                    return min(max(seconds, 0.0), 60.0)
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(0.5 * (2 ** attempt) + self._jitter() * 0.25, 10.0)
