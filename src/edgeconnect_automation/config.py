import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

from .errors import ConfigurationError


ALIASES = {
    "base_url": ("orchestrator_base_url", "ORCHESTRATOR_BASE_URL", "EDGECONNECT_BASE_URL", "EC_BASE_URL"),
    "api_key": ("orchestrator_api_key", "ORCHESTRATOR_API_KEY", "EDGECONNECT_API_KEY", "EC_API_KEY"),
    "ca_bundle": ("orchestrator_ca_bundle", "ORCHESTRATOR_CA_BUNDLE", "EDGECONNECT_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"),
    "api_key_header": ("orchestrator_api_key_header", "ORCHESTRATOR_API_KEY_HEADER", "EDGECONNECT_API_KEY_HEADER"),
}


@dataclass(frozen=True)
class Config:
    base_url: str
    api_key: str
    ca_bundle: Optional[str] = None
    api_key_header: str = "X-Auth-Token"
    timeout: float = 30.0
    max_read_attempts: int = 3
    verification_timeout: float = 120.0
    poll_interval: float = 5.0
    allow_http: bool = False


def parse_dotenv(path: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ConfigurationError("invalid dotenv line {}".format(number))
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise ConfigurationError("unterminated dotenv quote on line {}".format(number))
            value = value[1:-1]
        result[key] = value
    return result


def _first(source: Mapping[str, str], names: tuple) -> Optional[str]:
    for name in names:
        value = source.get(name)
        if value:
            return value
    return None


def load_config(dotenv_path: Optional[str] = None, environ: Optional[Mapping[str, str]] = None, allow_http: bool = False) -> Config:
    values: Dict[str, str] = {}
    if dotenv_path:
        values.update(parse_dotenv(dotenv_path))
    values.update(dict(os.environ if environ is None else environ))
    base_url = _first(values, ALIASES["base_url"])
    api_key = _first(values, ALIASES["api_key"])
    if not base_url or not api_key:
        raise ConfigurationError("Orchestrator base URL and API key are required")
    parsed = urlsplit(base_url)
    if parsed.scheme not in ({"https"} if not allow_http else {"https", "http"}) or not parsed.netloc:
        raise ConfigurationError("base URL must be an absolute {} URL".format("HTTPS" if not allow_http else "HTTP(S)"))
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ConfigurationError("base URL must not include credentials, query, or fragment")
    path = parsed.path.rstrip("/")
    if not path:
        path = "/gms/rest"
    elif path != "/gms/rest":
        raise ConfigurationError("base URL path must be empty or /gms/rest")
    normalized_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    ca_bundle = _first(values, ALIASES["ca_bundle"])
    if ca_bundle and not Path(ca_bundle).is_file():
        raise ConfigurationError("CA bundle does not exist")
    return Config(
        base_url=normalized_url,
        api_key=api_key,
        ca_bundle=ca_bundle,
        api_key_header=_first(values, ALIASES["api_key_header"]) or "X-Auth-Token",
        allow_http=allow_http,
    )
