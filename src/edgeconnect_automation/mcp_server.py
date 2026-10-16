"""Stdio MCP server exposing every Orchestrator REST operation through a small, guarded tool set.

The Orchestrator's own Swagger spec is the allowlist: only method + path pairs it documents can be
called. Reads are always available; writes need `<nickname>_mcp_writes=true` in .env for that
Orchestrator. Nothing listens on the network, and API keys never leave this process.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from . import __version__
from .client import ApiClient
from .config import Config, _profiles, load_config, parse_dotenv
from .errors import EdgeConnectError
from .util import redact

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
# Generic passthroughs that reach any appliance API or CLI, so the spec cannot constrain what they change.
PASSTHROUGH_PREFIXES = ("/appliance/rest", "/broadcastCli")
DEFAULT_MAX_CHARS = 60000
_PATH = re.compile(r"^/[A-Za-z0-9_\-./{}:@~%+,=]*$")

INSTRUCTIONS = (
    "Tools for HPE Aruba EdgeConnect Orchestrator. Workflow: list_orchestrators, then find_operations "
    "to locate the REST call, describe_operation for its parameters and body, then api_get (read) or "
    "api_write (change). Paths are relative to /gms/rest, e.g. /appliance. Writes only work on "
    "Orchestrators configured as writable; confirm intent with the user before any api_write. "
    "On 9.7 the spec has no write operations for deployment, BGP, OSPF, VRRP or static routes: read the "
    "appliance's own config with GET /appliance/rest (query url=<path>, e.g. deployment, bgp/config/neighbor), "
    "change it, and POST the whole object back; that needs passthrough writes enabled."
)


class ToolError(Exception):
    pass


def _error_text(exc: BaseException, name: str = "<nickname>") -> str:
    """One short, secret-free line: HTML error pages stripped, the TLS reason kept."""
    text = str(exc)
    reason = getattr(exc.__cause__, "reason", None) or exc.__cause__
    if reason is not None and str(reason) not in text:
        text += " ({})".format(reason)
    if "CERTIFICATE_VERIFY_FAILED" in text:
        text += "; for a self-signed Orchestrator set {0}_tls_sha256 (or {0}_ca_bundle) in .env".format(name)
    text = re.sub(r"(?is)<(script|style)\b.*?(?:</\1\s*>|$)", " ", redact(text))  # $: error bodies are cut at 4 KB
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]*>", " ", text)).strip()
    return text if len(text) <= 500 else text[:500] + " ..."


def _settings(dotenv: Optional[str]) -> Dict[str, str]:
    values = parse_dotenv(dotenv) if dotenv else {}
    return {key.lower(): value for source in (values, os.environ) for key, value in source.items()}


def _template_regex(template: str) -> "re.Pattern[str]":
    parts = re.split(r"(\{[^}/]+\})", template)
    return re.compile("^" + "".join("[^/]+" if part.startswith("{") else re.escape(part) for part in parts) + "/?$")


class Orchestrator:
    def __init__(self, name: str, config: Config, writes: bool, spec_source: Optional[str], client: Optional[ApiClient] = None, passthrough: bool = False) -> None:
        self.name = name
        self.config = config
        self.writes = writes
        self.passthrough = passthrough
        self.spec_source = spec_source
        self.client = client or ApiClient(config)
        self._operations: Optional[List[Dict[str, Any]]] = None
        self._definitions: Dict[str, Any] = {}

    @property
    def host(self) -> str:
        return self.config.base_url.split("/")[2]

    def operations(self) -> List[Dict[str, Any]]:
        if self._operations is None:
            specs = self._load_specs()
            operations = []
            for spec in specs:
                # Paths are relative to /gms/rest (Swagger 2 basePath or OpenAPI 3 servers[0].url).
                base = spec.get("basePath") or ((spec.get("servers") or [{}])[0].get("url") or "")
                base = base.split("/gms/rest", 1)[1] if "/gms/rest" in base else ""
                base = base.rstrip("/")
                self._definitions.update(spec.get("definitions") or {})
                self._definitions.update((spec.get("components") or {}).get("schemas") or {})
                for path, item in (spec.get("paths") or {}).items():
                    for method, operation in item.items():
                        if method.upper() not in ("GET",) + WRITE_METHODS or not isinstance(operation, dict):
                            continue
                        full = base + path
                        operations.append({
                            "method": method.upper(),
                            "path": full,
                            "summary": operation.get("summary") or "",
                            "description": operation.get("description") or "",
                            "tags": operation.get("tags") or [],
                            "parameters": list(item.get("parameters") or []) + list(operation.get("parameters") or []),
                            "requestBody": operation.get("requestBody"),
                            "regex": _template_regex(full),
                        })
            if not operations:
                raise ToolError("no operations found in the Orchestrator API spec for {}".format(self.name))
            self._operations = operations
        return self._operations

    def _load_specs(self) -> List[Mapping[str, Any]]:
        if self.spec_source:
            source = Path(self.spec_source).expanduser()
            files = sorted(source.glob("*.json")) if source.is_dir() else [source]
            return [json.loads(path.read_text(encoding="utf-8")) for path in files]
        # The same request the Orchestrator's Swagger UI (Support > REST APIs) makes; it rejects calls without these parameters.
        query = {"source": "menu_rest_apis_id", "api": "gmsApiInfo", "protocol": "https:", "hostname": self.host + ":"}
        try:
            spec = json.loads(self.client.request("GET", "/apiDocs", query=query, expect_json=False) or b"{}")
        except (EdgeConnectError, ValueError) as exc:
            raise ToolError("could not download the API spec from {}: {}".format(self.name, _error_text(exc, self.name)))
        return [spec] if isinstance(spec, dict) else []

    def match(self, method: str, path: str) -> Dict[str, Any]:
        lowered = path.lower()
        if not _PATH.match(path) or "//" in path or "/../" in path + "/" or "/./" in path + "/" or any(code in lowered for code in ("%2e", "%2f", "%5c")):
            raise ToolError("invalid path {!r}: use a path relative to /gms/rest such as /appliance, with query values in 'query'".format(path))
        candidates = [operation for operation in self.operations() if operation["regex"].match(path)]
        for operation in candidates:
            if operation["method"] == method:
                return operation
        if candidates:
            raise ToolError("{} is not a documented method for {}; documented: {}".format(method, path, ", ".join(sorted({c["method"] for c in candidates}))))
        raise ToolError("{} {} is not in the {} API spec; use find_operations".format(method, path, self.name))

    def resolve(self, schema: Any, seen: Tuple[str, ...] = ()) -> Any:
        if isinstance(schema, dict):
            ref = schema.get("$ref")
            if isinstance(ref, str):
                name = ref.rsplit("/", 1)[-1]
                if name in seen or len(seen) > 8 or name not in self._definitions:
                    return schema  # recursive or unknown schema: leave the reference
                return self.resolve(self._definitions[name], seen + (name,))
            return {key: self.resolve(value, seen) for key, value in schema.items()}
        if isinstance(schema, list):
            return [self.resolve(value, seen) for value in schema]
        return schema


class Server:
    def __init__(self, orchestrators: Mapping[str, Orchestrator], default: Optional[str] = None, log: Callable[[str], None] = lambda line: print(line, file=sys.stderr)) -> None:
        self.orchestrators = dict(orchestrators)
        self.default = default
        self.log = log

    @classmethod
    def from_dotenv(cls, dotenv: Optional[str]) -> "Server":
        settings = _settings(dotenv)
        names = list(_profiles(settings)) or ["orchestrator"]
        orchestrators = {}
        for name in names:
            config = load_config(dotenv, orchestrator=name if name != "orchestrator" else None, interactive=False)
            enabled = lambda option: settings.get("{}_{}".format(name, option), "").strip().lower() in ("1", "true", "yes")
            orchestrators[name] = Orchestrator(name, config, enabled("mcp_writes"), settings.get("{}_openapi".format(name)), passthrough=enabled("mcp_passthrough"))
        default = (settings.get("orch_default") or "").strip().lower()
        default = settings.get(default, default).strip().lower()  # orch_default may name a slot such as orch_2
        return cls(orchestrators, default if default in orchestrators else names[0])

    # --- tools -------------------------------------------------------------

    def tools(self) -> List[Dict[str, Any]]:
        orch = {"type": "string", "description": "Orchestrator nickname from list_orchestrators (default: {})".format(self.default)}
        query = {"type": "object", "description": "Query-string parameters", "additionalProperties": True}
        path = {"type": "string", "description": "Path relative to /gms/rest with path parameters filled in, e.g. /appliance or /appliance/2.NE"}
        max_chars = {"type": "integer", "description": "Truncate the response text to this many characters (default {})".format(DEFAULT_MAX_CHARS)}
        return [
            {"name": "list_orchestrators", "description": "List configured Orchestrators and whether writes and appliance passthrough writes are enabled for each.",
             "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}},
            {"name": "find_operations", "description": "Search the Orchestrator's own API spec for REST operations by keyword (path, summary, tag).",
             "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "orchestrator": orch, "method": {"type": "string", "enum": ["GET"] + list(WRITE_METHODS)}, "limit": {"type": "integer"}}, "required": ["query"]},
             "annotations": {"readOnlyHint": True}},
            {"name": "describe_operation", "description": "Show parameters and request body schema for one REST operation.",
             "inputSchema": {"type": "object", "properties": {"method": {"type": "string"}, "path": path, "orchestrator": orch}, "required": ["method", "path"]},
             "annotations": {"readOnlyHint": True}},
            {"name": "api_get", "description": "Run a read-only GET against the Orchestrator REST API.",
             "inputSchema": {"type": "object", "properties": {"path": path, "query": query, "orchestrator": orch, "max_chars": max_chars}, "required": ["path"]},
             "annotations": {"readOnlyHint": True, "openWorldHint": True}},
            {"name": "api_write", "description": "Run a POST, PUT, PATCH or DELETE against the Orchestrator REST API. Changes live network configuration; only allowed on Orchestrators with writes enabled. Confirm with the user first.",
             "inputSchema": {"type": "object", "properties": {"method": {"type": "string", "enum": list(WRITE_METHODS)}, "path": path, "query": query, "body": {"description": "JSON request body"}, "orchestrator": orch, "max_chars": max_chars}, "required": ["method", "path"]},
             "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}},
        ]

    def _orchestrator(self, arguments: Mapping[str, Any]) -> Orchestrator:
        name = str(arguments.get("orchestrator") or self.default or "").strip().lower()
        if name not in self.orchestrators:
            raise ToolError("unknown Orchestrator {!r}; configured: {}".format(name, ", ".join(self.orchestrators)))
        return self.orchestrators[name]

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> Any:
        if name == "list_orchestrators":
            return [{"name": o.name, "host": o.host, "writes_enabled": o.writes, "passthrough_writes_enabled": o.passthrough, "default": o.name == self.default} for o in self.orchestrators.values()]
        orchestrator = self._orchestrator(arguments)
        if name == "find_operations":
            words = str(arguments.get("query") or "").lower().split()
            method = str(arguments.get("method") or "").upper()
            limit = max(1, min(int(arguments.get("limit") or 25), 100))
            scored = []
            for operation in orchestrator.operations():
                if method and operation["method"] != method:
                    continue
                text = " ".join([operation["path"], operation["summary"], operation["description"], " ".join(operation["tags"])]).lower()
                score = sum(text.count(word) + 3 * operation["path"].lower().count(word) for word in words)
                if score and all(word in text for word in words):
                    scored.append((-score, operation["path"], operation))
            scored.sort(key=lambda item: item[:2])
            return {"total_matches": len(scored), "operations": [{"method": o["method"], "path": o["path"], "summary": o["summary"], "tags": o["tags"]} for _, _, o in scored[:limit]]}
        if name == "describe_operation":
            operation = orchestrator.match(str(arguments.get("method") or "").upper(), str(arguments.get("path") or ""))
            return orchestrator.resolve({key: operation[key] for key in ("method", "path", "summary", "description", "tags", "parameters", "requestBody")})
        if name == "api_get":
            return self._call(orchestrator, "GET", arguments)
        if name == "api_write":
            method = str(arguments.get("method") or "").upper()
            if method not in WRITE_METHODS:
                raise ToolError("api_write method must be one of {}".format(", ".join(WRITE_METHODS)))
            if not orchestrator.writes:
                raise ToolError("writes are disabled for {}; set {}_mcp_writes=true in .env to allow them".format(orchestrator.name, orchestrator.name))
            if "<REDACTED>" in json.dumps([arguments.get("body"), arguments.get("query")]):
                raise ToolError("the request contains <REDACTED> placeholders from a redacted read; send the real values or omit those fields")
            operation = orchestrator.match(method, str(arguments.get("path") or ""))
            if operation["path"].startswith(PASSTHROUGH_PREFIXES) and not orchestrator.passthrough:
                raise ToolError("{} is a raw appliance passthrough that the API spec cannot constrain; set {}_mcp_passthrough=true in .env to allow writes through it".format(operation["path"], orchestrator.name))
            return self._call(orchestrator, method, arguments)
        raise ToolError("unknown tool {!r}".format(name))

    def _call(self, orchestrator: Orchestrator, method: str, arguments: Mapping[str, Any]) -> Any:
        path = str(arguments.get("path") or "")
        orchestrator.match(method, path)
        if not orchestrator.client._url(path, None).startswith(orchestrator.config.base_url + "/"):
            raise ToolError("path {!r} does not stay under the Orchestrator REST base".format(path))
        query = arguments.get("query") or None
        if query is not None and not isinstance(query, dict):
            raise ToolError("query must be an object")
        body = arguments.get("body")
        if method != "GET":
            self.log("edgeconnect-mcp WRITE {} {} {} query={}".format(orchestrator.name, method, path, json.dumps(redact(query), sort_keys=True)))
        raw = orchestrator.client.request(method, path, query=query, json_body=body, expected_status=range(200, 300), expect_json=False, accept="application/json, text/plain, */*")
        text = (raw or b"").decode("utf-8", "replace")
        try:
            value = json.loads(text) if text else None
        except ValueError:
            value = text
        return {"status": "ok", "result": redact(value)}

    # --- protocol ----------------------------------------------------------

    def handle(self, message: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        method = message.get("method")
        if "id" not in message:
            return None  # notification
        identifier = message["id"]
        params = message.get("params") or {}
        if method == "initialize":
            requested = params.get("protocolVersion")
            result: Any = {
                "protocolVersion": requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "edgeconnect-orchestrator", "version": __version__},
                "instructions": INSTRUCTIONS,
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.tools()}
        elif method == "tools/call":
            max_chars = DEFAULT_MAX_CHARS
            try:
                arguments = params.get("arguments") or {}
                max_chars = max(1000, int(arguments.get("max_chars") or DEFAULT_MAX_CHARS))
                text, error = json.dumps(self.call_tool(str(params.get("name")), arguments), indent=1, ensure_ascii=False, default=str), False
            except (ToolError, EdgeConnectError, ValueError, TypeError) as exc:
                text, error = "Error: {}".format(_error_text(exc, str((params.get("arguments") or {}).get("orchestrator") or self.default))), True
            if len(text) > max_chars:
                text = text[:max_chars] + "\n... truncated {} of {} characters; narrow the query or raise max_chars".format(len(text) - max_chars, len(text))
            result = {"content": [{"type": "text", "text": text}], "isError": error}
        else:
            return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32601, "message": "method not found: {}".format(method)}}
        return {"jsonrpc": "2.0", "id": identifier, "result": result}

    def serve(self, stdin: Any = sys.stdin, stdout: Any = sys.stdout) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                response = self.handle(message) if isinstance(message, dict) else {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
            except ValueError:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            if response is not None:
                stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                stdout.flush()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="edgeconnect-mcp", description="MCP server (stdio) for EdgeConnect Orchestrator")
    parser.add_argument("--dotenv", default=os.environ.get("EDGECONNECT_DOTENV"), help="path to the .env file (default: $EDGECONNECT_DOTENV or ./.env)")
    args = parser.parse_args(argv)
    try:
        server = Server.from_dotenv(args.dotenv or (".env" if Path(".env").is_file() else None))
    except EdgeConnectError as exc:
        print("edgeconnect-mcp: {}".format(redact(str(exc))), file=sys.stderr)
        return 2
    server.serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
