import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

from .errors import ConfigurationError


DEFAULT_DOTENV = ".env"


ALIASES = {
    "base_url": ("orchestrator_base_url", "ORCHESTRATOR_BASE_URL", "EDGECONNECT_BASE_URL", "EC_BASE_URL"),
    "api_key": ("orchestrator_api_key", "ORCHESTRATOR_API_KEY", "EDGECONNECT_API_KEY", "EC_API_KEY"),
    "ca_bundle": ("orchestrator_ca_bundle", "ORCHESTRATOR_CA_BUNDLE", "EDGECONNECT_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"),
    "api_key_header": ("orchestrator_api_key_header", "ORCHESTRATOR_API_KEY_HEADER", "EDGECONNECT_API_KEY_HEADER"),
}
_SLOT = re.compile(r"^orch_(\d+)$")
_NICKNAME = re.compile(r"^[a-z0-9_]+$")
_RESERVED = {"default", "orchestrator", "edgeconnect", "ec"}


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
    alarm_wait: float = 30.0
    allow_http: bool = False
    name: str = ""


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


def _profiles(merged: Mapping[str, str]) -> Dict[str, Dict[str, str]]:
    """orch_<N>=<nickname> slots, in slot order, each read from <nickname>_base_url / _api_key / _ca_bundle / _api_key_header."""
    for key, value in merged.items():
        if key.startswith("orch_") and key != "orch_default" and not _SLOT.match(key):
            name = value.strip().lower() or "<nickname>"
            raise ConfigurationError("{}={}: Orchestrator slots must be numbered, for example orch_2={} with {}_base_url and {}_api_key".format(key, value, name, name, name))
    slots = sorted((int(match.group(1)), key, value.strip().lower()) for key, value in merged.items() for match in [_SLOT.match(key)] if match and value.strip())
    profiles: Dict[str, Dict[str, str]] = {}
    for _, slot, name in slots:
        if not _NICKNAME.match(name) or name in _RESERVED:
            raise ConfigurationError("{}={!r}: an Orchestrator nickname must use letters, digits or _ and must not be one of {}".format(slot, name, ", ".join(sorted(_RESERVED))))
        if name in profiles:
            raise ConfigurationError("Orchestrator nickname {!r} is used by both {} and {}".format(name, profiles[name]["slot"], slot))
        profiles[name] = {"slot": slot}
        for field in ("base_url", "api_key", "ca_bundle", "api_key_header"):
            if merged.get("{}_{}".format(name, field)):
                profiles[name][field] = merged["{}_{}".format(name, field)]
    return profiles


def _host(url: str) -> str:
    return urlsplit(url).netloc or url


def _choose_profile(profiles: Mapping[str, Mapping[str, str]], prompt: Callable[[str], str]) -> str:
    names = list(profiles)
    menu = "\n".join("  {}) {}  {}".format(index, name, _host(profiles[name].get("base_url", "<no URL>"))) for index, name in enumerate(names, 1))
    print("Multiple Orchestrators are configured:\n" + menu, file=sys.stderr)
    answer = prompt("Choose an Orchestrator (number or name): ").strip().lower()
    if answer.isdigit() and 1 <= int(answer) <= len(names):
        return names[int(answer) - 1]
    if answer in profiles:
        return answer
    raise ConfigurationError("unknown Orchestrator choice {!r}; configured: {}".format(answer, ", ".join(names)))


def load_config(
    dotenv_path: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    allow_http: bool = False,
    orchestrator: Optional[str] = None,
    interactive: Optional[bool] = None,
    prompt: Callable[[str], str] = input,
) -> Config:
    dotenv_values: Dict[str, str] = {}
    selected_dotenv = dotenv_path
    if selected_dotenv is None and Path(DEFAULT_DOTENV).is_file():
        selected_dotenv = DEFAULT_DOTENV
    if selected_dotenv:
        dotenv_values.update(parse_dotenv(selected_dotenv))
    environment_values = dict(os.environ if environ is None else environ)

    def configured_value(name: str) -> Optional[str]:
        return _first(environment_values, ALIASES[name]) or _first(dotenv_values, ALIASES[name])

    merged = {key.lower(): value for source in (dotenv_values, environment_values) for key, value in source.items()}
    profiles = _profiles(merged)
    if profiles and configured_value("base_url"):
        # Keep the single-Orchestrator keys selectable instead of silently ignoring them.
        profiles["orchestrator"] = {"slot": "orchestrator_base_url", "base_url": configured_value("base_url") or "", "api_key": configured_value("api_key") or ""}
    name = ""
    if profiles:
        name = (orchestrator or merged.get("orch_default") or "").strip().lower()
        name = next((profile for profile, values in profiles.items() if values["slot"] == name), name)
        if not name and len(profiles) == 1:
            name = next(iter(profiles))
        if not name:
            if not (sys.stdin.isatty() if interactive is None else interactive):
                raise ConfigurationError("multiple Orchestrators are configured ({}); choose one with --orchestrator NAME or set orch_default in .env".format(", ".join(profiles)))
            name = _choose_profile(profiles, prompt)
        if name not in profiles:
            raise ConfigurationError("unknown Orchestrator {!r}; configured: {}".format(name, ", ".join(profiles)))
        profile = profiles[name]
        base_url, api_key = profile.get("base_url"), profile.get("api_key")
        if not base_url or not api_key:
            raise ConfigurationError("Orchestrator {!r} ({}) needs both {}_base_url and {}_api_key".format(name, profile["slot"], name, name))
        ca_bundle = profile.get("ca_bundle") or configured_value("ca_bundle")
        api_key_header = profile.get("api_key_header") or configured_value("api_key_header")
    else:
        if orchestrator:
            raise ConfigurationError("--orchestrator {} was given, but no named Orchestrators are configured; add orch_1={} plus {}_base_url and {}_api_key".format(orchestrator, orchestrator, orchestrator, orchestrator))
        base_url = configured_value("base_url")
        api_key = configured_value("api_key")
        ca_bundle = configured_value("ca_bundle")
        api_key_header = configured_value("api_key_header")
    if not base_url or not api_key:
        raise ConfigurationError("Orchestrator base URL and API key are required; provide them in ./.env, process environment variables, or --dotenv <path>")
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
    if ca_bundle and not Path(ca_bundle).is_file():
        raise ConfigurationError("CA bundle does not exist")
    return Config(
        base_url=normalized_url,
        api_key=api_key,
        ca_bundle=ca_bundle,
        api_key_header=api_key_header or "X-Auth-Token",
        allow_http=allow_http,
        name=name,
    )
