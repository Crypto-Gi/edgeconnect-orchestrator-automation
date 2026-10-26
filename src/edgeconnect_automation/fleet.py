"""Fleet status: check every configured Orchestrator at once and say green, amber or red, with a plain reason.

Green: connected, the key works, release 9.3 or later, and the serial number is readable.
Amber: usable, with one thing to know (slow, busy, or no readable serial number).
Red: not usable as configured (missing or bad settings, no answer, key refused, too old, server error).
"""
import dataclasses
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, List, Mapping, Optional
from urllib.parse import urlsplit

from .client import ApiClient
from .config import load_config, orchestrator_profiles
from .errors import AuthenticationError, ConfigurationError, EdgeConnectError, PermissionDeniedError, RateLimitError, ServerError, TransportError
from .gateway import OrchestratorGateway, require_supported_release

GREEN, AMBER, RED = "green", "amber", "red"
CHECK_SECONDS = 5.0
SLOW_SECONDS = 2.0
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_ON, _OFF = {"on", "true", "yes", "1"}, {"off", "false", "no", "0", ""}


@dataclasses.dataclass(frozen=True)
class Status:
    name: str
    url: str
    status: str
    reason: str
    release: str = ""
    id: str = ""
    label: str = ""
    color: str = ""
    writes: bool = False
    seconds: float = 0.0


def check_all(
    dotenv_path: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    timeout: float = CHECK_SECONDS,
    client_factory: Callable[[Any], Any] = ApiClient,
    clock: Callable[[], float] = time.monotonic,
) -> List[Status]:
    """One Status per configured Orchestrator, in menu order; all are checked in parallel, each read gets one try of `timeout` seconds."""
    profiles = orchestrator_profiles(dotenv_path, environ)
    names = list(profiles) or [""]

    def check(name: str) -> Status:
        return _check(name, profiles.get(name, {}), dotenv_path, environ, timeout, client_factory, clock)

    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        return list(pool.map(check, names))


def _check(name: str, profile: Mapping[str, str], dotenv_path: Optional[str], environ: Optional[Mapping[str, str]], timeout: float, client_factory: Callable[[Any], Any], clock: Callable[[], float]) -> Status:
    url = _origin(profile.get("base_url", ""))
    try:
        gui = _gui_settings(name, profile)
        config = load_config(dotenv_path, environ, orchestrator=name or None, interactive=False)
    except ConfigurationError as error:
        return Status(name, url, RED, "fix the settings: {}".format(error))
    url = _origin(config.base_url)
    config = dataclasses.replace(config, timeout=timeout, max_read_attempts=1)
    gateway = OrchestratorGateway(client_factory(config))
    start = clock()
    try:
        release = require_supported_release(gateway.get_version())
        server_id = gateway.get_server_id()
    except RateLimitError:
        return Status(name, url, AMBER, "Orchestrator is busy (HTTP 429); check again shortly", **gui)
    except (AuthenticationError, PermissionDeniedError) as error:
        return Status(name, url, RED, "the API key was refused (HTTP {})".format(error.status), **gui)
    except ServerError as error:
        return Status(name, url, RED, "Orchestrator answered with a server error (HTTP {})".format(error.status), **gui)
    except TransportError as error:
        return Status(name, url, RED, _transport_reason(error, timeout), **gui)
    except EdgeConnectError as error:
        return Status(name, url, RED, str(error), **gui)
    seconds = round(clock() - start, 2)
    found = dict(release=release, id=server_id, seconds=seconds, **gui)
    if not server_id:
        return Status(name, url, AMBER, "connected (release {}), but the serial number is not readable, so a different Orchestrator at this address would not be noticed".format(release), **found)
    if seconds > SLOW_SECONDS:
        return Status(name, url, AMBER, "connected (release {}), but slow: {} s to answer".format(release, seconds), **found)
    return Status(name, url, GREEN, "connected (release {})".format(release), **found)


def _gui_settings(name: str, profile: Mapping[str, str]) -> dict:
    color = profile.get("gui_color", "")
    if color and not _COLOR.match(color):
        raise ConfigurationError("{}_gui_color must be a colour like #1f6feb".format(name))
    writes = profile.get("gui_writes", "").strip().lower()
    if writes not in _ON | _OFF:
        raise ConfigurationError("{}_gui_writes must be on or off".format(name))
    return {"label": profile.get("gui_label", ""), "color": color, "writes": writes in _ON}


def _origin(base_url: str) -> str:
    parts = urlsplit(base_url)
    return "{}://{}".format(parts.scheme, parts.netloc) if parts.netloc else ""


def _transport_reason(error: TransportError, timeout: float) -> str:
    cause = error.__cause__
    cause = getattr(cause, "reason", cause)  # URLError wraps the socket error
    if isinstance(cause, (TimeoutError, socket.timeout)):
        return "no answer within {:g} s".format(timeout)
    if isinstance(cause, ssl.SSLError):
        return "the certificate was not accepted; check the CA bundle or the certificate pin"
    if isinstance(cause, socket.gaierror):
        return "the address could not be found (DNS)"
    if isinstance(cause, ConnectionRefusedError):
        return "the connection was refused"
    return str(error)
