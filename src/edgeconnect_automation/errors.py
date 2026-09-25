from typing import Any, List, Mapping, Optional, Sequence


class EdgeConnectError(Exception):
    exit_code = 1


class ConfigurationError(EdgeConnectError):
    exit_code = 2


class ValidationError(EdgeConnectError):
    exit_code = 2

    def __init__(self, message: str = "", issues: Optional[Sequence[Mapping[str, Any]]] = None) -> None:
        super().__init__(message)
        self.issues: List[Mapping[str, Any]] = list(issues or [])


class ApprovalError(EdgeConnectError):
    exit_code = 3


class DriftError(EdgeConnectError):
    exit_code = 4


class PartialError(EdgeConnectError):
    exit_code = 5


class ApiError(EdgeConnectError):
    def __init__(self, message: str, status: Optional[int] = None, method: str = "", path: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.method = method
        self.path = path


class AuthenticationError(ApiError):
    pass


class PermissionDeniedError(ApiError):
    pass


class ResourceNotFoundError(ApiError):
    pass


class ConflictError(ApiError):
    pass


class RateLimitError(ApiError):
    pass


class ServerError(ApiError):
    pass


class TransportError(ApiError):
    pass


class ResponseFormatError(ApiError):
    pass
