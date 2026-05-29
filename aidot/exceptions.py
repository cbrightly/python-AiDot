"""AiDot exception hierarchy."""


class AidotError(Exception):
    """Base exception for all AiDot errors."""


class InvalidURL(AidotError):
    """Invalid URL."""


class HTTPError(AidotError):
    """HTTP request failed."""


class InvalidHost(AidotError):
    """Invalid host."""


class AidotAuthTokenExpired(AidotError):
    """Auth token is invalid or expired."""


class AidotAuthFailed(AidotError):
    """Authentication failed."""


class AidotNotLogin(AidotError):
    """Client is not logged in."""


class AidotUserOrPassIncorrect(AidotError):
    """Username or password is incorrect."""


class AidotOSError(AidotError):
    """OS-level error from the AiDot library."""
