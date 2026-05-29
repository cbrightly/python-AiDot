"""AiDot camera and device library."""

from .client import AidotClient
from .device_client import DeviceClient
from .discover import Discover
from .exceptions import (
    AidotAuthFailed,
    AidotAuthTokenExpired,
    AidotError,
    AidotNotLogin,
    AidotOSError,
    AidotUserOrPassIncorrect,
    HTTPError,
    InvalidHost,
    InvalidURL,
)

__all__ = [
    "AidotClient",
    "DeviceClient",
    "Discover",
    "AidotError",
    "AidotAuthFailed",
    "AidotAuthTokenExpired",
    "AidotNotLogin",
    "AidotOSError",
    "AidotUserOrPassIncorrect",
    "HTTPError",
    "InvalidHost",
    "InvalidURL",
]
