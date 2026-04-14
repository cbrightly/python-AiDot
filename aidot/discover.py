import re
import socket
import json
import time
import logging
import asyncio
import subprocess
import sys
from typing import Any, List, Tuple

from .aes_utils import aes_encrypt, aes_decrypt
from .const import CONF_ID, CONF_IPADDRESS
from .exceptions import AidotOSError

_LOGGER = logging.getLogger(__name__)
_DISCOVER_TIME = 5


def _get_broadcast_candidates() -> List[Tuple[str, str]]:
    """Return (bind_ip, broadcast_ip) pairs for every active IPv4 interface.

    Sends a separate broadcast per interface so cameras are reachable
    regardless of which interface the OS default route prefers.
    Falls back to a single ("0.0.0.0", "255.255.255.255") entry if
    interface enumeration is unavailable.
    """
    results: List[Tuple[str, str]] = []
    try:
        if sys.platform == "darwin":
            # macOS ifconfig: "inet 192.168.1.175 netmask 0xffffff00 broadcast 192.168.1.255"
            out = subprocess.check_output(
                ["/sbin/ifconfig"], text=True, stderr=subprocess.DEVNULL
            )
            for m in re.finditer(
                r"\binet\s+"
                r"((?!127\.|169\.254\.)\d+\.\d+\.\d+\.\d+)"
                r"\s+netmask\s+\S+"
                r"\s+broadcast\s+"
                r"(\d+\.\d+\.\d+\.\d+)",
                out,
            ):
                results.append((m.group(1), m.group(2)))
        else:
            # Linux: "inet 192.168.1.x/24 brd 192.168.1.255"
            out = subprocess.check_output(
                ["ip", "addr", "show"], text=True, stderr=subprocess.DEVNULL
            )
            for m in re.finditer(
                r"\binet\s+"
                r"((?!127\.|169\.254\.)\d+\.\d+\.\d+\.\d+)/\d+"
                r"\s+brd\s+"
                r"(\d+\.\d+\.\d+\.\d+)",
                out,
            ):
                results.append((m.group(1), m.group(2)))
    except Exception as exc:
        _LOGGER.debug("_get_broadcast_candidates: interface enumeration failed: %s", exc)

    if not results:
        # Fallback: let the OS pick the outgoing interface
        results = [("0.0.0.0", "255.255.255.255")]

    _LOGGER.debug("_get_broadcast_candidates: %s", results)
    return results


class BroadcastProtocol:
    _is_closed = False

    def __init__(self, callback, user_id, broadcast_addr: str = "255.255.255.255") -> None:
        self.aes_key = bytearray(32)
        key_string = "T54uednca587"
        key_bytes = key_string.encode()
        self.aes_key[: len(key_bytes)] = key_bytes

        self._discover_cb = callback
        self.user_id = user_id
        self._broadcast_addr = broadcast_addr

    def connection_made(self, transport) -> None:
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def send_broadcast(self) -> None:
        if self._is_closed:
            _LOGGER.error("%s: connection is closed", self.user_id)
            return
        current_timestamp_milliseconds = int(time.time() * 1000)
        seq = str(current_timestamp_milliseconds + 1)[-9:]
        message = {
            "protocolVer": "2.0.0",
            "service": "device",
            "method": "devDiscoveryReq",
            "seq": seq,
            "srcAddr": f"0.{self.user_id}]",
            "tst": current_timestamp_milliseconds,
            "payload": {
                "extends": {},
                "localCtrFlag": 1,
                "timestamp": str(current_timestamp_milliseconds),
            },
        }
        send_data = aes_encrypt(json.dumps(message).encode(), self.aes_key)
        try:
            sock = self.transport.get_extra_info("socket")
            local_addr = sock.getsockname() if sock else ("?", 0)
            self.transport.sendto(send_data, (self._broadcast_addr, 6666))
            _LOGGER.info(
                "discovery broadcast sent: %s:%s → %s:6666",
                local_addr[0], local_addr[1], self._broadcast_addr,
            )
        except Exception as error:
            _LOGGER.error("%s: send failed: %s", self.user_id, error)

    def datagram_received(self, data, addr) -> None:
        try:
            data_str = aes_decrypt(data, self.aes_key)
            data_json = json.loads(data_str)
        except Exception as exc:
            _LOGGER.debug("discovery: ignored undecodable packet from %s: %s", addr, exc)
            return
        if "payload" in data_json and "mac" in data_json["payload"]:
            devId = data_json["payload"]["devId"]
            if self._discover_cb:
                self._discover_cb(devId, {CONF_IPADDRESS: addr[0]})

    def error_received(self, exc) -> None:
        _LOGGER.error("%s: error occurred: %s", self.user_id, exc)

    def close(self) -> None:
        try:
            self.transport.close()
        except Exception as error:
            _LOGGER.error("close error: %s", error)

    def connection_lost(self, exc) -> None:
        self._is_closed = True
        if exc:
            _LOGGER.error("%s: connection lost: %s", self.user_id, exc)
        else:
            _LOGGER.info("%s: connection closed", self.user_id)


class Discover:
    _login_info: dict[str, Any] = None
    discovered_device: dict[str, str]
    _is_close: bool = False

    def __init__(self, login_info, callback):
        self.discovered_device = {}
        self._login_info = login_info
        self._callback = callback
        self._protocols: List[BroadcastProtocol] = []

    async def _ensure_sockets(self) -> None:
        """Create one datagram endpoint per active interface (idempotent)."""
        if self._protocols:
            return

        candidates = _get_broadcast_candidates()
        user_id = self._login_info[CONF_ID]

        for bind_ip, broadcast_ip in candidates:
            protocol = BroadcastProtocol(
                self._discover_callback, user_id, broadcast_addr=broadcast_ip
            )
            try:
                await asyncio.get_event_loop().create_datagram_endpoint(
                    lambda p=protocol: p,
                    local_addr=(bind_ip, 0),
                )
                self._protocols.append(protocol)
                _LOGGER.debug(
                    "discovery socket: bind=%s  broadcast=%s", bind_ip, broadcast_ip
                )
            except OSError as exc:
                _LOGGER.debug(
                    "discovery socket bind %s failed: %s", bind_ip, exc
                )

        if not self._protocols:
            # Last-resort fallback
            protocol = BroadcastProtocol(self._discover_callback, user_id)
            try:
                await asyncio.get_event_loop().create_datagram_endpoint(
                    lambda: protocol,
                    local_addr=("0.0.0.0", 0),
                )
                self._protocols.append(protocol)
            except OSError:
                raise AidotOSError

    # ---------------------------------------------------------------------- #
    # Public API (kept compatible with existing callers)
    # ---------------------------------------------------------------------- #

    async def try_create_broadcast(self) -> None:
        await self._ensure_sockets()

    async def send_broadcast(self) -> None:
        await self._ensure_sockets()
        for proto in self._protocols:
            proto.send_broadcast()

    async def repeat_broadcast(self) -> None:
        self._is_close = False
        while True:
            await self.send_broadcast()
            for _ in range(_DISCOVER_TIME):
                await asyncio.sleep(1)
                if self._is_close:
                    return

    async def fetch_devices_info(self) -> dict[str, str]:
        await self.send_broadcast()
        await asyncio.sleep(2)
        return self.discovered_device

    def _discover_callback(self, dev_id, event: dict[str, str]) -> None:
        self.discovered_device[dev_id] = event[CONF_IPADDRESS]
        if self._callback:
            self._callback(dev_id, event)

    def close(self) -> None:
        self._is_close = True
        for proto in self._protocols:
            proto.close()
        self._protocols.clear()
