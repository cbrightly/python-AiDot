"""Support for Aidot cameras."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AidotConfigEntry, AidotDeviceUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

# go2rtc RTSP server defaults (HA OS / Supervised built-in).
# Override via AIDOT_GO2RTC_RTSP_BASE env var or coordinator config.
_GO2RTC_RTSP_BASE = "rtsp://127.0.0.1:8554"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AidotConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Aidot camera entities."""
    coordinator = entry.runtime_data
    async_add_entities(
        AidotCamera(device_coordinator)
        for device_coordinator in coordinator.camera_coordinators.values()
    )


class AidotCamera(CoordinatorEntity[AidotDeviceUpdateCoordinator], Camera):
    """Representation of an Aidot IP camera."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, coordinator: AidotDeviceUpdateCoordinator) -> None:
        CoordinatorEntity.__init__(self, coordinator)
        Camera.__init__(self)
        info = coordinator.device_client.info
        self._attr_unique_id = info.dev_id

        model_id = info.model_id or ""
        manufacturer = model_id.split(".")[0] if model_id else "AiDot"
        model = model_id[len(manufacturer) + 1:] if model_id else model_id
        mac = info.mac or ""

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, info.dev_id)},
            connections={(CONNECTION_NETWORK_MAC, mac)} if mac else set(),
            manufacturer=manufacturer,
            model=model,
            name=info.name,
            hw_version=info.hw_version,
        )

        # Sanitised device ID safe to use as an RTSP stream name.
        self._rtsp_name = info.dev_id.replace("/", "_").replace(":", "_")
        # Cache for the last successfully fetched thumbnail bytes
        self._cached_image: bytes | None = None
        self._image_lock = asyncio.Lock()

    async def async_stream_source(self) -> Optional[str]:
        """Return RTSP URL for HA stream integration (go2rtc → WebRTC browser).

        Starts a keepalive stream on first call so subsequent viewer connections
        are served immediately from the already-warm session.  The first call
        will still take 25-70s for SDES cameras while the SCTP handshake runs.

        Returns None if go2rtc is not available; HA falls back to MJPEG.
        """
        dc = self.coordinator.device_client
        rtsp_url = f"{_GO2RTC_RTSP_BASE}/{self._rtsp_name}"

        if dc.stream_rtsp_url is None:
            # Start keepalive — fires and forgets; stream warms up in background.
            try:
                await dc.start_keepalive(rtsp_push_url=rtsp_url)
                _LOGGER.info(
                    "Started RTSP keepalive for %s → %s", self._rtsp_name, rtsp_url
                )
            except Exception as exc:
                _LOGGER.warning(
                    "Failed to start keepalive for %s: %s", self._rtsp_name, exc
                )
                return None

        return rtsp_url

    async def async_camera_image(
        self,
        width: int | None = None,
        height: int | None = None,
    ) -> bytes | None:
        """Return the latest JPEG from the background stream, or a cloud thumbnail."""
        # Prefer the persistent stream buffer (updated by the library every ~1s).
        live = self.coordinator.device_client.latest_jpeg
        if live is not None:
            return live

        # Fallback: fetch the most recent cloud event thumbnail.
        async with self._image_lock:
            url = await self.coordinator.device_client.async_get_latest_thumbnail()
            if not url:
                return self._cached_image

            try:
                session = async_get_clientsession(self.hass)
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        self._cached_image = await resp.read()
                        return self._cached_image
            except Exception as exc:
                _LOGGER.debug("Thumbnail fetch failed for %s: %s", self.unique_id, exc)

            return self._cached_image
