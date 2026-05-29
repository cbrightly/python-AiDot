"""Coordinator for Aidot."""

from datetime import timedelta
import logging

from aidot.client import AidotClient
from aidot.const import (
    CONF_ACCESS_TOKEN,
    CONF_AES_KEY,
    CONF_DEVICE_LIST,
    CONF_ID,
    CONF_PRODUCT,
    CONF_SERVICE_MODULES,
    CONF_IDENTITY,
    CONF_MODEL_ID,
)
from aidot.device_client import DeviceClient, DeviceStatusData
from aidot.exceptions import AidotAuthFailed, AidotUserOrPassIncorrect

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN

type AidotConfigEntry = ConfigEntry[AidotDeviceManagerCoordinator]
_LOGGER = logging.getLogger(__name__)

UPDATE_DEVICE_LIST_INTERVAL = timedelta(hours=6)
UPDATE_CAMERA_ATTRS_INTERVAL = timedelta(minutes=5)

_CONF_TYPE = "type"


def _is_camera_device(device: dict) -> bool:
    """Return True if the device is a camera (IPC model or camera service module)."""
    model = (device.get(CONF_MODEL_ID) or "").upper()
    if "IPC" in model:
        return True
    product = device.get(CONF_PRODUCT) or {}
    for module in product.get(CONF_SERVICE_MODULES) or []:
        ident = (module.get(CONF_IDENTITY) or "").lower()
        if "camera" in ident or "ipc" in ident:
            return True
    return False


def _is_light_device(device: dict) -> bool:
    """Return True if the device is a light (has aesKey and type=light)."""
    return (
        device.get(_CONF_TYPE) == "light"
        and CONF_AES_KEY in device
        and device[CONF_AES_KEY][0] is not None
    )


class AidotDeviceUpdateCoordinator(DataUpdateCoordinator[DeviceStatusData]):
    """Manage data for a single Aidot light device (TCP push updates)."""

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: AidotConfigEntry,
        device_client: DeviceClient,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=None,
        )
        self.device_client = device_client

    async def _async_setup(self) -> None:
        self.device_client.set_status_fresh_cb(self._handle_status_update)

    def _handle_status_update(self, status: DeviceStatusData) -> None:
        self.async_set_updated_data(status)

    async def _async_update_data(self) -> DeviceStatusData:
        return self.device_client.status


class AidotCameraUpdateCoordinator(AidotDeviceUpdateCoordinator):
    """Manage data for a single Aidot camera device (MQTT polled attributes)."""

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: AidotConfigEntry,
        device_client: DeviceClient,
    ) -> None:
        super().__init__(hass, config_entry, device_client)
        self.update_interval = UPDATE_CAMERA_ATTRS_INTERVAL

    async def _async_setup(self) -> None:
        # Camera devices don't push status via TCP — skip set_status_fresh_cb.
        # Start persistent WebRTC stream (no-op for SDES cameras).
        await self.device_client.async_start_streaming()

    async def _async_update_data(self) -> DeviceStatusData:
        try:
            attrs = await self.device_client.async_get_camera_attributes()
            if attrs:
                self.device_client.status.update_from_camera_attributes(attrs)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug(
                "Camera attribute poll failed for %s (will retry): %s",
                self.device_client.device_id, exc,
            )
        return self.device_client.status


class AidotDeviceManagerCoordinator(DataUpdateCoordinator[None]):
    """Manage the full AiDot device list and spawn per-device coordinators."""

    config_entry: AidotConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: AidotConfigEntry,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=UPDATE_DEVICE_LIST_INTERVAL,
        )
        self.client = AidotClient(
            session=async_get_clientsession(hass),
            token=config_entry.data,
        )
        self.client.set_token_fresh_cb(self.token_fresh_cb)
        self.device_coordinators: dict[str, AidotDeviceUpdateCoordinator] = {}
        self.camera_coordinators: dict[str, AidotCameraUpdateCoordinator] = {}

    async def _async_setup(self) -> None:
        try:
            await self.async_auto_login()
        except AidotUserOrPassIncorrect as error:
            raise ConfigEntryAuthFailed from error

    async def _async_update_data(self) -> None:
        try:
            data = await self.client.async_get_all_device()
        except AidotAuthFailed as error:
            raise ConfigEntryAuthFailed from error

        all_devices = data[CONF_DEVICE_LIST]

        current_lights = {
            d[CONF_ID]: d for d in all_devices if _is_light_device(d)
        }
        self._sync_light_coordinators(current_lights)

        current_cameras = {
            d[CONF_ID]: d for d in all_devices if _is_camera_device(d)
        }
        self._sync_camera_coordinators(current_cameras)

    def _sync_light_coordinators(self, current: dict[str, dict]) -> None:
        self._sync_coordinators(self.device_coordinators, current, is_camera=False)

    def _sync_camera_coordinators(self, current: dict[str, dict]) -> None:
        self._sync_coordinators(self.camera_coordinators, current, is_camera=True)

    def _sync_coordinators(
        self,
        coord_dict: dict[str, AidotDeviceUpdateCoordinator],
        current: dict[str, dict],
        *,
        is_camera: bool,
    ) -> None:
        removed = set(coord_dict) - set(current)
        for dev_id in removed:
            coord_dict.pop(dev_id).device_client.set_status_fresh_cb(None)
        if removed:
            self._purge_deleted_entries()
        for dev_id, device in current.items():
            if dev_id not in coord_dict:
                dc = self.client.get_device_client(device)
                coord: AidotDeviceUpdateCoordinator
                if is_camera:
                    coord = AidotCameraUpdateCoordinator(
                        self.hass, self.config_entry, dc
                    )
                else:
                    coord = AidotDeviceUpdateCoordinator(
                        self.hass, self.config_entry, dc
                    )
                self.hass.async_create_task(
                    coord.async_config_entry_first_refresh()
                )
                coord_dict[dev_id] = coord

    async def async_cleanup(self) -> None:
        for coord in self.device_coordinators.values():
            coord.device_client.set_status_fresh_cb(None)
        for coord in self.camera_coordinators.values():
            await coord.device_client.async_stop_streaming()
        await self.client.async_cleanup()

    def token_fresh_cb(self) -> None:
        self.hass.config_entries.async_update_entry(
            self.config_entry, data=self.client.login_info.copy()
        )

    async def async_auto_login(self) -> None:
        if self.client.login_info.get(CONF_ACCESS_TOKEN) is None:
            await self.client.async_post_login()

    def _purge_deleted_entries(self) -> None:
        device_reg = dr.async_get(self.hass)
        all_ids = {
            (DOMAIN, c.device_client.info.dev_id)
            for c in list(self.device_coordinators.values())
            + list(self.camera_coordinators.values())
        }
        for device in dr.async_entries_for_config_entry(
            device_reg, self.config_entry.entry_id
        ):
            if not set(device.identifiers) & all_ids:
                _LOGGER.debug("Removing obsolete device entry %s", device.name)
                device_reg.async_update_device(
                    device.id, remove_config_entry_id=self.config_entry.entry_id
                )
