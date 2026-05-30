"""Support for Aidot camera select entities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AidotConfigEntry, AidotDeviceUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class AidotSelectDescription(SelectEntityDescription):
    """Describes an Aidot camera select entity."""

    get_current_option: Any = None       # callable(DeviceStatusData) -> str | None
    async_select_option_fn: Any = None   # async callable(DeviceClient, str) -> None


CAMERA_SELECTS: tuple[AidotSelectDescription, ...] = (
    AidotSelectDescription(
        key="night_vision",
        translation_key="night_vision",
        icon="mdi:weather-night",
        options=["auto", "on", "off"],
        get_current_option=lambda s: s.night_vision_mode,
        async_select_option_fn=lambda c, v: c.async_set_night_vision(v),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AidotConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Aidot camera select entities."""
    coordinator = entry.runtime_data
    registered: set[str] = set()

    def _add_new_selects() -> None:
        new_coords = {
            dev_id: c
            for dev_id, c in coordinator.camera_coordinators.items()
            if dev_id not in registered
        }
        new = [
            AidotCameraSelect(c, desc)
            for c in new_coords.values()
            for desc in CAMERA_SELECTS
        ]
        if new:
            registered.update(new_coords)
            async_add_entities(new)

    _add_new_selects()
    entry.async_on_unload(coordinator.async_add_listener(lambda: _add_new_selects()))


class AidotCameraSelect(CoordinatorEntity[AidotDeviceUpdateCoordinator], SelectEntity):
    """A select entity for an Aidot camera setting."""

    _attr_has_entity_name = True
    entity_description: AidotSelectDescription

    def __init__(
        self,
        coordinator: AidotDeviceUpdateCoordinator,
        description: AidotSelectDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        info = coordinator.device_client.info
        self._attr_unique_id = f"{info.dev_id}_{description.key}"
        self._attr_options = list(description.options)

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

    @property
    def current_option(self) -> str | None:
        if self.coordinator.data is None:
            return None
        return self.entity_description.get_current_option(self.coordinator.data)

    async def async_select_option(self, option: str) -> None:
        await self.entity_description.async_select_option_fn(
            self.coordinator.device_client, option
        )
        self.async_write_ha_state()
