"""Number entities for Aidot cameras (e.g. motion detection sensitivity)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.number import NumberEntity, NumberEntityDescription, NumberMode
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AidotCameraUpdateCoordinator, AidotConfigEntry


@dataclass(frozen=True, kw_only=True)
class AidotNumberDescription(NumberEntityDescription):
    """Describes an Aidot camera number entity."""

    get_value: Any = None          # callable(DeviceStatusData) -> float | None
    async_set_fn: Any = None       # async callable(DeviceClient, float) -> bool


CAMERA_NUMBERS: tuple[AidotNumberDescription, ...] = (
    AidotNumberDescription(
        key="motion_sensitivity",
        translation_key="motion_sensitivity",
        icon="mdi:motion-sensor",
        native_min_value=1,
        native_max_value=5,
        native_step=1,
        mode=NumberMode.SLIDER,
        get_value=lambda s: s.motion_sensitivity,
        async_set_fn=lambda c, v: c.async_set_motion_sensitivity(int(v)),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AidotConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Aidot camera number entities."""
    coordinator = entry.runtime_data
    entities: list[AidotCameraNumber] = []
    for device_coordinator in coordinator.camera_coordinators.values():
        for description in CAMERA_NUMBERS:
            entities.append(AidotCameraNumber(device_coordinator, description))
    async_add_entities(entities)


class AidotCameraNumber(CoordinatorEntity[AidotCameraUpdateCoordinator], NumberEntity):
    """A number entity for an Aidot camera setting."""

    _attr_has_entity_name = True
    entity_description: AidotNumberDescription

    def __init__(
        self,
        coordinator: AidotCameraUpdateCoordinator,
        description: AidotNumberDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        info = coordinator.device_client.info
        self._attr_unique_id = f"{info.dev_id}_{description.key}"

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
    def native_value(self) -> float | None:
        if self.coordinator.data is None:
            return None
        return self.entity_description.get_value(self.coordinator.data)

    async def async_set_native_value(self, value: float) -> None:
        await self.entity_description.async_set_fn(self.coordinator.device_client, value)
        self.async_write_ha_state()
