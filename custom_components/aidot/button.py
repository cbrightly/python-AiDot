"""PTZ button entities for Aidot cameras."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AidotCameraUpdateCoordinator, AidotConfigEntry


@dataclass(frozen=True, kw_only=True)
class AidotButtonDescription(ButtonEntityDescription):
    """Describes an Aidot PTZ button."""

    async_press_fn: object = None  # async callable(DeviceClient) -> bool


PTZ_BUTTONS: tuple[AidotButtonDescription, ...] = (
    AidotButtonDescription(
        key="ptz_up",
        translation_key="ptz_up",
        icon="mdi:arrow-up-circle-outline",
        async_press_fn=lambda c: c.async_ptz_move("up"),
    ),
    AidotButtonDescription(
        key="ptz_down",
        translation_key="ptz_down",
        icon="mdi:arrow-down-circle-outline",
        async_press_fn=lambda c: c.async_ptz_move("down"),
    ),
    AidotButtonDescription(
        key="ptz_left",
        translation_key="ptz_left",
        icon="mdi:arrow-left-circle-outline",
        async_press_fn=lambda c: c.async_ptz_move("left"),
    ),
    AidotButtonDescription(
        key="ptz_right",
        translation_key="ptz_right",
        icon="mdi:arrow-right-circle-outline",
        async_press_fn=lambda c: c.async_ptz_move("right"),
    ),
    AidotButtonDescription(
        key="ptz_stop",
        translation_key="ptz_stop",
        icon="mdi:stop-circle-outline",
        async_press_fn=lambda c: c.async_ptz_stop(),
    ),
    AidotButtonDescription(
        key="ptz_zoom_in",
        translation_key="ptz_zoom_in",
        icon="mdi:magnify-plus-outline",
        async_press_fn=lambda c: c.async_ptz_move("zoom_in"),
    ),
    AidotButtonDescription(
        key="ptz_zoom_out",
        translation_key="ptz_zoom_out",
        icon="mdi:magnify-minus-outline",
        async_press_fn=lambda c: c.async_ptz_move("zoom_out"),
    ),
)


def _is_ptz_camera(coordinator: AidotCameraUpdateCoordinator) -> bool:
    """Return True if the camera supports PTZ (model A001064)."""
    model_id = coordinator.device_client.info.model_id or ""
    return "A001064" in model_id


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AidotConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Aidot PTZ buttons."""
    coordinator = entry.runtime_data
    registered: set[str] = set()

    def _add_new_buttons() -> None:
        new_coords = {
            dev_id: c
            for dev_id, c in coordinator.camera_coordinators.items()
            if dev_id not in registered and _is_ptz_camera(c)
        }
        new = [
            AidotPtzButton(c, desc)
            for c in new_coords.values()
            for desc in PTZ_BUTTONS
        ]
        if new:
            registered.update(new_coords)
            async_add_entities(new)

    _add_new_buttons()
    entry.async_on_unload(coordinator.async_add_listener(lambda: _add_new_buttons()))


class AidotPtzButton(CoordinatorEntity[AidotCameraUpdateCoordinator], ButtonEntity):
    """A button that sends one PTZ command when pressed."""

    _attr_has_entity_name = True
    entity_description: AidotButtonDescription

    def __init__(
        self,
        coordinator: AidotCameraUpdateCoordinator,
        description: AidotButtonDescription,
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

    async def async_press(self) -> None:
        await self.entity_description.async_press_fn(self.coordinator.device_client)
