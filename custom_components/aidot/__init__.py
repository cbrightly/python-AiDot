"""The aidot integration."""

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .coordinator import AidotConfigEntry, AidotDeviceManagerCoordinator

PLATFORMS: list[Platform] = [Platform.BUTTON, Platform.CAMERA, Platform.LIGHT, Platform.NUMBER, Platform.SELECT, Platform.SWITCH]


async def async_setup_entry(hass: HomeAssistant, entry: AidotConfigEntry) -> bool:
    """Set up aidot from a config entry."""
    coordinator = AidotDeviceManagerCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: AidotConfigEntry) -> bool:
    """Unload a config entry."""
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    await entry.runtime_data.async_cleanup()
    return ok
