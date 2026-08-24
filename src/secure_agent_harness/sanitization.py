"""Deterministic sanitization from raw synthetic records to safe aliases."""

from collections.abc import Mapping

from .contracts import SanitizedInstance

_STATE_ALIASES = {
    "pending": "PENDING",
    "running": "RUNNING",
    "stopped": "STOPPED",
    "terminated": "TERMINATED",
}

_SIZE_ALIASES = {
    "INSTANCE_TYPE_LARGE": "LARGE",
    "INSTANCE_TYPE_MEDIUM": "MEDIUM",
    "INSTANCE_TYPE_SMALL": "SMALL",
}


def sanitize_instance_record(
    raw: Mapping[str, object], resource_alias: str
) -> SanitizedInstance:
    """Return only allow-listed aliases and normalized state metadata."""

    if "InstanceId" not in raw or "State" not in raw:
        raise ValueError("Raw instance record is missing required fields.")

    raw_state = raw["State"]
    state_name = raw_state.get("Name") if isinstance(raw_state, Mapping) else None
    state = _STATE_ALIASES.get(state_name, "UNKNOWN") if isinstance(state_name, str) else "UNKNOWN"

    raw_instance_type = raw.get("InstanceType")
    size_class = (
        _SIZE_ALIASES.get(raw_instance_type, "UNKNOWN")
        if isinstance(raw_instance_type, str)
        else "UNKNOWN"
    )

    return SanitizedInstance(
        resource_alias=resource_alias,
        environment="SYNTHETIC_LAB",
        state=state,
        size_class=size_class,
    )
