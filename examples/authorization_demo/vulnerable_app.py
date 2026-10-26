"""Intentionally vulnerable control for the negative regression demonstration."""


def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:
    # Deliberately wrong: this legacy implementation does not authorize owner access.
    return bool(actor_id)
