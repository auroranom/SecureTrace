"""A tiny local authorization control used by the SecureTrace demo."""


def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:
    """Only the authenticated appointment owner may cancel it."""
    return bool(actor_id) and actor_id == appointment_owner_id
