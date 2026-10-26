try:
    from app import can_cancel_appointment
except ImportError:
    from examples.authorization_demo.app import can_cancel_appointment


def test_owner_can_cancel_appointment():
    assert can_cancel_appointment("user-17", "user-17")


def test_other_user_cannot_cancel_appointment():
    assert not can_cancel_appointment("user-22", "user-17")
