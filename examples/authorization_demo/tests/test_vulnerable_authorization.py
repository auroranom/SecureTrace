try:
    from vulnerable_app import can_cancel_appointment
except ImportError:
    from examples.authorization_demo.vulnerable_app import can_cancel_appointment


def test_other_user_cannot_cancel_appointment_on_vulnerable_control():
    # This approved negative demonstration must fail against vulnerable_app.py.
    assert not can_cancel_appointment("user-22", "user-17")
