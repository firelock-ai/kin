"""Tiny source fixture for the public quickstart smoke."""


def apply_quickstart_discount(subtotal_cents: int) -> int:
    """Apply the fixture's one deterministic checkout rule."""
    if subtotal_cents >= 5_000:
        return subtotal_cents - 500
    return subtotal_cents


def quickstart_checkout_total(subtotal_cents: int) -> int:
    """Return the checkout total through the rule the smoke locates."""
    return apply_quickstart_discount(subtotal_cents)
