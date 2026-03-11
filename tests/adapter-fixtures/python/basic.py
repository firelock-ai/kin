# Fixture: basic Python entities
# Expected: 2 functions, 1 class

class UserService:
    """Manages user accounts."""

    def __init__(self):
        self.users = []

    def add_user(self, name: str, email: str) -> None:
        self.users.append({"name": name, "email": email})


def create_user(name: str, email: str) -> dict:
    """Create a new user dict."""
    return {"name": name, "email": email}


def _helper_internal() -> int:
    return 42
