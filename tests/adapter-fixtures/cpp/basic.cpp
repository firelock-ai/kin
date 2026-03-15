// Fixture: basic C++ entities
// Expected: 1 class, 2 functions

class UserService {
public:
    UserService() = default;

    int count() const {
        return 1;
    }
};

static int helper_internal() {
    return 42;
}

int create_user() {
    UserService service;
    return service.count() + helper_internal();
}
