// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: basic C entities
// Expected: 2 functions, 1 struct, 1 constant

struct UserProfile {
    const char* name;
    const char* email;
};

static const int DEFAULT_PORT = 8080;

int helper_internal(void) {
    return DEFAULT_PORT;
}

struct UserProfile create_user(const char* name, const char* email) {
    struct UserProfile profile = {name, email};
    return profile;
}
