// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

// Fixture: basic Go entities
// Expected: 2 functions, 1 struct

package user

type UserProfile struct {
	Name  string
	Email string
}

func CreateUser(name, email string) UserProfile {
	return UserProfile{Name: name, Email: email}
}

func helperInternal() int {
	return 42
}
