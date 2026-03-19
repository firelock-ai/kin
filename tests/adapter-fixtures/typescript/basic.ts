// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

// Fixture: basic TypeScript entities
// Expected: 2 functions, 1 class, 1 interface

export interface UserProfile {
  name: string;
  email: string;
}

export class UserService {
  private users: UserProfile[] = [];

  addUser(user: UserProfile): void {
    this.users.push(user);
  }
}

export function createUser(name: string, email: string): UserProfile {
  return { name, email };
}

function helperInternal(): number {
  return 42;
}
