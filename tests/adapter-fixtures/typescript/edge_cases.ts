// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: TypeScript edge cases
// Tests: generics, decorators, abstract classes, enums, type guards,
// mapped types, conditional types, async/await, namespace

export interface Repository<T> {
  findById(id: string): Promise<T | null>;
  findAll(): Promise<T[]>;
  save(entity: T): Promise<T>;
  delete(id: string): Promise<boolean>;
}

export abstract class BaseEntity {
  abstract get id(): string;

  isNew(): boolean {
    return !this.id;
  }
}

export class User extends BaseEntity {
  constructor(
    private _id: string,
    public name: string,
    public email: string,
  ) {
    super();
  }

  get id(): string {
    return this._id;
  }
}

// Enum with string values
export enum UserRole {
  Admin = "admin",
  Editor = "editor",
  Viewer = "viewer",
}

// Type guard function
export function isAdmin(user: User & { role: UserRole }): user is User & { role: UserRole.Admin } {
  return user.role === UserRole.Admin;
}

// Generic class implementing generic interface
export class InMemoryRepository<T extends BaseEntity> implements Repository<T> {
  private items: Map<string, T> = new Map();

  async findById(id: string): Promise<T | null> {
    return this.items.get(id) ?? null;
  }

  async findAll(): Promise<T[]> {
    return Array.from(this.items.values());
  }

  async save(entity: T): Promise<T> {
    this.items.set(entity.id, entity);
    return entity;
  }

  async delete(id: string): Promise<boolean> {
    return this.items.delete(id);
  }
}

// Mapped type
export type Readonly<T> = {
  readonly [P in keyof T]: T[P];
};

// Conditional type
export type NonNullable<T> = T extends null | undefined ? never : T;

// Utility function with generics
export async function withRetry<T>(
  fn: () => Promise<T>,
  retries: number = 3,
): Promise<T> {
  let lastError: Error | undefined;
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (e) {
      lastError = e as Error;
    }
  }
  throw lastError;
}

// Constants
export const MAX_PAGE_SIZE = 100;
export const DEFAULT_TIMEOUT = 30_000;

// Namespace (module pattern)
export namespace Validators {
  export function isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  export function isValidName(name: string): boolean {
    return name.length >= 2 && name.length <= 100;
  }
}
