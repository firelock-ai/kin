// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: JavaScript edge cases
// Tests: prototype patterns, closures, generators, async/await,
// destructuring, default exports, computed properties, symbols

import EventEmitter from 'events';

// Class with private fields and getters
export class Store extends EventEmitter {
  #state = {};
  #listeners = new Map();

  constructor(initialState = {}) {
    super();
    this.#state = { ...initialState };
  }

  get state() {
    return { ...this.#state };
  }

  dispatch(action) {
    const prev = this.#state;
    this.#state = this.#reduce(this.#state, action);
    this.emit('change', this.#state, prev);
  }

  #reduce(state, action) {
    switch (action.type) {
      case 'SET':
        return { ...state, [action.key]: action.value };
      case 'DELETE':
        const { [action.key]: _, ...rest } = state;
        return rest;
      default:
        return state;
    }
  }
}

// Generator function
export function* range(start, end, step = 1) {
  for (let i = start; i < end; i += step) {
    yield i;
  }
}

// Async generator
export async function* fetchPages(baseUrl, maxPages = 10) {
  for (let page = 1; page <= maxPages; page++) {
    const response = await fetch(`${baseUrl}?page=${page}`);
    const data = await response.json();
    yield data;
    if (!data.hasMore) break;
  }
}

// Factory function (closure pattern)
export function createCounter(initial = 0) {
  let count = initial;
  return {
    increment: () => ++count,
    decrement: () => --count,
    get value() { return count; },
    reset: () => { count = initial; },
  };
}

// Prototype-based extension
function LegacyRouter() {
  this.routes = [];
}

LegacyRouter.prototype.addRoute = function(path, handler) {
  this.routes.push({ path, handler });
};

LegacyRouter.prototype.match = function(path) {
  return this.routes.find(r => r.path === path);
};

// Computed property names
const METHODS = ['get', 'post', 'put', 'delete'];
const methodHandlers = Object.fromEntries(
  METHODS.map(m => [m, (url) => fetch(url, { method: m.toUpperCase() })])
);

// Symbol-based constants
export const STORE_KEY = Symbol('store');
export const INIT_EVENT = Symbol('init');

// Default export function
export default function createApp(config = {}) {
  const store = new Store(config.initialState);
  return { store, config };
}

// Constants
export const VERSION = '1.0.0';
export const MAX_LISTENERS = 100;
