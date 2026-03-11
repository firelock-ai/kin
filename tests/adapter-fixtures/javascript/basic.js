// Fixture: basic JavaScript entities
// Expected: 2 functions, 1 class

class UserService {
  constructor() {
    this.users = [];
  }

  addUser(user) {
    this.users.push(user);
  }
}

function createUser(name, email) {
  return { name, email };
}

function helperInternal() {
  return 42;
}
