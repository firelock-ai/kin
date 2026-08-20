// Fixture for call-resolution tests.
// The parser must emit simple-name Calls edges, not dotted "obj.method" strings.

function plain() {
    bare();
}

function member() {
    console.log("hi");
}

function chained() {
    a.b().c();
}

function optional() {
    obj?.maybe();
}

function constructed() {
    return new Widget();
}

class Greeter {
    greet() {
        this.sayHi();
        helperCall();
    }
}

// A property-chain receiver: the express hand-off shape. `this.router` is a
// property whose value comes from outside this tree, so the callee stays the
// bare leaf and the receiver is what says where it was read.
class Application {
    handle(req, res) {
        this.router.handle(req, res);
        this.own();
        deps[0].run();
        make().run();
    }

    own() {}
}
