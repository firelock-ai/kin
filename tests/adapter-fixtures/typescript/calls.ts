// Fixture for call-resolution tests.
// The parser must emit simple-name Calls edges, not dotted "obj.method" strings.

function plain(): void {
    bare();
}

function member(): void {
    console.log("hi");
}

function chained(): void {
    a.b().c();
}

function optional(): void {
    obj?.maybe();
}

function constructed(): Widget {
    return new Widget();
}

class Greeter {
    greet(): void {
        this.sayHi();
        helperCall();
    }
}

// A property-chain receiver: the express hand-off shape. `this.router` is a
// property whose value comes from outside this tree, so the callee stays the
// bare leaf and the receiver is what says where it was read.
class Application {
    handle(req: Request, res: Response): void {
        this.router.handle(req, res);
        this.own();
        deps[0].run();
        make().run();
    }

    own(): void {}
}
