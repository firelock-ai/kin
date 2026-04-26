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
