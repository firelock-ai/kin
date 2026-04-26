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
