import Foundation

class Service {
    func plainCall() {
        helper()
    }

    func memberCall(obj: Worker) {
        obj.run()
    }

    func chainedCall(registry: Registry) {
        registry.adapter().execute()
    }

    func selfCall() {
        self.helper()
    }
}

class Worker {
    func run() {}
}

class Registry {
    func adapter() -> Adapter { return Adapter() }
}

class Adapter {
    func execute() {}
}

func helper() {}
