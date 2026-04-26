package fixtures

import kotlin.collections.List

class Service {
    fun plainCall() {
        helper()
    }

    fun memberCall(obj: Worker) {
        obj.run()
    }

    fun chainedCall(registry: Registry) {
        registry.adapter().execute()
    }

    fun safeCall(maybe: Worker?) {
        maybe?.run()
    }

    fun packageCall() {
        kotlin.io.println("hi")
    }
}

class Worker {
    fun run() {}
}

class Registry {
    fun adapter(): Adapter = Adapter()
}

class Adapter {
    fun execute() {}
}

fun helper() {}
