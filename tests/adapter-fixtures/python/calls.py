"""Fixture for call-resolution tests."""

class Service:
    def __init__(self):
        self.store = Store()

    def process(self, item):
        # self-call
        self.validate(item)
        # attribute call on instance member
        self.store.save(item)

    def validate(self, item):
        return item is not None

class Store:
    def save(self, item):
        pass

def handler():
    app = Flask()
    # attribute call on local — dst should be "add_url_rule", not "app.add_url_rule"
    app.add_url_rule("/", view_func=handler)
    # chained call — at least "query" should appear as a dst
    db.session.query().filter(x=1).all()
    # super() not covered here — separate scenario

def plain():
    # simple call
    handler()

def requires_auth(fn):
    return fn

class App:
    def route(self, path):
        def wrap(fn): return fn
        return wrap

app = App()

@staticmethod
def bare_decorator():
    pass

@requires_auth
def protected():
    pass

@app.route("/")
def home():
    pass

@app.route("/api")
@requires_auth
def api_endpoint():
    pass
