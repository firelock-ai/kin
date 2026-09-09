"""Falsify readiness and interrupted-store preconditions without starting a daemon."""
import ast
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parent / 'release-proof/startup-recovery'

def load_function(file, name, namespace):
    tree = ast.parse(file.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(file), 'exec'), namespace)
    return namespace[name]

def refuses(action, message):
    try:
        action()
    except AssertionError as error:
        assert message in str(error), error
        return
    raise AssertionError('negative control unexpectedly passed: ' + message)

class Response(io.StringIO):
    def __init__(self, code, body):
        super().__init__(json.dumps(body))
        self.code = code

def readiness(sequence, mutate=False):
    clock = [0]
    observations = []
    def fetch(request, timeout):
        assert request.full_url.endswith('/readiness')
        assert request.get_header('Authorization') == 'Bearer test-token'
        status, ready = sequence[min(len(observations), len(sequence) - 1)]
        if status == 503:
            raise urllib.error.HTTPError(request.full_url, status, 'warming', {}, Response(status, {'ready': ready}))
        return Response(status, {'ready': ready})
    fake = types.SimpleNamespace(request=types.SimpleNamespace(Request=urllib.request.Request, urlopen=fetch), error=urllib.error)
    ns = {'json': json, 'urllib': fake, 'time': types.SimpleNamespace(monotonic=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds))}
    function = load_function(ROOT / 'probe_startup_binary.py', 'wait_ready', ns)
    if mutate:
        source = (ROOT / 'probe_startup_binary.py').read_text().replace("status == 200 and body.get('ready') is True", 'True')
        tree = ast.parse(source)
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'wait_ready')
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<omitted readiness guard>', 'exec'), ns)
        function = ns['wait_ready']
    function(1234, 'test-token', types.SimpleNamespace(poll=lambda: None), .3, observations)
    return observations

assert readiness([(503, False), (200, True)])[-1] == {'status': 200, 'body': {'ready': True}}
for sequence in ([(503, False)], [(200, False)], [(503, True)]):
    refuses(lambda: readiness(sequence), 'readiness timeout')
# The same negative scenario passes when the readiness predicate is removed.
assert readiness([(503, False)], mutate=True)[-1]['status'] == 503
source = (ROOT / 'probe_startup_binary.py').read_text()
assert source.index("wait_ready(port, token, process, deadline, result['readiness_observations'])") < source.index('        def tool(path):')

ns = {'hashlib': __import__('hashlib'), 'json': json}
profile = load_function(ROOT / 'run.py', 'assert_fixture_profile', ns)
for label in ('legacy-fixed', 'recorded-fixed'):
    fixture = ROOT / 'fixtures' / label
    receipt = json.loads((ROOT / 'fixtures' / (label + '-receipt.json')).read_text())
    profile(fixture, receipt, label)
    for key, value in [('durable_entities', 1), ('live_entities', 1), ('orphan_cas_entities', 0), ('legacy', not receipt['legacy']), ('authority_generation', 4), ('empty_cas_entities', 1)]:
        changed = copy.deepcopy(receipt)
        changed[key] = value
        refuses(lambda: profile(fixture, changed, label), 'receipt profile changed')
    changed = copy.deepcopy(receipt)
    changed['semantic_debt'] = [] if label == 'recorded-fixed' else [{'path': 'orphan.py', 'body': receipt['orphan_body']}]
    refuses(lambda: profile(fixture, changed, label), 'receipt profile changed')
    mutated_source = (ROOT / 'run.py').read_text().replace("assert profile == expected, 'interrupted recovery receipt profile changed'", 'assert True')
    tree = ast.parse(mutated_source)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'assert_fixture_profile')
    mutant_ns = {'hashlib': __import__('hashlib'), 'json': json}
    exec(compile(ast.Module(body=[node], type_ignores=[]), '<omitted receipt guard>', 'exec'), mutant_ns)
    changed = copy.deepcopy(receipt)
    changed['durable_entities'] = 1
    mutant_ns['assert_fixture_profile'](fixture, changed, label)
    if label == 'recorded-fixed':
        for index in (1, 2):
            changed = copy.deepcopy(receipt)
            del changed['semantic_debt'][index]
            refuses(lambda: profile(fixture, changed, label), 'receipt profile changed')

for name in ('run.py', 'probe_startup_binary.py'):
    result = subprocess.run([sys.executable, '-O', str(ROOT / name), '--help'], capture_output=True, text=True)
    assert result.returncode != 0 and 'without optimization' in result.stderr, name
print('STARTUP_PROOF_READINESS_AND_PRECONDITION_CONTROLS_PASS')
