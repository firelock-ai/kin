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
ready_at = source.index("wait_ready(port, token, process, deadline, result['readiness_observations'])")
for helper in ('        def cli(*arguments):', '        def inspect(name):', '        def conversion_source(path):', '        def tool(path, name=None):'):
    assert ready_at < source.index(helper), helper
assert "'list_file_entities'" not in source, 'the probe must not ask the agent surface for a file catalog'

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

# The debt a daemon is held to is read from repository authority. `owed` runs the
# candidate CLI's `kin graph owed --json` in the fixture and returns every
# workspace's records, and refuses a failed read or a ledger of another schema.
calls = []
ledger = {'schema': 'kin.graph.owed-derivations.v1', 'workspaces': [
    {'records': [{'path': 'orphan.py', 'body': 'b' * 64, 'cause': 'legacy'}]},
    {'records': [{'path': None, 'path_hex': 'ff', 'body': 'c' * 64, 'cause': 'publication'}]}]}
outcome = {'returncode': 0, 'ledger': ledger}
def fake_run(command, cwd, env, capture_output, text, timeout):
    calls.append((command, cwd, env))
    return types.SimpleNamespace(returncode=outcome['returncode'],
                                 stdout=json.dumps(outcome['ledger']), stderr='refused by fixture')
owed_ns = {'subprocess': types.SimpleNamespace(run=fake_run), 'json': json,
           'kin': Path('/owned/kin'), 'fixture': Path('/owned/fixture'),
           'env': {'PATH': '/usr/bin', 'HOME': '/owned/home', 'TMPDIR': '/owned/home'}}
owed = load_function(ROOT / 'probe_startup_binary.py', 'owed', owed_ns)
assert [record['path'] for record in owed()] == ['orphan.py', None]
assert calls[-1][:2] == (['/owned/kin', 'graph', 'owed', '--json'], Path('/owned/fixture'))
assert calls[-1][2] is owed_ns['env'], 'the ledger read must run in the probe environment'
outcome['returncode'] = 1
refuses(owed, 'kin graph owed refused')
outcome['returncode'] = 0
outcome['ledger'] = dict(ledger, schema='kin.graph.owed-derivations.v0')
refuses(owed, 'unexpected owed ledger schema')
source = (ROOT / 'probe_startup_binary.py').read_text()
for key in ('debt_before_stop', 'debt_after_stop'):
    assert f"result['{key}'] = owed()" in source, key
    assert f"result['{key}'] = legacy_debt()" not in source, key
assert "result['debt_before_start'] = legacy_debt()" in source
assert "result['owed_before_start'] = owed()" in source
# The fixtures still ship their original bytes: the manifest pins them, and the
# runner must hand the probe the candidate CLI it reads the ledger with.
assert '"--kin", str(args.kin.resolve())' in (ROOT / 'run.py').read_text()

# Evaluate the actual candidate environment assignments with credential canaries.
import os
for name in ('run.py', 'probe_startup_binary.py'):
    tree = ast.parse((ROOT / name).read_text())
    assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'env' for t in n.targets))
    fake_os = types.SimpleNamespace(environ={'PATH': '/usr/bin:/bin',
        'ACTIONS_RUNTIME_TOKEN': 'credential-canary', 'GITHUB_ENV': 'command-file-canary',
        'AWS_SECRET_ACCESS_KEY': 'cloud-canary', 'KIN_DAEMON_AUTH_TOKEN': 'old-token'},
        defpath=os.defpath)
    env_ns = {'os': fake_os, 'home': Path('/owned/home'), 'output': Path('/owned/output')}
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), name, 'exec'), env_ns)
    assert set(env_ns['env']) == {'PATH', 'HOME', 'TMPDIR'}, env_ns['env']
    assert env_ns['env']['HOME'].startswith('/owned/')
    assert 'canary' not in json.dumps(env_ns['env'])
    inherited = dict(fake_os.environ)
    assert set(inherited) != {'PATH', 'HOME', 'TMPDIR'}, 'credential inheritance mutant survived'

for name in ('run.py', 'probe_startup_binary.py'):
    result = subprocess.run([sys.executable, '-O', str(ROOT / name), '--help'], capture_output=True, text=True)
    assert result.returncode != 0 and 'without optimization' in result.stderr, name
print('STARTUP_PROOF_READINESS_AND_PRECONDITION_CONTROLS_PASS')
