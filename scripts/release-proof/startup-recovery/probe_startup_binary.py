"""Probe an owned interrupted-admission fixture through a real daemon binary."""
if not __debug__:
    raise RuntimeError("proof assertions require Python without optimization")

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import time
import urllib.request
import urllib.error
import uuid

def wait_ready(port, token, process, deadline, observations):
    while True:
        assert process.poll() is None, 'owned daemon exited before readiness'
        assert time.monotonic() < deadline, 'readiness timeout'
        request = urllib.request.Request(
            f'http://127.0.0.1:{port}/readiness',
            headers={'Authorization': 'Bearer ' + token})
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            body = json.load(response)
        observations.append({'status': status, 'body': body})
        if status == 200 and body.get('ready') is True:
            return
        assert status in (200, 503), 'unexpected readiness response'
        time.sleep(.1)


parser = argparse.ArgumentParser()
parser.add_argument('--daemon', type=pathlib.Path, required=True)
parser.add_argument('--fixture', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--expect', choices=['recovered', 'broken'], required=True)
parser.add_argument('--empty-control', action='store_true')
parser.add_argument('--require-orphan-debt', action='store_true')
parser.add_argument('--orphan-body')
args = parser.parse_args()
daemon, fixture, output = (p.resolve() for p in (args.daemon, args.fixture, args.output))
assert daemon.is_file() and os.access(daemon, os.X_OK)
assert (fixture / '.kin').is_dir() and (fixture / 'orphan.py').is_file()
assert not (fixture / '.kin/daemon.port').exists(), 'fixture must not have a live endpoint'
output.mkdir(parents=True, exist_ok=False)
token = uuid.uuid4().hex
env = {key: value for key, value in os.environ.items() if not key.startswith('KIN_')}
env.update(KIN_EMBED_BACKEND='cpu', KIN_DAEMON_AUTO_EMBED='false',
           KIN_HOME=str(output / 'isolated-home'), KIN_DAEMON_AUTH_TOKEN=token,
           KIN_DAEMON_BIND_HOST='127.0.0.1', KIN_DAEMON_IDLE_TIMEOUT_SECS='0')
(output / 'isolated-home').mkdir()
command = [str(daemon), '--repo', str(fixture), '--port', '0', '--storage', 'local']
result = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'command': command, 'fixture': str(fixture), 'expect': args.expect,
          'binary_sha256': hashlib.sha256(daemon.read_bytes()).hexdigest(),
          'orphan_observations': []}
print('COMMAND', command, flush=True)

def debt():
    marker = fixture / '.kin/semantic-debt.json'
    return json.loads(marker.read_text()) if marker.exists() else []

result['debt_before_start'] = debt()
def owes_orphan(entries):
    return any(e['path'] == 'orphan.py' and e['body'] == args.orphan_body for e in entries)

if args.require_orphan_debt:
    assert args.orphan_body and len(args.orphan_body) == 64, 'exact orphan body is required'
    assert owes_orphan(result['debt_before_start']), 'fixture owes exact orphan semantics'
    result['expected_orphan_body'] = args.orphan_body

def certified_empty(answer):
    return answer.get('entities') == [] and answer['file_coverage']['certifies_enumeration'] is True

def recovered(answer):
    return (any(e.get('name') == 'orphan' for e in answer.get('entities', []))
            and answer['file_coverage']['certifies_enumeration'] is True)

with (output / 'daemon.log').open('w') as log:
    process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    result['owned_pid'] = process.pid
    try:
        deadline = time.monotonic() + 90
        endpoint = fixture / '.kin/daemon.port'
        while not endpoint.exists():
            assert process.poll() is None, 'owned daemon exited before endpoint'
            assert time.monotonic() < deadline, 'endpoint timeout'
            time.sleep(.1)
        port = int(endpoint.read_text().strip())
        assert 0 < port < 65536
        result['port'] = port
        result['readiness_observations'] = []
        wait_ready(port, token, process, deadline, result['readiness_observations'])

        def tool(path):
            payload = json.dumps({'name': 'list_file_entities', 'arguments': {'path': path}}).encode()
            request = urllib.request.Request(
                f'http://127.0.0.1:{port}/mcp/tools/call', data=payload,
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
            with urllib.request.urlopen(request, timeout=5) as response:
                outer = json.load(response)
            assert not outer.get('isError'), outer
            return json.loads(outer['content'][0]['text'])

        def observe():
            answer = tool('orphan.py')
            result['orphan_observations'].append(answer)
            if args.expect == 'recovered':
                assert not certified_empty(answer), 'known admitted function was certified empty'
            return answer

        deadline = time.monotonic() + 60
        while True:
            answer = observe()
            if (recovered(answer) if args.expect == 'recovered' else certified_empty(answer)):
                break
            assert process.poll() is None, 'owned daemon exited during startup'
            assert time.monotonic() < deadline, 'startup outcome timeout'
            time.sleep(.1)
        result['orphan_after_startup'] = answer
        deadline = time.monotonic() + 60
        attempt = 0
        control_name = 'sentinel_ready_' + uuid.uuid4().hex[:8]
        result['sentinel_control_name'] = control_name
        while True:
            attempt += 1
            (fixture / 'sentinel.py').write_text(f'def {control_name}():\n    return {attempt}\n')
            time.sleep(.1)
            sentinel = tool('sentinel.py')
            observe()
            if (any(e.get('name') == control_name for e in sentinel.get('entities', []))
                    and sentinel['file_coverage']['certifies_enumeration'] is True):
                break
            assert process.poll() is None, 'owned daemon exited during sentinel control'
            assert time.monotonic() < deadline, 'tracked sentinel progress timeout'
        result['sentinel_after_progress'] = sentinel
        final = observe()
        result['orphan_after_progress'] = final
        assert (recovered(final) if args.expect == 'recovered' else certified_empty(final)), final
        if args.empty_control:
            empty = tool('empty.pyi')
            result['legitimate_empty_control'] = empty
            assert certified_empty(empty), 'legitimate empty CAS parse must still certify enumeration'
        result['debt_before_stop'] = debt()
        if args.require_orphan_debt:
            assert owes_orphan(result['debt_before_stop']), 'uncommitted exact orphan debt was cleared'
        result['verdict'] = 'PASS'
        print('BINARY_PROBE_PASS', args.expect, result['binary_sha256'], flush=True)
    except BaseException as error:
        result['verdict'] = 'FAIL'
        result['probe_error'] = repr(error)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        result['owned_process_exit'] = process.returncode
        if args.require_orphan_debt:
            try:
                result['debt_after_stop'] = debt()
                assert owes_orphan(result['debt_after_stop']), 'exact orphan debt lost after stop'
            except Exception as error:
                result['post_stop_error'] = repr(error)
                result['verdict'] = 'FAIL'
        result['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / 'probe-result.json').write_text(json.dumps(result, indent=2) + '\n')
assert result['verdict'] == 'PASS', result
