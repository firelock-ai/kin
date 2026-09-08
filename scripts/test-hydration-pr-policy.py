#!/usr/bin/env python3
"""Require unconditional PR hydration guards and exercise their real command."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def policy(text):
    trigger = text.split('jobs:', 1)[0]
    assert re.search(r'^  pull_request:', trigger, re.M), 'missing PR trigger'
    assert not re.search(r'^    paths(?:-ignore)?:', trigger, re.M), 'path-filtered PR trigger'
    match = re.search(r'^  fast-gate-lint:\n(.*?)(?=^  [\w-]+:|\Z)', text, re.M | re.S)
    assert match, 'missing fast-gate-lint'
    job = match.group(1)
    prefix = job.split('    steps:', 1)[0]
    assert not re.search(r'^    (if|needs):', prefix, re.M), 'conditional lint job'
    for name, command in (
        ('Check Hydration Replay Semantics', 'python3 scripts/verify-hydration-semantics.py'),
        ('Falsify Hydration Replay Semantics guard', 'python3 scripts/falsify-hydration-semantics.py "$poisoned"'),
    ):
        step = re.search(r'^      - name: ' + re.escape(name) + r'\n(.*?)(?=^      - |\Z)', job, re.M | re.S)
        assert step, 'missing ' + name
        assert not re.search(r'^        (if|continue-on-error):', step.group(1), re.M), 'conditional ' + name
        active = [line for line in step.group(1).splitlines() if not line.lstrip().startswith('#')]
        assert any(line.strip() in (command, 'run: ' + command) for line in active), 'missing command ' + name
    return job


def main():
    text = (ROOT / '.github/workflows/ci.yml').read_text()
    policy(text)
    for mutation in (
        text.replace('  fast-gate-lint:\n', '  fast-gate-lint:\n    if: false\n', 1),
        text.replace('      - name: Check Hydration Replay Semantics\n',
                     '      - name: Check Hydration Replay Semantics\n        if: false\n', 1),
        text.replace('      - name: Falsify Hydration Replay Semantics guard\n',
                     '      - name: Falsify Hydration Replay Semantics guard\n        if: false\n', 1),
        text.replace('run: python3 scripts/verify-hydration-semantics.py', 'run: true', 1),
        text.replace('  pull_request:\n', '  pull_request:\n    paths: ["docs/**"]\n', 1),
    ):
        try:
            policy(mutation)
        except AssertionError:
            continue
        raise AssertionError('workflow policy mutation survived')
    manifest = json.loads((ROOT / 'scripts/hydration-semantics-manifest.json').read_text())
    with tempfile.TemporaryDirectory(prefix='hydration-pr-policy-') as directory:
        copy = Path(directory)
        files = {entry['file'] for entry in manifest['guarded']}
        files.update(('scripts/verify-hydration-semantics.py', 'scripts/hydration-semantics-manifest.json',
                      'crates/kin-index/src/history.rs'))
        for name in files:
            dest = copy / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, dest)
        command = [sys.executable, 'scripts/verify-hydration-semantics.py']
        def run():
            return subprocess.run(command, cwd=copy, capture_output=True, text=True)
        result = run()
        assert result.returncode == 0, result.stdout + result.stderr
        script = copy / 'scripts/verify-hydration-semantics.py'
        spec = importlib.util.spec_from_file_location('guard', script)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        entry = manifest['guarded'][0]
        source = copy / entry['file']
        original = source.read_text()
        function, _ = guard.extract_function(original, entry['function'])
        assert function is not None
        brace = function.index('{')
        poison = function[:brace + 1] + '\n let _policy_probe = 1;' + function[brace + 1:]
        source.write_text(original.replace(function, poison, 1))
        result = run()
        assert result.returncode != 0 and entry['function'] in result.stdout, result.stdout + result.stderr
        # A reviewed digest and version change passes the same PR command.
        entry['digest'] = guard.digest_of(poison)
        version_path = copy / guard.VERSION_FILE
        version = manifest['hydration_semantics_version'] + 1
        updated, count = re.subn(r'(const\s+' + guard.VERSION_CONST + r'\s*:\s*u32\s*=\s*)\d+',
                                 lambda m: m.group(1) + str(version), version_path.read_text(), count=1)
        assert count == 1
        version_path.write_text(updated)
        manifest['hydration_semantics_version'] = version
        (copy / 'scripts/hydration-semantics-manifest.json').write_text(json.dumps(manifest))
        result = run()
        assert result.returncode == 0, result.stdout + result.stderr
    print('Hydration PR policy: unconditional coverage, five workflow mutations, poisoned replay and reviewed update verified.')


if __name__ == '__main__':
    main()
