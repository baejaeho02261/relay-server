"""Run every registered regression independently, retaining nonzero exit evidence.
Unlike npm test (the fail-fast release gate), this diagnostic runner continues.
A blocked test is NEVER a PASS. Uses only temporary non-operating DATA_DIRs.
Usage: python GameWeb/scripts/review-regression.py --output OUTPUT_DIRECTORY
"""
from __future__ import annotations
import argparse, ast, collections, json, os, pathlib, shutil, subprocess, tempfile, time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    root = pathlib.Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = (root / 'scripts/regression.js').read_text(encoding='utf-8')
    checks = ast.literal_eval(source.split('const checks = ', 1)[1].split('\nfor (const', 1)[0].rstrip().rstrip(';'))
    def node(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(['node', *arguments], cwd=root, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
    dependencies = {}
    for name in ('better-sqlite3', 'jsdom', 'hash-wasm'):
        probe = node('-e', "try { console.log(require.resolve(process.argv[1])); } catch(e) { console.error(e.code); process.exit(1); }", name)
        dependencies[name] = {'available': probe.returncode == 0, 'exitCode': probe.returncode,
                              'diagnostic': probe.stdout.strip()}
    node_version = node('--version').stdout.strip()
    results = []
    for index, check in enumerate(checks, 1):
        if not isinstance(check, list) or not check or any(not isinstance(x, str) for x in check):
            raise ValueError('Invalid registered regression entry')
        data = tempfile.mkdtemp(prefix='game-delivery-review-')
        env = {**os.environ, 'DATA_DIR': data, 'HA_ENABLED': '0', 'STORAGE_ENGINE': 'json'}
        started = time.monotonic()
        try:
            process = subprocess.run(['node', str(root / 'scripts' / check[0]), *check[1:]],
                cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=args.timeout)
            text, code = process.stdout, process.returncode
            status = 'PASS' if code == 0 else 'FAIL'
            blocker = None
            if code != 0:
                if 'Cannot find module' in text or 'better-sqlite3 runtime driver' in text or 'fpc was not found' in text:
                    status, blocker = 'BLOCKED_DEPENDENCY', 'Module/compiler unavailable; see raw log.'
                elif 'DESKTOP_WRITER_LOCK_UNAVAILABLE' in text and not dependencies['better-sqlite3']['available']:
                    status, blocker = 'BLOCKED_DEPENDENCY', 'Required better-sqlite3 absent in preflight; OS single-writer admission failed. Lock was not bypassed.'
        except subprocess.TimeoutExpired as error:
            value = error.stdout or b''
            text = value.decode(errors='replace') if isinstance(value, bytes) else value
            code, status, blocker = None, 'TIMEOUT', 'Diagnostic runner time limit; not a pass.'
        finally:
            shutil.rmtree(data, ignore_errors=True)
        log = f'{index:02d}-{check[0]}' + ('-sqlite' if '--sqlite' in check else '') + '.log'
        (output / log).write_text(text, encoding='utf-8')
        row = {'suite': ' '.join(check), 'status': status, 'exitCode': code,
               'seconds': round(time.monotonic() - started, 2), 'log': log}
        if blocker:
            row['blocker'] = blocker
        results.append(row)
        (output / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(f'{index}/{len(checks)} {status} {row["suite"]}', flush=True)
    report = {'version': 1, 'node': node_version, 'platform': os.name,
              'timeoutSecondsPerSuite': args.timeout, 'dependencies': dependencies,
              'registeredSuites': len(checks), 'counts': dict(collections.Counter(x['status'] for x in results)),
              'allSuitesPassed': all(x['status'] == 'PASS' for x in results),
              'meaning': 'Independent diagnostic run. Raw nonzero exits retained. BLOCKED is not PASS. Native Windows not implied.'}
    (output / 'summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['counts']))
    return 0 if report['allSuitesPassed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
