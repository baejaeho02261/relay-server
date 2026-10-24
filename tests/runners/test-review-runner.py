"""Exercise the diagnostic registry reader without running production suites."""
import importlib.util
from pathlib import Path
import tempfile

source = Path(__file__).with_name('review-regression.py')
spec = importlib.util.spec_from_file_location('review_runner', source)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
count = 0
with tempfile.TemporaryDirectory(prefix='game-review-registry-') as tmp:
    root = Path(tmp)
    scripts = root / 'tests'
    scripts.mkdir()
    (scripts / 'sample.js').write_text("throw Error('MUST_NOT_RUN');\n")
    registry = scripts / 'peace.regression.js'
    registry.write_text("module.exports = [['sample.js', '--sqlite']];\n"
                        "if (require.main === module) throw Error('MUST_NOT_RUN');\n")
    assert runner.registered_checks(root) == [['sample.js', '--sqlite']]
    count += 1
    for exported in ('null', '{}', '[]', '[null]', "[['../sample.js']]",
                     "[['missing.js']]", "[['sample.js', 1]]"):
        registry.write_text('module.exports = ' + exported + ';\n')
        try:
            runner.registered_checks(root)
        except ValueError:
            count += 1
        else:
            raise AssertionError('Invalid registry accepted: ' + exported)
print(f'Review runner: {count} tests passed; registry loading runs no suite.')
