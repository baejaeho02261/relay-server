#!/usr/bin/env python3
"""Validate the complete source binding multiset of each fault-test program.
This does not compile Delphi or establish Windows ABI/runtime correctness.
"""
from pathlib import Path
import collections
import contextlib
import io
import re
import runpy

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
with contextlib.redirect_stdout(io.StringIO()):
    generator = runpy.run_path(str(ROOT / 'Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py'))


def test_source(text, defined):
    output, stack, active, previous = [], [], True, 0
    directive = re.compile(r'\{\$\s*(IFDEF|IFNDEF|IF|ELSE|ENDIF|IFEND)\b([^}]*)\}', re.I)
    for match in directive.finditer(text):
        segment = text[previous:match.start()]
        if active:
            if any(condition is None for _, condition, _ in stack) and re.search(r'\b(?:BindApiPointer|uses)\b', segment, re.I):
                raise AssertionError('binding inside unevaluated compile-time expression')
            output.append(segment)
        command, symbol = match.group(1).upper(), match.group(2).strip().upper()
        if command in ('IFDEF', 'IFNDEF'):
            known = symbol in defined or symbol in generator['PRODUCTION_DISABLED'] or symbol == 'GAME_APPLICATION_BUILD'
            assert known, 'unrecognized build conditional ' + symbol
            condition = symbol in defined
            if command == 'IFNDEF':
                condition = not condition
            stack.append((active, condition, False))
            active = active and condition
        elif command == 'IF':
            stack.append((active, None, False))
        elif command == 'ELSE':
            assert stack and not stack[-1][2]
            parent, condition, _ = stack[-1]
            stack[-1] = (parent, condition, True)
            active = parent and (condition is None or not condition)
        else:
            assert stack
            active = stack.pop()[0]
        previous = match.end()
    assert not stack
    if active:
        output.append(text[previous:])
    return ''.join(output)


def identities(entries):
    return collections.Counter((row['module'], row['hash'], row['optional']) for row in entries)


startup = (ROOT / 'Cozy.Source/Cozy.Application/Cozy.Startup.pas').read_text(encoding='utf-8-sig')
assert 'AppendProductFaultApiContract' not in generator['production_source'](startup)
block = re.search(r'procedure AppendProductFaultApiContract\(.*?\nend;', startup, re.S).group()
extra = collections.Counter()
slots = set()
for index, module, symbol, copies, optional in re.findall(
        r"SetApiContract\(Items\[First \+ (\d+)\], '([^']+)', (HASH_\w+), (\d+), (True|False)\);", block):
    assert int(index) not in slots
    slots.add(int(index))
    extra[(module, generator['hashes'][symbol], optional == 'True')] += int(copies)
assert slots == set(range(10)) and sum(extra.values()) == 10
assert 'SetLength(Items, First + 10);' in block
assert re.search(r'FillRoleApiContract\(Role, Items\);\s*\{\$IFDEF GAME_PRODUCT_FAULT_TESTS\}\s*AppendProductFaultApiContract\(Items\);\s*\{\$ENDIF\}', startup)
assert 'if not ApiPointerTargetsMatch(Targets) then' in startup

for role, product in [('gcrLauncher', 'Cozy.Launcher'), ('gcrConnect', 'Cozy.Client'), ('gcrOverlay', 'Cozy.Overlay')]:
    defined = {'CPUX64', 'MSWINDOWS', 'WIN64', 'RELEASE', 'GAME_PRODUCT_FAULT_TESTS'}
    if role == 'gcrOverlay':
        defined.add('GAME_IMGUI_FAULT_TESTS')
    # Use the same reviewed binding extractor, with the actual isolated test
    # defines, to walk the complete transitive test DPR dependency closure.
    generator['source'].__globals__['production_source'] = lambda text: test_source(text, defined)
    seen = {}
    main = ROOT / 'Cozy.Tests/Cozy.FaultInjection' / (product + 'FaultTest.dpr')
    generator['closure'](main, seen)
    actual = [entry for path in seen.values() for entry in generator['bindings'](path)]
    expected = identities(generator['roles'][role]) + extra
    assert identities(actual) == expected, (role, identities(actual) - expected, expected - identities(actual))
    assert f'RequireNativeStartup({role});' in main.read_text(encoding='utf-8-sig')
    print(f'PASS {role}: production exact multiset + 10 isolated fault bindings = {len(actual)} slots')

print('PRODUCT FAULT STARTUP SOURCE PASS; Delphi compile and Windows execution NOT_RUN.')
