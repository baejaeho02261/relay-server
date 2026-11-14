#!/usr/bin/env python3
"""Exact full-role startup fixture dependencies; Delphi/Windows execution NOT_RUN."""
from pathlib import Path
import collections
import contextlib
import io
import re
import runpy
import xml.etree.ElementTree as ET

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
with contextlib.redirect_stdout(io.StringIO()):
    generator = runpy.run_path(str(ROOT / 'Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py'))
globals_ = generator['production_source'].__globals__
globals_['PRODUCTION_DEFINED'] = (generator['PRODUCTION_DEFINED'] - {'GAME_APPLICATION_BUILD'}) | {'GAME_STARTUP_ROLE_PROBE'}
globals_['PRODUCTION_DISABLED'] = (generator['PRODUCTION_DISABLED'] - {'GAME_STARTUP_ROLE_PROBE'}) | {'GAME_APPLICATION_BUILD'}

def identities(entries):
    return collections.Counter((row['module'], row['lookup'], row['procName'], row['hash'], row['optional']) for row in entries)

for role, product in [('gcrLauncher', 'Cozy.Launcher'), ('gcrConnect', 'Cozy.Client'), ('gcrOverlay', 'Cozy.Overlay')]:
    main = ROOT / 'Cozy.Tests/Cozy.Startup' / (product + 'StartupProbe.dpr')
    seen = {}
    generator['closure'](main, seen)
    actual = [row for unit in seen.values() for row in generator['bindings'](unit)]
    expected = identities(generator['roles'][role])
    assert identities(actual) == expected, (role, identities(actual) - expected, expected - identities(actual))
    text = main.read_text(encoding='utf-8-sig')
    assert f'RunStartupRoleProbe({role});' in text
    assert not re.search(r'\b(?:RunLauncher|RunGameConsole|RunLicenseClient|RunOverlay|RequireCozyProtection)\s*(?:\(|;)', text)
    resource = re.search(r"\{\$R '([^']+)'\}", text).group(1)
    assert main.parent.joinpath(*resource.split('\\')).resolve() == (ROOT / 'Cozy.Projects' / product / (product + 'Resources.res')).resolve()
    xml = ET.parse(main.with_suffix('.dproj')).getroot()
    assert xml.find('.//{*}TestOnlyDefine').text == 'GAME_STARTUP_ROLE_PROBE'
    print(f'PASS {role}: isolated startup fixture matches {len(actual)} production API bindings and exact role resources')

print('STARTUP ROLE SOURCE CONTRACTS PASS; actual Delphi compilation and Windows role execution NOT_RUN.')
