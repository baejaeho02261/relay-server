#!/usr/bin/env python3
"""Validate explicit native project paths after restructuring; no Delphi build claim."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

root = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
errors = []
count = 0
for path in root.rglob('*'):
    if path.is_file() and not path.name.startswith('Cozy.'):
        errors.append(f'Unprefixed file: {path.relative_to(root)}')
for path in root.rglob('*.pas'):
    text = path.read_text(encoding='utf-8-sig')
    match = re.search(r'(?im)^\s*unit\s+([\w.]+)\s*;', text)
    if not match or match.group(1).lower() != path.stem.lower():
        errors.append(f'Unit/filename mismatch: {path.relative_to(root)}')
for path in root.rglob('*.dpr'):
    for name in re.findall(r"\bin\s+'([^']+)'", path.read_text(encoding='utf-8-sig'), re.I):
        count += 1
        if not (path.parent / name.replace('\\', '/')).is_file():
            errors.append(f'Missing DPR dependency: {path.relative_to(root)} -> {name}')
for path in root.rglob('*'):
    if path.suffix.lower() not in {'.dproj','.groupproj','.props','.targets','.vcxproj'}:
        continue
    for entry in ET.parse(path).iter():
        candidates=[entry.get(key) for key in ['Include','Project','Projects']]
        if entry.tag.split('}')[-1] in {'MainSource','Manifest_File'}:
            candidates.append(entry.text)
        for name in candidates:
            if name and '$' not in name and Path(name).suffix.lower() in ('.pas','.dpr','.rc','.manifest','.inc','.dproj','.props','.targets','.cpp'):
                count += 1
                if not (path.parent / name.replace('\\', '/')).is_file():
                    errors.append(f'Missing project dependency: {path.relative_to(root)} -> {name}')
for path in root.rglob('*'):
    if path.suffix.lower() not in {'.pas','.dpr','.inc'}:
        continue
    text=path.read_text(encoding='utf-8-sig')
    for directive, name in re.findall(r"\{\$([IR])\s+([^}]+)\}",text,re.I):
        name=name.strip().strip("'\"")
        if '*' in name or '$' in name:
            continue
        count += 1
        if not (path.parent/name.replace('\\','/')).is_file():
            errors.append(f'Missing {directive} dependency: {path.relative_to(root)} -> {name}')
if errors:
    raise SystemExit('\n'.join(errors))
print(f'PASS: Cozy prefixes, Pascal unit identities and {count} explicit native project references; Delphi build NOT_RUN.')
