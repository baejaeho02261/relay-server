#!/usr/bin/env python3
"""Focused E2169 source regression. This is not a Delphi parser/compiler."""
import re
from pathlib import Path
root = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
failures=[]; count=0
for path in (root/'Cozy.Source').rglob('*.pas'):
    text=path.read_text(encoding='utf-8-sig')
    text=re.sub(r'\{.*?\}|\(\*.*?\*\)|//[^\n]*','',text,flags=re.S)
    for match in re.finditer(r'(\w+)\s*=\s*class(?:\([^)]*\))?\s*\n(.*?)\bend\s*;',text,re.S|re.I):
        count+=1; seen_method=False; continuing=False; depth=0
        for line in match.group(2).splitlines():
            line=line.strip()
            if re.fullmatch(r'(?:strict\s+)?(?:private|public|protected|published)',line,re.I):
                seen_method=False; continue
            if continuing:
                depth+=line.count('(')-line.count(')')
                if depth<=0 and line.endswith(';'):continuing=False
                continue
            if re.match(r'(?:(?:class|static)\s+)?(?:function|procedure|constructor|destructor|property)\b',line,re.I):
                seen_method=True; depth=line.count('(')-line.count(')')
                continuing=depth>0 or not line.endswith(';'); continue
            if seen_method and re.match(r'^\w+(?:\s*,\s*\w+)*\s*:\s*',line):
                failures.append(f'{path.name}: {match.group(1)} field after method: {line}')
if failures:raise SystemExit('\n'.join(failures))
print(f'PASS: {count} native class declarations checked for fields after methods; dcc64 still required.')
