#!/usr/bin/env python3
"""Read native source contracts using their actual editable string constants.

This reader does not hide uses/imports or modify source. It validates the pure
constant units before expanding references for source generators/checkers.
"""
from pathlib import Path
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('cozy_string_units', ROOT / 'Cozy.Build/Cozy.Extract-StringUnits.py')
_units = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_units)
_cache = None


def read_source(path):
    global _cache
    path = Path(path).resolve()
    text = path.read_text(encoding='utf-8-sig')
    if path.suffix.lower() not in ('.pas', '.dpr', '.inc') or not path.is_relative_to(ROOT):
        return text
    if not any(t['kind'] == 'id' and t['text'].startswith('CozyText_') for t in _units.lex(text)):
        return text
    if _cache is None:
        mapping = json.loads((ROOT / _units.MAP).read_text(encoding='utf-8'))
        if mapping.get('format') != _units.FORMAT:
            _units.fail('FORMAT')
        constants = _units.constants_from_units(ROOT, mapping)
        _cache = (mapping, constants)
    mapping, constants = _cache
    relative = path.relative_to(ROOT).as_posix()
    if relative in {u['path'] for u in mapping['units']}:
        return text  # Declarations, not uses of constants.
    entry = next((e for e in mapping['sources'] if e['path'] == relative), None)
    if entry is None:
        _units.fail('UNMAPPED_SOURCE:' + relative)
    required = set(entry['unitNames'])
    if path.suffix.lower() == '.inc':
        owners = entry.get('owners', [])
        if not owners:
            _units.fail('INCLUDE_OWNER_MISSING:' + relative)
        for owner in owners:
            if not required <= set(_units.used_units((ROOT / owner).read_text(encoding='utf-8-sig'))):
                _units.fail('INCLUDE_IMPORT_MISSING:' + relative)
    elif not required <= set(_units.used_units(text)):
        _units.fail('IMPORT_MISSING:' + relative)
    return _units.expand_text(text, constants)
