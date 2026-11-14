#!/usr/bin/env python3
"""One editable source catalogue for public diagnostic/UI Pascal text.

Default check is read-only. It never executes A/B/O or contacts a server.
The generated Pascal still contains public literals; this is not encryption.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid

CATALOG = 'Cozy.Source/Cozy.Configuration/Cozy.StringCatalog.json'
PAS_TOP = frozenset(('Cozy.Source', 'Cozy.Projects', 'Cozy.Tests'))
PAS_EXT = frozenset(('.pas', '.inc', '.dpr'))
CPP_EXT = frozenset(('.h', '.hpp', '.c', '.cpp'))
FORMAT = 'COZY_PUBLIC_SOURCE_STRINGS_V1'
MAX_SOURCE = 8 * 1024 * 1024
MAX_CATALOG = 32 * 1024 * 1024
MAX_TEXT = 4096
IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*')

class CatalogError(ValueError):
    pass

def fail(code):
    raise CatalogError('STRING_CATALOG_' + code)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def exact(left, right):
    return json.dumps(left, sort_keys=True, ensure_ascii=True, separators=(',', ':')) == json.dumps(right, sort_keys=True, ensure_ascii=True, separators=(',', ':'))

def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def check_root(root):
    root = Path(os.path.abspath(root))
    for part in [*reversed(root.parents), root]:
        if part.is_symlink() or getattr(part, 'is_junction', lambda: False)():
            fail('LINK_FORBIDDEN')
    if not root.is_dir():
        fail('ROOT_REQUIRED')
    return root

def owned_path(root, name, exists=True):
    if not isinstance(name, str) or '\\' in name:
        fail('PATH_INVALID')
    rel = PurePosixPath(name)
    if rel.is_absolute() or rel.as_posix() != name or any(x in ('', '.', '..') for x in rel.parts):
        fail('PATH_INVALID')
    file = root.joinpath(*rel.parts)
    for part in [*list(file.parents)[:len(rel.parts)-1], file]:
        if part.is_symlink() or getattr(part, 'is_junction', lambda: False)():
            fail('LINK_FORBIDDEN')
    if exists:
        info = file.stat()
        if not file.is_file() or info.st_nlink != 1:
            fail('REGULAR_OWNED_FILE_REQUIRED')
    elif file.exists():
        fail('OUTPUT_EXISTS')
    return file

def read_source(root, name):
    file = owned_path(root, name)
    if file.stat().st_size > MAX_SOURCE:
        fail('SOURCE_TOO_LARGE')
    data = file.read_bytes()
    if len(data) > MAX_SOURCE:
        fail('SOURCE_TOO_LARGE')
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError:
        fail('UTF8_REQUIRED')
    return data, text

def pascal_tokens(text):
    """Quoted tokens, # tokens, and compiler directives; comments are excluded.

    Multiline Delphi literals are explicitly unsupported rather than guessed.
    The current sources do not use them. New syntax must get a reviewed adapter.
    """
    i = 0
    literals, exceptions = [], []
    line_starts = [0] + [m.end() for m in re.finditer('\n', text)]
    parens = []
    bracket_depth = 0
    recent = ''
    while i < len(text):
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = len(text) if end < 0 else end + 1
            continue
        if text.startswith('(*', i) or text[i] == '{':
            marker = '*)' if text.startswith('(*', i) else '}'
            width = 2 if marker == '*)' else 1
            end = text.find(marker, i + width)
            if end < 0:
                fail('COMMENT_UNCLOSED')
            if text[i + width:i + width + 1] == '$':
                exceptions.append({'kind': 'compiler_directive', 'line': bisect.bisect_right(line_starts, i), 'spelling': text[i:end + len(marker)]})
            i = end + len(marker)
            continue
        if text[i] == "'":
            start = i
            i += 1
            value = []
            while i < len(text):
                if text[i] == "'":
                    if text[i:i + 2] == "''":
                        value.append("'"); i += 2
                    else:
                        i += 1; break
                else:
                    if text[i] in '\r\n':
                        fail('MULTILINE_LITERAL_UNSUPPORTED')
                    value.append(text[i]); i += 1
            else:
                fail('LITERAL_UNCLOSED')
            line = bisect.bisect_right(line_starts, start)
            literals.append({'start': start, 'end': i, 'value': ''.join(value), 'spelling': text[start:i], 'line': line, 'column': start - line_starts[line - 1] + 1, 'calls': [p[0] for p in parens], 'callArguments': [(p[0], p[2]) for p in parens], 'previous': recent})
            recent = '<literal>'
            continue
        if text[i] == '#' and i + 1 < len(text) and (text[i + 1].isdigit() or text[i + 1] == '$'):
            start = i; i += 1
            if text[i] == '$':
                i += 1
                while i < len(text) and text[i] in '0123456789abcdefABCDEF': i += 1
            else:
                while i < len(text) and text[i].isdigit(): i += 1
            exceptions.append({'kind': 'character_code', 'line': bisect.bisect_right(line_starts, start), 'spelling': text[start:i]})
            recent = '<character-code>'
            continue
        match = IDENTIFIER.match(text, i)
        if match:
            recent = match.group(0); i += len(recent); continue
        ch = text[i]
        if ch == '(':
            parens.append([recent, i, 0, bracket_depth]); recent = '('
        elif ch == ')':
            if parens: parens.pop()
            recent = ')'
        elif ch == '[':
            bracket_depth += 1; recent = ch
        elif ch == ']':
            bracket_depth = max(0, bracket_depth - 1); recent = ch
        elif ch == ',':
            if parens and bracket_depth == parens[-1][3]: parens[-1][2] += 1
            recent = ch
        elif not ch.isspace():
            recent = ch
        i += 1
    return literals, exceptions

def looks_human(value):
    return bool(re.search(r'\s|[^\x00-\x7f]', value)) and not re.fullmatch(r'[A-Z0-9_ .:-]+', value)

def literal_mode(name, item):
    value = item['value']
    if name.startswith('Cozy.Source/Cozy.Security.NHW/'):
        return 'read_only', 'imported_sensor_contract'
    if name.startswith('Cozy.Tests/'):
        return 'read_only', 'test_fixture'
    if name.endswith('.dpr'):
        return 'read_only', 'project_or_linker_contract'
    if not value:
        return 'read_only', 'empty_literal'
    if len(value) == 1:
        return 'read_only', 'character_or_role'
    if re.fullmatch(r'\{[0-9A-Fa-f-]{36}\}', value):
        return 'read_only', 'interface_guid'
    if value.lower().endswith('.dll'):
        return 'read_only', 'platform_module'
    if name.endswith('.inc'):
        return 'read_only', 'generated_or_compile_contract'
    if re.fullmatch(r'[A-Z][A-Z0-9_]{2,}', value):
        return 'read_only', 'error_code_or_protocol'
    if item['previous'].lower() in ('external', 'name'):
        return 'read_only', 'linker_symbol'
    # These syntactic call sites use human diagnostics, not protocol identities.
    # The literal spelling/type stays at the original call site after apply.
    diagnostic = any(re.fullmatch(r'E[A-Za-z_0-9]*\.Create(?:Fmt)?', c) for c in item['calls'])
    ui = any(c in ('ImGuiText', 'ImGuiButton', 'SetWindowTextW', 'SetWindowText') for c in item['calls'])
    ui = ui or name.endswith('/Cozy.Overlay.State.pas') or name.endswith('/Cozy.UserErrors.pas')
    if looks_human(value) and (diagnostic or ui):
        return 'editable_text', 'diagnostic_or_ui'
    return 'read_only', 'protocol_abi_or_unclassified'

def pascal_entry(name, data, text):
    items, exceptions = pascal_tokens(text)
    rows = []
    for index, item in enumerate(items):
        mode, kind = literal_mode(name, item)
        rows.append({'token': index, 'line': item['line'], 'column': item['column'], 'mode': mode, 'kind': kind, 'sourceValue': item['value'], 'value': item['value']})
    return {'path': name, 'sourceSha256': digest(data), 'encoding': 'utf-8-bom' if data.startswith(b'\xef\xbb\xbf') else 'utf-8', 'literals': rows, 'readOnlySyntax': exceptions}

def cpp_literals(text):
    """Read-only quote inventory, preserving spelling instead of decoding C escapes."""
    out = []; i = 0
    while i < len(text):
        if text.startswith('//', i):
            end = text.find('\n', i); i = len(text) if end < 0 else end + 1
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0: fail('CPP_COMMENT_UNCLOSED')
            i = end + 2
        elif text.startswith('R"', i):
            start = i; begin = text.find('(', i + 2, i + 19)
            if begin < 0: fail('CPP_RAW_LITERAL_UNSUPPORTED')
            delimiter = text[i + 2:begin]
            close = ')' + delimiter + '"'; end = text.find(close, begin + 1)
            if end < 0: fail('CPP_LITERAL_UNCLOSED')
            i = end + len(close)
            out.append({'line': text.count('\n', 0, start) + 1, 'spelling': text[start:i]})
        elif text[i] in ('"', "'"):
            quote = text[i]; start = i; i += 1
            while i < len(text):
                if text[i] == '\\': i += 2
                elif text[i] == quote: i += 1; break
                else: i += 1
            else: fail('CPP_LITERAL_UNCLOSED')
            if quote == '"': out.append({'line': text.count('\n', 0, start) + 1, 'spelling': text[start:i]})
        else: i += 1
    return out

def source_names(root):
    pas, cpp, refs = [], [], []
    ignored = {'dcu', 'node_modules', '.git', '__pycache__', '__history', '__recovery', 'cozy.buildoutputs'}
    for top in sorted(PAS_TOP | {'Cozy.ImGui'}):
        base = root / top
        if base.is_symlink() or getattr(base, 'is_junction', lambda: False)(): fail('LINK_FORBIDDEN')
        if not base.is_dir(): continue
        for current, directories, filenames in os.walk(base, followlinks=False):
            directories[:] = sorted(name for name in directories if name.lower() not in ignored)
            for name in directories:
                folder = Path(current) / name
                if folder.is_symlink() or getattr(folder, 'is_junction', lambda: False)(): fail('LINK_FORBIDDEN')
            for name in sorted(filenames):
                file = Path(current) / name
                rel = file.relative_to(root).as_posix()
                if file.is_symlink() or getattr(file, 'is_junction', lambda: False)(): fail('LINK_FORBIDDEN')
                if not file.is_file(): continue
                if file.suffix.lower() in PAS_EXT and top in PAS_TOP:
                    pas.append(rel)
                elif file.suffix.lower() in CPP_EXT:
                    cpp.append(rel)
                elif file.suffix.lower() in ('.rc', '.manifest', '.json') and rel != CATALOG:
                    refs.append(rel)
    if not pas: fail('SOURCE_EMPTY')
    return sorted(pas), sorted(cpp), sorted(refs)

def build_catalog(root, overrides=None):
    overrides = overrides or {}
    pas, cpp, refs = source_names(root)
    files, other, managed = [], [], []
    for name in pas:
        data, text = read_source(root, name)
        if name in overrides:
            data = overrides[name]; text = data.decode('utf-8-sig')
        files.append(pascal_entry(name, data, text))
    for name in cpp:
        data, text = read_source(root, name)
        other.append({'path': name, 'sourceSha256': digest(data), 'mode': 'read_only', 'kind': 'cpp_vendor' if '/Cozy.Vendor/' in name else 'cpp_project', 'literals': cpp_literals(text)})
    for name in refs:
        data, text = read_source(root, name)
        owner = 'Cozy.Source/Cozy.Configuration/Cozy.ReleaseMetadata.json' if name.endswith(('.rc', '.manifest')) else name
        managed.append({'path': name, 'sourceSha256': digest(data), 'mode': 'read_only_reference', 'managedBy': owner})
    return {'schemaVersion': 1, 'format': FORMAT, 'purpose': 'Public source text management, not encryption or secret storage', 'editableScope': 'Reviewed production Pascal diagnostic/UI literals only', 'files': files, 'readOnlyCpp': other, 'managedSources': managed, 'exclusions': ['Comments and legal notices are preserved in original sources.', 'RTL strings, compiler-generated names, build-script text and compiled binary strings are outside the catalogue.']}

def encode_catalog(value):
    data = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if len(data) > MAX_CATALOG: fail('CATALOG_TOO_LARGE')
    return data

def load_catalog(root):
    file = owned_path(root, CATALOG)
    if file.stat().st_size > MAX_CATALOG: fail('CATALOG_TOO_LARGE')
    raw = file.read_bytes()
    if len(raw) > MAX_CATALOG: fail('CATALOG_TOO_LARGE')
    try:
        data = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=no_duplicates, parse_constant=lambda _: fail('JSON_NONFINITE'))
    except (UnicodeError, json.JSONDecodeError):
        fail('JSON_INVALID')
    validate_shape(data)
    return raw, data

def validate_shape(value):
    def keys(item, expected):
        if not isinstance(item, dict) or set(item) != set(expected.split()): fail('SCHEMA_INVALID')
    def array(item):
        if not isinstance(item, list): fail('SCHEMA_INVALID')
    keys(value, 'schemaVersion format purpose editableScope files readOnlyCpp managedSources exclusions')
    if type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or value['format'] != FORMAT: fail('SCHEMA_INVALID')
    for section in ('files', 'readOnlyCpp', 'managedSources', 'exclusions'): array(value[section])
    seen = set()
    for entry in value['files']:
        keys(entry, 'path sourceSha256 encoding literals readOnlySyntax')
        name = entry['path']
        if not isinstance(name, str) or name in seen or '\\' in name: fail('FILE_SET_CHANGED')
        rel = PurePosixPath(name)
        if rel.as_posix() != name or rel.is_absolute() or '..' in rel.parts or not rel.parts or rel.parts[0] not in PAS_TOP or rel.suffix.lower() not in PAS_EXT: fail('PATH_INVALID')
        seen.add(name)
        if entry['encoding'] not in ('utf-8', 'utf-8-bom') or not isinstance(entry['sourceSha256'], str) or not re.fullmatch('[a-f0-9]{64}', entry['sourceSha256']): fail('SCHEMA_INVALID')
        array(entry['literals']); array(entry['readOnlySyntax'])
        for row in entry['literals']:
            keys(row, 'token line column mode kind sourceValue value')
            if any(type(row[k]) is not int or row[k] < (0 if k == 'token' else 1) for k in ('token', 'line', 'column')): fail('SCHEMA_INVALID')
            if row['mode'] not in ('read_only', 'editable_text') or any(not isinstance(row[k], str) for k in ('kind', 'sourceValue', 'value')): fail('SCHEMA_INVALID')
        for row in entry['readOnlySyntax']: keys(row, 'kind line spelling')
    for entry in value['readOnlyCpp']:
        keys(entry, 'path sourceSha256 mode kind literals'); array(entry['literals'])
        for row in entry['literals']: keys(row, 'line spelling')
    for entry in value['managedSources']: keys(entry, 'path sourceSha256 mode managedBy')

def delphi_format_tokens(value):
    # Consume EVERY percent occurrence. findall alone would silently ignore a
    # trailing percent or an unknown conversion while retaining all old matches.
    # Documented Delphi grammar: %[index:][-][width][.precision]type or %%.
    pattern = re.compile(r'%(?:%|(?:(?:[0-9]+|\*):)?-?(?:[0-9]+|\*)?(?:\.(?:[0-9]+|\*))?[dDuUeEfFgGnNmMpPsSxX])')
    result = []
    at = 0
    while True:
        start = value.find('%', at)
        if start < 0: return result
        match = pattern.match(value, start)
        if match is None: fail('FORMAT_SYNTAX_INVALID')
        result.append(match.group(0)); at = match.end()


def is_format_argument(item):
    positions = {'createfmt': 0, 'format': 0, 'fmtstr': 1, 'formatbuf': 2}
    return any(positions.get(callee.rsplit('.', 1)[-1].lower()) == argument
               for callee, argument in item['callArguments'])


def validate_text(value, original, formatted=False):
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT:
        fail('TEXT_INVALID')
    if any(ord(ch) < 32 or 0x7f <= ord(ch) < 0xa0 or 0xd800 <= ord(ch) <= 0xdfff for ch in value):
        fail('TEXT_INVALID')
    if not looks_human(value): fail('DIAGNOSTIC_TEXT_REQUIRED')
    # Only actual formatting arguments interpret percent syntax. Plain UI or
    # Exception.Create text may contain a literal 50%, trailing % or even %s.
    if formatted and delphi_format_tokens(value) != delphi_format_tokens(original):
        fail('FORMAT_PLACEHOLDER_CHANGED')

def validate_catalog(root, value):
    expected = build_catalog(root)
    if not isinstance(value, dict) or set(value) != set(expected): fail('SCHEMA_INVALID')
    for key in expected:
        if key != 'files' and not exact(value[key], expected[key]): fail('READ_ONLY_METADATA_CHANGED')
    if not isinstance(value['files'], list) or len(value['files']) != len(expected['files']): fail('FILE_SET_CHANGED')
    changes = {}
    for given, wanted in zip(value['files'], expected['files']):
        if not isinstance(given, dict) or set(given) != set(wanted): fail('SCHEMA_INVALID')
        if given['path'] != wanted['path']: fail('FILE_SET_CHANGED')
        if given['sourceSha256'] != wanted['sourceSha256']: fail('SOURCE_STALE')
        for key in wanted:
            if key != 'literals' and not exact(given[key], wanted[key]): fail('READ_ONLY_METADATA_CHANGED')
        if not isinstance(given['literals'], list) or len(given['literals']) != len(wanted['literals']): fail('TOKEN_SET_CHANGED')
        data, text = read_source(root, wanted['path'])
        if digest(data) != wanted['sourceSha256']: fail('SOURCE_STALE')
        spans, _ = pascal_tokens(text)
        replacements = []
        for desired, original, span in zip(given['literals'], wanted['literals'], spans):
            if not isinstance(desired, dict) or set(desired) != set(original): fail('SCHEMA_INVALID')
            if any(not exact(desired[k], original[k]) for k in original if k != 'value'): fail('READ_ONLY_METADATA_CHANGED')
            if not isinstance(desired['value'], str): fail('TEXT_INVALID')
            if desired['value'] != original['value']:
                if original['mode'] != 'editable_text': fail('READ_ONLY_LITERAL_CHANGED')
                validate_text(desired['value'], original['value'], is_format_argument(span))
                if wanted['encoding'] == 'utf-8' and any(ord(c) > 127 for c in desired['value']) and not re.search(r'\{\$CODEPAGE\s+UTF8\}', text, re.I):
                    fail('UNICODE_SOURCE_MARKER_REQUIRED')
                replacements.append((span['start'], span['end'], "'" + desired['value'].replace("'", "''") + "'"))
        if replacements:
            for start, end, replacement in reversed(replacements): text = text[:start] + replacement + text[end:]
            # Reparse every changed file before any write. Token count must not change.
            parsed, _ = pascal_tokens(text)
            if len(parsed) != len(spans): fail('TOKEN_SET_CHANGED')
            output = (b'\xef\xbb\xbf' if wanted['encoding'] == 'utf-8-bom' else b'') + text.encode('utf-8')
            if len(output) > MAX_SOURCE: fail('SOURCE_TOO_LARGE')
            changes[wanted['path']] = (data, output)
    return expected, changes

def stage(file, data):
    temporary = file.with_name('Cozy.StringCatalog.' + uuid.uuid4().hex + '.tmp')
    created = False
    try:
        with temporary.open('xb') as stream:
            created = True
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        if file.exists(): os.chmod(temporary, stat.S_IMODE(file.stat().st_mode))
        return temporary
    except BaseException:
        if created and temporary.exists(): temporary.unlink()
        raise

def transaction(root, changes):
    """Validate all, then per-file atomic replacement with guarded rollback.

    This is not an OS-wide atomic transaction or a power-loss guarantee.
    """
    pending, backups, committed, keep = {}, {}, [], set()
    try:
        for name, (before, after) in changes.items():
            file = owned_path(root, name)
            if file.read_bytes() != before: fail('SOURCE_STALE')
        for name, (before, after) in changes.items():
            file = owned_path(root, name)
            pending[name] = stage(file, after)
            backups[name] = stage(file, before)
        for name, (before, after) in changes.items():
            file = owned_path(root, name)
            if file.read_bytes() != before: fail('SOURCE_STALE')
            os.replace(pending[name], file)
            committed.append(name)
    except BaseException:
        conflicts = False
        for name in reversed(committed):
            try:
                file = owned_path(root, name)
                if file.read_bytes() != changes[name][1]: raise OSError('Concurrent edit')
                os.replace(backups[name], file)
            except BaseException:
                conflicts = True; keep.add(backups[name])
        if conflicts: fail('ROLLBACK_CONFLICT_BACKUP_RETAINED')
        raise
    finally:
        for file in [*pending.values(), *backups.values()]:
            if file not in keep and file.exists(): file.unlink()

def create_catalog(root):
    target = owned_path(root, CATALOG, exists=False)
    if not target.parent.is_dir(): fail('CATALOG_DIRECTORY_REQUIRED')
    result = build_catalog(root)
    temporary = stage(target, encode_catalog(result))
    try:
        # Atomic create-only publication; a concurrent existing file is not overwritten.
        os.link(temporary, target)
    finally:
        temporary.unlink()
    return result

def refresh_catalog(root):
    raw, value = load_catalog(root)
    if not isinstance(value, dict) or value.get('format') != FORMAT or not isinstance(value.get('files'), list): fail('SCHEMA_INVALID')
    for file in value['files']:
        if not isinstance(file, dict) or not isinstance(file.get('literals'), list): fail('SCHEMA_INVALID')
        for row in file['literals']:
            if not isinstance(row, dict) or 'value' not in row or 'sourceValue' not in row: fail('SCHEMA_INVALID')
            if row['value'] != row['sourceValue']: fail('PENDING_EDITS')
    fresh = build_catalog(root)
    transaction(root, {CATALOG: (raw, encode_catalog(fresh))})
    return fresh

def run(root, command):
    root = check_root(root)
    if command == 'init': result = create_catalog(root); changed = 0
    elif command == 'refresh': result = refresh_catalog(root); changed = 0
    else:
        raw, value = load_catalog(root)
        result, changes = validate_catalog(root, value)
        if command == 'check' and changes: fail('PENDING_EDITS')
        changed = len(changes)
        if command == 'apply' and changes:
            result = build_catalog(root, {name: after for name, (before, after) in changes.items()})
            changes[CATALOG] = (raw, encode_catalog(result))
            transaction(root, changes)
    return {'status': 'PASS', 'command': command, 'pascalFiles': len(result['files']), 'quotedTokens': sum(len(x['literals']) for x in result['files']), 'editableTextOccurrences': sum(r['mode'] == 'editable_text' for f in result['files'] for r in f['literals']), 'readOnlyCppFiles': len(result['readOnlyCpp']), 'readOnlyCppLiterals': sum(len(x['literals']) for x in result['readOnlyCpp']), 'managedSourceReferences': len(result['managedSources']), 'sourceFilesChanged': changed, 'windowsExecution': 'NOT_RUN', 'encryption': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', choices=('check', 'init', 'apply', 'refresh'), default='check')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.root, args.command), ensure_ascii=False))
        return 0
    except (CatalogError, OSError, UnicodeError) as error:
        code = str(error) if isinstance(error, CatalogError) else 'STRING_CATALOG_IO_FAILED'
        print(code, file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
