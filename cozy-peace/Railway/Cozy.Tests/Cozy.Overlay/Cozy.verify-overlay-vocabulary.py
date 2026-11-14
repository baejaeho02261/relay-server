#!/usr/bin/env python3
"""Reject UI text changes whose Korean glyphs are absent from the bounded atlas.
The production Overlay currently has only fixed UI, with no username/text feed.
This static guard complements the actual C++ glyph/font/lifecycle tests.
"""
from pathlib import Path
import re, importlib.util, sys

root = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('cozy_source_strings', root / 'Cozy.Build/Cozy.SourceStrings.py')
_strings = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_strings)
renderer = _strings.read_source(root / 'Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas')
state = _strings.read_source(root / 'Cozy.Source/Cozy.Overlay/Cozy.Overlay.State.pas')
bridge = (root / 'Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp').read_text()
sinks = []
for path in (root/'Cozy.Source').rglob('*.pas'):
    if path.name == 'Cozy.Overlay.ImGui.pas':
        continue
    text = _strings.read_source(path)
    sinks += [(path.name, line.strip()) for line in text.splitlines()
              if re.match(r'^\s*ImGui(?:Text|Button)\(', line)]
assert len(sinks) == 3 and all(name == 'Cozy.Overlay.Renderer.pas' for name, _ in sinks), 'Review every new text sink'
inputs = re.findall(r'ImGui(?:Text|Button)\(FContext,\s*PAnsiChar\(UTF8String\((.*?)\)\)', renderer, re.S)
assert len(inputs) == 3 and inputs.count('FPrivacyStatus') == 1
literals = [value[1:-1] for value in inputs if value.startswith("'") and value.endswith("'")]
assert len(literals) == 2, 'Server/user strings require a reviewed glyph admission policy'
assignments = re.findall(r'FPrivacyStatus\s*:=\s*(.*?);', renderer, re.S)
assert assignments == ['OverlayCapturePrivacyStatus(Requested, SetOK, ReadOK, Observed)']
start = state.rfind('function OverlayCapturePrivacyStatus(')
block = state[start:state.index('\nend;', start)]
statuses = sorted(set(re.findall(r"(?:Result\s*:=\s*|Exit\()'([^']*)'", block)))
assert len(statuses) == 6, 'Review fixed privacy status branches'
texts = literals + statuses
needed = {ord(char) for text in texts for char in text if ord(char) > 126}
array = re.search(r'GameKoreanCodepoints\[\]=\{([^}]+)\}', bridge).group(1)
baked = {int(value, 16) for value in re.findall(r'0x([A-Fa-f0-9]+)u', array)}
assert needed == baked, f'UI/baked vocabulary mismatch: missing={needed-baked}, unused={baked-needed}'
assert 'ImFontFlags_LockBakedSizes|ImFontFlags_NoLoadGlyphs' in bridge
assert 'UTF8String(FPrivacyStatus)' in renderer
print(f'PASS: all 3 Overlay text sinks are fixed UI, all {len(texts)} labels and {len(needed)} Korean codepoints covered; no dynamic username/text feed.')
