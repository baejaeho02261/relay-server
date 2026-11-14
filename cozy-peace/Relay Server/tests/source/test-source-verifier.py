"""Temporary-copy corruption tests for the current read-only manifest verifier."""
from pathlib import Path
import importlib.util,tempfile,shutil,json,hashlib
HERE=Path(__file__).resolve().parents[1];ROOT=HERE.parent.parent
spec=importlib.util.spec_from_file_location('verifier',HERE/'verify-source.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
count=0
with tempfile.TemporaryDirectory(prefix='source-verifier-') as tmp:
    root=Path(tmp);shutil.copytree(ROOT/'Relay Server',root/'Relay Server',ignore=shutil.ignore_patterns('node_modules','desktop-bootstrap','data','__pycache__'));shutil.copytree(ROOT/'Railway',root/'Railway')
    for name in json.loads((ROOT/'Relay Server/maintenance/source-manifest.json').read_text())['files']:
        rel=Path(name)
        if rel.parts[0] not in {'Relay Server','Railway'}:
            assert not rel.is_absolute() and '..' not in rel.parts
            (root/rel).parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(ROOT/rel,root/rel)
    assert not v.verify(root);count+=1
    path=root/'Railway/cozy.Client.dproj';raw=path.read_bytes();path.unlink();assert any('Missing' in e and 'cozy.Client.dproj' in e for e in v.verify(root));count+=1;path.write_bytes(raw)
    path=root/'Railway/cozy.Api.Pointer.pas';raw=path.read_bytes();path.write_bytes(raw+b'changed');assert any('Changed:' in e for e in v.verify(root));count+=1;path.write_bytes(raw)
    path=root/'Relay Server/services/operations/peace.desktop-workspace.js';raw=path.read_bytes();path.unlink();assert any('Missing' in e for e in v.verify(root));count+=1;path.write_bytes(raw)
    manifest=json.loads((root/'Relay Server/maintenance/source-manifest.json').read_text());old=root/manifest['retiredExecutableSources'][0];old.parent.mkdir(parents=True,exist_ok=True);old.write_text('//old');assert any('retired source' in e for e in v.verify(root));count+=1;old.unlink()
    extra=root/'Railway/unneeded.json';extra.write_text('{}');assert any('belongs under' in e for e in v.verify(root));count+=1;extra.unlink()
    extra=root/'Railway/cozy.tests/unneeded.js';extra.write_text('// not an approved native test');assert any('belongs under' in e for e in v.verify(root));count+=1;extra.unlink()
    mp=root/'Relay Server/maintenance/source-manifest.json';original=mp.read_bytes();data=json.loads(original);data['files'].pop('Railway/cozy.tests/cozy.compare-native-abi.js');mp.write_text(json.dumps(data));assert any('belongs under' in e and 'cozy.compare-native-abi.js' in e for e in v.verify(root));count+=1;mp.write_bytes(original)
    path=root/'Relay Server/services/operations/peace.desktop-workspace.js';raw=path.read_bytes();path.unlink();path.symlink_to(root/'Relay Server/peace.relay-server.js');assert any('symlink' in e for e in v.verify(root));count+=1;path.unlink();path.write_bytes(raw)
    mp=root/'Relay Server/maintenance/source-manifest.json';data=json.loads(mp.read_text());data['files']['../outside.js']='0'*128;mp.write_text(json.dumps(data));assert any('Invalid manifest path' in e for e in v.verify(root));count+=1
print(f'Source verifier: {count} tests passed. Temporary copies only.')
