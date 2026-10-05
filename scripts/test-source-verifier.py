"""Temporary-copy corruption tests for the current read-only manifest verifier."""
from pathlib import Path
import importlib.util,tempfile,shutil,json,hashlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parent
spec=importlib.util.spec_from_file_location('verifier',HERE/'verify-source.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
count=0
with tempfile.TemporaryDirectory(prefix='source-verifier-') as tmp:
    root=Path(tmp);shutil.copytree(ROOT/'GameWeb',root/'GameWeb',ignore=shutil.ignore_patterns('node_modules','__pycache__'));shutil.copytree(ROOT/'GameConnect_Win64',root/'GameConnect_Win64')
    delivered=json.loads((ROOT/'GameWeb/maintenance/source-manifest.json').read_text())
    for name in delivered['files']:
        if len(Path(name).parts)==1:
            shutil.copy2(ROOT/name,root/name)
    assert not v.verify(root);count+=1
    path=root/'GameConnect_Win64/Game.Api.Pointer.pas';raw=path.read_bytes();path.write_bytes(raw+b'changed');assert any('Changed:' in e for e in v.verify(root));count+=1;path.write_bytes(raw)
    path=root/'GameWeb/services/desktopWorkspace.js';raw=path.read_bytes();path.unlink();assert any('Missing' in e for e in v.verify(root));count+=1;path.write_bytes(raw)
    manifest=json.loads((root/'GameWeb/maintenance/source-manifest.json').read_text());old=root/manifest['retiredExecutableSources'][0];old.parent.mkdir(parents=True,exist_ok=True);old.write_text('//old');assert any('retired source' in e for e in v.verify(root));count+=1;old.unlink()
    extra=root/'GameConnect_Win64/unneeded.json';extra.write_text('{}');assert any('belongs under' in e for e in v.verify(root));count+=1;extra.unlink()
    path=root/'GameWeb/services/desktopWorkspace.js';raw=path.read_bytes();path.unlink();path.symlink_to(root/'GameWeb/server.js');assert any('symlink' in e for e in v.verify(root));count+=1;path.unlink();path.write_bytes(raw)
    mp=root/'GameWeb/maintenance/source-manifest.json';data=json.loads(mp.read_text());data['files']['../outside.js']='0'*64;mp.write_text(json.dumps(data));assert any('Invalid manifest path' in e for e in v.verify(root));count+=1
print(f'Source verifier: {count} tests passed. Temporary copies only.')
