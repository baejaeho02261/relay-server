#!/usr/bin/env python3
"""Negative source-contract checks; no claim of a Delphi runtime test."""
from pathlib import Path
import re, shutil, subprocess, sys, tempfile, importlib.util
sys.dont_write_bytecode=True
root = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
runner=root/'Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py'
subprocess.run([sys.executable,str(runner)],check=True)
with tempfile.TemporaryDirectory(prefix='game-startup-contract-') as temp:
    target=Path(temp)/'Cozy source path (한글)'
    target.mkdir()
    for folder in ['Cozy.Source','Cozy.Projects','Cozy.Build','Cozy.Tests/Cozy.Startup']:
        shutil.copytree(root/folder,target/folder)
    def must_reject(label,expected=None):
        result=subprocess.run([sys.executable,str(target/'Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py')],capture_output=True,text=True)
        if result.returncode==0:raise AssertionError(label+' was accepted')
        if expected and expected not in result.stderr+result.stdout:raise AssertionError(label+' failed for wrong reason: '+result.stderr+result.stdout)
        print('PASS: '+label+' rejected by exact source contract')
    def must_accept(label):
        result=subprocess.run([sys.executable,str(target/'Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py')],capture_output=True,text=True)
        if result.returncode!=0:raise AssertionError(label+' rejected: '+result.stderr+result.stdout)
        print('PASS: '+label+' accepted by exact source contract')
    def mutate_file(file,pattern,replacement,label,expected):
        original=file.read_bytes()
        text,count=re.subn(pattern,replacement if callable(replacement) else lambda _:replacement,
                           original.decode('utf-8-sig'),count=1,flags=re.M)
        assert count==1,'Mutation target missing: '+label
        try:
            file.write_text(text,encoding='utf-8-sig')
            must_reject(label,expected)
        finally:
            file.write_bytes(original)
    reader_spec=importlib.util.spec_from_file_location('relocated_source_strings',target/'Cozy.Build/Cozy.SourceStrings.py')
    reader=importlib.util.module_from_spec(reader_spec);reader_spec.loader.exec_module(reader)
    def expanded(file): return reader.read_source(file)
    # The same complete source tree works under a relocated, spaced/Unicode
    # parent. These checks do not evaluate MSBuild or execute Delphi itself.
    generated=target/'Cozy.Source/Cozy.Configuration/Cozy.IssuedA.Trust.bin'
    if generated.exists():generated.unlink()
    must_accept('relocated source directory with spaces and Unicode, before public resource generation')
    restricted=r"^[ \t]*Cozy\.Handoff\.Restricted\s+in\s+'[^']+'[ \t]*,[ \t]*\r?\n"
    for name in ['Cozy.Launcher','Cozy.Client','Cozy.Overlay']:
        project=target/'Cozy.Projects'/name/(name+'.dpr')
        mutate_file(project,restricted,'',name+' missing restricted-unit mapping',
                    'Missing explicit project mapping: Cozy.Handoff.Restricted')
    launcher=target/'Cozy.Projects/Cozy.Launcher/Cozy.Launcher.dpr'
    project=launcher.with_suffix('.dproj')
    mutate_file(launcher,r"^[ \t]*Cozy\.IssuedA\s+in\s+'[^']+'[ \t]*,[ \t]*\r?\n",'',
                'launcher missing issued-A unit mapping','Missing explicit project mapping: Cozy.IssuedA')
    mutate_file(launcher,r"(?<=')\.\.\\\.\.\\Cozy\.Source\\Cozy\.Handoff\\Cozy\.Handoff\.Restricted\.pas(?=')",
                r'..\..\Cozy.Source\Cozy.Handoff\Cozy.Handoff.pas',
                'mapped filename exists but declares another unit','Project unit path identity mismatch: Cozy.Handoff.Restricted')
    mutate_file(target/'Cozy.Source/Cozy.Handoff/Cozy.Handoff.Restricted.pas',
                r'unit Cozy\.Handoff\.Restricted;','unit Cozy.Handoff.RestrictedAlias;',
                'canonical filename declares a different unit','Project unit path identity mismatch: Cozy.Handoff.Restricted')
    mutate_file(launcher,restricted,lambda m:m.group(0)+
                "  cozy.handoff.restricted in '..\\..\\Cozy.Source\\Cozy.Handoff\\Cozy.Handoff.Restricted.pas',\n",
                'case-insensitive duplicate project mapping','Duplicate explicit project unit: cozy.handoff.restricted')
    mutate_file(project,r'^[ \t]*<DCCReference\s+Include="[^"\r\n]*Cozy\.Handoff\.Restricted\.pas"\s*/>[ \t]*\r?\n','',
                'project missing transitive DCCReference','Missing project DCCReference: Cozy.Handoff.Restricted')
    mutate_file(project,r'^[ \t]*<None\s+Include="[^"\r\n]*Cozy\.IssuedA\.Trust\.inc"\s*/>[ \t]*\r?\n','',
                'project missing issuer public include','Missing issuer public trust include in project')
    mutate_file(project,r'Cozy\.IssuedA\.Trust\.inc','Cozy.Metadata.inc',
                'project issuer include points to another existing file','Missing issuer public trust include in project')
    mutate_file(project,r'Cozy\.IssuedA\.Trust\.bin','Cozy.Unknown.Public.bin',
                'unreviewed generated public file name','Missing or outside project file')
    original=(target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').read_bytes()
    expanded_tls=expanded(target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas')
    probe_binding="BindApiPointer(ProbeOnlySlot, RequireProcAddressHash64('ncrypt.dll', $B5563F48));"
    guarded='{$IFDEF GAME_DEVICE_IDENTITY_PROBE}\n{$IFDEF MSWINDOWS}\n'+probe_binding+'\n{$ENDIF}\n{$ENDIF}\n'
    text=expanded_tls.replace('initialization','initialization\n'+guarded,1)
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_text(text,encoding='utf-8-sig');must_accept('nested probe-only binding')
    text=expanded_tls.replace('initialization','initialization\n'+probe_binding,1)
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_text(text,encoding='utf-8-sig');must_reject('unguarded extra binding')
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_bytes(original)
    # A probe-like name still needs explicit review in the production define set.
    text=expanded_tls.replace('initialization',
        'initialization\n{$IFDEF GAME_UNREVIEWED_PROBE}\n'+probe_binding+'\n{$ENDIF}\n',1)
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_text(text,encoding='utf-8-sig')
    must_reject('unreviewed probe-like conditional','Unknown production conditional GAME_UNREVIEWED_PROBE')
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_bytes(original)
    renderer=target/'Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas'; renderer_original=renderer.read_bytes(); expanded_renderer=expanded(renderer)
    renderer.write_text(expanded_renderer.replace("OptionalSystemProcAddressHash64('wtsapi32.dll', HASH_WTSRegisterSessionNotification)","OptionalSystemProcAddressHash64('wtsapi32.dll', HASH_WTSUnRegisterSessionNotification)",1),encoding='utf-8-sig')
    must_reject('optional WTS slot with wrong API identity','Wrong optional session API identity')
    renderer.write_bytes(renderer_original)
    text=expanded_tls
    text,n=re.subn(r'  BindApiPointer\(ApiSlot_EncryptMessage, RequireProcAddressHash64\([^;]+;','',text,count=1)
    assert n==1
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_text(text,encoding='utf-8-sig');must_reject('missing mandatory TLS API')
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_bytes(original)
    text=expanded_tls.replace("RequireProcAddressHash64('secur32.dll', HASH_EncryptMessage)","RequireProcAddressHash64('secur32.dll', HASH_DecryptMessage)",1)
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_text(text,encoding='utf-8-sig');must_reject('same slot count with wrong API identity')
    (target/'Cozy.Source/Cozy.Network/Cozy.Tls.pas').write_bytes(original)
    central=target/'Cozy.Source/Cozy.Platform/Cozy.Api.ROR13.pas';central_original=central.read_bytes()
    central_text=central_original.decode('utf-8-sig')
    central.write_text(central_text.replace('$3BD09A6B','$3BD09A6A',1),encoding='utf-8-sig')
    must_reject('incorrect ROR13 value','Incorrect ROR13 constant HASH_FindResourceW')
    central.write_bytes(central_original)
    for label,declarations,expected in [
        ('duplicate central identifier','HASH_FindResourceW: Cardinal = $3BD09A6B;','Duplicate API hash identifier'),
        ('case-insensitive Pascal duplicate','HASH_findresourcew: Cardinal = $3BD09A6B;','Duplicate API hash identifier'),
        ('real lookup collision','HASH_ProbemhCdNONDi: Cardinal = $B7123054;\nHASH_ProbeiZoHNPUnw: Cardinal = $B7123054;','Ambiguous ROR13 API constants')]:
        central.write_text(central_text.replace('implementation','const\n'+declarations+'\nimplementation',1),encoding='utf-8-sig')
        must_reject(label,expected);central.write_bytes(central_original)
    startup=target/'Cozy.Source/Cozy.Application/Cozy.Startup.pas';startup_original=startup.read_bytes()
    startup.write_text(startup_original.decode('utf-8-sig').replace('HASH_FindResourceW','$3BD09A6B',1),encoding='utf-8-sig')
    must_reject('raw numeric resolver identifier','Raw API hash outside central constants')
    startup.write_text(startup_original.decode('utf-8-sig').replace('HASH_FindResourceW','HASH_NotACentralApi',1),encoding='utf-8-sig')
    must_reject('undefined central API identifier','Unknown API hash symbol')
    startup.write_bytes(startup_original)
    text=(target/'Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dpr').read_text(encoding='utf-8-sig').replace('Cozy.Overlay in', 'Cozy.Launcher in',1)
    (target/'Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dpr').write_text(text,encoding='utf-8-sig');must_reject('wrong role dependency closure')
print('PASS: role manifests and project file paths track identities and dependencies, not count or file existence alone.')
