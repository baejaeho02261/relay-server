#!/usr/bin/env python3
"""Check project source mappings and generate role API binding manifests.
Does not compile Delphi or establish Windows ABI/runtime correctness.
"""
from pathlib import Path, PureWindowsPath
import argparse, collections, json, re, importlib.util, sys
import xml.etree.ElementTree as ET
ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'Cozy.Source').is_dir())
sys.dont_write_bytecode = True
_string_spec = importlib.util.spec_from_file_location('cozy_source_strings', ROOT / 'Cozy.Build/Cozy.SourceStrings.py')
_strings = importlib.util.module_from_spec(_string_spec)
_string_spec.loader.exec_module(_strings)
ROLES={'gcrLauncher':'Cozy.Projects/Cozy.Launcher/Cozy.Launcher.dpr','gcrConnect':'Cozy.Projects/Cozy.Client/Cozy.Client.dpr','gcrOverlay':'Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dpr'}
PRODUCTION_DEFINED = {'CPUX64', 'MSWINDOWS', 'WIN64', 'GAME_APPLICATION_BUILD', 'RELEASE'}
# Reviewed test-only features are explicitly false for production. Unknown
# conditionals still fail; a new test-like name does not silently hide code.
PRODUCTION_DISABLED = {
    'FPC', 'DEBUG', 'COZY_CRC32C_REFERENCE_ONLY', 'COZY_POINTER_GRAPH_PROBE',
    'COZY_HASH_WORKER_TESTS', 'GAME_CRC_PE_PROBE', 'GAME_DEVICE_IDENTITY_PROBE',
    'GAME_DEVICE_KEY_PROBE', 'GAME_DEVICE_SECURITY_TESTS',
    'GAME_HANDOFF_CONTRACT_TESTS', 'GAME_IMGUI_FAULT_TESTS', 'GAME_ISSUED_A_TESTS',
    'GAME_LICENSE_CONTRACT_TESTS', 'GAME_LIFECYCLE_CONTRACT_TESTS',
    'GAME_MEASUREMENT_TESTS', 'GAME_NATIVE_ABI_TESTS', 'GAME_OVERLAY_CONTRACT_TESTS',
    'GAME_OWN_MEASUREMENT_TESTS', 'GAME_PRODUCT_FAULT_TESTS',
    'GAME_RECOVERY_DEVICE_PROBE', 'GAME_RELAY_SOCKET_CONTRACT_TESTS',
    'GAME_STARTUP_ROLE_PROBE', 'GAME_TLS_CONTRACT_TESTS', 'GAME_TRANSPORT_TESTS',
    'NHW_FINAL12_TESTS', 'NHW_HARDENING_TESTS', 'NHW_NATIVE5_TESTS',
    'NHW_NATIVE5B_TESTS', 'NHW_NATIVE5C_TESTS', 'NHW_NATIVE5D_TESTS',
    'NHW_NATIVE5E_TESTS', 'NHW_NATIVE5F_TESTS', 'NHW_NATIVE5G_TESTS',
    'NHW_NATIVE5H_TESTS', 'NHW_NATIVE5I_TESTS', 'NHW_NATIVE5J_TESTS',
    'NHW_NATIVE5K_TESTS', 'NHW_NATIVE5L_TESTS', 'NHW_NATIVE10M_TESTS',
    'NHW_NATIVE10N_TESTS', 'NHW_NATIVE10O_TESTS', 'NHW_NATIVE10P_TESTS',
    'NHW_NATIVE10Q_TESTS', 'NHW_REFACTOR10AA_TESTS', 'COZY_NHW_DIAGNOSTIC_OUTPUT',
}
NHW_ROOT = ROOT / 'Cozy.Source/Cozy.Security.NHW'
NHW_LOCAL_OPTIONS = {'NS_RESTORE_OVERFLOW_CHECK', 'NHW_OBSERVER_RESTORE_OPT'}
def defined_expression(expression, defined, disabled):
    # Restricted Boolean grammar for generated conditional unit imports. No eval.
    parts = re.findall(r'DEFINED|[A-Z_][A-Z_0-9]*|[()]', expression)
    if ''.join(parts) != re.sub(r'\s+', '', expression):
        return None
    at = 0
    def atom():
        nonlocal at
        if at >= len(parts): raise ValueError()
        token = parts[at]; at += 1
        if token == 'NOT': return not atom()
        if token == '(':
            result = disjunction()
            if at >= len(parts) or parts[at] != ')': raise ValueError()
            at += 1; return result
        if token != 'DEFINED' or at + 2 >= len(parts) or parts[at] != '(' or parts[at+2] != ')':
            raise ValueError()
        name = parts[at+1]; at += 3
        if name in defined: return True
        if name in disabled: return False
        raise ValueError('Unknown production conditional '+name)
    def conjunction():
        nonlocal at
        result = atom()
        while at < len(parts) and parts[at] == 'AND':
            at += 1; right = atom(); result = result and right
        return result
    def disjunction():
        nonlocal at
        result = conjunction()
        while at < len(parts) and parts[at] == 'OR':
            at += 1; right = conjunction(); result = result or right
        return result
    try:
        result = disjunction()
        return result if at == len(parts) else None
    except ValueError as error:
        if str(error).startswith('Unknown production conditional'): raise
        return None

def production_source(text, nhw=False):
    # The manifest is for the Win64 application, not any opt-in test build.
    # Removing directives while retaining their bodies incorrectly required
    # probe-only bindings at runtime (for example NCryptDeleteKey).
    defined=PRODUCTION_DEFINED
    disabled=PRODUCTION_DISABLED
    out=[]; stack=[]; active=True; previous=0
    directive=re.compile(r'\{\$\s*(IFDEF|IFNDEF|IFOPT|IF|ELSE|ENDIF|IFEND)\b([^}]*)\}',re.I)
    for match in directive.finditer(text):
        segment=text[previous:match.start()]
        if active:
            if any(condition is None for _,condition,_ in stack) and re.search(r'\b(?:BindApiPointer|uses)\b',segment,re.I):
                raise ValueError('API dependency inside unevaluated compile-time expression')
            out.append(segment)
        command=match.group(1).upper(); value=match.group(2).strip().upper()
        if command in ('IFDEF','IFNDEF'):
            if value in defined: condition=True
            elif value in disabled: condition=False
            elif nhw and value in NHW_LOCAL_OPTIONS: condition=None
            else: raise ValueError('Unknown production conditional '+value)
            if command=='IFNDEF' and condition is not None: condition=not condition
            stack.append((active,condition,False)); active=active and (condition is None or condition)
        elif command=='IFOPT':
            # NHW locally restores optimization/overflow switches. Neither
            # branch may add project dependencies or sealed API bindings.
            if not nhw or value not in {'Q+', 'O+'}:
                raise ValueError('Unknown production compiler option '+value)
            stack.append((active,None,False))
        elif command=='IF':
            # ABI assertions contain no dependency/binding calls. Their actual
            # values remain the Delphi compiler/probe's responsibility.
            condition=defined_expression(value, defined, disabled)
            stack.append((active,condition,False)); active=active and (condition is None or condition)
        elif command=='ELSE':
            if not stack or stack[-1][2]: raise ValueError('Unbalanced conditional ELSE')
            parent,condition,_=stack[-1]; stack[-1]=(parent,condition,True)
            active=parent and (condition is None or not condition)
        else:
            if not stack: raise ValueError('Unbalanced conditional ENDIF')
            active=stack.pop()[0]
        previous=match.end()
    if stack: raise ValueError('Unclosed production conditional')
    if active: out.append(text[previous:])
    return ''.join(out)
def clean(text, nhw=False):
    return re.sub(r'\{.*?\}|\(\*.*?\*\)|//[^\n]*','',production_source(text, nhw),flags=re.S)
def source(path):return clean(_strings.read_source(path), path.is_relative_to(NHW_ROOT))
units={p.stem.lower():p for p in (ROOT/'Cozy.Source').rglob('*.pas')}
def ror13(name):
    value=0
    for octet in name.encode('ascii'):
        value=(((value >> 13) | (value << 19)) + octet) & 0xFFFFFFFF
    return value
hashes={}; canonical_names=set(); hash_names={}
for name,hexval in re.findall(r'(HASH_\w+)\s*:\s*Cardinal\s*=\s*\$([0-9A-Fa-f]+)',source(ROOT/'Cozy.Source/Cozy.Platform/Cozy.Api.ROR13.pas')):
    value=int(hexval,16)
    if name.lower() in canonical_names: raise ValueError('Duplicate API hash identifier '+name)
    if value != ror13(name[5:]): raise ValueError('Incorrect ROR13 constant '+name)
    if value in hash_names: raise ValueError('Ambiguous ROR13 API constants '+hash_names[value]+' / '+name)
    canonical_names.add(name.lower()); hashes[name]=value; hash_names[value]=name
for path in (ROOT/'Cozy.Source').rglob('*.pas'):
    contents=source(path)
    identifiers=re.sub(r"'(?:[^']|'')*'", "''", contents)
    if path.is_relative_to(NHW_ROOT):
        # The imported FNV digest seed is unrelated to export lookup.
        identifiers=re.sub(r'\bHASH_SEED\b','NHW_FNV_SEED',identifiers)
    if path.name!='Cozy.Api.ROR13.pas':
        if re.search(r'\bHASH_\w+\s*(?::\s*Cardinal)?\s*=',identifiers,re.I):
            raise ValueError('API hash declaration outside central unit: '+path.name)
        for symbol in re.findall(r'\bHASH_\w+\b',identifiers):
            if symbol not in hashes: raise ValueError('Unknown API hash symbol '+symbol+' in '+path.name)
    if re.search(r'\b(?:RequireProcAddressHash64|OptionalSystemProcAddressHash64|GetProcAddressHash64)\s*\([^;]*?,\s*\$[0-9A-Fa-f]+\s*\)',contents,re.S):
        raise ValueError('Raw API hash outside central constants: '+path.name)

def hashvalue(value):
    value=value.strip()
    if value.startswith('$'):raise ValueError('Raw API hash must use central HASH_ symbol '+value)
    if value in hashes:return hashes[value]
    raise ValueError('Unknown API hash '+value)
def closure(path,seen):
    if path.name in seen:return
    seen[path.name]=path
    for clause in re.findall(r'\buses\s+(.*?);',source(path),re.S|re.I):
        # A project's quoted `in` path is a filename, not another used unit.
        # In particular Cozy.Overlay in a directory name must not add O to B.
        unquoted=re.sub(r"'(?:[^']|'')*'", "''", clause)
        for entry in unquoted.split(','):
            match=re.match(r'\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\b',entry)
            if match and match.group(1).lower() in units:
                closure(units[match.group(1).lower()],seen)
            elif match and match.group(1).lower().startswith('cozy.'):
                raise ValueError('Unknown production unit: '+match.group(1))
def project_file(project,relative):
    # File mappings must survive relocating the complete Railway directory and
    # opening either the DPR or DPROJ, without an inherited IDE search path.
    if (not relative or PureWindowsPath(relative).drive or
        relative.startswith(('/', '\\')) or any(c in relative for c in '$%*?\r\n\x00')):
        raise ValueError('Invalid explicit project path: '+project.name)
    target=project.parent.joinpath(*relative.replace('\\','/').split('/'))
    resolved=target.resolve()
    if not resolved.is_relative_to(ROOT.resolve()) or not resolved.is_file():
        raise ValueError('Missing or outside project file: '+relative)
    return resolved
def project_metadata_file(project,relative):
    # Only the exact public-key resource generated by the reviewed launcher
    # pre-build step may be absent from an unconfigured source delivery.
    # Ordinary source mappings and every other missing None entry still fail.
    canonical='../../Cozy.Source/Cozy.Configuration/Cozy.IssuedA.Trust.bin'
    launcher=ROOT.resolve()/'Cozy.Projects/Cozy.Launcher/Cozy.Launcher.dpr'
    if project.resolve()!=launcher or relative.replace('\\','/')!=canonical:
        return project_file(project,relative)
    expected=ROOT.resolve()/'Cozy.Source/Cozy.Configuration/Cozy.IssuedA.Trust.bin'
    target=project.parent.joinpath(*canonical.split('/'))
    if target.is_symlink() or target.resolve()!=expected:
        raise ValueError('Invalid generated issuer public resource path')
    if target.exists():
        return project_file(project,relative)
    return expected

def declared_unit(path):
    match=re.search(r'\bunit\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;',source(path),re.I)
    if not match:raise ValueError('Project unit declaration missing: '+path.name)
    return match.group(1)
def project_mappings(project,seen):
    expected={p.stem.lower():p.resolve() for p in seen.values() if p.suffix.lower()=='.pas'}
    mappings={}
    for clause in re.findall(r'\buses\s+(.*?);',source(project),re.S|re.I):
        for entry in clause.split(','):
            match=re.fullmatch(r"\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(?:in\s+'((?:''|[^'])*)')?\s*",entry,re.I)
            if not match:raise ValueError('Invalid project uses entry: '+project.name)
            name,relative=match.groups();key=name.lower()
            if key not in units:continue
            if key in mappings:raise ValueError('Duplicate explicit project unit: '+name)
            if relative is None:raise ValueError('Missing explicit project mapping: '+name)
            target=project_file(project,relative.replace("''", "'"))
            if target!=units[key].resolve() or declared_unit(target).lower()!=key:
                raise ValueError('Project unit path identity mismatch: '+name)
            mappings[key]=target
    for key,target in expected.items():
        if mappings.get(key)!=target:
            raise ValueError('Missing explicit project mapping: '+units[key].stem)
    xml=ET.parse(project.with_suffix('.dproj')).getroot()
    references={}
    for node in xml.findall('.//{*}DCCReference'):
        target=project_file(project,node.get('Include',''))
        name=declared_unit(target);key=name.lower()
        if key in references:raise ValueError('Duplicate project DCCReference: '+name)
        if key not in units or target!=units[key].resolve():
            raise ValueError('Project DCCReference identity mismatch: '+name)
        references[key]=target
    for key,target in expected.items():
        if references.get(key)!=target:
            raise ValueError('Missing project DCCReference: '+units[key].stem)
    if project.stem=='Cozy.Launcher':
        trust=(ROOT/'Cozy.Source/Cozy.Configuration/Cozy.IssuedA.Trust.inc').resolve()
        includes={project_metadata_file(project,node.get('Include','')) for node in xml.findall('.//{*}None')}
        if trust not in includes:raise ValueError('Missing issuer public trust include in project')
    return len(expected)
def calls(text):
    for match in re.finditer(r'\bBindApiPointer\s*\(',text):
        if re.search(r'\bprocedure\s*$',text[max(0,match.start()-25):match.start()],re.I):continue
        start=match.end(); pos=start; depth=1; quote=False
        while pos<len(text) and depth:
            ch=text[pos]
            if ch=="'":
                if quote and pos+1<len(text) and text[pos+1]=="'":pos+=2;continue
                quote=not quote
            elif not quote:
                if ch=='(':depth+=1
                elif ch==')':depth-=1
            pos+=1
        if depth:raise ValueError('Unbalanced BindApiPointer call')
        yield text[start:pos-1]
def bindings(path):
    out=[]
    clock_names={'QueryPerformanceCounter','QueryPerformanceFrequency','CreateEventW',
                 'WaitForSingleObject','CloseHandle','GetLastError','SetLastError'}
    if path.name=='Cozy.Clock.pas':
        helper=re.search(r'\bfunction\s+RequireClockApi\(Name:\s*PAnsiChar\):\s*Pointer\s*;.*?\bbegin\b(.*?)\bend\s*;',source(path),re.S|re.I)
        if not helper or not re.search(r"\bModule\s*:=\s*Winapi\.Windows\.GetModuleHandleW\(\s*'kernel32\.dll'\s*\)\s*;",helper.group(1)) or not re.search(r'\bResult\s*:=\s*Winapi\.Windows\.GetProcAddress\(\s*Module\s*,\s*Name\s*\)\s*;',helper.group(1)):
            raise ValueError('Named clock bindings require the documented kernel32 export helper')
    for call in calls(source(path)):
        match=re.fullmatch(r"\s*(\w+(?:\[\d+\])?)\s*,\s*RequireProcAddressHash64\(\s*'([^']+)'\s*,\s*([\w$]+)\s*\)\s*",call,re.S)
        optional=False; lookup='hash'; proc_name=''
        if match: slot,module,h=match.groups(); h=hashvalue(h)
        elif path.name=='Cozy.Clock.pas':
            named=re.fullmatch(r"\s*(ClockSlot_\w+)\s*,\s*RequireClockApi\(\s*'(\w+)'\s*\)\s*",call,re.S)
            if not named or named.group(2) not in clock_names or named.group(1)!='ClockSlot_'+named.group(2):
                raise ValueError('Unmapped named clock binding '+call)
            slot,proc_name=named.groups(); module='kernel32.dll'; h=0; lookup='name'
        elif path.name=='Cozy.Platform.ExportResolver.pas':
            slot,value=map(str.strip,call.split(',',1)); module='kernel32.dll'
            h=hashes['HASH_GetProcAddress'] if value=='Address' else hashvalue(re.fullmatch(r'RequireCoreExport\((\w+)\)',value).group(1))
        elif path.name=='Cozy.ProcessMitigations.pas':
            slot,value=map(str.strip,call.split(',',1)); optional=True
            choices={'ApiSlot_GetMitigation':('kernel32.dll','HASH_GetProcessMitigationPolicy'),
                     'ApiSlot_SetMitigation':('kernel32.dll','HASH_SetProcessMitigationPolicy'),
                     'ApiSlot_RtlGetVersion':('ntdll.dll','HASH_RtlGetVersion')}
            if value!='Address' or slot not in choices:
                raise ValueError('Unmapped optional mitigation binding '+call)
            module,symbol=choices[slot]
            contents=source(path)
            if module=='kernel32.dll':
                if not re.search(r"\bModuleBase\s*:=\s*GetModuleBase64\(\s*'kernel32\.dll'\s*\)\s*;",contents,re.I):
                    raise ValueError('Wrong mitigation API module '+call)
                base=r'ModuleBase'
            else:
                base=r"GetModuleBase64\(\s*'ntdll\.dll'\s*\)"
            assignment=rf'\bAddress\s*:=\s*GetProcAddressHash64\(\s*{base}\s*,\s*{re.escape(symbol)}\s*\)\s*;\s*if\s+Address\s*<>\s*nil\s+then\s+BindApiPointer\(\s*{re.escape(slot)}\s*,\s*Address\s*\)\s*;'
            if not re.search(assignment,contents,re.I):
                raise ValueError('Wrong optional mitigation API identity '+call)
            h=hashes[symbol]
        elif path.name=='Cozy.ModuleInventory.pas':
            slot,value=map(str.strip,call.split(',',1)); module='ntdll.dll'; optional=True
            if value!='Address' or slot not in ('ApiSlot_LdrRegisterDllNotification','ApiSlot_LdrUnregisterDllNotification'):
                raise ValueError('Unmapped module loader binding '+call)
            h=hashes['HASH_'+slot[len('ApiSlot_'):]]
        elif path.name=='Cozy.ThreadInventory.pas':
            slot,value=map(str.strip,call.split(',',1)); module='ntdll.dll'; optional=True
            if value!='Address' or slot not in ('Slot_NtGetNextThread','Slot_NtQueryInformationThread'):
                raise ValueError('Unmapped thread inventory binding '+call)
            h=hashes['HASH_'+slot[len('Slot_'):]]
        elif path.name=='Cozy.DeviceSignals.pas':
            slot,value=map(str.strip,call.split(',',1)); module='iphlpapi.dll'; optional=True
            if value!='Address' or slot not in ('Slot_GetIfTable2','Slot_FreeMibTable'):
                raise ValueError('Unmapped device signals binding '+call)
            h=hashes['HASH_'+slot[len('Slot_'):]]
        elif path.name=='Cozy.Overlay.Renderer.pas':
            slot,value=map(str.strip,call.split(',',1)); module='wtsapi32.dll'; optional=True
            choices={'Slot_WTSRegisterSessionNotification':('RegisterAddress','HASH_WTSRegisterSessionNotification'),
                     'Slot_WTSUnRegisterSessionNotification':('UnregisterAddress','HASH_WTSUnRegisterSessionNotification')}
            if slot not in choices or value!=choices[slot][0]:
                raise ValueError('Unmapped optional session binding '+call)
            assignment=rf"\b{re.escape(value)}\s*:=\s*OptionalSystemProcAddressHash64\(\s*'wtsapi32\.dll'\s*,\s*{re.escape(choices[slot][1])}\s*\)\s*;"
            if not re.search(assignment,source(path),re.I):
                raise ValueError('Wrong optional session API identity '+call)
            h=hashes[choices[slot][1]]
        else:raise ValueError(f'Unmapped binding in {path.name}: {call}')
        if lookup=='name':api_name=proc_name
        else:
            names=sorted(name[5:] for name,value in hashes.items() if value==h)
            if len(names)!=1: raise ValueError('Unmapped or ambiguous API hash '+str(h))
            api_name=names[0]
        ownership='Synchronous borrowed inputs; caller owns output storage; validate returned status and lengths.'
        if api_name in ['CreateFileW','CreateEventW','CreateEvent','CreateProcessW','CreatePipe','DuplicateHandle']:
            ownership='Successful output kernel handles transfer to caller; CloseHandle once after operations drain.'
        elif api_name.startswith('BCrypt'):
            ownership='Borrow byte spans for call only; provider/key/hash handles pair with matching BCryptClose/Destroy; outputs publish after success.'
        elif api_name.startswith('NCrypt'):
            ownership='Borrow call arguments; owned provider/key handles pair with NCryptFreeObject after operation gate drains.'
        elif api_name in ['AcquireCredentialsHandleW','InitializeSecurityContextW','QueryContextAttributesW','EncryptMessage','DecryptMessage']:
            ownership='SSPI context/credential owner is TLS stream; caller spans bounded; provider token/certificate outputs released with exact provider free routine.'
        elif api_name in ['LoadLibraryExW','GetModuleHandleExW','GetProcAddress']:
            ownership='Loader reference retained to process exit; resolved actual target module pinned by role startup gate.'
        out.append({'unit':path.stem,'slot':slot,'module':module.lower(),'hash':h,'lookup':lookup,'procName':proc_name,'optional':optional,
                    'api':api_name,'callingConvention':('Win64 C/C++ cdecl and explicit variadic bridge typedefs' if module.lower()=='ucrtbase.dll' else 'Windows x64 typed function pointer; native stdcall declaration'),
                    'ownershipContract':ownership})
    if path.name=='Cozy.Clock.pas' and (len(out)!=len(clock_names) or
        {entry['procName'] for entry in out}!=clock_names):
        raise ValueError('Incomplete or duplicate named clock bindings')
    return out
roles={};project_counts={}
for role,main in ROLES.items():
    seen={};closure(ROOT/main,seen)
    project_counts[role]=project_mappings(ROOT/main,seen)
    roles[role]=[entry for path in sorted(seen.values()) for entry in bindings(path)]
lines=['{ Generated by Cozy.Tests/Cozy.Startup/Cozy.generate-startup-contracts.py; checked against actual',
       '  transitive production binding units. Do not hand-edit. }','procedure FillRoleApiContract(Role: TGameComponentRole; var Items: TStartupApiContracts);','begin','  case Role of']
for role,items in roles.items():
    count=collections.Counter((x['module'],x['lookup'],x['procName'],x['hash'],x['optional']) for x in items)
    lines += [f'    {role}:', '    begin',f'      SetLength(Items, {len(count)});']
    for i,((module,lookup,proc_name,h,optional),copies) in enumerate(sorted(count.items())):
        if lookup=='name':
            if optional or h!=0 or copies!=1:raise ValueError('Invalid named API contract')
            lines += [f"      SetNamedApiContract(Items[{i}], '{module}', '{proc_name}', {copies});"]
        else:
            lines += [f"      SetApiContract(Items[{i}], '{module}', {hash_names[h]}, {copies}, {'True' if optional else 'False'});"]
    lines += ['    end;']
lines += ["  else raise EArgumentException.Create('STARTUP_ROLE_INVALID');",'  end;','end;','']
outputs={ROOT/'Cozy.Source/Cozy.Application/Cozy.Startup.ApiContracts.inc':'\n'.join(lines),ROOT/'Cozy.Tests/Cozy.Startup/Cozy.Startup_Binding_Contracts.json':json.dumps({'schema':2,'purpose':'source and runtime API target contract; not process attestation','roles':roles},indent=2)+'\n'}
parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
for path,text in outputs.items():
    if args.write:
        if path.suffix.lower()=='.inc': path.write_bytes(b'\xef\xbb\xbf'+text.replace('\n','\r\n').encode('utf-8'))
        else: path.write_text(text,encoding='utf-8')
    elif not path.exists() or path.read_text(encoding='utf-8-sig')!=text:raise SystemExit('STALE STARTUP CONTRACT: '+path.name+'; run generator --write after reviewing binding changes')
print('PASS: per-role exact API source contracts '+', '.join(f'{r}={len(v)} slots' for r,v in roles.items()))
print('PASS: explicit DPR/DPROJ production unit paths '+', '.join(f'{r}={n} units' for r,n in project_counts.items()))
