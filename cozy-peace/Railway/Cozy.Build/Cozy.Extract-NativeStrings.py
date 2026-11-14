#!/usr/bin/env python3
"""Separate public C/C++ literals into editable language-specific headers.

The headers contain ordinary literal macros, not encryption or runtime state.
`refresh` records intentional header edits; `verify-migration` proves the
initial byte-exact inverse transformation against original source hashes.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys
from pathlib import Path

DIRECTORY='Cozy.ImGui/Cozy.Strings'
MAP=DIRECTORY+'/Cozy.NativeStrings.map.json'
FORMAT='COZY_NATIVE_STRING_UNITS_V1'
EXTS={'.h','.hpp','.c','.cpp'}
IDENT=re.compile(r'[A-Za-z_][A-Za-z_0-9]*')
START=re.compile(r'(?:u8|u|U|L)?R"|(?:u8|u|U|L)?["\x27]')
def sha(data):return hashlib.sha256(data).hexdigest()
def fail(code):raise ValueError('NATIVE_STRING_UNITS_'+code)
def decode(data):return data.decode('utf-8-sig')
def encode(text,source):return (b'\xef\xbb\xbf' if source.startswith(b'\xef\xbb\xbf') else b'')+text.encode('utf8')

def lex(text):
    out=[];i=0;line=1
    while i<len(text):
        start=i;kind='symbol'
        if text[i].isspace():
            kind='space';i+=1
            while i<len(text) and text[i].isspace():i+=1
        elif text.startswith('//',i):
            kind='comment';end=text.find('\n',i);i=len(text) if end<0 else end
        elif text.startswith('/*',i):
            kind='comment';end=text.find('*/',i+2)
            if end<0:fail('UNCLOSED_COMMENT')
            i=end+2
        else:
            match=START.match(text,i)
            if match:
                prefix=match.group(0);quote=prefix[-1];kind='string' if quote=='"' else 'char';i=match.end()
                if prefix.endswith('R"'):
                    opening=text.find('(',i,i+17)
                    if opening<0:fail('RAW_DELIMITER')
                    delimiter=text[i:opening]
                    if any(c.isspace() or c in '()\\' for c in delimiter):fail('RAW_DELIMITER')
                    endmark=')'+delimiter+'"';end=text.find(endmark,opening+1)
                    if end<0:fail('UNCLOSED_RAW_LITERAL')
                    i=end+len(endmark)
                else:
                    while i<len(text):
                        if text[i]=='\\':i+=2
                        elif text[i]==quote:i+=1;break
                        elif text[i] in '\r\n':fail('MULTILINE_LITERAL')
                        else:i+=1
                    else:fail('UNCLOSED_LITERAL')
                suffix=IDENT.match(text,i)
                if suffix:i=suffix.end()
            else:
                match=IDENT.match(text,i)
                if match:kind='id';i=match.end()
                else:i+=1
        out.append({'kind':kind,'text':text[start:i],'start':start,'end':i,'line':line})
        line+=text[start:i].count('\n')
    return out

def directive_at(text,index):
    start=text.rfind('\n',0,index)+1
    while start>0 and text[:start].rstrip('\r\n').endswith('\\'):
        start=text.rfind('\n',0,max(0,start-2))+1
    end=text.find('\n',index)
    if end<0:end=len(text)
    while end<len(text) and text[start:end].rstrip('\r').endswith('\\'):
        nxt=text.find('\n',end+1);end=len(text) if nxt<0 else nxt
    line=text[start:end]
    match=re.match(r'\s*#\s*([A-Za-z_]+)',line)
    return (match.group(1).lower(),line) if match else ('','')

def stringify_macros(files):
    sensitive={'assert','IM_STRINGIFY_HELPER'};aliases={}
    for raw,text in files.values():
        for line in text.splitlines():
            m=re.match(r'\s*#\s*define\s+([A-Za-z_]\w*)(\([^\n]*?\))?\s+(.*)',line)
            if not m:continue
            name,args,body=m.groups()
            code=[t for t in lex(body) if t['kind'] not in ('space','comment','string','char')]
            if args and any(t['text']=='#' for t in code):sensitive.add(name)
            elif not args and re.fullmatch(r'[A-Za-z_]\w*',body.strip()):aliases[name]=body.strip()
    changed=True
    while changed:
        changed=False
        for name,target in aliases.items():
            if target in sensitive and name not in sensitive:sensitive.add(name);changed=True
    return sensitive

def literals(text,sensitive):
    stack=[];previous='';out=[]
    for t in lex(text):
        if t['kind'] in ('space','comment'):continue
        if t['kind']=='string':
            directive,line=directive_at(text,t['start']);reason=''
            if directive and directive!='define':reason='preprocessor_include_pragma_or_condition'
            elif directive=='define' and re.fullmatch(r'"[^"\r\n]*\.(?:h|hpp)"',t['text']):reason='preprocessor_include_configuration'
            elif directive=='define' and any(x['text']=='#' for x in lex(line)[1:] if x['kind'] not in ('string','char','comment','space')):
                # Remove the initial directive '#' before checking operators.
                body=re.sub(r'^\s*#\s*define\s+\w+(?:\([^\n]*?\))?\s*','',line)
                if any(x['text']=='#' for x in lex(body) if x['kind'] not in ('string','char','comment','space')):reason='preprocessor_stringify_or_paste'
            if not reason and previous=='extern' and t['text'] in ('"C"','"C++"'):reason='extern_linkage_syntax'
            if not reason and any(x in sensitive for x in stack):reason='macro_stringification_contract'
            if not reason and 'R"' in t['text'][:5] and '\n' in t['text']:reason='multiline_raw_macro_boundary'
            out.append({**t,'reason':reason})
        if t['text']=='(':stack.append(previous)
        elif t['text']==')':
            if stack:stack.pop()
        previous=t['text']
    return out

def files_at(root):
    result={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink():fail('SYMLINK:'+str(p))
        if not p.is_file() or p.suffix not in EXTS or 'Cozy.Strings' in p.parts:continue
        if p.stat().st_nlink!=1:fail('HARDLINK:'+str(p))
        raw=p.read_bytes()
        if len(raw)>8*1024*1024:fail('SOURCE_TOO_LARGE:'+str(p))
        result[p.relative_to(root).as_posix()]=(raw,decode(raw))
    return result

def group(name):
    return 'Vendor' if '/Cozy.Vendor/' in name else 'Tests' if '/Cozy.Tests/' in name or name.startswith('Cozy.Tests/') else 'Bridge'

def constant_name(name,t):
    owner=re.sub('[^A-Za-z0-9]+','_',Path(name).stem.removeprefix('Cozy.')).upper()[:32]
    spelling=t['text'];words=re.findall(r'[A-Za-z0-9]+',spelling)
    if spelling.startswith(('u8"','u"','U"','L"')):words=words[1:]
    meaning='_'.join(words).upper()[:48] or 'TEXT'
    return 'COZY_TEXT_'+owner+'_'+meaning+'_'+sha((name+'\0'+spelling).encode())[:8].upper()

def write_map(root,m):
    p=root/MAP;temporary=p.with_name(p.name+'.pending');temporary.write_text(json.dumps(m,ensure_ascii=True,indent=2)+'\n');os.replace(temporary,p)

def update_provenance(root):
    p=root/'Cozy.ImGui/Cozy.Provenance/Cozy.SOURCE_PROVENANCE.txt'
    if not p.exists():return
    m=json.loads(p.read_text())
    for entry in m.get('files',[]):
        file=root/'Cozy.ImGui/Cozy.Vendor'/entry['file']
        if not file.exists():fail('PROVENANCE_FILE:'+entry['file'])
        entry['sha512']=hashlib.sha512(file.read_bytes()).hexdigest()
    sentence='Public C/C++ string literals are referenced through editable Cozy.Strings literal macro headers. Literal spelling, encoding prefixes and compile-time array semantics are preserved; include/pragma/linkage and stringification syntax exceptions are recorded separately. Original upstream identities remain unchanged.'
    if sentence not in m.setdefault('transformations',[]):m['transformations'].append(sentence)
    p.write_text(json.dumps(m,ensure_ascii=False,indent=2)+'\n')

def extract(root):
    if (root/MAP).exists():fail('ALREADY_EXTRACTED')
    files=files_at(root);sensitive=stringify_macros(files);units={};sources=[];exceptions=[];planned={}
    for name,(raw,text) in files.items():
        entries=[];section=group(name);unitpath=DIRECTORY+'/Cozy.Strings.'+section+'.h'
        for t in literals(text,sensitive):
            if t['reason']:
                exceptions.append({'path':name,'line':t['line'],'reason':t['reason'],'expression':t['text']});continue
            identifier=constant_name(name,t);table=units.setdefault(unitpath,{})
            constant=table.setdefault(identifier,{'name':identifier,'expression':t['text'],'origins':[]})
            if constant['expression']!=t['text']:fail('IDENTIFIER_COLLISION')
            constant['origins'].append({'path':name,'line':t['line']})
            entries.append({'start':t['start'],'end':t['end'],'name':identifier,'expression':t['text']})
        if not entries:continue
        output=text
        for e in reversed(entries):output=output[:e['start']]+e['name']+output[e['end']:]
        nl='\r\n' if '\r\n' in text else '\n'
        relative=os.path.relpath(unitpath,Path(name).parent).replace('\\','/')
        prefix='/* Cozy central native text imports. */'+nl+'#include "'+relative+'"'+nl+'#line 1'+nl
        output=prefix+output;planned[name]=encode(output,raw)
        sources.append({'path':name,'unitPaths':[unitpath],'originalSha256':sha(raw),'migratedSha256':sha(planned[name]),'includeText':prefix,'replacements':entries})
    (root/DIRECTORY).mkdir(parents=True,exist_ok=True);unitrows=[]
    for file,constants in sorted(units.items()):
        guard='COZY_NATIVE_STRINGS_'+Path(file).stem.split('.')[-1].upper()+'_H'
        lines=['/* Public editable literal constants. Source organization, not encryption. */','#ifndef '+guard,'#define '+guard,'']
        for c in sorted(constants.values(),key=lambda x:x['name']):
            origin=c['origins'][0];lines+=['/* '+origin['path']+':'+str(origin['line'])+' */','#define '+c['name']+' '+c['expression']]
        lines+=['','#endif',''];planned[file]='\n'.join(lines).encode('utf8')
        unitrows.append({'path':file,'constants':sorted(constants.values(),key=lambda x:x['name'])})
    for name,(raw,_) in files.items():
        if (root/name).read_bytes()!=raw:fail('SOURCE_CHANGED:'+name)
    for name,raw in planned.items():(root/name).write_bytes(raw)
    m={'format':FORMAT,'units':unitrows,'sources':sources,'exceptions':exceptions,'scannedFiles':len(files),
       'sourceOrganizationOnly':True,'windowsExecution':'NOT_RUN'}
    write_map(root,m);update_provenance(root);return check(root,verify=True)

def read_constants(root,m,refresh=False):
    constants={}
    for u in m['units']:
        text=decode((root/u['path']).read_bytes())
        guard='COZY_NATIVE_STRINGS_'+Path(u['path']).stem.split('.')[-1].upper()+'_H'
        # Only the include guard and plain literal definitions are allowed.
        # In particular refresh must never approve executable declarations,
        # imports, a function-like macro, or expressions hidden after a value.
        consumed=[]
        found={}
        for match in re.finditer(r'^#define (COZY_TEXT_[A-Za-z0-9_]+) ',text,re.M):
            end=text.find('\n',match.end())
            if end<0:end=len(text)
            while end<len(text) and text[match.end():end].rstrip('\r').endswith('\\'):
                nextline=text.find('\n',end+1);end=len(text) if nextline<0 else nextline
            body=text[match.end():end]
            following=lex(body);literal=next((t for t in following if t['kind']!='space'),None)
            if not literal or literal['kind']!='string':fail('LITERAL_DEFINITION:'+match.group(1))
            expression=literal['text']
            if any(t['kind'] not in ('space','comment') for t in lex(body[literal['end']:])):fail('EXTRA_DEFINITION_TOKENS:'+match.group(1))
            if match.group(1) in found:fail('DUPLICATE_CONSTANT')
            found[match.group(1)]=expression
            consumed.append((match.start(),end))
        remaining=text
        for start,end in reversed(consumed):remaining=remaining[:start]+remaining[end:]
        scaffold=''.join(t['text'] for t in lex(remaining) if t['kind']!='comment')
        expected='#ifndef '+guard+'\n#define '+guard+'\n#endif'
        if '\n'.join(line.strip() for line in scaffold.splitlines() if line.strip())!=expected:fail('HEADER_SCAFFOLD:'+u['path'])
        if set(found)!={c['name'] for c in u['constants']}:fail('CONSTANT_SET_CHANGED:'+u['path'])
        for c in u['constants']:
            if refresh:c['expression']=found[c['name']]
            elif c['expression']!=found[c['name']]:fail('CONSTANT_CHANGED_RUN_REFRESH:'+c['name'])
            constants[c['name']]=found[c['name']]
    return constants

def expand(text,constants):
    edits=[]
    for t in lex(text):
        if t['kind']=='id' and t['text'].startswith('COZY_TEXT_'):
            if t['text'] not in constants:fail('UNDECLARED_CONSTANT:'+t['text'])
            edits.append((t['start'],t['end'],constants[t['text']]))
    for a,b,value in reversed(edits):text=text[:a]+value+text[b:]
    return text

def remaining_literals(files,sources):
    normalized={name:(raw,text[len(sources[name]['includeText']):] if name in sources and text.startswith(sources[name]['includeText']) else text) for name,(raw,text) in files.items()}
    sensitive=stringify_macros(normalized)
    remaining=[]
    for name,(_,text) in normalized.items():
        for t in literals(text,sensitive):
            if not t['reason']:fail('UNCENTRALIZED_LITERAL:'+name+':'+str(t['line']))
            remaining.append({'path':name,'line':t['line'],'reason':t['reason'],'expression':t['text']})
    return remaining

def check(root,verify=False,baseline=None,document=None):
    m=document if document is not None else json.loads((root/MAP).read_text())
    if m['format']!=FORMAT:fail('FORMAT')
    constants=read_constants(root,m);count=0
    units={u['path']:{c['name']:constants[c['name']] for c in u['constants']} for u in m['units']}
    files=files_at(root)
    if len(files)!=m['scannedFiles']:fail('SOURCE_INVENTORY_CHANGED')
    sources={e['path']:e for e in m['sources']}
    if remaining_literals(files,sources)!=m['exceptions']:fail('STRUCTURAL_EXCEPTIONS_CHANGED')
    for e in m['sources']:
        raw=(root/e['path']).read_bytes();text=decode(raw)
        if sha(raw)!=e['migratedSha256']:fail('SOURCE_CHANGED_RUN_REFRESH:'+e['path'])
        if not text.startswith(e['includeText']):fail('INCLUDE_MISSING:'+e['path'])
        for unit in e['unitPaths']:
            relative=os.path.relpath(unit,Path(e['path']).parent).replace('\\','/')
            if '#include "'+relative+'"' not in e['includeText']:fail('UNIT_LINKAGE:'+e['path'])
        linked={name:value for unit in e['unitPaths'] for name,value in units[unit].items()}
        restored=expand(text[len(e['includeText']):],linked)
        if verify:
            original=encode(restored,raw)
            if sha(original)!=e['originalSha256']:fail('ROUNDTRIP_MISMATCH:'+e['path'])
            if baseline and original!=(baseline/e['path']).read_bytes():fail('BASELINE_MISMATCH:'+e['path'])
        count+=len(e['replacements'])
    return {'status':'PASS','units':len(m['units']),'constants':len(constants),'movedOccurrences':count,
            'sources':len(m['sources']),'scannedFiles':m['scannedFiles'],'structuralExceptions':len(m['exceptions']),
            'byteExactRoundTrip':verify,'windowsExecution':'NOT_RUN'}

def refresh(root):
    m=json.loads((root/MAP).read_text())
    if m['format']!=FORMAT:fail('FORMAT')
    read_constants(root,m,refresh=True)
    for e in m['sources']:e['migratedSha256']=sha((root/e['path']).read_bytes())
    m['exceptions']=remaining_literals(files_at(root),{e['path']:e for e in m['sources']})
    result=check(root,document=m)
    write_map(root,m);update_provenance(root);return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['extract','check','refresh','verify-migration']);p.add_argument('--root',type=Path,required=True);p.add_argument('--baseline',type=Path);a=p.parse_args();root=a.root.resolve()
    try:
        result=extract(root) if a.command=='extract' else refresh(root) if a.command=='refresh' else check(root,a.command=='verify-migration',a.baseline)
        print(json.dumps(result));return 0
    except (OSError,ValueError,KeyError) as e:print(str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
