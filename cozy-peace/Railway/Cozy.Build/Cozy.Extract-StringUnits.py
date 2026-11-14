#!/usr/bin/env python3
"""Extract public Pascal source literals into real compile-time units.

This is source organization, not encryption. Check/verify never execute A/B/O.
Generated protocol blobs and syntax-only literals retain explicit exceptions.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys, tempfile
from pathlib import Path

CONFIG = 'Cozy.Source/Cozy.Configuration'
MAP = CONFIG + '/Cozy.StringUnits.map.json'
FORMAT = 'COZY_STRING_UNITS_V1'
ID = re.compile(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*')
def sha(b): return hashlib.sha256(b).hexdigest()
def fail(message): raise ValueError('STRING_UNITS_' + message)
def encode(text, original): return (b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b'') + text.encode('utf8')
def decode(data): return data.decode('utf-8-sig')

def lex(text):
    out=[];i=0;line=1
    while i<len(text):
        start=i;kind='symbol'
        if text[i].isspace():
            kind='space';i+=1
            while i<len(text) and text[i].isspace(): i+=1
        elif text.startswith('//',i):
            kind='comment';end=text.find('\n',i);i=len(text) if end<0 else end
        elif text[i]=='{' or text.startswith('(*',i):
            width=1 if text[i]=='{' else 2;endmark='}' if width==1 else '*)'
            kind='directive' if text[i+width:i+width+1]=='$' else 'comment'
            end=text.find(endmark,i+width)
            if end<0: fail('UNCLOSED_COMMENT')
            i=end+len(endmark)
        elif text[i]=="'":
            kind='string';i+=1
            while i<len(text):
                if text[i]=="'":
                    if text[i:i+2]=="''": i+=2
                    else: i+=1;break
                else:
                    if text[i] in '\r\n': fail('MULTILINE_LITERAL')
                    i+=1
            else: fail('UNCLOSED_LITERAL')
        elif text[i]=='#' and i+1<len(text) and (text[i+1].isdigit() or text[i+1]=='$'):
            kind='charcode';i+=1
            if text[i]=='$':
                i+=1
                while i<len(text) and text[i] in 'abcdefABCDEF0123456789':i+=1
            else:
                while i<len(text) and text[i].isdigit():i+=1
        else:
            match=ID.match(text,i)
            if match:kind='id';i=match.end()
            else:i+=1
        out.append({'kind':kind,'text':text[start:i],'start':start,'end':i,'line':line})
        line+=text[start:i].count('\n')
    return out

def value_of(expression):
    result=''
    for t in lex(expression):
        if t['kind']=='string':result+=t['text'][1:-1].replace("''", "'")
        elif t['kind']=='charcode':result+=chr(int(t['text'][2:],16) if t['text'].startswith('#$') else int(t['text'][1:]))
        elif t['kind']!='space':fail('NON_LITERAL_CONSTANT')
    return result

def literal_groups(text):
    tokens=lex(text);out=[];i=0;previous=None
    while i<len(tokens):
        t=tokens[i]
        if t['kind'] not in ('string','charcode'):
            if t['kind'] not in ('space','comment','directive'):previous=t
            i+=1;continue
        start=i;last=i;j=i+1
        while j<len(tokens):
            if tokens[j]['kind']=='space':j+=1;continue
            if tokens[j]['kind'] in ('string','charcode'):last=j;j+=1;continue
            break
        spelling=text[t['start']:tokens[last]['end']]
        out.append({**t,'end':tokens[last]['end'],'expression':spelling,'value':value_of(spelling),
                    'previous':previous['text'] if previous else '',
                    'hasQuoted':any(x['kind']=='string' for x in tokens[start:last+1])})
        previous=tokens[last];i=last+1
    return out

def generated(name,text):
    if name.endswith('/Cozy.Version.inc'):return True
    if Path(name).suffix=='.inc' and re.search(r'\bGenerated\b',text[:400],re.I):return True
    return False

def reason(name,text,item):
    if generated(name,text):return 'generator_owned_contract'
    if not item['hasQuoted']:return 'character_code_syntax'
    v=item['value'];prev=item['previous'].lower()
    if not v:return 'empty_literal_type_context'
    if len(v)==1:return 'character_range_delimiter_or_role_type_context'
    if prev=='in' and name.endswith('.dpr'):return 'project_unit_file_path'
    if prev in ('external','name','deprecated'):return 'compiler_linker_spelling'
    if re.fullmatch(r'\{[A-Fa-f0-9-]{36}\}',v):return 'interface_guid_attribute'
    statement=text[max(text.rfind(';',0,item['start']),text.rfind('\n',0,item['start'])-500)+1:item['start']]
    if re.search(r'array\s*\[[^]]*\]\s*of\s*(?:Ansi|Wide)?Char\s*=\s*$',statement,re.I):return 'fixed_character_array_initializer'
    return ''

def group(name):
    parts=Path(name).parts
    if parts[0]=='Cozy.Projects':return 'Projects'
    g=parts[1].removeprefix('Cozy.')
    return ('Tests' if parts[0]=='Cozy.Tests' else '')+re.sub(r'[^A-Za-z0-9]','',g)

def identifier(name,item):
    owner=Path(name).stem.removeprefix('Cozy.')
    owner=re.sub(r'[^A-Za-z0-9]','_',owner)[:36]
    value=item['value']
    if value.startswith(('{','[')):meaning='JsonFixture'
    elif value.startswith('^'):meaning='Pattern'
    elif re.fullmatch(r'[a-fA-F0-9]{32,}',value):meaning='Digest'
    else:
        words=re.findall(r'[A-Za-z0-9]+',value)
        meaning='_'.join(words)[:48] or 'Text'
    return 'CozyText_'+owner+'_'+meaning+'_'+sha((name+'\0'+item['expression']).encode('utf8'))[:8]

def includes(name,text,root):
    out=[]
    for t in lex(text):
        if t['kind']!='directive':continue
        m=re.match(r'\{\$I(?:NCLUDE)?\s+([^}]+)\}',t['text'],re.I)
        if not m:continue
        relative=m[1].strip().strip("'\"").replace('\\','/')
        p=(root/name).parent/relative
        if not p.exists():continue
        p=p.resolve()
        if not p.is_relative_to(root):fail('INCLUDE_ESCAPE:'+name)
        out.append(p.relative_to(root).as_posix())
    return out

def conditional_includes(name,text,root):
    out=[];stack=[]
    for t in lex(text):
        if t['kind']!='directive':continue
        m=re.match(r'\{\$(IFDEF|IFNDEF|IF|ELSEIF|ELSE|ENDIF|IFEND)\b\s*([^}]*)\}',t['text'],re.I)
        if m:
            op,arg=m[1].upper(),m[2].strip()
            if op in ('IFDEF','IFNDEF','IF'):
                cond=('not ' if op=='IFNDEF' else '')+'Defined('+arg+')' if op!='IF' else '('+arg+')'
                stack.append([cond,cond])
            elif op in ('ENDIF','IFEND'):
                if not stack:fail('UNBALANCED_DIRECTIVE:'+name)
                stack.pop()
            elif op=='ELSE':
                if not stack:fail('UNBALANCED_DIRECTIVE:'+name)
                stack[-1][1]='not ('+stack[-1][0]+')'
            elif op=='ELSEIF':
                if not stack:fail('UNBALANCED_DIRECTIVE:'+name)
                before=stack[-1][0];stack[-1]=['('+before+') or ('+arg+')','not ('+before+') and ('+arg+')']
            continue
        include=re.match(r'\{\$I(?:NCLUDE)?\s+([^}]+)\}',t['text'],re.I)
        if not include:continue
        rel=include[1].strip().strip("'\"").replace('\\','/');p=((root/name).parent/rel).resolve()
        if p.exists() and p.is_relative_to(root):out.append((p.relative_to(root).as_posix(),' and '.join('('+x[1]+')' for x in stack)))
    return out

def conjunction(a,b):return '('+a+') and ('+b+')' if a and b else a or b
def merge_conditions(target,source,prefix=''):
    for unit,condition in source.items():
        condition=conjunction(prefix,condition)
        if unit not in target:target[unit]=condition
        elif not target[unit] or not condition:target[unit]=''
        elif target[unit]!=condition:target[unit]='('+target[unit]+') or ('+condition+')'

def used_units(text):
    tokens=[t for t in lex(text) if t['kind'] not in ('space','comment','directive')]
    out=[];active=False;skip_path=False
    for t in tokens:
        if t['kind']=='id' and t['text'].lower()=='uses':active=True;skip_path=False;continue
        if not active:continue
        if t['text']==';':active=False;continue
        if t['kind']=='id' and t['text'].lower()=='in':skip_path=True;continue
        if t['text']==',':skip_path=False;continue
        if t['kind']=='id' and not skip_path:out.append(t['text'])
    return out

def add_imports(name,text,names,conditions=None):
    if not names:return text,''
    nl='\r\n' if '\r\n' in text else '\n'
    tokens=[t for t in lex(text) if t['kind'] not in ('space','comment','directive')]
    impl=next((t['start'] for t in tokens if t['kind']=='id' and t['text'].lower()=='implementation'),len(text))
    start=next((t for t in tokens if t['kind']=='id' and t['text'].lower()=='uses' and (name.endswith('.dpr') or t['start']<impl)),None)
    if name.endswith('.dpr'):
        refs=[]
        for unit in names:
            target=CONFIG+'/'+unit+'.pas'
            rel=os.path.relpath(target,Path(name).parent).replace('/','\\')
            refs.append("  "+unit+" in '"+rel+"'")
    else:refs=['  '+unit for unit in names]
    lines=[]
    for index,(unit,ref) in enumerate(zip(names,refs)):
        condition=(conditions or {}).get(unit,'')
        if condition:lines.append('{$IF '+condition+'}')
        lines.append(ref+(',' if start or index<len(refs)-1 else ';'))
        if condition:lines.append('{$ENDIF}')
    if start:
        block=nl+'{ Cozy central text imports. }'+nl+nl.join(lines)+nl
        return text[:start['end']]+block+text[start['end']:],block
    if name.endswith('.dpr'):fail('PROJECT_USES_REQUIRED:'+name)
    interface=next((t for t in tokens if t['kind']=='id' and t['text'].lower()=='interface'),None)
    if not interface:fail('UNIT_INTERFACE_REQUIRED:'+name)
    block=nl+'{ Cozy central text imports. }'+nl+'uses'+nl+nl.join(lines)+nl
    return text[:interface['end']]+block+text[interface['end']:],block

def safe_sources(root):
    out={}
    for top in ('Cozy.Source','Cozy.Projects','Cozy.Tests'):
        for p in sorted((root/top).rglob('*')):
            if p.is_symlink():fail('SYMLINK:'+str(p))
            if not p.is_file() or p.suffix not in ('.pas','.dpr','.inc'):continue
            name=p.relative_to(root).as_posix()
            # Keep the ported NHW source and its regression fixtures together.
            # Their exact literal types are part of the upstream ABI and tests.
            if name.startswith(('Cozy.Source/Cozy.Security.NHW/', 'Cozy.Tests/Cozy.NHW/')):continue
            if p.name.startswith('Cozy.Strings.'):continue
            if p.stat().st_nlink!=1:fail('HARDLINK:'+name)
            data=p.read_bytes()
            if len(data)>8*1024*1024:fail('SOURCE_TOO_LARGE:'+name)
            out[name]=(data,decode(data))
    return out

def publish(root,changes):
    staged={};committed=[]
    def matches(file,before):return not file.exists() if before is None else file.is_file() and file.read_bytes()==before
    try:
        for name,(before,after) in changes.items():
            file=root/name
            if not matches(file,before):fail('SOURCE_CHANGED:'+name)
            fd,tmp=tempfile.mkstemp(prefix='.cozy-strings-',suffix='.pending',dir=file.parent)
            with os.fdopen(fd,'wb') as stream:stream.write(after);stream.flush();os.fsync(stream.fileno())
            staged[name]=Path(tmp)
        for name,(before,after) in changes.items():
            file=root/name
            if not matches(file,before):fail('SOURCE_CHANGED:'+name)
            os.replace(staged[name],file);committed.append(name)
    except BaseException:
        conflicts=[]
        for name in reversed(committed):
            before,after=changes[name];file=root/name
            if not matches(file,after):conflicts.append(name);continue
            if before is None:file.unlink()
            else:file.write_bytes(before)
        if conflicts:fail('ROLLBACK_CONCURRENT_EDIT:'+','.join(conflicts))
        raise
    finally:
        for file in staged.values():
            if file.exists():file.unlink()

def project_reference_changes(root, entries):
    changes={}
    for e in entries:
        if not e['path'].endswith('.dpr'):continue
        path=(root/e['path']).with_suffix('.dproj')
        if not path.exists():continue
        raw=path.read_bytes();text=decode(raw);lines=[]
        for unit in e['unitNames']:
            relative=os.path.relpath(root/CONFIG/(unit+'.pas'),path.parent).replace('/', '\\')
            if re.search(r'<DCCReference\b[^>]*\bInclude="'+re.escape(relative)+r'"',text,re.I):continue
            lines.append('    <DCCReference Include="'+relative+'" />')
        if not lines:continue
        newline='\r\n' if '\r\n' in text else '\n'
        block=newline.join(['  <ItemGroup>', '    <!-- IDE file references only; DPR conditional uses control compilation. -->', *lines, '  </ItemGroup>', ''])
        if text.count('</Project>')!=1:fail('PROJECT_XML:'+str(path))
        text=text.replace('</Project>',block+'</Project>')
        changes[path.relative_to(root).as_posix()]=(raw,encode(text,raw))
    return changes

def sync_projects(root):
    m=json.loads((root/MAP).read_text())
    changes=project_reference_changes(root,m['sources'])
    publish(root,changes)
    return {'status':'PASS','projectsUpdated':len(changes)}

def extract(root):
    if (root/MAP).exists():fail('ALREADY_EXTRACTED_USE_CHECK')
    files=safe_sources(root);units={};entries={};exceptions=[];rewritten={};direct={}
    for name,(raw,text) in files.items():
        edits=[];unit='Cozy.Strings.'+group(name)
        for item in literal_groups(text):
            why=reason(name,text,item)
            if why:
                exceptions.append({'path':name,'line':item['line'],'reason':why,'expression':item['expression']});continue
            constant=identifier(name,item);table=units.setdefault(unit,{})
            entry=table.setdefault(constant,{'name':constant,'expression':item['expression'],'value':item['value'],'origins':[]})
            entry['origins'].append({'path':name,'line':item['line']})
            edits.append({'start':item['start'],'end':item['end'],'name':constant,'expression':item['expression']})
        if edits:
            new=text
            for e in reversed(edits):new=new[:e['start']]+e['name']+new[e['end']:]
            rewritten[name]=new;direct[name]={unit}
            entries[name]={'path':name,'originalSha256':sha(raw),'unitNames':[unit],'replacements':edits,'importText':''}
        else:direct[name]=set()
    deps={n:includes(n,t,root) for n,(_,t) in files.items()}
    conditional_deps={n:conditional_includes(n,t,root) for n,(_,t) in files.items()}
    unitfiles={}
    for name,(_,text) in files.items():
        m=re.search(r'\bunit\s+([A-Za-z_][\w.]*)\s*;',text,re.I)
        if m:unitfiles[m[1].lower()]=name
    def inc_units(name,seen=None):
        seen=set() if seen is None else seen
        if name in seen:return set()
        seen.add(name);result=set(direct.get(name,()))
        for inc in deps.get(name,()):result|=inc_units(inc,seen)
        return result
    def inc_files(name,seen=None):
        seen=set() if seen is None else seen
        if name in seen:return set()
        seen.add(name);result=set(deps.get(name,()))
        for inc in deps.get(name,()):result|=inc_files(inc,seen)
        return result
    def project_units(name,seen=None):
        seen=set() if seen is None else seen
        if name in seen:return set()
        seen.add(name);result=inc_units(name)
        for u in used_units(files[name][1]):
            target=unitfiles.get(u.lower())
            if target:result|=project_units(target,seen)
        return result
    def conditional_inc_units(name,seen=None):
        seen=set() if seen is None else seen
        if name in seen:return {}
        seen.add(name);result={u:'' for u in direct.get(name,())}
        for inc,condition in conditional_deps.get(name,()):merge_conditions(result,conditional_inc_units(inc,set(seen)),condition)
        return result
    def conditional_project_units(name,seen=None):
        seen=set() if seen is None else seen
        if name in seen:return {}
        seen.add(name);result=conditional_inc_units(name)
        for u in used_units(files[name][1]):
            target=unitfiles.get(u.lower())
            if target:merge_conditions(result,conditional_project_units(target,seen))
        return result
    for name,(raw,text) in files.items():
        if name.endswith('.inc'):continue
        conditions=conditional_project_units(name) if name.endswith('.dpr') else conditional_inc_units(name)
        names=sorted(conditions)
        if not names:continue
        new,insert=add_imports(name,rewritten.get(name,text),names,conditions)
        rewritten[name]=new
        e=entries.setdefault(name,{'path':name,'originalSha256':sha(raw),'unitNames':[],'replacements':[]})
        e['unitNames']=names;e['importText']=insert
        e['unitConditions']=conditions
    for name,e in entries.items():
        e['migratedSha256']=sha(encode(rewritten[name],files[name][0]))
        if name.endswith('.inc'):
            e['owners']=[n for n in files if not n.endswith('.inc') and name in inc_files(n)]
            if not e['owners']:fail('INCLUDE_OWNER_REQUIRED:'+name)
    generated_units=[];changes={}
    for unit,table in sorted(units.items()):
        file=CONFIG+'/'+unit+'.pas';lines=['unit '+unit+';','{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}','',
            '{ Public source constants. Edit values here; this is not encryption. }','interface','const']
        for c in sorted(table.values(),key=lambda x:x['name']):
            origin=c['origins'][0];lines+=['  { '+origin['path']+':'+str(origin['line'])+' }','  '+c['name']+' = '+c['expression']+';']
        lines+=['','implementation','end.','']
        data=b'\xef\xbb\xbf'+'\r\n'.join(lines).encode('utf8')
        generated_units.append({'unit':unit,'path':file,'constants':sorted(table.values(),key=lambda x:x['name'])})
        changes[file]=(None,data)
    for name,text in rewritten.items():changes[name]=(files[name][0],encode(text,files[name][0]))
    m={'format':FORMAT,'scope':'Pascal source literals; source organization only','units':generated_units,
       'sources':sorted(entries.values(),key=lambda x:x['path']),'exceptions':exceptions,
       'nonPascalPolicy':'C/C++ uses language-specific literal headers; build scripts and resources retain their own language syntax and the searchable catalog.',
       'windowsCompilationExecution':'NOT_RUN'}
    changes.update(project_reference_changes(root,m['sources']))
    values={c['name']:c['expression'] for u in generated_units for c in u['constants']}
    for name,e in entries.items():
        restored=expand_text(rewritten[name],values)
        if e['importText']:restored=restored.replace(e['importText'],'',1)
        if encode(restored,files[name][0])!=files[name][0]:fail('PREFLIGHT_ROUNDTRIP:'+name)
    changes[MAP]=(None,(json.dumps(m,ensure_ascii=True,indent=2)+'\n').encode('utf8'))
    publish(root,changes)
    return check(root,verify=True)

def constants_from_units(root,m,refresh=False):
    out={}; declared=set()
    for u in m['units']:
        raw=(root/u['path']).read_bytes();text=decode(raw)
        if not re.search(r'\bunit\s+'+re.escape(u['unit'])+r'\s*;',text):fail('UNIT_NAME:'+u['path'])
        lexical=lex(text)
        directives=[t['text'].upper() for t in lexical if t['kind']=='directive']
        meaningful=0
        for token in lexical:
            if token['kind']=='directive' and meaningful!=3:fail('CONSTANT_UNIT_DIRECTIVE_POSITION:'+u['unit'])
            if token['kind'] not in ('space','comment','directive'):meaningful+=1
        if directives!=['{$IFDEF FPC}','{$MODE DELPHI}','{$CODEPAGE UTF8}','{$ENDIF}']:fail('CONSTANT_UNIT_DIRECTIVES:'+u['unit'])
        found={}
        tokens=[t for t in lex(text) if t['kind'] not in ('space','comment','directive')]
        if [t['text'].lower() for t in tokens[:5]]!=['unit',u['unit'].lower(),';','interface','const']:fail('CONSTANT_UNIT_HEADER:'+u['unit'])
        i=5
        while i<len(tokens) and tokens[i]['text'].startswith('CozyText_'):
            t=tokens[i]
            if i+2>=len(tokens) or tokens[i+1]['text']!='=':fail('CONSTANT_DECLARATION:'+t['text'])
            j=i+2
            while j<len(tokens) and tokens[j]['kind'] in ('string','charcode'):j+=1
            if j==i+2 or j>=len(tokens) or tokens[j]['text']!=';':fail('NON_LITERAL_CONSTANT:'+t['text'])
            expression=text[tokens[i+2]['start']:tokens[j-1]['end']].strip()
            if t['text'].lower() in declared:fail('DUPLICATE_CONSTANT:'+t['text'])
            declared.add(t['text'].lower())
            found[t['text']]=expression
            i=j+1
        if [t['text'].lower() for t in tokens[i:]]!=['implementation','end','.']:fail('CONSTANT_UNIT_RUNTIME_CODE:'+u['unit'])
        expected={c['name']:c for c in u['constants']}
        if not refresh and set(found)!=set(expected):fail('CONSTANT_SET_CHANGED_RUN_REFRESH:'+u['unit'])
        fresh=[]
        for name,expression in sorted(found.items()):
            value=value_of(expression);c=expected.get(name,{'name':name,'origins':[]})
            if refresh:c['expression']=expression;c['value']=value
            elif expression!=c['expression'].strip():fail('CONSTANT_CHANGED_RUN_REFRESH:'+name)
            fresh.append(c);out[name]=expression
        if refresh:u['constants']=fresh
    return out

def expand_text(text,constants):
    edits=[]
    for t in lex(text):
        if t['kind']=='id' and t['text'].startswith('CozyText_'):
            if t['text'] not in constants:fail('UNDECLARED_CONSTANT:'+t['text'])
            edits.append((t['start'],t['end'],constants[t['text']]))
    for a,b,value in reversed(edits):text=text[:a]+value+text[b:]
    return text

def check(root,baseline=None,verify=False,mapping=None):
    m=json.loads((root/MAP).read_text()) if mapping is None else mapping
    if m['format']!=FORMAT:fail('FORMAT')
    constants=constants_from_units(root,m);paths={u['unit']:u['path'] for u in m['units']};count=0
    for e in m['sources']:
        raw=(root/e['path']).read_bytes();text=decode(raw)
        if sha(raw)!=e['migratedSha256']:fail('SOURCE_CHANGED_RUN_REFRESH:'+e['path'])
        if not e['path'].endswith('.inc'):
            names=set(used_units(text))
            if not set(e['unitNames'])<=names:fail('IMPORT_MISSING:'+e['path'])
        else:
            for owner in e.get('owners',[]):
                if not set(e['unitNames'])<=set(used_units(decode((root/owner).read_bytes()))):fail('INCLUDE_IMPORT_MISSING:'+e['path'])
        restored=expand_text(text,constants)
        if verify:
            if e['importText']:
                if restored.count(e['importText'])!=1:fail('IMPORT_BLOCK_CHANGED:'+e['path'])
                restored=restored.replace(e['importText'],'',1)
            restored_raw=encode(restored,raw)
            if sha(restored_raw)!=e['originalSha256']:fail('ROUNDTRIP_MISMATCH:'+e['path'])
            if baseline and restored_raw!=(baseline/e['path']).read_bytes():fail('BASELINE_MISMATCH:'+e['path'])
        count+=len(e['replacements'])
    for name,(_,text) in safe_sources(root).items():
        for item in literal_groups(text):
            if not reason(name,text,item):fail('UNMANAGED_LITERAL:'+name+':'+str(item['line']))
    return {'status':'PASS','units':len(m['units']),'constants':len(constants),'movedOccurrences':count,'sources':len(m['sources']),
            'structuralExceptions':len(m['exceptions']),'byteExactRoundTrip':bool(verify),'windowsExecution':'NOT_RUN'}

def refresh(root):
    m=json.loads((root/MAP).read_text())
    if m['format']!=FORMAT:fail('FORMAT')
    constants_from_units(root,m,refresh=True)
    for e in m['sources']:e['migratedSha256']=sha((root/e['path']).read_bytes())
    result=check(root,mapping=m)
    before=(root/MAP).read_bytes();after=(json.dumps(m,ensure_ascii=True,indent=2)+'\n').encode('utf8')
    publish(root,{MAP:(before,after)})
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['extract','check','refresh','verify-migration','sync-projects']);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--baseline',type=Path);a=p.parse_args();root=a.root.resolve()
    try:
        result=extract(root) if a.command=='extract' else sync_projects(root) if a.command=='sync-projects' else refresh(root) if a.command=='refresh' else check(root,a.baseline,verify=a.command=='verify-migration')
        print(json.dumps(result,ensure_ascii=False));return 0
    except (OSError,ValueError,KeyError) as e:print(str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
