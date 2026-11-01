'use strict';
// Test-only semantic source view. Read actual moved constants, never replace a
// source with its old baseline. Raw extraction/wiring is checked separately.
// This is not a Delphi compiler and does not establish Windows execution.
const fs = require('node:fs'), path = require('node:path');
const MAP = 'Cozy.Source/Cozy.Configuration/Cozy.StringUnits.map.json';
const CPP_MAP = 'Cozy.ImGui/Cozy.Strings/Cozy.NativeStrings.map.json';
const NAME = /^CozyText_[A-Za-z0-9_]+_[a-fA-F0-9]{8}$/;
const CPP_NAME = /^COZY_TEXT_[A-Za-z0-9_]+_[a-fA-F0-9]{8}$/;
function Fail(code) { throw Error('NATIVE_STRING_CONTRACT_' + code); }
function Tokens(text, collectDirectives=false) {
 const result=[];let i=0;
 while(i<text.length){
  if(/\s/.test(text[i])){i++;continue;}
  if(text.startsWith('//',i)){const end=text.indexOf('\n',i);i=end<0?text.length:end+1;continue;}
  if(text[i]==='{'||text.startsWith('(*',i)){
   const close=text[i]==='{'?'}':'*)',width=close.length,end=text.indexOf(close,i+width);
   if(end<0)Fail('COMMENT');
   if(collectDirectives&&text[i+width]==='$')result.push({kind:'directive',value:text.slice(i+width+1,end).trim(),start:i,end:end+width});
   i=end+width;continue;
  }
  const start=i;
  if(text[i]==="'"){
   i++;let closed=false;
   while(i<text.length){if(text[i]==="'"){if(text[i+1]==="'"){i+=2;continue;}i++;closed=true;break;}if(text[i]==='\r'||text[i]==='\n')Fail('STRING');i++;}
   if(!closed)Fail('STRING');result.push({kind:'literal',value:text.slice(start,i),start,end:i});continue;
  }
  if(text[i]==='#'){
   const match=/^#(?:\$[a-fA-F0-9]+|[0-9]+)/.exec(text.slice(i));if(!match)Fail('CHAR_CODE');
   i+=match[0].length;result.push({kind:'literal',value:match[0],start,end:i});continue;
  }
  const id=/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/.exec(text.slice(i));
  if(id){i+=id[0].length;result.push({kind:'id',value:id[0],start,end:i});continue;}
  i++;result.push({kind:'punctuation',value:text[start],start,end:i});
 }
 return result;
}
function UnitConstants(text, expectedUnit) {
 const allTokens=Tokens(text,true),values=new Map(),names=new Set();let at=0;
 const directives=allTokens.filter(t=>t.kind==='directive').map(t=>t.value.replace(/\s+/g,' ').toUpperCase());
 if(directives.length&&directives.join('|')!=='IFDEF FPC|MODE DELPHI|CODEPAGE UTF8|ENDIF')Fail('UNIT_DIRECTIVE');
 for(let i=0;i<allTokens.length;i++)if(allTokens[i].kind==='directive'&&allTokens.slice(0,i).filter(t=>t.kind!=='directive').length!==3)Fail('UNIT_DIRECTIVE');
 const tokens=allTokens.filter(t=>t.kind!=='directive');
 const expect=value=>{if(tokens[at++]?.value.toLowerCase()!==value.toLowerCase())Fail('UNIT_SCAFFOLD');};
 if(tokens[0]?.value.toLowerCase()!=='unit'||tokens[1]?.value.toLowerCase()!==expectedUnit.toLowerCase())Fail('UNIT_NAME');
 expect('unit');expect(expectedUnit);expect(';');expect('interface');expect('const');
 while(tokens[at]?.value.toLowerCase()!=='implementation'){
  const token=tokens[at++];if(token?.kind!=='id'||!NAME.test(token.value))Fail('DECLARATION');
  if(tokens[at++]?.value!=='=')Fail('DECLARATION');
  const first=tokens[at];if(first?.kind!=='literal')Fail('EXPRESSION');
  let last=first,expectLiteral=false,previous;
  while(tokens[at]&&tokens[at].value!==';'){
   const t=tokens[at];
   if(t.kind==='literal'){
    if(previous?.kind==='literal'&&previous.value.startsWith("'")&&t.value.startsWith("'"))Fail('EXPRESSION');
    last=t;expectLiteral=false;
   }else if(t.value==='+'&&previous?.kind==='literal'&&!expectLiteral)expectLiteral=true;
   else Fail('EXPRESSION');previous=t;at++;
  }
  if(!tokens[at]||expectLiteral)Fail('EXPRESSION');at++;
  if(names.has(token.value.toLowerCase()))Fail('DUPLICATE');names.add(token.value.toLowerCase());
  values.set(token.value,text.slice(first.start,last.end));
 }
 expect('implementation');expect('end');expect('.');if(at!==tokens.length)Fail('UNIT_SCAFFOLD');
 return values;
}
function UsedUnits(text) {
 const tokens=Tokens(text),names=new Set();
 for(let i=0;i<tokens.length;i++)if(tokens[i].kind==='id'&&tokens[i].value.toLowerCase()==='uses'){
  let needName=true;
  while(++i<tokens.length&&tokens[i].value!==';'){
   const t=tokens[i];if(needName){if(t.kind!=='id')Fail('USES');names.add(t.value.toLowerCase());needName=false;}
   else if(t.value===',')needName=true;
  }
 }
 return names;
}
function OwnedPath(root, relative) {
 if(typeof relative!=='string'||relative.includes('\\')||relative.split('/').some(x=>!x||x==='.'||x==='..')||path.isAbsolute(relative))Fail('PATH');
 const full=path.join(root,relative);
 let at=root;
 for(const part of relative.split('/')){at=path.join(at,part);if(fs.lstatSync(at).isSymbolicLink())Fail('LINK');}
 if(!fs.statSync(full).isFile())Fail('FILE');return full;
}
function NativeRoot(file) {
 let at=path.dirname(path.resolve(String(file)));
 while(path.dirname(at)!==at){if(path.basename(at)==='Railway')return at;at=path.dirname(at);}return null;
}
function IncludeReachable(root,owner,target,seen=new Set()) {
 const key=path.resolve(owner);if(seen.has(key))return false;seen.add(key);
 const text=fs.readFileSync(key,'utf8');
 for(const token of Tokens(text,true).filter(t=>t.kind==='directive')){
  const match=/^I(?:NCLUDE)?\s+([^\r\n]+)$/i.exec(token.value);if(!match)continue;
  const name=match[1].trim().replace(/^'|'$/g,'').replaceAll('\\','/');
  let include=path.resolve(path.dirname(key),name);
  if(!fs.existsSync(include)){
   const candidates=[];
   function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){if(e.isSymbolicLink())continue;const p=path.join(dir,e.name);if(e.isDirectory())walk(p);else if(e.name.toLowerCase()===path.basename(name).toLowerCase())candidates.push(p);}}
   walk(root);if(candidates.length!==1)continue;include=candidates[0];
  }
  const relative=path.relative(root,include).split(path.sep).join('/');OwnedPath(root,relative);
  if(include===target||IncludeReachable(root,include,target,seen))return true;
 }
 return false;
}
function ExpandPascal(text,file) {
 const tokens=Tokens(text),references=tokens.filter(t=>t.kind==='id'&&NAME.test(t.value));
 if(!references.length)return text;
 const root=NativeRoot(file);if(!root)return text;
 const relative=path.relative(root,file).split(path.sep).join('/');
 const map=JSON.parse(fs.readFileSync(OwnedPath(root,MAP),'utf8'));
 if(!Array.isArray(map.units)||!Array.isArray(map.sources))Fail('MAP');
 if(new Set(map.units.map(u=>String(u.unit).toLowerCase())).size!==map.units.length||
    new Set(map.units.map(u=>u.path)).size!==map.units.length||
    new Set(map.sources.map(s=>s.path)).size!==map.sources.length)Fail('MAP_DUPLICATE');
 if(map.units.some(u=>u.path===relative))return text;
 const source=map.sources.find(s=>s.path===relative);if(!source||!Array.isArray(source.unitNames))Fail('SOURCE');
 const declared=UsedUnits(text),values=new Map();
 if(path.extname(file).toLowerCase()==='.inc'){
  if(!Array.isArray(source.owners)||!source.owners.length)Fail('INCLUDE_OWNER');
  let linked=false;
  for(const owner of source.owners){
   const ownerPath=OwnedPath(root,owner),ownerUnits=UsedUnits(fs.readFileSync(ownerPath,'utf8'));
   if(source.unitNames.some(name=>!ownerUnits.has(name.toLowerCase())))Fail('INCLUDE_USES_MISSING');
   if(IncludeReachable(root,ownerPath,path.resolve(file)))linked=true;
  }
  if(!linked)Fail('INCLUDE_OWNER');
 }
 for(const name of source.unitNames){
  const unit=map.units.find(u=>u.unit===name);if(!unit)Fail('MISSING_UNIT');
  if(path.extname(file).toLowerCase()!=='.inc'&&!declared.has(name.toLowerCase()))Fail('USES_MISSING');
  const actual=UnitConstants(fs.readFileSync(OwnedPath(root,unit.path),'utf8'),name);
  if(!Array.isArray(unit.constants))Fail('MAP_CONSTANTS');
  for(const c of unit.constants){
   if(!NAME.test(c.name)||!actual.has(c.name)||actual.get(c.name)!==c.expression)Fail('CONSTANT_CHANGED');
   if(values.has(c.name))Fail('DUPLICATE');values.set(c.name,actual.get(c.name));
  }
  if(actual.size!==unit.constants.length)Fail('UNINDEXED_CONSTANT');
 }
 const edits=references.map(t=>{const value=values.get(t.value);if(value===undefined)Fail('REFERENCE');return {...t,replacement:value};});
 for(const edit of edits.reverse())text=text.slice(0,edit.start)+edit.replacement+text.slice(edit.end);
 return text;
}
function ReadContractFile(file,options) {
 const value=fs.readFileSync(file,options);
 if(typeof value!=='string'||!NativeRoot(file))return value;
 const ext=path.extname(String(file)).toLowerCase(),absolute=path.resolve(String(file));
 if(['.pas','.dpr','.inc'].includes(ext))return ExpandPascal(value,absolute);
 if(['.cpp','.c','.h','.hpp'].includes(ext))return ExpandCpp(value,absolute);
 return value;
}
function CppLiteral(text,start){
 const input=text.slice(start),raw=/^(?:u8|u|U|L)?R"([^\s()\\]{0,16})\(/.exec(input);
 if(raw){const end=text.indexOf(')'+raw[1]+'"',start+raw[0].length);if(end<0)Fail('CPP_RAW_STRING');return {kind:'literal',start,end:end+raw[1].length+2,value:text.slice(start,end+raw[1].length+2)};}
 const normal=/^(?:u8|u|U|L)?(["'])/.exec(input);if(!normal)return null;
 const quote=normal[1];let at=start+normal[0].length;
 while(at<text.length){if(text[at]==='\\'){at+=2;continue;}if(text[at]===quote){at++;return {kind:'literal',start,end:at,value:text.slice(start,at)};}if(text[at]==='\n'||text[at]==='\r')Fail('CPP_STRING');at++;}
 Fail('CPP_STRING');
}
function CppTokens(text){
 const tokens=[];let at=0;
 while(at<text.length){
  if(/\s/.test(text[at])){at++;continue;}
  if(text.startsWith('//',at)){const end=text.indexOf('\n',at);at=end<0?text.length:end+1;continue;}
  if(text.startsWith('/*',at)){const end=text.indexOf('*/',at+2);if(end<0)Fail('CPP_COMMENT');at=end+2;continue;}
  const literal=CppLiteral(text,at);if(literal){tokens.push(literal);at=literal.end;continue;}
  const id=/^[A-Za-z_][A-Za-z0-9_]*/.exec(text.slice(at));if(id){tokens.push({kind:'id',start:at,end:at+id[0].length,value:id[0]});at+=id[0].length;continue;}
  tokens.push({kind:'punctuation',start:at,end:at+1,value:text[at]});at++;
 }
 return tokens;
}
function CppConstants(text){
 const tokens=CppTokens(text),values=new Map();let at=0;
 const expect=value=>{if(tokens[at++]?.value!==value)Fail('CPP_SCAFFOLD');};
 const directive=()=>{const t=tokens[at];expect('#');if(text.slice(text.lastIndexOf('\n',t.start-1)+1,t.start).trim())Fail('CPP_SCAFFOLD');};
 directive();expect('ifndef');const guard=tokens[at++];if(guard?.kind!=='id')Fail('CPP_SCAFFOLD');
 directive();expect('define');expect(guard.value);
 while(tokens[at+1]?.value!=='endif'){
  directive();expect('define');const name=tokens[at++];if(name?.kind!=='id'||!CPP_NAME.test(name.value))Fail('CPP_DECLARATION');
  const expression=tokens[at++];if(expression?.kind!=='literal'||!/^(?:u8|u|U|L)?(?:R"|")/.test(expression.value))Fail('CPP_EXPRESSION');
  if(values.has(name.value))Fail('CPP_DUPLICATE');values.set(name.value,expression.value);
 }
 directive();expect('endif');if(at!==tokens.length)Fail('CPP_SCAFFOLD');
 return values;
}
function CppIncludes(text,file){
 const t=CppTokens(text),out=new Set();
 for(let i=0;i<t.length-2;i++)if(t[i].value==='#'&&t[i+1].value==='include'&&t[i+2].kind==='literal'&&t[i+2].value.startsWith('"')){
  const prefix=text.slice(text.lastIndexOf('\n',t[i].start-1)+1,t[i].start);if(prefix.trim())continue;
  const name=t[i+2].value.slice(1,-1);if(name.includes('\\'))Fail('CPP_INCLUDE');out.add(path.resolve(path.dirname(file),name));
 }
 return out;
}
function ExpandCpp(text,file){
 const references=CppTokens(text).filter(t=>t.kind==='id'&&CPP_NAME.test(t.value));if(!references.length)return text;
 const root=NativeRoot(file);if(!root)return text;
 const map=JSON.parse(fs.readFileSync(OwnedPath(root,CPP_MAP),'utf8')),relative=path.relative(root,file).split(path.sep).join('/');
 if(!Array.isArray(map.units)||!Array.isArray(map.sources))Fail('CPP_MAP');
 if(new Set(map.units.map(u=>u.path)).size!==map.units.length||new Set(map.sources.map(s=>s.path)).size!==map.sources.length)Fail('CPP_MAP_DUPLICATE');
 if(map.units.some(u=>u.path===relative))return text;
 const source=map.sources.find(s=>s.path===relative);if(!source||!Array.isArray(source.unitPaths))Fail('CPP_SOURCE');
 const includes=CppIncludes(text,file),values=new Map();
 for(const unitPath of source.unitPaths){
  const unit=map.units.find(u=>u.path===unitPath);if(!unit)Fail('CPP_UNIT');
  const header=OwnedPath(root,unitPath);if(!includes.has(header))Fail('CPP_INCLUDE_MISSING');
  const actual=CppConstants(fs.readFileSync(header,'utf8'));if(!Array.isArray(unit.constants))Fail('CPP_MAP_CONSTANTS');
  for(const c of unit.constants){if(!CPP_NAME.test(c.name)||actual.get(c.name)!==c.expression)Fail('CPP_CONSTANT_CHANGED');if(values.has(c.name))Fail('CPP_DUPLICATE');values.set(c.name,actual.get(c.name));}
  if(actual.size!==unit.constants.length)Fail('CPP_UNINDEXED_CONSTANT');
 }
 for(const ref of references.reverse()){const expression=values.get(ref.value);if(expression===undefined)Fail('CPP_REFERENCE');text=text.slice(0,ref.start)+expression+text.slice(ref.end);}
 return text;
}
module.exports={ReadContractFile,ExpandPascal,UnitConstants,UsedUnits,ExpandCpp,CppConstants};
