'use strict';
// Compiler configuration metadata, bound by the final EXE approval hash.
// An export is not proof of compiler authenticity or successful Windows tests.
const {ExportTable}=require('./peace.desktop-pe-exports');
function Fail(code='SECURITY_BUILD_CONFIGURATION_INVALID') {
  const error=Error(code);error.desktopError=true;error.status=400;throw error;
}
function ReadBuildConfiguration(bytes) {
  const table=ExportTable(bytes);
  if(table.status==='NO_EXPORTS')return {configuration:'UNMARKED',markerVersion:0};
  if(table.status!=='MEASURED')Fail();
  const block=table.normalized.subarray(-table.span);
  const functions=block.readUInt32LE(28)-table.rva;
  const names=block.readUInt32LE(32)-table.rva;
  const ordinals=block.readUInt32LE(36)-table.rva;
  const count=block.readUInt32LE(24);
  let configuration=null;
  for(let i=0;i<count;i++) {
    const nameAt=block.readUInt32LE(names+i*4)-table.rva;
    const name=block.toString('ascii',nameAt,block.indexOf(0,nameAt));
    if(!/^GAME_BUILD_(?:DEBUG|RELEASE)_/.test(name))continue;
    if(configuration||!/^GAME_BUILD_(DEBUG|RELEASE)_V1$/.test(name))Fail();
    const target=block.readUInt32LE(functions+block.readUInt16LE(ordinals+i*2)*4);
    if(!target||target>=table.rva&&target<table.rva+table.span)Fail();
    const pe=bytes.readUInt32LE(60),sectionAt=pe+24+bytes.readUInt16LE(pe+20);
    let executable=false;
    for(let j=0;j<bytes.readUInt16LE(pe+6);j++) {
      const at=sectionAt+j*40,rva=bytes.readUInt32LE(at+12),raw=bytes.readUInt32LE(at+16);
      const span=bytes.readUInt32LE(at+8)||raw,flags=bytes.readUInt32LE(at+36);
      if(target>=rva&&target-rva<Math.min(span,raw)&&
         (flags&0x60000000)===0x60000000&&!(flags&0x80000000))executable=true;
    }
    if(!executable)Fail();
    configuration=name==='GAME_BUILD_RELEASE_V1'?'RELEASE':'DEBUG';
  }
  return configuration?{configuration,markerVersion:1}:{configuration:'UNMARKED',markerVersion:0};
}
function HasProductFaultMarker(bytes) {
  // Deliberate test-build identifiers, independent of filename or config label.
  // No environment variable can admit these to normal production operations.
  return ['GAME_PRODUCT_FAULT_TEST_V1','GAME-PRODUCT-FAULT-TEST-V1'].some(value=>
    bytes.includes(Buffer.from(value,'ascii'))||bytes.includes(Buffer.from(value,'utf16le')));
}
function AssertProductionConfiguration(bytes,{requireMarker=false}={}) {
  if(HasProductFaultMarker(bytes))Fail('SECURITY_TEST_BUILD_NOT_PUBLISHABLE');
  const result=ReadBuildConfiguration(bytes);
  if(result.configuration==='DEBUG')Fail('SECURITY_DEBUG_BUILD_NOT_PUBLISHABLE');
  if(requireMarker&&result.configuration==='UNMARKED')Fail('SECURITY_BUILD_CONFIGURATION_REQUIRED');
  return result;
}
function AssertIsolatedTestConfiguration(bytes) {
  // Only an explicitly loaded isolated fixture adapter calls this function.
  // Normal admission/approval always calls AssertProductionConfiguration.
  if(!HasProductFaultMarker(bytes))Fail('SECURITY_PRODUCT_FAULT_MARKER_REQUIRED');
  const result=ReadBuildConfiguration(bytes);
  if(result.configuration!=='RELEASE')Fail('SECURITY_PRODUCT_FAULT_CONFIGURATION_REQUIRED');
  return result;
}
module.exports={ReadBuildConfiguration,AssertProductionConfiguration,HasProductFaultMarker,AssertIsolatedTestConfiguration};
