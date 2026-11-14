'use strict';
// Not an application server. Only the fixed pure-parser allowlist is executable.
try{const [target,s,n]=process.argv.slice(2);const result=require("../../services/security/peace.parser-fuzz-cases").Run(target,Number(s),Number(n));if(process.send)process.send(result,()=>process.disconnect());else process.stdout.write(JSON.stringify(result));}catch(e){if(process.send)process.send({status:'FAIL',error:/^FUZZ_[A-Z_]+$/.test(e.message)?e.message:'FUZZ_CHILD_FAILED'},()=>process.disconnect());process.exitCode=1;}
