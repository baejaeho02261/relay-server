'use strict';
// Native authorization travels exclusively over the pinned TLS transport.
// Never retain a reverse-proxy JSON path that bypasses that boundary.
async function Handle(req,res,url){
 const pathname=(url||new URL(req.url,'http://localhost')).pathname;
 if(!['/api/desktop/challenge','/api/desktop/execute'].includes(pathname))return false;
 req.resume();
 res.writeHead(410,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Connection':'close'});
 res.end(JSON.stringify({ok:false,error:'DESKTOP_TLS_TRANSPORT_REQUIRED',message:'최신 Windows 프로그램의 보안 연결을 사용해 주세요.'}));
 return true;
}
module.exports={Handle};
