const http = require('http');
const fs = require('fs');
const path = require('path');
const PORT = Number(process.env.PORT || 3000);
const root = __dirname;
const mime = {'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon'};
http.createServer((req,res)=>{
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); } catch { res.writeHead(400); return res.end('Bad Request'); }
  const requested = path.resolve(root, '.' + pathname);
  if (requested !== root && !requested.startsWith(root + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  let file = requested;
  try { if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html'); } catch { /* handled below */ }
  fs.readFile(file, (err, data)=>{
    if (err) { res.writeHead(404); return res.end('Not Found'); }
    res.writeHead(200, {'Content-Type':mime[path.extname(file).toLowerCase()] || 'application/octet-stream','X-Content-Type-Options':'nosniff'});
    res.end(data);
  });
}).listen(PORT, '0.0.0.0', ()=>console.log(`Enxoval Pro running on port ${PORT}`));
