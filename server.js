'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {Pool}=require('pg');
const port=Number(process.env.PORT||3000);
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,max:6,connectionTimeoutMillis:10000,...(process.env.DATABASE_SSL==='true'?{ssl:{rejectUnauthorized:false}}:{})}):null;
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const pass=(p,s)=>crypto.scryptSync(p,s,64).toString('hex');
const send=(r,s,d)=>{r.writeHead(s,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});r.end(JSON.stringify(d))};
const fail=(status,msg)=>Object.assign(new Error(msg),{status});
const validRole=['admin','manager','operator','hotel'];
const publicUser=u=>({id:u.id,username:u.username,role:u.role,hotelId:u.hotel_id,active:u.active});
let initPromise;
async function init(){if(!pool)throw fail(503,'DATABASE_URL não configurada');await pool.query(`CREATE TABLE IF NOT EXISTS enxoval_state (id integer PRIMARY KEY CHECK(id=1),version bigint NOT NULL DEFAULT 0,data jsonb NOT NULL DEFAULT '{"hotels":[],"entries":[]}'::jsonb,updated_at timestamptz NOT NULL DEFAULT now())`);await pool.query('INSERT INTO enxoval_state(id) VALUES(1) ON CONFLICT DO NOTHING');await pool.query(`CREATE TABLE IF NOT EXISTS enxoval_users(id bigserial PRIMARY KEY,username text UNIQUE NOT NULL,pass_hash text NOT NULL,salt text NOT NULL,role text NOT NULL,hotel_id text,active boolean NOT NULL DEFAULT true,created_at timestamptz DEFAULT now())`);await pool.query(`CREATE TABLE IF NOT EXISTS enxoval_sessions(token_hash text PRIMARY KEY,user_id bigint NOT NULL REFERENCES enxoval_users(id) ON DELETE CASCADE,expires_at timestamptz NOT NULL)`);await pool.query(`CREATE TABLE IF NOT EXISTS enxoval_audit(id bigserial PRIMARY KEY,user_id bigint,action text NOT NULL,at timestamptz NOT NULL DEFAULT now())`);
const count=await pool.query('SELECT count(*)::int AS n FROM enxoval_users');if(count.rows[0].n===0){const name=process.env.ADMIN_USER,secret=process.env.ADMIN_PASSWORD;if(!name||!secret||secret.length<12)throw fail(503,'Defina ADMIN_USER e ADMIN_PASSWORD (mínimo 12 caracteres) no Render');const salt=crypto.randomBytes(16).toString('hex');await pool.query('INSERT INTO enxoval_users(username,pass_hash,salt,role) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[name.toLowerCase(),pass(secret,salt),salt,'admin']);}}
async function auth(req){const t=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization||'');if(!t)throw fail(401,'Faça login');const r=await pool.query(`SELECT u.* FROM enxoval_sessions s JOIN enxoval_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true`,[hash(t[1])]);if(!r.rowCount)throw fail(401,'Sessão inválida ou expirada');return r.rows[0]}
async function body(req){let s='';for await(const c of req){s+=c;if(s.length>3000000)throw fail(413,'Arquivo muito grande')}try{return JSON.parse(s)}catch{throw fail(400,'JSON inválido')}}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

function scoped(state, user) {
  const role = user.role;

  if (role === 'admin') {
    return state;
  }

  if (role === 'manager' || role === 'hotel') {
    const hotelId = String(user.hotel_id || '');

    const hotels = state.hotels
      .filter(h => String(h.id) === hotelId)
      .map(h => {
        if (role === 'manager') {
          return h;
        }

        return {
          id: h.id,
          name: h.name
        };
      });

    const entries = state.entries.filter(
      e => String(e.hotelId) === hotelId
    );

    return { hotels, entries };
  }

  if (role === 'operator') {
    return {
      hotels: state.hotels.map(h => {
        const { prices, priceTable, ...rest } = h;
        return rest;
      }),
      entries: state.entries
    };
  }

  return { hotels: [], entries: [] };
}

function entryValid(e){return e&&typeof e==='object'&&typeof e.hotelId==='string'&&typeof e.item==='string'&&/^\d{4}-\d\d-\d\d$/.test(e.date||'')&&['saida','entrada','relaveSaida','relaveEntrada'].every(k=>Number.isSafeInteger(Number(e[k]||0))&&Number(e[k]||0)>=0)}
async function api(req,res,url){if(!initPromise)initPromise=init().catch(e=>{initPromise=null;throw e});await initPromise;
if(url==='/api/login'&&req.method==='POST'){const b=await body(req);const username=String(b.username||'').trim().toLowerCase();const r=await pool.query('SELECT * FROM enxoval_users WHERE username=$1 AND active=true',[username]);const u=r.rows[0];const salt=u?.salt||'00000000000000000000000000000000';const expected=Buffer.from(u?.pass_hash||'0'.repeat(128),'hex'),actual=Buffer.from(pass(String(b.password||''),salt),'hex');if(!u||!crypto.timingSafeEqual(expected,actual))throw fail(401,'Usuário ou senha inválidos');const token=crypto.randomBytes(32).toString('hex');await pool.query("INSERT INTO enxoval_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '12 hours')",[hash(token),u.id]);return send(res,200,{token,user:publicUser(u)})}
const user=await auth(req);
if(url==='/api/me'&&req.method==='GET')return send(res,200,{user:publicUser(user)});
if(url==='/api/logout'&&req.method==='POST'){const t=req.headers.authorization.slice(7);await pool.query('DELETE FROM enxoval_sessions WHERE token_hash=$1',[hash(t)]);return send(res,200,{ok:true})}
if(url==='/api/users'&&req.method==='GET'){if(user.role!=='admin')throw fail(403,'Apenas administrador');const r=await pool.query('SELECT id,username,role,hotel_id,active FROM enxoval_users ORDER BY id');return send(res,200,{users:r.rows.map(publicUser)})}
if(url==='/api/users'&&req.method==='POST'){if(user.role!=='admin')throw fail(403,'Apenas administrador');const b=await body(req),username=String(b.username||'').trim().toLowerCase(),role=b.role,password=String(b.password||''),hotelId=role==='hotel'?String(b.hotelId||''):null;if(!/^[a-z0-9._-]{3,50}$/.test(username)||!validRole.includes(role)||password.length<10)throw fail(400,'Usuário inválido ou senha com menos de 10 caracteres');if(role==='hotel'){const st=await pool.query('SELECT data FROM enxoval_state WHERE id=1');if(!st.rows[0].data.hotels.some(h=>String(h.id)===hotelId))throw fail(400,'Selecione um hotel cadastrado')}const salt=crypto.randomBytes(16).toString('hex');try{await pool.query('INSERT INTO enxoval_users(username,pass_hash,salt,role,hotel_id) VALUES($1,$2,$3,$4,$5)',[username,pass(password,salt),salt,role,hotelId])}catch(e){if(e.code==='23505')throw fail(409,'Usuário já cadastrado');throw e}return send(res,201,{ok:true})}
if(url.startsWith('/api/users/')&&req.method==='PATCH'){if(user.role!=='admin')throw fail(403,'Apenas administrador');const id=Number(url.split('/')[3]),b=await body(req);if(!Number.isSafeInteger(id))throw fail(400,'ID inválido');if(id===Number(user.id)&&b.active===false)throw fail(400,'Não é possível desativar a própria conta');if(typeof b.password==='string'&&b.password.length){if(b.password.length<10)throw fail(400,'Senha deve ter 10 caracteres ou mais');const salt=crypto.randomBytes(16).toString('hex');await pool.query('UPDATE enxoval_users SET pass_hash=$1,salt=$2 WHERE id=$3',[pass(b.password,salt),salt,id]);await pool.query('DELETE FROM enxoval_sessions WHERE user_id=$1',[id])}if(typeof b.active==='boolean'){await pool.query('UPDATE enxoval_users SET active=$1 WHERE id=$2',[b.active,id]);if(!b.active)await pool.query('DELETE FROM enxoval_sessions WHERE user_id=$1',[id])}return send(res,200,{ok:true})}
if(url==='/api/state'&&req.method==='GET'){const r=await pool.query('SELECT version,data FROM enxoval_state WHERE id=1');return send(res,200,{version:Number(r.rows[0].version),data:scoped(r.rows[0].data,user)})}
if(url==='/api/state'&&req.method==='PUT'){if(user.role==='hotel')throw fail(403,'Hotel somente consulta');const b=await body(req);if(!Number.isSafeInteger(b.version)||!b.data||!Array.isArray(b.data.hotels)||!Array.isArray(b.data.entries)||b.data.hotels.length>5000||b.data.entries.length>100000||!b.data.entries.every(entryValid))throw fail(400,'Dados inválidos');const client=await pool.connect();try{await client.query('BEGIN');const old=await client.query('SELECT version,data FROM enxoval_state WHERE id=1 FOR UPDATE');const current=old.rows[0];if(Number(current.version)!==b.version)throw fail(409,'Dados atualizados por outro usuário. Recarregue a página');if(user.role!=='admin'){const oldHotels=scoped(current.data,user).hotels;if(!same(oldHotels,b.data.hotels))throw fail(403,'Somente administrador pode alterar hotéis e preços');if(user.role==='operator'){if(b.data.entries.length<current.data.entries.length||!same(b.data.entries.slice(0,current.data.entries.length),current.data.entries))throw fail(403,'Operador pode apenas adicionar lançamentos')}}const newState=user.role==='admin'?b.data:{hotels:current.data.hotels,entries:b.data.entries};const r=await client.query('UPDATE enxoval_state SET version=version+1,data=$1::jsonb,updated_at=now() WHERE id=1 RETURNING version',[JSON.stringify(newState)]);await client.query('INSERT INTO enxoval_audit(user_id,action) VALUES($1,$2)',[user.id,'Atualização de dados']);await client.query('COMMIT');return send(res,200,{version:Number(r.rows[0].version)})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}
throw fail(404,'Recurso não encontrado')}
http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost').pathname;if(url.startsWith('/api/'))return await api(req,res,url);if(req.method!=='GET'&&req.method!=='HEAD')throw fail(405,'Método inválido');if(url!=='/'&&url!=='/index.html')throw fail(404,'Não encontrado');res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"frame-ancestors 'none'"});fs.createReadStream(path.join(__dirname,'index.html')).pipe(res)}catch(e){if(e.status!==401&&e.status!==403)console.error(e.message);send(res,e.status||503,{error:e.status?e.message:'Servidor ou banco indisponível'})}}).listen(port,'0.0.0.0',()=>console.log('Enxoval Pro com perfis na porta '+port));
