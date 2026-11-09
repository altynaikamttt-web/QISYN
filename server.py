import os,sqlite3,secrets,hashlib,hmac,json,re
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from urllib.parse import urlparse
from http.cookies import SimpleCookie
from pathlib import Path
DB=Path(__file__).with_name('qisyn.db'); PORT=int(os.getenv('PORT','8000')); SESS={}
def conn():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def hashpw(p,s=None):
 s=s or secrets.token_hex(16);return s+'$'+hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),260000).hex()
def verify(p,v):
 try:s,h=v.split('$');return hmac.compare_digest(hashpw(p,s).split('$')[1],h)
 except:return False
def init():
 with conn() as c:
  c.executescript('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,login TEXT UNIQUE,passhash TEXT,role TEXT);CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY,user_id INTEGER,score INTEGER,total INTEGER,created TEXT DEFAULT CURRENT_TIMESTAMP);')
  if not c.execute('SELECT 1 FROM users WHERE role="teacher"').fetchone():
   pw=os.getenv('QISYN_ADMIN_PASSWORD')
   if not pw or len(pw)<12:raise RuntimeError('Set QISYN_ADMIN_PASSWORD (at least 12 characters) before first launch')
   c.execute('INSERT INTO users(login,passhash,role) VALUES(?,?,?)',('teacher',hashpw(pw),'teacher'))
class H(BaseHTTPRequestHandler):
 def send(self,obj,status=200,cookie=None):
  b=json.dumps(obj,ensure_ascii=False).encode();self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(b)
 def body(self):
  try:
   n=int(self.headers.get('Content-Length','0'))
   if n>10000:raise ValueError()
   return json.loads(self.rfile.read(n))
  except:return {}
 def user(self):
  co=SimpleCookie()
  try:co.load(self.headers.get('Cookie',''))
  except:return None
  token=co.get('qisyn');return SESS.get(token.value) if token else None
 def do_GET(self):
  p=urlparse(self.path).path;u=self.user()
  if p=='/':
   b=Path(__file__).with_name('index.html').read_bytes();self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(b);return
  if p=='/api/me':return self.send({'user':u})
  if not u:return self.send({'error':'Кіру қажет'},401)
  if p=='/api/results':
   with conn() as c:
    if u['role']=='teacher':rows=c.execute('SELECT users.login,results.score,results.total,results.created FROM results JOIN users ON users.id=results.user_id ORDER BY results.id DESC LIMIT 200').fetchall()
    else:rows=c.execute('SELECT score,total,created FROM results WHERE user_id=? ORDER BY id DESC LIMIT 20',(u['id'],)).fetchall()
   return self.send({'results':[dict(x) for x in rows]})
  if p=='/api/students' and u['role']=='teacher':
   with conn() as c:rows=c.execute("SELECT id,login FROM users WHERE role='student' ORDER BY login").fetchall()
   return self.send({'students':[dict(x) for x in rows]})
  return self.send({'error':'Табылмады'},404)
 def do_POST(self):
  p=urlparse(self.path).path;d=self.body();u=self.user()
  if p=='/api/login':
   with conn() as c:r=c.execute('SELECT * FROM users WHERE login=?',(str(d.get('login','')),)).fetchone()
   if not r or not verify(str(d.get('password','')),r['passhash']):return self.send({'error':'Логин немесе құпиясөз қате'},401)
   t=secrets.token_urlsafe(32);SESS[t]={'id':r['id'],'login':r['login'],'role':r['role']};return self.send({'user':SESS[t]},cookie=f'qisyn={t}; HttpOnly; SameSite=Lax; Path=/')
  if p=='/api/logout':
   co=SimpleCookie();co.load(self.headers.get('Cookie',''));t=co.get('qisyn')
   if t:SESS.pop(t.value,None)
   return self.send({'ok':True},cookie='qisyn=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/')
  if not u:return self.send({'error':'Кіру қажет'},401)
  if p=='/api/students' and u['role']=='teacher':
   login=str(d.get('login','')).strip();pw=str(d.get('password',''))
   if not re.fullmatch(r'[a-zA-Z0-9_-]{3,30}',login) or len(pw)<10:return self.send({'error':'Логин 3–30 таңба, құпиясөз кемінде 10 таңба'},400)
   try:
    with conn() as c:c.execute('INSERT INTO users(login,passhash,role) VALUES(?,?,?)',(login,hashpw(pw),'student'))
   except sqlite3.IntegrityError:return self.send({'error':'Логин бар'},409)
   return self.send({'ok':True})
  if p=='/api/results' and u['role']=='student':
   # Only server-side verified quiz answers; client cannot submit arbitrary scores.
   ans=d.get('answers');keys=[1,0,1,0,1,0,1,1,0,1]
   if not isinstance(ans,list) or len(ans)!=len(keys) or any(type(x)!=int or x not in (0,1) for x in ans):return self.send({'error':'Жауаптар жарамсыз'},400)
   score=sum(a==b for a,b in zip(ans,keys))*10
   with conn() as c:c.execute('INSERT INTO results(user_id,score,total) VALUES(?,?,?)',(u['id'],score,100))
   return self.send({'score':score,'total':100,'correct':keys})
  return self.send({'error':'Рұқсат жоқ'},403)
if __name__=='__main__':
 init();print(f'QISYN http://localhost:{PORT}');ThreadingHTTPServer(('127.0.0.1',PORT),H).serve_forever()
