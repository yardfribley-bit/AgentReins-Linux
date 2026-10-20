#!/usr/bin/env python3
"""Public read-only runtime console; ingestion and operator mutations use separate keys."""
import hashlib,hmac,json,os,time,urllib.parse,threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
try:from .engine import Store,RULES,Conflict,compact
except ImportError:from engine import Store,RULES,Conflict,compact
class App:
 def __init__(self,root,config):
  self.root=Path(root);self.config=config;self.store=Store(config['database']);self.failures={};self.lock=threading.Lock()
 def principal(self,headers):
  key=headers.get('Authorization','').removeprefix('Bearer ')
  if not key:return None
  if hmac.compare_digest(key,self.config['operatorToken']):return {'role':'operator','name':self.config.get('operatorName','site-operator')}
  for source,token in self.config['sources'].items():
   if hmac.compare_digest(key,token):return {'role':'sensor','name':source}
  return None
 def handler(self):
  app=self
  class H(BaseHTTPRequestHandler):
   protocol_version='HTTP/1.1'
   def log_message(self,*a):pass
   def send(self,status,value,ctype='application/json; charset=utf-8',extra=None):
    raw=value if isinstance(value,bytes) else compact(value).encode();self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','same-origin')
    self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    for k,v in (extra or {}).items():self.send_header(k,v)
    self.end_headers()
    if self.command!='HEAD':self.wfile.write(raw)
   def do_HEAD(self):self.do_GET()
   def do_GET(self):
    try:
     url=urllib.parse.urlsplit(self.path);path=url.path;q=urllib.parse.parse_qs(url.query)
     if path in ('/runtime','/runtime/'):
      return self.send(200,(app.root/'index.html').read_bytes(),'text/html; charset=utf-8')
     assets={'/runtime/app.js':('app.js','application/javascript; charset=utf-8'),'/runtime/style.css':('style.css','text/css; charset=utf-8')}
     if path in assets:
      name,ctype=assets[path];return self.send(200,(app.root/name).read_bytes(),ctype)
     if path=='/runtime/api/alerts':return self.send(200,app.store.listing(q))
     if path=='/runtime/api/rules':return self.send(200,{'items':RULES,'intelligence':app.store.intelligence()})
     if path=='/runtime/api/me':
      p=app.principal(self.headers);return self.send(200,{'role':p['role'] if p else 'viewer','name':p['name'] if p else '公开只读'})
     if path.startswith('/runtime/api/alerts/'):
      a=app.store.detail(path.rsplit('/',1)[-1]);return self.send(200,a)
     if path.startswith('/runtime/api/gates/'):
      p=app.principal(self.headers)
      if not p or p['role']!='sensor':return self.send(403,{'error':'需要执行器凭证'})
      return self.send(200,app.store.gate_get(p['name'],path.rsplit('/',1)[-1]))
     return self.send(404,{'error':'不存在'})
    except KeyError as e:self.send(404,{'error':str(e)})
    except ValueError as e:self.send(400,{'error':str(e)[:200]})
    except Exception:self.send(503,{'error':'服务暂不可用，请稍后重试'})
   def do_POST(self):
    try:
     if self.headers.get('Transfer-Encoding'):return self.send(400,{'error':'不支持分块请求'})
     size=int(self.headers.get('Content-Length','0'))
     if not 0<size<=1024*1024:return self.send(413,{'error':'请求需在 1MiB 内'})
     p=app.principal(self.headers)
     if not p:return self.send(403,{'error':'公开界面仅可读；处置需要操作凭证'})
     body=json.loads(self.rfile.read(size));path=urllib.parse.urlsplit(self.path).path
     if not isinstance(body,dict):raise ValueError('请求必须为对象')
     if p['role']=='sensor':
      if path=='/runtime/api/heartbeat':app.store.heartbeat(p['name'],body);return self.send(200,{'ok':True})
      if path=='/runtime/api/ingest':return self.send(200,{'inserted':app.store.ingest(p['name'],body.get('events',[]))})
      if path=='/runtime/api/gates':return self.send(201,app.store.gate_create(p['name'],body))
      parts=path.split('/')
      if len(parts)==6 and parts[3]=='gates':
       gid=parts[4]
       if parts[5]=='claim':return self.send(200,app.store.claim(p['name'],gid,body.get('hash','')))
       if parts[5]=='complete':return self.send(200,app.store.complete(p['name'],gid,body))
      return self.send(403,{'error':'采集器无人工处置权限'})
     if path.startswith('/runtime/api/alerts/') and path.endswith('/review'):
      return self.send(200,app.store.review(path.split('/')[-2],body,p['name']))
     if path=='/runtime/api/intelligence':return self.send(201,app.store.intel_import(body,p['name']))
     self.send(404,{'error':'不存在'})
    except Conflict as e:self.send(409,{'error':str(e)})
    except KeyError as e:self.send(404,{'error':str(e)})
    except (ValueError,TypeError) as e:self.send(400,{'error':str(e)[:200]})
    except Exception:self.send(503,{'error':'服务暂不可用，请稍后重试'})
  return H
if __name__=='__main__':
 config=json.loads(Path(os.environ.get('AGENTREINS_RUNTIME_CONFIG','/etc/agentreins-runtime/config.json')).read_text());app=App(Path(__file__).parent,config)
 ThreadingHTTPServer((config.get('bind','127.0.0.1'),config.get('port',18920)),app.handler()).serve_forever()
