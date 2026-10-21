"""Conservative curl/wget and shell path extraction; does not execute commands."""
import posixpath,re,shlex,urllib.parse
SHELLS={'sh','bash','dash','zsh'}
def absolute(path,cwd):
 if not path or path=='-' or '://' in path:return None
 if path.startswith('/'):return posixpath.normpath(path)
 return posixpath.normpath(posixpath.join(cwd,path)) if cwd else None

def parse(command,cwd=None):
 result={'execPaths':[],'parseLimitations':[]}
 try:argv=shlex.split(command)
 except ValueError:return {**result,'parseLimitations':['无法解析命令参数']}
 if not argv:return result
 name=posixpath.basename(argv[0])
 if name in SHELLS and '-c' in argv and argv.index('-c')+1<len(argv):return parse(argv[argv.index('-c')+1],cwd)
 if name in ('curl','wget'):
  url=next((x for x in argv[1:] if x.startswith(('http://','https://'))),None);output=None;remote=False;redirect=None
  i=1
  while i<len(argv):
   a=argv[i]
   if (name=='curl' and a in ('-o','--output')) or (name=='wget' and a in ('-O','--output-document')):
    if i+1<len(argv):output=argv[i+1];i+=1
   elif name=='curl' and a in ('-O','--remote-name'):remote=True
   elif name=='curl' and a.startswith('-o') and len(a)>2:output=a[2:]
   elif name=='wget' and a.startswith('-O') and len(a)>2:output=a[2:]
   elif name=='curl' and a.startswith('--output='):output=a.split('=',1)[1]
   elif name=='wget' and a.startswith('--output-document='):output=a.split('=',1)[1]
   elif a in ('>','1>') and i+1<len(argv):redirect=argv[i+1]
   i+=1
  redir=re.search(r'(?:^|\s)(?:1)?>\s*([^\s;&|]+)',command)
  if redir:redirect=redir.group(1).strip('"\'')
  if output is None and (remote or name=='wget') and url:output=posixpath.basename(urllib.parse.urlsplit(url).path)
  if output is None and not remote and name=='curl':output=redirect
  if output and output!='-':
   path=absolute(output,cwd)
   if path:result['downloadPath']=path
   else:result['parseLimitations'].append('相对落地路径缺少 cwd，未关联')
  if url:result['destination']=url
  return result
 # Only executable or interpreter script operand; never arbitrary output flags.
 operands=[]
 if argv[0].startswith(('/','./','../')):operands.append(argv[0])
 if name in SHELLS|{'python','python3','node','perl','ruby'}:
  for a in argv[1:]:
   if a in ('-c','-e','-m'):break
   if not a.startswith('-'):operands.append(a);break
 result['execPaths']=[p for a in operands if (p:=absolute(a,cwd))]
 if operands and not result['execPaths']:result['parseLimitations'].append('相对执行路径缺少 cwd，未关联')
 return result
