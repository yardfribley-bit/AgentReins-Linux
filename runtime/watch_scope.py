"""Generate bounded sensitive-file audit watches from existing paths only.
Run as root with --apply after reviewing --preview. Missing categories are reported.
"""
import argparse,glob,json,subprocess
from pathlib import Path
CANDIDATES={
 'system':['/etc/shadow','/etc/gshadow'],'ssh':['/root/.ssh','/home/*/.ssh'],
 'env':['/home/*/dify/docker/.env','/opt/*/.env','/var/lib/agentreins-runtime/lab/.env'],
 'kubernetes':['/root/.kube/config','/home/*/.kube/config'],
 'container':['/root/.docker/config.json','/home/*/.docker/config.json'],
 'git':['/root/.git-credentials','/home/*/.git-credentials'],'netrc':['/root/.netrc','/home/*/.netrc'],
 'aws':['/root/.aws/credentials','/home/*/.aws/credentials'],
 'gcloud':['/root/.config/gcloud/application_default_credentials.json','/home/*/.config/gcloud/application_default_credentials.json'],
 'azure':['/root/.azure','/home/*/.azure'],'key':['/home/*/*.pem','/home/*/*.key'],
 'secrets':['/opt/*/secrets.yaml']}
def apply(config,install=False):
 mapping=config.get('watchCandidates',CANDIDATES);result={};existing=subprocess.check_output(['auditctl','-l'],text=True) if install else '';lines=[]
 for category,patterns in mapping.items():
  paths=sorted({p for pattern in patterns for p in glob.glob(pattern)})[:100];accepted=[]
  for p in paths:
   if any(c.isspace() for c in p):continue
   rule='-w '+p+' -p r -k agentreins_sensitive'
   if not install or rule in existing or subprocess.run(['auditctl','-w',p,'-p','r','-k','agentreins_sensitive'],capture_output=True).returncode==0:accepted.append(p);lines.append(rule)
  result[category]=accepted
 if install:Path('/etc/audit/rules.d/61-agentreins-sensitive.rules').write_text('\n'.join(lines)+'\n')
 return {'fileWatchCategories':result,'fileWatchScope':[x for paths in result.values() for x in paths],'unwatchedCategories':[k for k,v in result.items() if not v]}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--config',default='/etc/agentreins-runtime/sensor.json');p.add_argument('--apply',action='store_true');args=p.parse_args();file=Path(args.config);config=json.loads(file.read_text());scope=apply(config,args.apply)
 if args.apply:config.update(scope);file.write_text(json.dumps(config))
 print(json.dumps(scope,ensure_ascii=False,indent=2))
