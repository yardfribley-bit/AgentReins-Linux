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
# Write and attribute watches. Only paths that exist are installed. Directories are not recursive.
PERSIST={
 'env':['/home/*/dify/docker/.env','/opt/*/.env','/var/lib/agentreins-runtime/lab/.env','/home/*/.env'],
 'ssh':['/root/.ssh/authorized_keys','/home/*/.ssh/authorized_keys'],
 'shell':['/root/.bashrc','/root/.profile','/home/*/.bashrc','/home/*/.profile'],
 'cron':['/etc/crontab','/etc/cron.d','/etc/cron.daily','/var/spool/cron/crontabs'],
 'systemd':['/etc/systemd/system','/etc/ld.so.preload'],
 'git':['/home/*/.git/hooks','/opt/*/.git/hooks'],
 'workflow':['/home/*/.github/workflows','/opt/*/.github/workflows'],
 'account':['/etc/sudoers','/etc/sudoers.d']}
def _install(mapping,permission,key,existing,install):
 result={};lines=[]
 for category,patterns in mapping.items():
  paths=sorted({p for pattern in patterns for p in glob.glob(pattern)})[:100];accepted=[]
  for p in paths:
   if any(c.isspace() for c in p):continue
   rule='-w '+p+' -p '+permission+' -k '+key
   if not install or rule in existing or subprocess.run(['auditctl','-w',p,'-p',permission,'-k',key],capture_output=True).returncode==0:accepted.append(p);lines.append(rule)
  result[category]=accepted
 return result,lines
def apply(config,install=False):
 mapping=config.get('watchCandidates',CANDIDATES);persist=config.get('persistCandidates',PERSIST)
 existing='';audit_error=None
 if install:
  try:existing=subprocess.check_output(['auditctl','-l'],text=True,stderr=subprocess.STDOUT)
  except (OSError,subprocess.CalledProcessError) as exc:
   audit_error=str(exc);install=False
 result,lines=_install(mapping,'r','agentreins_sensitive',existing,install)
 written,write_lines=_install(persist,'wa','agentreins_persist',existing,install)
 if install:
  try:
   Path('/etc/audit/rules.d/61-agentreins-sensitive.rules').write_text('\n'.join(lines)+('\n' if lines else ''))
   Path('/etc/audit/rules.d/62-agentreins-persist.rules').write_text('\n'.join(write_lines)+('\n' if write_lines else ''))
  except OSError as exc:
   audit_error=(audit_error+'; ' if audit_error else '')+str(exc)
 scope=[x for paths in result.values() for x in paths]+[x for paths in written.values() for x in paths]
 missing=[k for k,v in {**result,**written}.items() if not v]
 out={'fileWatchCategories':result,'persistWatchCategories':written,'fileWatchScope':scope,'unwatchedCategories':missing}
 if audit_error:out['auditApplyError']=audit_error
 return out
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--config',default='/etc/agentreins-runtime/sensor.json');p.add_argument('--apply',action='store_true');args=p.parse_args();file=Path(args.config);config=json.loads(file.read_text());scope=apply(config,args.apply)
 if args.apply:config.update(scope);file.write_text(json.dumps(config))
 print(json.dumps(scope,ensure_ascii=False,indent=2))
