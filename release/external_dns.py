"""Credential-free DNS comparison using only the already configured resolver."""
import json
import os
import subprocess
import sys

HOSTS = ("gitee.com", "gitlab.com")
PROFILES = ("system", "tcp")
RESULTS = {"RESOLVED", "DNS_TEMPORARY_FAILURE", "DNS_NAME_NOT_FOUND", "DNS_OTHER_FAILURE"}
QUERY = '''import socket,json,sys
try:
 socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM);result="RESOLVED"
except socket.gaierror as e:
 result="DNS_TEMPORARY_FAILURE" if e.errno==socket.EAI_AGAIN else "DNS_NAME_NOT_FOUND" if e.errno==socket.EAI_NONAME else "DNS_OTHER_FAILURE"
except Exception:result="DNS_OTHER_FAILURE"
print(json.dumps({"result":result}))
'''

def query(host, profile, run=subprocess.run):
    report = {"host":host if host in HOSTS else "invalid", "profile":profile if profile in PROFILES else "invalid"}
    if host not in HOSTS or profile not in PROFILES:
        return dict(report,result="INVALID_INPUT")
    env = {k:v for k,v in os.environ.items() if not k.startswith("GIT_") and not any(x in k.upper() for x in ("TOKEN","PASSWORD","SECRET"))}
    if profile == "tcp":
        env["RES_OPTIONS"] = env.get("RES_OPTIONS","") + " use-vc timeout:2 attempts:1"
    try:
        p=run([sys.executable,"-c",QUERY,host],env=env,capture_output=True,text=True,timeout=12,stdin=subprocess.DEVNULL)
        try:
            data=json.loads(p.stdout) if p.returncode==0 and len(p.stdout)<1024 else {}
        except (ValueError,TypeError):
            data={}
        result=data.get("result") if isinstance(data,dict) else None
        return dict(report,result=result if isinstance(result,str) and result in RESULTS else "INVALID_CHILD_RESULT")
    except subprocess.TimeoutExpired:
        return dict(report,result="DNS_QUERY_TIMEOUT")
    except Exception:
        return dict(report,result="DNS_QUERY_FAILED")

def main():
    rows=[query(host,profile) for host in HOSTS for profile in PROFILES]
    print(json.dumps({"diagnostic":"fixed_dns_transport","writes_attempted":0,"resolver_changed":False,"queries":rows}))
    return 0 if all(r["result"]=="RESOLVED" for r in rows if r["profile"]=="system") else 1

if __name__=="__main__":raise SystemExit(main())
