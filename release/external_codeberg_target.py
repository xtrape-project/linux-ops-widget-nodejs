"""Create only the fixed, empty public Codeberg target; never alter a repository."""
import json
import os
import urllib.error
import urllib.request
from external_preflight import credential_input
from external_source import REPOSITORY, SHA, TARGETS, NoRedirect, Refusal
from external_source import execute, git_environment, remote_head, source_origin_matches

READ_URL = 'https://codeberg.org/api/v1/repos/' + REPOSITORY
CREATE_URL = 'https://codeberg.org/api/v1/orgs/xtrape-project/repos'
CREATE_BODY = {'name':'linux-ops-widget-nodejs','private':False,'auto_init':False,'default_branch':'main'}
GIT_URL = TARGETS['codeberg'][0]

def request(method, token, opener=None):
    if method not in ('GET','POST'):
        raise Refusal('INVALID_TARGET_OPERATION')
    req=urllib.request.Request(READ_URL if method=='GET' else CREATE_URL,
        method=method, data=None if method=='GET' else json.dumps(CREATE_BODY).encode(),
        headers={'Authorization':'token '+token,'Accept':'application/json',
                 'Content-Type':'application/json','User-Agent':'xtrape-public-source/0.8.7'})
    opener=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    try:
        with opener.open(req,timeout=15) as response:
            if response.status not in (200,201):
                return response.status,None
            raw=response.read(1048577)
            if len(raw)>1048576:
                raise Refusal('CODEBERG_TARGET_RESPONSE_INVALID')
            return response.status,json.loads(raw)
    except urllib.error.HTTPError as error:
        status=error.code
        try:error.close()
        except Exception:pass
        return status,None
    except Refusal:
        raise
    except Exception:
        raise Refusal('CODEBERG_TARGET_TRANSPORT_UNCONFIRMED') from None

def public_metadata(data):
    if not isinstance(data,dict) or data.get('full_name')!=REPOSITORY or data.get('private') is not False or data.get('clone_url')!=GIT_URL:
        raise Refusal('CODEBERG_TARGET_IDENTITY_OR_VISIBILITY_REFUSED')

def prepare(call=request, run=execute):
    report={'platform':'codeberg','operation':'fixed_empty_public_target','phase':'source_validation','writes_attempted':0}
    try:
        if os.environ.get('GITHUB_REPOSITORY')!=REPOSITORY or os.environ.get('GITHUB_REF')!='refs/heads/main':
            raise Refusal('SOURCE_CONTEXT_REFUSED')
        source=os.environ.get('SOURCE_SHA','')
        if not SHA.fullmatch(source):raise Refusal('INVALID_SOURCE_SHA')
        env=git_environment(GIT_URL)
        if run(['rev-parse','HEAD'],env)!=source:
            raise Refusal('CHECKOUT_SOURCE_MISMATCH')
        if not source_origin_matches(run(['remote','get-url','origin'],env),os.environ.get('SOURCE_SERVER_URL','')):
            raise Refusal('SOURCE_ORIGIN_REFUSED')
        token,shape=credential_input(os.environ.get('CODEBERG_PUBLISH_TOKEN',''))
        if not token or any(shape[k] for k in ('embedded_control_character','header_wrapper_present','assignment_wrapper_present','quoted_value','placeholder_value')):
            raise Refusal('INVALID_CREDENTIAL_INPUT')
        report['phase']='target_metadata'
        status,data=call('GET',token)
        if status==200:
            public_metadata(data)
            result='EXISTING_PUBLIC_TARGET'
        elif status==404:
            # 404 does not prove absence. Atomic create cannot overwrite an
            # existing name; conflicts never authorize a visibility change.
            report['phase']='create'
            report['writes_attempted']=1
            try:
                status,data=call('POST',token)
                if status==201:
                    public_metadata(data)
                    if data.get('empty') is not True:
                        raise Refusal('CODEBERG_CREATED_TARGET_NOT_EMPTY')
                    result='CREATED_EMPTY_PUBLIC_TARGET'
                elif status in (401,403):
                    raise Refusal('CODEBERG_CREATE_ACCESS_REJECTED')
                else:
                    raise Refusal('CODEBERG_CREATE_UNCONFIRMED')
            except Refusal as failure:
                if str(failure) in ('CODEBERG_CREATE_ACCESS_REJECTED','CODEBERG_CREATED_TARGET_NOT_EMPTY','CODEBERG_TARGET_IDENTITY_OR_VISIBILITY_REFUSED'):
                    raise
                # A write timeout/conflict is reconciled with GET, never POST.
                report['phase']='create_readback'
                checked,observed=call('GET',token)
                if checked!=200:raise Refusal('CODEBERG_CREATE_UNCONFIRMED') from None
                public_metadata(observed)
                if observed.get('empty') is not True:
                    raise Refusal('CODEBERG_CREATE_RECONCILIATION_NOT_EMPTY')
                result='CREATE_RECONCILED_EMPTY_PUBLIC_TARGET'
        elif status in (401,403):
            raise Refusal('CODEBERG_TARGET_ACCESS_REJECTED')
        else:
            raise Refusal('CODEBERG_TARGET_LOOKUP_UNCONFIRMED')
        report['phase']='anonymous_git_readback'
        target_head=remote_head(GIT_URL,env,run)
        if result!='EXISTING_PUBLIC_TARGET' and target_head is not None:
            raise Refusal('CODEBERG_CREATED_TARGET_NOT_EMPTY')
        report.update(result=result,anonymous_git_readable=True,source_sha=source)
    except Refusal as error:
        report['result']=str(error)
    return report

def main():
    report=prepare()
    print(json.dumps(report))
    return 0 if report['result'] in ('EXISTING_PUBLIC_TARGET','CREATED_EMPTY_PUBLIC_TARGET','CREATE_RECONCILED_EMPTY_PUBLIC_TARGET') else 1

if __name__=='__main__':raise SystemExit(main())
