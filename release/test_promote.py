import json
import unittest
from unittest.mock import patch
import promote as p

class Fake:
    def __init__(self):
        self.source='a'*40
        self.config=json.dumps({'config':{'Labels':{'org.opencontainers.image.revision':self.source,'org.opencontainers.image.version':'0.8.7','org.opencontainers.image.source':'https://forgejo.xtrape.com/xtrape-project/xtrape-platform-ce'}}}).encode()
        self.raw=json.dumps({'schemaVersion':2,'mediaType':p.MEDIA[0],'config':{'digest':p.sha(self.config)},'layers':[]}).encode()
        self.record={'repo':'xtrape-platform-ce','public_source_sha':self.source,'run_id':1,'public_digest':p.sha(self.raw)}
        self.refs={'candidate-'+self.source+'-1-attempt-1':self.raw,p.sha(self.raw):self.raw}
        self.writes=[]
    def token(self,write=False):return 'writer' if write else 'anonymous'
    def manifest(self,ref,token):return self.refs.get(ref)
    def blob(self,digest,token):return self.config
    def put(self,tag,raw,media,token):self.writes.append(tag);self.refs[tag]=raw

class Tests(unittest.TestCase):
    def run_promotion(self,f):
        with patch('builtins.print'):
            p.promote(f.record,'xtrape-project/xtrape-platform-ce',f)
    def test_exact_bytes_and_idempotence(self):
        f=Fake();self.run_promotion(f);self.assertEqual(len(f.writes),2);self.assertEqual(f.refs['0.8.7'],f.raw);self.run_promotion(f);self.assertEqual(len(f.writes),2)
    def test_conflict_prevents_all_writes(self):
        f=Fake();f.refs['sha-'+f.source]=b'conflict'
        with self.assertRaises(p.Refusal):self.run_promotion(f)
        self.assertEqual(f.writes,[])
    def test_race_conflict_refused(self):
        f=Fake();old=f.manifest
        f.manifest=lambda ref,token:b'conflict' if token=='writer' else old(ref,token)
        with self.assertRaises(p.Refusal):self.run_promotion(f)
        self.assertEqual(f.writes,[])
    def test_bad_labels(self):
        f=Fake();f.config=b'{}'
        with self.assertRaises(p.Refusal):self.run_promotion(f)
        self.assertEqual(f.writes,[])
    def test_candidate_mismatch(self):
        f=Fake();f.record['public_digest']='sha256:'+'0'*64
        with self.assertRaises(p.Refusal):self.run_promotion(f)
    def test_wrong_repository(self):
        f=Fake()
        with self.assertRaises(p.Refusal):p.promote(f.record,'xtrape/xtrape-platform-ce',f)
    def test_index_refused(self):
        f=Fake();f.raw=json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json'}).encode();f.record['public_digest']=p.sha(f.raw);f.refs={k:f.raw for k in f.refs};f.refs[p.sha(f.raw)]=f.raw
        with self.assertRaises(p.Refusal):self.run_promotion(f)
    def test_positive_absence_only(self):
        r=p.Registry('xtrape-project/xtrape-platform-ce')
        for status,body,absent in [(404,{'errors':[{'code':'MANIFEST_UNKNOWN'}]},True),(404,{'errors':[]},False),(404,{'errors':[{'code':'MANIFEST_UNKNOWN'},{'code':'DENIED'}]},False),(403,{'errors':[{'code':'MANIFEST_UNKNOWN'}]},False),(500,{},False),(302,{},False)]:
            with self.subTest(status=status,body=body),patch.object(r,'request',return_value=(status,json.dumps(body).encode())):
                if absent:self.assertIsNone(r.manifest('0.8.7','anonymous'))
                else:
                    with self.assertRaises(p.Refusal):r.manifest('0.8.7','anonymous')
    def test_html_network_fail_closed(self):
        r=p.Registry('xtrape-project/xtrape-platform-ce')
        with patch.object(r,'request',return_value=(404,b'<html>404</html>')):
            with self.assertRaises(ValueError):r.manifest('0.8.7','a')
        with patch.object(r,'request',side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):r.manifest('0.8.7','a')
    def test_write_uncertain_never_repeated(self):
        f=Fake();f.put=lambda *args: (_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(TimeoutError):self.run_promotion(f)
    def test_readback_failure(self):
        f=Fake();f.put=lambda *args:None
        with self.assertRaises(p.Refusal):self.run_promotion(f)

class IndexTests(unittest.TestCase):
    def run_promotion(self,f):
        with patch('builtins.print'):
            p.promote(f.record,'xtrape-project/xtrape-platform-ce',f)
    def index_fixture(self):
        f=Fake(); image=f.raw
        config=b'{}'; proof=b'{"predicateType":"https://slsa.dev/provenance/v0.2"}'
        blobs={p.sha(f.config):f.config,p.sha(config):config,p.sha(proof):proof}
        att=json.dumps({'schemaVersion':2,'mediaType':p.MEDIA[0],
            'config':{'digest':p.sha(config),'size':len(config)},
            'layers':[{'digest':p.sha(proof),'size':len(proof)}]}).encode()
        index={'schemaVersion':2,'mediaType':p.INDEX,'manifests':[
            {'mediaType':p.MEDIA[0],'digest':p.sha(image),'size':len(image),'platform':{'os':'linux','architecture':'amd64'}},
            {'mediaType':p.MEDIA[0],'digest':p.sha(att),'size':len(att),'platform':{'os':'unknown','architecture':'unknown'},'annotations':{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':p.sha(image)}}]}
        f.refs[p.sha(image)]=image;f.refs[p.sha(att)]=att
        f.blob=lambda digest,token:blobs[digest]
        self.set_index(f,index)
        return f,index
    def set_index(self,f,index):
        f.raw=json.dumps(index).encode();f.record['public_digest']=p.sha(f.raw)
        f.refs['candidate-'+f.source+'-1-attempt-1']=f.raw;f.refs[p.sha(f.raw)]=f.raw
    def test_index_preserved_exactly(self):
        f,index=self.index_fixture();self.run_promotion(f)
        self.assertEqual(f.refs['0.8.7'],f.raw);self.assertEqual(len(f.writes),2)
    def test_index_bad_shapes(self):
        for mode in ['empty','extra','platform','binding','size','missing','corrupt','media','proof']:
            with self.subTest(mode=mode):
                f,index=self.index_fixture();d=index['manifests'][0]
                if mode=='empty':index['manifests']=[]
                if mode=='extra':index['manifests'].append(dict(d))
                if mode=='platform':d['platform']['architecture']='arm64'
                if mode=='binding':index['manifests'][1]['annotations']['vnd.docker.reference.digest']='sha256:'+'0'*64
                if mode=='size':d['size']+=1
                if mode=='missing':del f.refs[d['digest']]
                if mode=='corrupt':f.refs[d['digest']]=b'{}'
                if mode=='media':d['mediaType']='unknown'
                if mode=='proof':f.blob=lambda digest,token:b'corrupt'
                self.set_index(f,index)
                with self.assertRaises(p.Refusal):self.run_promotion(f)
                self.assertEqual(f.writes,[])

if __name__=='__main__':unittest.main()
