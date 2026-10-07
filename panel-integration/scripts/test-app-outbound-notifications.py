#!/usr/bin/env python3
"""Actual signed-panel webhook acceptance on explicitly isolated QA hosts."""
import argparse
import hashlib
import hmac
import json
import os
import pathlib
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = 'qa-outbound-signing-fixture-only'
parser = argparse.ArgumentParser()
parser.add_argument('--receiver', type=pathlib.Path)
parser.add_argument('--port', type=int, default=27141)
args = parser.parse_args()
if args.receiver:
    args.receiver.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *unused): pass
        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 4096:
                self.send_response(413); self.end_headers(); return
            raw = self.rfile.read(length)
            delivery = self.headers.get('X-Yunzhan-Delivery-ID', '')
            stamp = self.headers.get('X-Yunzhan-Timestamp', '')
            signature = 'sha256=' + hmac.new(SECRET.encode(), (stamp+'.'+delivery+'.').encode()+raw, hashlib.sha256).hexdigest()
            valid = hmac.compare_digest(signature, self.headers.get('X-Yunzhan-Signature', '')) and abs(time.time()-int(stamp)) < 300
            value = json.loads(raw)
            assert all(s not in raw.decode() for s in ('private-file-content', 'private-password', 'private-token'))
            records = json.loads(args.receiver.read_text()) if args.receiver.exists() else []
            status = 204
            tests = [r for r in records if r['payload']['kind'] == 'test']
            if value['kind'] == 'test' and (not tests or self.path == '/always-retry'): status = 429
            if not valid: status = 401
            records.append({'id':delivery, 'valid':valid, 'status':status, 'payload':value})
            temporary = args.receiver.with_suffix('.next')
            temporary.write_text(json.dumps(records))
            temporary.chmod(0o600); temporary.replace(args.receiver)
            self.send_response(status)
            if status == 429: self.send_header('Retry-After', '15')
            self.end_headers()
    HTTPServer(('127.0.0.1', args.port), Receiver).serve_forever()
    sys.exit(0)

from panel_client import PanelClient
assert os.environ.get('PANEL_VM') in ('panel-compat-ubuntu24', 'panel-store-apps-debian13'), 'Isolated QA host required'
root = pathlib.Path(__file__).resolve().parents[1]
state = root / os.environ['OUTBOUND_QA_STATE']
assert not state.exists(), 'Inspect existing fixture state before rerunning'
p = PanelClient()
token = uuid.uuid4().hex[:8]
v = {'sites':[], 'channel':'', 'unit':'panel-qa-outbound-'+token, 'checks':[], 'passed':False}
receiver_path = '/var/lib/panel-qa-outbound-'+token+'/received.json'
port = args.port
def checkpoint():
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(v, indent=2)+'\n'); state.chmod(0o600)
def passed(text): v['checks'].append(text); checkpoint(); print('PASS', text, flush=True)
def poll(check, timeout=40):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            if check(): return
        except RuntimeError as e:
            if not any(s in str(e) for s in ('HTTP 409', 'HTTP 502', 'HTTP 503', '执行服务连接失败')): raise
        time.sleep(.5)
    raise AssertionError('Actual business result not observed before deadline')
def write(path, body, method='POST'):
    for attempt in range(20):
        try: return p.api(path, body, method)
        except RuntimeError as e:
            if '推送处理中' not in str(e) or attempt==19: raise
            time.sleep(.5)
def module(id, action='run', **body): return p.api('/app-modules/'+id+'/'+action, body)
def channel(): return next(c for c in p.api('/notification-channels')['channels'] if c['id']==v['channel'])
def history(): return p.api('/notification-channels/'+v['channel']+'/deliveries')['deliveries']
def received():
    out=p.vm('sudo','python3','-c','import json,pathlib,sys;p=pathlib.Path(sys.argv[1]);print(p.read_text() if p.exists() else "[]")',receiver_path).stdout
    return json.loads(out)
def queue_test(): return write('/notification-channels/'+v['channel']+'/test',{'revision':channel()['revision']})['event_id']
def cleanup():
    if v['channel']:
        c=channel()
        if c['enabled']: write('/notification-channels/'+c['id'],{'name':c['name'],'kinds':c['kinds'],'enabled':False,'revision':c['revision']},'PUT')
    for site_id in v['sites']:
        for id in ('file-monitor','website-tamper-proof','enterprise-tamper-proof'):
            if any(x['site_id']==site_id for x in module(id,'policies')['policies']): module(id,'pause',site_id=site_id)
        site=next(x for x in p.api('/sites') if x['id']==site_id)
        assert site['slug'].startswith('outbound-') and site['domain']==site['slug']+'.example.test'
        p.wait(p.api('/sites/'+site_id,{'confirm_domain':site['domain']},'DELETE')['job_id'],timeout=120)
    p.vm('sudo','systemctl','stop',v['unit'])
    v['cleaned_up']=True;checkpoint()
try:
    checkpoint()
    executable='/workspace'+str(pathlib.Path(__file__).resolve()).split('/panel',1)[1]
    # Host paths have an external drive prefix; only the verified workspace mount is used in the guest.
    p.vm('sudo','systemd-run','--unit='+v['unit'],'--property=RuntimeMaxSec=600','--property=Restart=no','python3',executable,'--receiver',receiver_path,'--port',str(port))
    for _ in range(2):
        slug='outbound-'+uuid.uuid4().hex[:8]
        p.wait(p.api('/sites',{'name':slug,'slug':slug,'domain':slug+'.example.test','php_version_id':''})['job_id'],timeout=120)
        v['sites'].append(next(s['id'] for s in p.api('/sites') if s['slug']==slug));checkpoint()
    source,target=v['sites']
    for site,text in ((source,'private-file-content'),(target,'user-owned')):
        p.api('/sites/'+site+'/files/action',{'action':'create','path':'watch.txt','content':text})
    c=write('/notification-channels',{'name':'QA-'+token,'url':'http://127.0.0.1:'+str(port)+'/notify','secret':SECRET,'enabled':True,'kinds':['integrity','sync','daily']})
    v['channel']=c['id'];checkpoint()
    redacted=json.dumps(p.api('/notification-channels'))
    assert SECRET not in redacted and '/notify' not in redacted and c['secret_set']
    passed('authenticated configuration redacts full endpoint and secret')
    event=queue_test()
    poll(lambda:any(d['event_id']==event and d['state']=='pending' and d['attempts']==1 and d['http_status']==429 for d in history()))
    p.vm('sudo','systemctl','restart','panel')
    poll(lambda:any(d['event_id']==event and d['state']=='succeeded' and d['attempts']==2 for d in history()),timeout=45)
    records=[r for r in received() if r['payload']['event_id']==event]
    assert len(records)==2 and records[0]['id']==records[1]['id'] and all(r['valid'] for r in records)
    passed('actual receiver verified HMAC, HTTP 429 delay and durable same-ID retry across panel restart')
    for id in ('file-monitor','website-tamper-proof','enterprise-tamper-proof'):
        module(id,'baseline',site_id=source,interval=86400,realtime=True,auto_restore=False)
    old=p.api('/sites/'+source+'/files/text?path=watch.txt')
    p.api('/sites/'+source+'/files/action',{'action':'save','path':'watch.txt','content':'changed-private-file-content','expected_sha256':old['sha256']})
    poll(lambda:len([r for r in received() if r['payload']['kind']=='integrity' and r['status']==204])>=3)
    passed('three actual kernel file monitors emit signed external change alerts without file content')
    result=module('files-sync','sync',site_id=source,target_site_id=target)
    assert result['conflicts_count']>=1
    poll(lambda:any(r['payload']['kind']=='sync' and r['status']==204 for r in received()))
    assert p.api('/sites/'+target+'/files/text?path=watch.txt')['content']=='user-owned'
    passed('actual sync conflict produces delivered alert and preserves target data')
    module('daily-report','run')
    # A report generated earlier today is intentionally not pushed twice.
    summary=p.api('/app-modules/daily-report')['report']
    assert summary['sites']>=2
    passed('real daily report generated; numeric/privacy push and per-day dedup additionally covered by durable-queue tests')
    c=channel(); old_revision=c['revision']
    c=write('/notification-channels/'+c['id'],{'name':c['name'],'url':'http://127.0.0.1:'+str(port)+'/always-retry','enabled':True,'kinds':c['kinds'],'revision':c['revision']},'PUT')
    try: p.api('/notification-channels/'+c['id'],{'name':c['name'],'enabled':False,'kinds':c['kinds'],'revision':old_revision},'PUT')
    except RuntimeError as e: assert 'HTTP 409' in str(e)
    else: raise AssertionError('stale channel revision accepted')
    event=queue_test()
    poll(lambda:any(d['event_id']==event and d['state']=='pending' and d['attempts']==1 for d in history()))
    write('/notification-channels/'+c['id'],{'name':c['name'],'enabled':False,'kinds':c['kinds'],'revision':c['revision']},'PUT')
    assert any(d['event_id']==event and d['state']=='cancelled' for d in history())
    before=len(received())
    deadline=time.monotonic()+18
    while time.monotonic()<deadline: time.sleep(.5)
    assert len(received())==before
    passed('stale writes rejected; disable cancels pending retry and produces no later request')
    v['passed']=True;checkpoint()
finally:
    try: cleanup()
    finally: p.close()
