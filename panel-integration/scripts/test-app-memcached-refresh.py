#!/usr/bin/env python3
import json,pathlib,uuid,time
from panel_client import PanelClient
from test_app_registry_common import wait_job
c=PanelClient();p=None
try:
 job=c.api('/app-registry/memcached/install',{'name':'memcached-refresh-'+uuid.uuid4().hex[:8],'host_port':21211});wait_job(c,job)
 p=next(v for v in c.api('/docker/projects')['projects'] if v['id']==job['project_id'])
 code=r'''import socket,time
for _ in range(30):
 try:s=socket.create_connection(('127.0.0.1',21211),2);break
 except OSError:time.sleep(.5)
f=s.makefile('rb');s.sendall(b'set cloudstack-qa 0 60 8\r\nverified\r\n');assert f.readline()==b'STORED\r\n';s.sendall(b'get cloudstack-qa\r\n');assert f.readline().startswith(b'VALUE cloudstack-qa');assert f.readline()==b'verified\r\n';assert f.readline()==b'END\r\n';s.sendall(b'version\r\n');assert f.readline()==b'VERSION 1.6.45\r\n';s.close();print('Memcached protocol verified')'''
 assert 'verified' in c.vm('python3','-c',code).stdout
 wait_job(c,c.api('/docker/projects/'+p['id']+'/restart',{}));assert 'verified' in c.vm('python3','-c',code).stdout
 report={'apps':{'memcached':{'passed':True,'evidence':'实际 Memcached 1.6.45 协议 SET/GET/VERSION 和服务重启通过'}}}
 (pathlib.Path(__file__).resolve().parents[1]/'.local/app-memcached-acceptance.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print('PASS memcached',flush=True)
finally:
 if p:wait_job(c,c.api('/docker/projects/'+p['id'],{'confirm_name':p['name']},method='DELETE'))
 c.close()
