from pathlib import Path
import json,os,sys
os.umask(0o077);base=Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes());private=Path(sys.argv[1]).resolve(strict=True);setup=json.loads((private/'owned-root-setup.json').read_bytes());proxy=json.loads((private/'proxy-ready.json').read_bytes());origin=proxy['origin'];assert origin.startswith('http://127.0.0.1:')and not origin.endswith((':19100',':19101'))
for phase in ['legacy','upgrade']:
 out=private/phase;out.mkdir(mode=0o700);cfg={'origin':origin,'credentials':str(private/'root-credentials.json'),'phase':phase,'site':setup['site'],'site_name':setup['site_name'],'catalogue_commit':pins['catalogue_head'],'manifest_sha256':pins['manifest_sha256']};(out/'web-store-config.json').open('x').write(json.dumps(cfg))
viewer=private/'viewer';viewer.mkdir(mode=0o700);access=json.loads((private/'viewer-credentials.json').read_bytes());access.update(panel_origin=origin,programme_source_inputs_sha256=pins['new']['programme_source_inputs_sha256']);(viewer/'local-native-credentials.json').open('x').write(json.dumps(access));access.clear();print(json.dumps({'ok':True,'browser_cases':3,'factors_stay_in_same_job':True}))
