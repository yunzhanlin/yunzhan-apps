from pathlib import Path
import copy,hashlib,json
from jsonschema import Draft202012Validator
root=Path(__file__).resolve().parent.parent;schema=json.loads((root/'schema/current-app.schema.json').read_bytes());assert (root/'schema/current-app.schema.json').read_bytes()==(root/'candidate/schema/current-app.schema.json').read_bytes();Draft202012Validator.check_schema(schema);validator=Draft202012Validator(schema);catalogue=json.loads((root/'candidate/dist/catalog-v1.json').read_bytes());assert len(catalogue['apps'])==40;positive=[]
for app in catalogue['apps']:
 value=json.loads((root/'candidate/dist/apps'/app['id']/app['version']/'manifest.json').read_bytes());validator.validate(value);positive.append(app['id']+':'+app['version'])
for version in ['1.3.2','1.3.3']:validator.validate(json.loads((root/'candidate/dist/apps/mobile'/version/'manifest.json').read_bytes()));positive.append('retained-mobile:'+version)
app=json.loads((root/'candidate/dist/apps/mobile/1.4.0/manifest.json').read_bytes());assert app['required_panel_features']==['mobile-web-workspace-v140'];negative=[]
def refused(label,value):
 assert list(validator.iter_errors(value)),label;negative.append(label)
for item in catalogue['apps']:
 original=json.loads((root/'candidate/dist/apps'/item['id']/item['version']/'manifest.json').read_bytes());value=copy.deepcopy(original);value['delivery']['target']='foreign-target';refused(item['id']+':foreign-target',value);value=copy.deepcopy(original);value['required_panel_features']=['daily-report-schedule-v1' if item['id']=='mobile' else 'mobile-web-workspace-v140'];refused(item['id']+':borrowed-feature',value)
for stage in ['ready','integration','design']:
 for provider in ['panel-module','runtime','compose']:
  for identity in ['foreign-id','foreign-target']:
   value=copy.deepcopy(app);value['stage']=stage;value['delivery']['provider']=provider
   if identity=='foreign-id':value['id']='user-manager'
   else:value['delivery']['target']='user-manager'
   refused(stage+':'+provider+':'+identity,value)
for version in ['1.4.1','1.4.0-compat1','01.4.0']:value=copy.deepcopy(app);value['version']=version;refused(version,value)
for features in [[],['mobile-native-delivery-v132'],['mobile-native-delivery-v133'],['mobile-web-workspace-v140','mobile-web-workspace-v140']]:value=copy.deepcopy(app);value['required_panel_features']=features;refused('feature:'+json.dumps(features),value)
value=copy.deepcopy(app);value['delivery']['manage_route']='security';refused('foreign-route',value);assert len(positive)==42 and len(negative)==106
print(json.dumps({'ok':True,'independent_Draft202012':True,'positive_manifests':len(positive),'negative_cases':len(negative),'schema_sha256':hashlib.sha256((root/'schema/current-app.schema.json').read_bytes()).hexdigest(),'original132_133_and_exact140_separate':True}))
