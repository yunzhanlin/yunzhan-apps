"""Synthetic owned-site inputs, never an implementation or acceptance receipt."""
import hashlib,json,re,urllib.parse

def php_fixture(marker,counter_path):
 assert re.fullmatch('apache24-php-[a-f0-9]{32}',marker)
 assert re.fullmatch('/srv/panel/sites/[a-f0-9]{32}/private/qa-apache24-counter-[a-f0-9]{32}',counter_path)
 return '''<?php declare(strict_types=1);
header('Content-Type: application/json');
$id=$_SERVER['HTTP_X_YUNZHAN_QA_REQUEST']??'';
if(!preg_match('/^[a-f0-9]{32}$/D',$id)){http_response_code(400);exit;}
$f=fopen(COUNTER,'c+b');
if($f===false||!flock($f,LOCK_EX)){http_response_code(500);exit;}
fseek($f,0,SEEK_END);$size=ftell($f);
if($size===false||$size>16384||fwrite($f,$id."\\n")!==33||!fflush($f)){fclose($f);http_response_code(500);exit;}
flock($f,LOCK_UN);fclose($f);
$body=file_get_contents('php://input');
$term=$_POST['term']??null;
$files=[];
foreach($_FILES as $name=>$v){
 if(count($files)>=8||!is_array($v)||!is_string($name)){http_response_code(500);exit;}
 $error=$v['error']??-1;$temporary=$v['tmp_name']??'';
 $files[$name]=['error'=>$error,'bytes'=>$v['size']??-1,'sha256'=>$error===0&&is_string($temporary)&&is_uploaded_file($temporary)?hash_file('sha256',$temporary):null];
}
header('X-Yunzhan-QA-Reached: '.$id);
echo json_encode(['marker'=>MARKER,'php'=>PHP_VERSION,'pid'=>getmypid(),'raw_bytes'=>strlen($body),'raw_sha256'=>hash('sha256',$body),'post_count'=>count($_POST),'term_bytes'=>is_string($term)?strlen($term):null,'term_sha256'=>is_string($term)?hash('sha256',$term):null,'files'=>$files],JSON_THROW_ON_ERROR);
'''.replace('COUNTER',json.dumps(counter_path)).replace('MARKER',json.dumps(marker))

def request_cases(marker):
 assert re.fullmatch('apache24-body-[a-f0-9]{32}',marker)
 def row(name,ctype,body,status=200,method='POST',encoding='',term=None,upload=None):
  if isinstance(body,str):body=body.encode()
  return {'name':name,'method':method,'content_type':ctype,'body_hex':body.hex(),'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),'block_status':status,'encoding':encoding,'expected_term_sha256':hashlib.sha256(term.encode()).hexdigest()if term is not None else None,'expected_upload_sha256':hashlib.sha256(upload).hexdigest()if upload is not None else None}
 def form(v):return urllib.parse.urlencode({'term':v,'private_note':marker})
 def nested(v):return json.dumps({'nested':{'term':v},'private_note':marker},separators=(',',':'))
 def multipart(v):
  boundary='YunzhanOwned'+marker[-32:];content=b'ordinary owned upload content\n';body=('--'+boundary+'\r\nContent-Disposition: form-data; name="term"\r\n\r\n'+v+'\r\n--'+boundary+'\r\nContent-Disposition: form-data; name="upload"; filename="ordinary.txt"\r\nContent-Type: text/plain\r\n\r\n').encode()+content+('\r\n--'+boundary+'--\r\n').encode();return body,'multipart/form-data; boundary='+boundary,content
 sqli="1' OR '1'='1' -- "+marker;xss="<script>alert('"+marker+"')</script>";safe,safe_type,file_data=multipart('ordinary field');attack,attack_type,_=multipart(xss)
 cases=[row('ordinary_get','','',method='GET'),row('ordinary_form','application/x-www-form-urlencoded',form('ordinary search'),term='ordinary search'),row('ordinary_json','application/json',nested('ordinary search')),row('ordinary_put','application/json',nested('ordinary search'),method='PUT'),row('ordinary_patch','application/json',nested('ordinary search'),method='PATCH'),row('ordinary_upload',safe_type,safe,term='ordinary field',upload=file_data),row('ordinary_xml','application/xml','<x><term>ordinary</term></x>'),row('ordinary_vendor_json','application/vnd.api+json; charset=utf-8',nested('ordinary search')),row('ordinary_depth64_object','application/json','{"a":'*64+'0'+'}'*64),row('ordinary_depth64_array','application/json','['*64+'0'+']'*64),row('ordinary_empty_object','application/json','{}'),row('ordinary_empty_array','application/json','[]')]
 for name,ctype,body,term in [('form_sqli','application/x-www-form-urlencoded',form(sqli),sqli),('json_sqli','application/json',nested(sqli),None),('vendor_json_sqli','application/vnd.api+json; charset=utf-8',nested(sqli),None),('form_xss','application/x-www-form-urlencoded',form(xss),xss),('json_xss','application/json',nested(xss),None),('command','application/x-www-form-urlencoded',form('; cat /etc/passwd; '+marker),'; cat /etc/passwd; '+marker),('traversal','application/x-www-form-urlencoded',form('../../../../etc/passwd'),'../../../../etc/passwd'),('upload_xss',attack_type,attack,xss),('xml_sqli','application/xml','<x><term>'+sqli+'</term></x>',None)]:cases.append(row(name,ctype,body,403,term=term,upload=file_data if name=='upload_xss'else None))
 cases.extend([row('malformed_json','application/json','{"nested":'+marker,400),row('body_limit','application/x-www-form-urlencoded','term='+'a'*(129*1024),413),row('nonfile_limit','application/x-www-form-urlencoded','term='+'a'*(65*1024),413),row('depth_limit','application/json','{"a":'*65+'0'+'}'*65,400),row('depth_limit_array','application/json','['*65+'0'+']'*65,400),row('argument_limit','application/x-www-form-urlencoded',urllib.parse.urlencode({'field_%03d'%i:'ordinary'for i in range(257)}),400),row('encoded_body','application/json',nested('ordinary'),415,encoding='gzip')])
 assert len(cases)==28 and len({c['name']for c in cases})==28
 return cases
