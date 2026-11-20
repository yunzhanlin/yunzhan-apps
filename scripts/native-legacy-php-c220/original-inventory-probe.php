
$root='/var/www/html'; $files=array(); $total=0;$entries=0;
function walk($dir,$prefix) { global $files,$total,$entries;
 $h=opendir($dir); if(!$h) exit(11);
 while(false!==($n=readdir($h))) { if($n==='.'||$n==='..')continue;
  if(++$entries>100000||strlen($prefix)>2048)exit(16);
  $p=$dir.'/'.$n;$rel=$prefix.$n;
  if(is_link($p))exit(12);
  if(is_dir($p)) {walk($p,$rel.'/');continue;}
  if(!is_file($p)||count($files)>=10000)exit(13);
  $size=filesize($p);$total+=$size;if($size>8388608||$total>268435456)exit(14);
  $hash=hash_file('sha256',$p);if(!$hash)exit(15);
  $files[$rel]=array('sha256'=>$hash,'size'=>$size,'mode'=>fileperms($p)&0777);
 } closedir($h);
}
walk($root,'');echo json_encode(count($files)?$files:new stdClass());
