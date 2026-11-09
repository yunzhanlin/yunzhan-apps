//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Fixed, PHP 5.2-compatible programs; uploaded files are never included/evaluated.
const legacyInventoryPHP = `
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
`
const legacyWritePHP = `
$v=json_decode(stream_get_contents(STDIN),true);if(!is_array($v))exit(20);
$rel=$v['path'];if(!is_string($rel)||strlen($rel)>2048||strpos($rel,chr(0))!==false)exit(21);
$parts=explode('/',$rel);$root='/var/www/html';$dir=$root;
foreach($parts as $i=>$n){if($n===''||$n==='.'||$n==='..')exit(22);if($i===count($parts)-1)break;
 $dir.='/'.$n;if(is_link($dir))exit(23);if(!is_dir($dir)&&!mkdir($dir,0755))exit(24);
 if(strpos(realpath($dir),$root.'/')!==0)exit(25);
}
$target=$root.'/'.$rel;if(is_link($target)||(file_exists($target)&&!is_file($target)))exit(26);
$cur=file_exists($target)?hash_file('sha256',$target):'';if($cur!==$v['expected'])exit(27);
$exists=file_exists($target);if($exists&&((fileperms($target)&0777)!==$v['expected_mode']||filesize($target)!==$v['expected_size']))exit(27);
$data=base64_decode($v['data'],true);if($data===false||strlen($data)>8388608||hash('sha256',$data)!==$v['sha256'])exit(28);
$tmp=tempnam($dir,'.cloudstack-');if(!$tmp)exit(29);
if(file_put_contents($tmp,$data)!==strlen($data)||!chmod($tmp,$v['mode']&0777)){@unlink($tmp);exit(30);}
clearstatcache();if(is_link($target)||file_exists($target)!==$exists||($exists&&(!is_file($target)||hash_file('sha256',$target)!==$cur||(fileperms($target)&0777)!==$v['expected_mode']||filesize($target)!==$v['expected_size']))){@unlink($tmp);exit(27);}
if($exists){$ok=rename($tmp,$target);}else{$ok=link($tmp,$target);@unlink($tmp);}
if(!$ok){@unlink($tmp);exit(30);}
echo json_encode(array('sha256'=>hash_file('sha256',$target)));
`

func legacyExec(ctx context.Context, container, script string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/docker", "exec", "-i", "--user", "1000:1000", container, "php", "-r", script)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Stdin = bytes.NewReader(input)
	out := &boundedBuffer{max: 2 << 20}
	stderr := &boundedBuffer{max: 2048}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if e := cmd.Run(); e != nil {
		return nil, errors.New("隔离 PHP 文件操作失败：" + e.Error())
	}
	if out.Len() >= 2<<20 {
		return nil, errors.New("隔离 PHP 文件清单超过上限")
	}
	return out.Bytes(), nil
}
func (s *Service) moduleSyncLegacy(ctx context.Context, in core.AppModuleInput, preview bool) (any, error) {
	// Preview remains read-only. An actual synchronization shares the existing
	// runtime/Compose mutation interlock with project/container updates.
	if !preview {
		bound, unlock, err := composeLock(ctx)
		if err != nil {
			return nil, err
		}
		defer unlock()
		ctx = bound
	}
	authority, e := openLegacySyncAuthority(dockerProjects, in.TargetProjectID)
	if e != nil {
		return nil, e
	}
	defer authority.directory.Close()
	if e = authority.check(ctx, legacySyncDockerRead); e != nil {
		return nil, e
	}
	container := authority.container
	source, e := s.openFiles(in.SiteID)
	if e != nil {
		return nil, e
	}
	defer source.Close()
	a, partial, e := scanModuleFiles(ctx, source.public, in.Excludes, nil)
	if e != nil || partial {
		return nil, errors.New("来源扫描不完整")
	}
	if e = authority.check(ctx, legacySyncDockerRead); e != nil {
		return nil, e
	}
	raw, e := legacyExec(ctx, container, legacyInventoryPHP, nil)
	if e != nil {
		return nil, e
	}
	b := map[string]moduleFile{}
	if e = json.Unmarshal(raw, &b); e != nil {
		return nil, e
	}
	checkpoint := filepath.Join(s.moduleDir("files-sync"), in.SiteID+"-"+in.TargetProjectID+".json")
	old := map[string]moduleFile{}
	if err := moduleRead(checkpoint, &old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("同步检查点损坏，拒绝覆盖目标")
	}
	copies, conflicts := []string{}, []string{}
	for p, v := range a {
		if !fs.ValidPath(p) || strings.ContainsRune(p, 0) {
			return nil, errors.New("来源路径无效")
		}
		cur, exists := b[p]
		if exists && cur == v {
			continue
		}
		prev, tracked := old[p]
		factory := p == "index.php" && cur.SHA == core.Hash(core.LegacyPHPPlaceholder)
		if exists && !factory && (!tracked || cur != prev) {
			conflicts = append(conflicts, p)
			continue
		}
		copies = append(copies, p)
	}
	sort.Strings(copies)
	sort.Strings(conflicts)
	if !preview {
		for _, p := range copies {
			data, err := readModuleFile(source.public, p)
			if err != nil {
				return nil, err
			}
			if core.Hash(string(data)) != a[p].SHA {
				return nil, errors.New("同步时来源改变")
			}
			payload, _ := json.Marshal(map[string]any{"path": p, "data": base64.StdEncoding.EncodeToString(data), "expected": b[p].SHA, "expected_mode": b[p].Mode, "expected_size": b[p].Size, "mode": a[p].Mode, "sha256": a[p].SHA})
			e = withDockerMutation(ctx, func(bound context.Context) error {
				if err := authority.check(bound, legacySyncDockerRead); err != nil {
					return err
				}
				result, err := legacyExec(bound, container, legacyWritePHP, payload)
				if err != nil {
					return err
				}
				return legacySyncWriteReceipt(result, a[p].SHA)
			})
			if e != nil {
				return nil, e
			}
			old[p] = a[p]
			if e = moduleWrite(checkpoint, old); e != nil {
				return nil, e
			}
		}
		if e = authority.check(ctx, legacySyncDockerRead); e != nil {
			return nil, e
		}
		if e = moduleWrite(checkpoint, old); e != nil {
			return nil, e
		}
	}
	if e = authority.check(ctx, legacySyncDockerRead); e != nil {
		return nil, e
	}
	result := syncReport(preview, copies, conflicts, filepath.Base(checkpoint))
	result["target_project_id"] = in.TargetProjectID
	return result, nil
}

func legacySyncWriteReceipt(raw []byte, expected string) error {
	if len(raw) == 0 || len(raw) > 256 || len(expected) != 64 || !dockerObjectPattern.MatchString(expected) {
		return errLegacySyncAuthority
	}
	f, err := dockerPullJSONObject(raw)
	if err != nil || len(f) != 1 || memcachedDaemonJSON(raw) != nil {
		return errLegacySyncAuthority
	}
	var digest string
	if json.Unmarshal(f["sha256"], &digest) != nil || digest != expected {
		return errLegacySyncAuthority
	}
	return nil
}
