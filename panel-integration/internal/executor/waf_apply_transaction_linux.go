//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func (s *Service) verifyWAFBodyEngine(cfg core.WAFConfig) error {
	if cfg.Body == nil {
		return nil
	}
	for _, site := range cfg.Body.Sites {
		if _, on := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); on {
			if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
				return errors.New("请求体引擎仅可在真实受管环境启用，不能把模拟命令当成原生验收")
			}
			return VerifyWAFEngineBuild(cfg.Body.EngineJobID)
		}
	}
	return nil
}

func (s *Service) prepareWAFBodyTemporary(cfg core.WAFConfig) error {
	if cfg.Body == nil {
		return nil
	}
	for _, site := range cfg.Body.Sites {
		if _, on := core.WAFEffectiveBodyPolicy(cfg, site.SiteID); !on {
			continue
		}
		if err := s.prepareWAFBodyLog(); err != nil {
			return err
		}
		account, err := user.Lookup("www-data")
		if err != nil {
			return err
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil || uid == 0 {
			return errors.New("Nginx 请求体缓存账户无效")
		}
		gid, err := strconv.Atoi(account.Gid)
		if err != nil {
			return err
		}
		base := s.systemPath("/var/cache/panel-waf-body")
		if err := s.wafOwnedDirectory(base, true); err != nil {
			return err
		}
		if err := os.Chown(base, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(base, 0750); err != nil {
			return err
		}
		// The master parses config as root. Only the www-data worker may use
		// this site's private temporary directory; website/PHP accounts cannot
		// read it. Never take ownership of an existing foreign directory.
		path := filepath.Join(base, site.SiteID)
		if err := os.Mkdir(path, 0700); err == nil {
			if err := os.Chown(path, uid, gid); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
		st, err := os.Lstat(path)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 {
			return errors.New("网站请求体缓存目录类型或权限异常")
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(uid) || stat.Gid != uint32(gid) {
			return errors.New("网站请求体缓存目录归属异常")
		}
	}
	return nil
}

func (s *Service) recoverWAFBeforeMutation(ctx context.Context, nginx string) error {
	restored, err := s.recoverWAFTransaction()
	if err != nil || !restored {
		return err
	}
	if _, err := s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return err
	}
	generation, err := s.captureWAFReloadGeneration(ctx, nginx)
	if err != nil {
		return err
	}
	if _, err = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		return err
	}
	return waitWAFReloadGeneration(ctx, generation)
}

func (s *Service) applyWAFTransaction(ctx context.Context, cfg core.WAFConfig, uninstall bool, nginx string, add func(string)) error {
	return s.applyWAFTransactionChecked(ctx, cfg, uninstall, nginx, add, nil)
}

func (s *Service) applyWAFTransactionChecked(ctx context.Context, cfg core.WAFConfig, uninstall bool, nginx string, add func(string), legacy *softwareManifest) error {
	if !uninstall {
		if err := s.verifyWAFBodyEngine(cfg); err != nil {
			return err
		}
	}
	changes, err := s.planWAFConfiguration(cfg, uninstall)
	if err != nil {
		return err
	}
	if legacy != nil {
		if err := s.verifyWAFLegacyUpgradePlan(*legacy, cfg, changes); err != nil {
			return err
		}
	}
	backupPath, err := s.backupWAFConfiguration()
	if err != nil {
		return err
	}
	if !uninstall {
		if err := s.prepareWAFBodyTemporary(cfg); err != nil {
			return err
		}
	}
	tx, err := s.startWAFTransaction(changes)
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_, restoreErr := s.recoverWAFTransaction()
		if restoreErr == nil {
			bounded, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, restoreErr = s.Config.Run(bounded, nginx, "-t", "-c", s.Config.NginxConf)
			if restoreErr == nil {
				var generation *wafReloadGeneration
				generation, restoreErr = s.captureWAFReloadGeneration(bounded, nginx)
				if restoreErr == nil {
					_, restoreErr = s.Config.Run(bounded, "/usr/bin/systemctl", "reload", "nginx")
				}
				if restoreErr == nil {
					restoreErr = waitWAFReloadGeneration(bounded, generation)
				}
			}
			cancel()
		}
		return fmt.Errorf("WAF 配置未确认生效，已恢复=%v；恢复证据保留: %w", restoreErr == nil, errors.Join(cause, restoreErr))
	}
	manifestPath := s.softwareManifestPath("nginx-waf")
	for _, c := range changes {
		if c.Path == manifestPath {
			continue
		}
		if err := ctx.Err(); err != nil {
			return rollback(err)
		}
		match, err := s.wafCurrentMatches(c, false)
		if err != nil || !match {
			return rollback(errors.New("WAF 配置在应用过程中被外部修改"))
		}
		if err := wafApplyChange(c, true); err != nil {
			return rollback(err)
		}
	}
	if _, err := s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return rollback(err)
	}
	generation, err := s.captureWAFReloadGeneration(ctx, nginx)
	if err != nil {
		return rollback(err)
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); err != nil {
		return rollback(err)
	}
	if !uninstall {
		if err := s.verifyWAFReloadGeneration(ctx, cfg, nginx, core.WAFVersion, generation); err != nil {
			return rollback(err)
		}
	} else if s.Config.SystemRoot == "/" && s.Config.SitesDir == "/srv/panel/sites" {
		if err := s.wafNginxRunning(ctx, nginx); err != nil {
			return rollback(err)
		}
		if err := waitWAFReloadGeneration(ctx, generation); err != nil {
			return rollback(err)
		}
	}
	for _, c := range changes {
		if c.Path == manifestPath {
			match, err := s.wafCurrentMatches(c, false)
			if err != nil || !match {
				return rollback(errors.New("WAF 清单被外部修改"))
			}
			if err := wafApplyChange(c, true); err != nil {
				return rollback(err)
			}
		}
		match, err := s.wafCurrentMatches(c, true)
		if err != nil || !match {
			return rollback(errors.New("WAF 最终规则或清单字节未通过核对"))
		}
	}
	tx.State = "committed"
	if err := s.finishWAFTransaction(tx); err != nil {
		return fmt.Errorf("Nginx 已验证新版配置，但事务归档未完成；证据保留，请刷新核对: %w", err)
	}
	add("变更前配置已备份：" + backupPath)
	add("完整配置恢复事务已提交：" + tx.ID)
	if uninstall {
		add("移除云栈请求体模块加载、网站规则和软件清单；保留日志、程序、备份及空 include 插入点")
	} else {
		add("按每网站策略生成独立规则；请求体防护仅启用明确选中的网站")
	}
	add("通过实际 nginx -t、服务重载与规则指纹验证")
	add("旧工作进程已停止接收新连接；重载前已接收的长连接和请求继续使用原配置，未强制断开")
	return nil
}
