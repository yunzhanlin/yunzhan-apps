//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A body-only ready record, another architecture's DSO, or a new file copied
// into an old immutable release never confers CC authority.
func verifyApacheCCBuildContext(ctx context.Context, id string) error {
	record, err := readApacheBodyBuildRecord(id)
	if err != nil {
		return err
	}
	if !apacheCCFormatHasModule(record.Format) || record.CCEngine != apacheCCEngineForFormat(record.Format) || !record.CCABIValidated {
		return errors.New("所选 Apache 引擎没有经独立核验的原生 CC 模块；构建包含 CC 的新引擎后再明确选择")
	}
	if err := apacheBodyRecordContract(record); err != nil {
		return err
	}
	return verifyApacheBodyRetainedBytes(ctx, record)
}

func probeApacheCCModule(ctx context.Context, s *Service, apache, prefix, build string) error {
	conf := filepath.Join(build, "cc-abi-probe.conf")
	var out strings.Builder
	fmt.Fprintf(&out, "ServerRoot %s\nServerName 127.0.0.1\nPidFile %s\nListen 127.0.0.1:19080\nErrorLog %s\n", strconv.Quote(apache), strconv.Quote(filepath.Join(build, "cc-abi-probe.pid")), strconv.Quote(filepath.Join(build, "cc-abi-probe.error.log")))
	for _, name := range []string{"mpm_event", "unixd", "authz_core", "log_config"} {
		module := filepath.Join(apache, "modules/mod_"+name+".so")
		if err := ownedRuntimePath(module, false); err != nil {
			return err
		}
		fmt.Fprintf(&out, "LoadModule %s_module %s\n", name, strconv.Quote(module))
	}
	fmt.Fprintf(&out, "LoadModule yunzhan_cc_module %s\n<VirtualHost 127.0.0.1:19080>\nServerName cc-abi.invalid\nYunzhanCCSite %s block 5 1 %s\nYunzhanCCRule %s 2f6c6f67696e exact 1 1\n</VirtualHost>\n", strconv.Quote(filepath.Join(prefix, "apache/mod_yunzhan_cc.so")), strings.Repeat("0", 32), strings.Repeat("0", 64), strings.Repeat("1", 32))
	if err := atomicWrite(conf, []byte(out.String()), 0600); err != nil {
		return err
	}
	_, err := s.moduleCommand(ctx, 30*time.Second, filepath.Join(apache, "bin/httpd"), "-t", "-f", conf)
	return err
}
