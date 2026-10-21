package executor

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"path/filepath"
)

const analyticsHTMLProgramSHA = "8e7fa5f7b02576de78f893037f02fd1d493241dd043a543fe98b8113a7b220f9"
const analyticsHTMLProgramRoot = "/opt/panel/app-modules/website-analytics/html-programs"

//go:embed analytics_html_vendor/analytics-html.js analytics_html_vendor/source.json analytics_html_vendor/parse5-LICENSE analytics_html_vendor/entities-LICENSE
var analyticsHTMLAssets embed.FS

func analyticsHTMLProgramPath() string {
	return filepath.Join(analyticsHTMLProgramRoot, analyticsHTMLProgramSHA+".js")
}

func verifiedAnalyticsHTMLProgram() ([]byte, error) {
	data, err := analyticsHTMLAssets.ReadFile("analytics_html_vendor/analytics-html.js")
	if err != nil {
		return nil, err
	}
	sha := sha256.Sum256(data)
	if hex.EncodeToString(sha[:]) != analyticsHTMLProgramSHA {
		return nil, errors.New("HTML 自动接入程序摘要不在固定发布清单中")
	}
	return data, nil
}
