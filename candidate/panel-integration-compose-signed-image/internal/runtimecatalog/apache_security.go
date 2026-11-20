package runtimecatalog

import "errors"

const ApacheCurrentID = "apache-2.4.71"
const ApacheLegacyID = "apache-2.4.68"

// This is a dated vendor-advisory admission check, not a claim that a bound
// website has switched executables. The legacy manifest remains recognizable.
func ApacheInstallAdmission(r Release) error {
	known, ok := Find(r.ID)
	if !ok || known != r || r.ID != ApacheCurrentID {
		return errors.New("此 Apache 版本不再允许新建或重建；请安装 2.4.71 安全更新。现有程序、站点与回退证据保留，安装不会自动切换网站")
	}
	return nil
}

type ApacheReleaseChoice struct {
	Release
	InstallationAllowed bool `json:"installation_allowed"`
}

func ApacheReleaseChoices() []ApacheReleaseChoice {
	rows := []ApacheReleaseChoice{}
	for _, r := range Apache {
		rows = append(rows, ApacheReleaseChoice{r, ApacheInstallAdmission(r) == nil})
	}
	return rows
}
