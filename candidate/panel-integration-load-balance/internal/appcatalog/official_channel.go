package appcatalog

import "errors"

// Both channels belong to the same publisher and use the SAME compiled
// Ed25519 trust root. This is not a runtime URL/key/capability override.
// Ordinary builds stay stable. Only explicitly labelled candidate programme
// builds select the fixed candidate branch at build time.
const CandidateBaseURL = "https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/refs/heads/codex/app-candidate/candidate"

var officialCatalogChannel = "stable"

type officialGitHubSource struct {
	referenceURL, reference, prefix string
}

const githubCandidateRefURL = "https://api.github.com/repos/yunzhanlin/yunzhan-apps/git/ref/heads/codex/app-candidate"

func (c *Client) officialGitHubSource() (officialGitHubSource, bool) {
	if c == nil {
		return officialGitHubSource{}, false
	}
	switch c.BaseURL {
	case DefaultBaseURL:
		return officialGitHubSource{githubCatalogRefURL, "refs/heads/main", ""}, true
	case CandidateBaseURL:
		return officialGitHubSource{githubCandidateRefURL, "refs/heads/codex/app-candidate", "candidate/"}, true
	default:
		return officialGitHubSource{}, false
	}
}

func officialCatalogReferenceURL(raw string) bool {
	return raw == githubCatalogRefURL || raw == githubCandidateRefURL
}

func officialCatalogBaseURL(channel string) (string, error) {
	switch channel {
	case "stable":
		return DefaultBaseURL, nil
	case "candidate":
		return CandidateBaseURL, nil
	default:
		return "", errors.New("面板编译的官方应用渠道无效；拒绝回退或访问其他仓库")
	}
}

// Read-only programme provenance; neither environment nor browser input may
// choose a channel. An invalid linked value is never silently stable.
func OfficialCatalogChannel() string {
	if _, err := officialCatalogBaseURL(officialCatalogChannel); err != nil {
		return ""
	}
	return officialCatalogChannel
}

// Candidate-only until the normal installer, recovery and store acceptance
// qualify this exact implementation. A stable programme cannot borrow the
// candidate handler merely by receiving a signed newer version label.
func LoadBalanceStreamAvailable() bool {
	return panelFeatureAvailable(LoadBalanceStreamFeature)
}
