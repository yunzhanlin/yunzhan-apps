package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var errPHPSwitchConfig = errors.New("原网站配置无法安全定位 PHP 绑定与健康检查；保留原配置，请先核对网站")

type phpSwitchEdit struct {
	start, end int
	value      string
}
type phpSwitchDirective struct {
	tokens []statisticsNginxToken
	parent int
}
type phpSwitchBlock struct {
	head                      []statisticsNginxToken
	parent, open, first, last int
	directives                []int
}
type phpSwitchPlan struct{ original, candidate string }

// A PHP-only operation may change neither settings nor the selected host. Its
// old instance is explicit, so no process, socket, include or neighboring site
// can be adopted by a guessed PHP version.
func phpSwitchPair(previous, next core.Site) error {
	if !core.ValidID(previous.ID) || previous.ID != next.ID || previous.Domain != next.Domain || !core.ValidDomain(next.Domain) || previous.Slug != next.Slug {
		return errPHPSwitchConfig
	}
	for _, id := range []string{previous.PHPVersionID, next.PHPVersionID} {
		r, ok := runtimecatalog.Find(id)
		if !ok || r.Family != "php" {
			return errPHPSwitchConfig
		}
	}
	previous.Settings = core.DefaultSiteSettings(previous.Settings)
	next.Settings = core.DefaultSiteSettings(next.Settings)
	if previous.Settings.WebServer != "nginx" || next.Settings.WebServer != "nginx" || !reflect.DeepEqual(previous.Settings, next.Settings) ||
		core.ValidateSiteSettings(previous.Settings, previous.Domain, previous.PHPVersionID) != nil ||
		core.ValidateSiteSettings(next.Settings, next.Domain, next.PHPVersionID) != nil ||
		previous.RuntimeInstanceID != core.PHPInstanceID(previous) {
		return errPHPSwitchConfig
	}
	return nil
}

// The existing bounded lexer supplies real token spans. Quoted text, comments,
// an if body and an unrelated location can never masquerade as a server-level
// managed probe. Every other byte, including operator protection rules, stays.
func phpSwitchNginxConfig(source string, previous, next core.Site, enabled bool) (string, error) {
	if err := phpSwitchPair(previous, next); err != nil {
		return "", err
	}
	if len(source) == 0 || len(source) > 65536 || !strings.HasPrefix(source, "# managed by panel; site="+next.ID) {
		return "", errPHPSwitchConfig
	}
	if !enabled {
		if source != fmt.Sprintf("# managed by panel; site=%s; disabled\n", next.ID) {
			return "", errPHPSwitchConfig
		}
		return source, nil
	}
	if strings.Contains(strings.SplitN(source, "\n", 2)[0], "; disabled") {
		return "", errPHPSwitchConfig
	}
	marker := strings.SplitN(source, "\n", 2)[0]
	if marker != "# managed by panel; site="+next.ID && marker != "# managed by panel; site="+next.ID+"; panel-waf-disabled" {
		return "", errPHPSwitchConfig
	}
	tokens, err := statisticsNginxTokens([]byte(source))
	if err != nil {
		return "", errPHPSwitchConfig
	}
	blocks := []phpSwitchBlock{{parent: -1}}
	directives := []phpSwitchDirective{}
	stack := []int{0}
	pending := []statisticsNginxToken{}
	servers := []int{}
	for i, t := range tokens {
		switch {
		case !t.quoted && t.value == "{":
			if len(pending) == 0 {
				return "", errPHPSwitchConfig
			}
			parent := stack[len(stack)-1]
			b := phpSwitchBlock{head: append([]statisticsNginxToken{}, pending...), parent: parent, open: t.end, first: i - len(pending), last: -1}
			blocks = append(blocks, b)
			index := len(blocks) - 1
			if parent == 0 && pending[0].value == "server" {
				if len(pending) != 1 || pending[0].quoted {
					return "", errPHPSwitchConfig
				}
				servers = append(servers, index)
			}
			if len(stack) >= 64 {
				return "", errPHPSwitchConfig
			}
			stack = append(stack, index)
			pending = nil
		case !t.quoted && t.value == "}":
			if len(stack) == 1 || len(pending) != 0 {
				return "", errPHPSwitchConfig
			}
			blocks[stack[len(stack)-1]].last = i + 1
			stack = stack[:len(stack)-1]
		case !t.quoted && t.value == ";":
			if len(pending) == 0 {
				return "", errPHPSwitchConfig
			}
			parent := stack[len(stack)-1]
			directives = append(directives, phpSwitchDirective{tokens: append([]statisticsNginxToken{}, pending...), parent: parent})
			blocks[parent].directives = append(blocks[parent].directives, len(directives)-1)
			pending = nil
		default:
			pending = append(pending, t)
		}
	}
	if len(stack) != 1 || len(pending) != 0 || len(servers) < 1 || len(servers) > 2 {
		return "", errPHPSwitchConfig
	}
	owner := func(index int) int {
		for index > 0 && blocks[index].parent > 0 {
			index = blocks[index].parent
		}
		return index
	}
	selected := map[int]bool{}
	for _, index := range servers {
		selected[index] = true
	}
	edits := []phpSwitchEdit{}
	oldSocket := "unix:/run/panel-php-" + core.PHPInstanceID(previous) + "/fpm.sock"
	newSocket := "unix:/run/panel-php-" + core.PHPInstanceID(next) + "/fpm.sock"
	passes := 0
	for _, d := range directives {
		t := d.tokens
		if t[0].value != "fastcgi_pass" {
			continue
		}
		if t[0].quoted {
			return "", errPHPSwitchConfig
		}
		if !selected[owner(d.parent)] || len(t) != 2 {
			return "", errPHPSwitchConfig
		}
		// A mixed or dynamic upstream cannot prove that the selected site's
		// PHP requests all moved to the requested release.
		if t[1].value != oldSocket {
			return "", errPHPSwitchConfig
		}
		replacement := newSocket
		if t[1].quoted {
			replacement = strconv.Quote(newSocket)
		}
		edits = append(edits, phpSwitchEdit{t[1].start, t[1].end, replacement})
		passes++
	}
	if passes > 16 || (core.DefaultSiteSettings(next.Settings).Mode == "files" && passes == 0) {
		return "", errPHPSwitchConfig
	}
	expectedNames := append([]string{next.Domain}, next.Settings.Domains...)
	sort.Strings(expectedNames)
	path := siteHealthPath(next)
	body := siteHealthBody(next)
	header := core.Hash(body)
	bodyPattern := regexp.MustCompile("^panel:" + regexp.QuoteMeta(next.ID) + "(?::[a-f0-9]{64})?$")
	for _, server := range servers {
		names := 0
		headers := []statisticsNginxToken{}
		health := -1
		for _, index := range blocks[server].directives {
			t := directives[index].tokens
			if t[0].value == "server_name" {
				if t[0].quoted {
					return "", errPHPSwitchConfig
				}
				actual := []string{}
				for _, name := range t[1:] {
					actual = append(actual, name.value)
				}
				sort.Strings(actual)
				if !reflect.DeepEqual(actual, expectedNames) {
					return "", errPHPSwitchConfig
				}
				names++
			}
		}
		if names != 1 {
			return "", errPHPSwitchConfig
		}
		for _, d := range directives {
			t := d.tokens
			if owner(d.parent) != server || t[0].value != "add_header" || len(t) < 2 || t[1].value != "X-Panel-Config" {
				continue
			}
			if t[0].quoted || d.parent != server || len(t) != 4 || t[3].value != "always" {
				return "", errPHPSwitchConfig
			}
			headers = append(headers, t[2])
		}
		for index, b := range blocks {
			if index == 0 || owner(index) != server || len(b.head) == 0 || b.head[0].value != "location" {
				continue
			}
			mentions := false
			for _, t := range b.head[1:] {
				if strings.Contains(t.value, path) {
					mentions = true
				}
			}
			if !mentions {
				continue
			}
			if b.head[0].quoted || b.parent != server || health != -1 || len(b.head) != 3 || b.head[1].value != "=" || b.head[2].value != path {
				return "", errPHPSwitchConfig
			}
			health = index
		}
		if health < 0 {
			if len(headers) != 0 {
				return "", errPHPSwitchConfig
			}
			text := fmt.Sprintf("\n  location = %s { default_type text/plain; access_log off; return 200 %s; }\n  add_header X-Panel-Config %s always;\n", path, strconv.Quote(body), strconv.Quote(header))
			edits = append(edits, phpSwitchEdit{blocks[server].open, blocks[server].open, text})
			continue
		}
		h := blocks[health]
		if len(headers) != 1 || len(h.directives) != 3 {
			return "", errPHPSwitchConfig
		}
		count := map[string]int{}
		var oldBody statisticsNginxToken
		for _, index := range h.directives {
			t := directives[index].tokens
			if t[0].quoted {
				return "", errPHPSwitchConfig
			}
			count[t[0].value]++
			switch t[0].value {
			case "default_type":
				if len(t) != 2 || t[1].value != "text/plain" {
					return "", errPHPSwitchConfig
				}
			case "access_log":
				if len(t) != 2 || t[1].value != "off" {
					return "", errPHPSwitchConfig
				}
			case "return":
				if len(t) != 3 || t[1].value != "200" || !bodyPattern.MatchString(t[2].value) {
					return "", errPHPSwitchConfig
				}
				oldBody = t[2]
			default:
				return "", errPHPSwitchConfig
			}
		}
		for _, b := range blocks {
			if b.parent == health {
				return "", errPHPSwitchConfig
			}
		}
		if count["default_type"] != 1 || count["access_log"] != 1 || count["return"] != 1 || headers[0].value != core.Hash(oldBody.value) {
			return "", errPHPSwitchConfig
		}
		edits = append(edits, phpSwitchEdit{oldBody.start, oldBody.end, strconv.Quote(body)}, phpSwitchEdit{headers[0].start, headers[0].end, strconv.Quote(header)})
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var output strings.Builder
	end := 0
	for _, e := range edits {
		if e.start < end || e.end < e.start || e.end > len(source) {
			return "", errPHPSwitchConfig
		}
		output.WriteString(source[end:e.start])
		output.WriteString(e.value)
		end = e.end
	}
	output.WriteString(source[end:])
	if output.Len() > 65536 {
		return "", errPHPSwitchConfig
	}
	return output.String(), nil
}

func (s *Service) phpSwitchPreservationPlan(in core.ApplyRequest) (*phpSwitchPlan, error) {
	if !in.PreserveNginx {
		if in.PreviousSite != nil {
			return nil, errPHPSwitchConfig
		}
		return nil, nil
	}
	if in.PreviousSite == nil {
		return nil, errPHPSwitchConfig
	}
	previous := *in.PreviousSite
	if (previous.Status != "running" && previous.Status != "stopped") || in.Site.Status != previous.Status || in.Enabled != (previous.Status == "running") {
		return nil, errPHPSwitchConfig
	}
	if err := phpSwitchPair(previous, in.Site); err != nil {
		return nil, err
	}
	binding := filepath.Join(s.Config.SystemRoot, "etc/panel/php-sites/bindings", in.Site.ID+".json")
	if err := ordinary(binding, false); err == nil {
		raw, err := readPHPSwitchConfig(binding)
		if err != nil {
			return nil, errPHPSwitchConfig
		}
		var bound core.Site
		if json.Unmarshal(raw, &bound) != nil || bound.ID != previous.ID || bound.Domain != previous.Domain || bound.PHPVersionID != previous.PHPVersionID || bound.RuntimeInstanceID != previous.RuntimeInstanceID ||
			!reflect.DeepEqual(core.DefaultSiteSettings(bound.Settings), core.DefaultSiteSettings(previous.Settings)) {
			return nil, errPHPSwitchConfig
		}
	} else if !os.IsNotExist(err) {
		return nil, errPHPSwitchConfig
	}
	path := filepath.Join(s.Config.ConfDir, in.Site.ID+".conf")
	raw, err := readPHPSwitchConfig(path)
	if err != nil {
		return nil, errPHPSwitchConfig
	}
	candidate, err := phpSwitchNginxConfig(string(raw), previous, in.Site, in.Enabled)
	if err != nil {
		return nil, err
	}
	if in.ExpectedConfigSHA != "" && core.Hash(string(raw)) != in.ExpectedConfigSHA {
		return nil, errPHPSwitchConfig
	}
	return &phpSwitchPlan{original: string(raw), candidate: candidate}, nil
}

func readPHPSwitchConfig(path string) ([]byte, error) {
	if err := ordinary(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, errPHPSwitchConfig
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errPHPSwitchConfig
	}
	return raw, nil
}

func (s *Service) phpSwitchPreviewRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/php-preview", func(w http.ResponseWriter, r *http.Request) {
		var in core.ApplyRequest
		if !readJSON(w, r, &in) {
			return
		}
		site := in.Site
		if in.JobID != "" || len(in.Sites) != 0 || in.ExpectedConfigSHA != "" || !core.ValidID(site.ID) || !core.ValidDomain(site.Domain) || core.ValidateSite(site.Name, site.Slug) != nil || (site.Status != "running" && site.Status != "stopped") || in.Enabled != (site.Status == "running") {
			respond(w, 400, map[string]string{"error": "无效 PHP 切换预览"})
			return
		}
		in.Site.Settings = core.DefaultSiteSettings(site.Settings)
		site = in.Site
		if err := core.ValidateSiteSettings(site.Settings, site.Domain, site.PHPVersionID); err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := s.checkDomainOwners(site); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		plan, err := s.phpSwitchPreservationPlan(in)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		var current, candidate string
		if plan != nil {
			current, candidate = plan.original, plan.candidate
		} else {
			raw, e := readPHPSwitchConfig(filepath.Join(s.Config.ConfDir, site.ID+".conf"))
			if e != nil {
				respond(w, 409, map[string]string{"error": "站点配置尚未就绪"})
				return
			}
			current = string(raw)
			candidate, err = renderSiteConfig(site, filepath.Join(s.Config.SitesDir, site.ID, "public"))
			if err == nil && !in.Enabled {
				candidate = fmt.Sprintf("# managed by panel; site=%s; disabled\n", site.ID)
			} else if err == nil {
				candidate, err = s.preserveWAFBodySiteConfig(candidate, site.ID)
			}
			if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
		}
		respond(w, 200, map[string]any{"protocol": "php-vhost-switch-v1", "site_id": site.ID, "release_id": site.PHPVersionID, "revision": site.SettingsRevision, "current": current, "candidate": candidate, "config_sha": core.Hash(current), "preserves_custom_config": plan != nil})
	})
}
