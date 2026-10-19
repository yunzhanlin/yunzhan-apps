package executor

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
)

const statisticsHealthBegin = "# panel statistics-log health begin\n"
const statisticsHealthEnd = "# panel statistics-log health end\n"

var statisticsHealthNonceOnlyPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var statisticsHealthNoncePattern = regexp.MustCompile(`yunzhan-statistics-log-v2:([a-f0-9]{32})`)
var statisticsHealthSocketPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

func statisticsHealthBlock(socket, nonce string) ([]byte, error) {
	if len(socket) > 100 || !statisticsHealthSocketPattern.MatchString(socket) || filepath.Clean(socket) != socket || !statisticsHealthNonceOnlyPattern.MatchString(nonce) {
		return nil, errors.New("统计生效探针位置或标识异常")
	}
	return []byte(fmt.Sprintf("%sserver { listen unix:%s; server_name panel-statistics-log-health; access_log off; location = / { default_type text/plain; return 200 'yunzhan-statistics-log-v2:%s'; } }\n%s", statisticsHealthBegin, socket, nonce, statisticsHealthEnd)), nil
}
func statisticsHealthConfigNonce(source []byte, socket string) (string, error) {
	begin, end := bytes.Index(source, []byte(statisticsHealthBegin)), bytes.Index(source, []byte(statisticsHealthEnd))
	if begin < 0 && end < 0 {
		return "", nil
	}
	if begin < 0 || end < begin || bytes.Count(source, []byte(statisticsHealthBegin)) != 1 || bytes.Count(source, []byte(statisticsHealthEnd)) != 1 {
		return "", errors.New("统计生效探针标记重复或不完整，未改写配置")
	}
	end += len(statisticsHealthEnd)
	candidate := source[begin:end]
	matches := statisticsHealthNoncePattern.FindAllSubmatch(candidate, 2)
	if len(matches) != 1 {
		return "", errors.New("统计生效探针身份无法核对")
	}
	nonce := string(matches[0][1])
	expected, err := statisticsHealthBlock(socket, nonce)
	if err != nil || !bytes.Equal(candidate, expected) {
		return "", errors.New("统计生效探针内容被外部修改，未覆盖")
	}
	// A marker inside a quoted directive, comment-only document, or nested
	// server is not the managed top-level HTTP listener.
	tokens, err := statisticsNginxTokens(source)
	if err != nil {
		return "", err
	}
	depth, inHTTP, found := 0, false, false
	pending := []statisticsNginxToken{}
	for _, token := range tokens {
		if token.start == begin+len(statisticsHealthBegin) {
			found = depth == 1 && inHTTP && len(pending) == 0 && !token.quoted && token.value == "server"
			break
		}
		if !token.quoted && token.value == "{" {
			if depth == 0 {
				inHTTP = len(pending) == 1 && pending[0].value == "http"
			}
			depth++
			pending = nil
		} else if !token.quoted && token.value == "}" {
			depth--
			if depth == 0 {
				inHTTP = false
			}
			pending = nil
		} else if !token.quoted && token.value == ";" {
			pending = nil
		} else {
			pending = append(pending, token)
		}
	}
	if !found || bytes.Count(source, []byte("listen unix:"+socket)) != 1 {
		return "", errors.New("统计探针不在唯一顶层 HTTP 监听位置，未覆盖配置")
	}
	return nonce, nil
}
func statisticsNginxHealthConfig(source []byte, socket, nonce string) ([]byte, error) {
	if len(source) > 1<<20 {
		return nil, errors.New("统计日志配置超过固定备份预算，未改写")
	}
	block, err := statisticsHealthBlock(socket, nonce)
	if err != nil {
		return nil, err
	}
	oldNonce, err := statisticsHealthConfigNonce(source, socket)
	if err != nil {
		return nil, err
	}
	cleaned := bytes.Clone(source)
	if oldNonce != "" {
		previous, _ := statisticsHealthBlock(socket, oldNonce)
		cleaned = bytes.Replace(cleaned, previous, nil, 1)
	}
	candidate, _, err := statisticsRequestIDNginxConfig(cleaned)
	if err != nil {
		return nil, err
	}
	tokens, err := statisticsNginxTokens(candidate)
	if err != nil {
		return nil, err
	}
	depth := 0
	inHTTP := false
	pending := []statisticsNginxToken{}
	closeAt := -1
	for _, t := range tokens {
		if !t.quoted && t.value == "{" {
			if depth == 0 {
				inHTTP = len(pending) == 1 && pending[0].value == "http"
			}
			depth++
			pending = nil
			continue
		}
		if !t.quoted && t.value == "}" {
			depth--
			if depth == 0 && inHTTP {
				closeAt = t.start
				inHTTP = false
			}
			pending = nil
			continue
		}
		if !t.quoted && t.value == ";" {
			pending = nil
			continue
		}
		pending = append(pending, t)
	}
	if closeAt < 0 {
		return nil, errStatisticsNginxCustom
	}
	out := append([]byte{}, candidate[:closeAt]...)
	out = append(out, block...)
	out = append(out, candidate[closeAt:]...)
	if len(out) > 1<<20 {
		return nil, errors.New("统计候选日志配置超过固定恢复预算，未开始事务")
	}
	if actual, err := statisticsHealthConfigNonce(out, socket); err != nil || actual != nonce {
		return nil, errors.New("统计探针配置生成不完整")
	}
	return out, nil
}
