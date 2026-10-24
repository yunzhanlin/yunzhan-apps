package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

const statisticsNginxLegacyFormat = `{"time":"$time_iso8601","remote":"$remote_addr","method":"$request_method","path":"$panel_log_path","status":$status,"bytes":$body_bytes_sent,"seconds":$request_time,"agent":"$http_user_agent","referer":"$panel_log_referer"}`
const statisticsNginxRequestFormat = `{"request_id":"$request_id","time":"$time_iso8601","remote":"$remote_addr","method":"$request_method","path":"$panel_log_path","status":$status,"bytes":$body_bytes_sent,"seconds":$request_time,"agent":"$http_user_agent","referer":"$panel_log_referer"}`
const statisticsNginxPathMap = `map $request_uri $panel_log_path { ~^(?<panel_original_path>[^?]*) $panel_original_path; default $uri; }`
const statisticsNginxRefererMap = `map $http_referer $panel_log_referer { ~^(?<panel_referer_base>[^?]*) $panel_referer_base; default ''; }`

type statisticsNginxToken struct {
	value      string
	start, end int
	quoted     bool
}

var errStatisticsNginxCustom = errors.New("受管网站日志格式或隐私映射无法核对；未改写自定义 Nginx 配置")

// Only token spans of the known managed log_format are replaceable. Comments,
// strings and nested blocks cannot impersonate a top-level HTTP directive.
func statisticsNginxTokens(source []byte) ([]statisticsNginxToken, error) {
	if len(source) == 0 || len(source) > 1<<20 || bytes.IndexByte(source, 0) >= 0 {
		return nil, errStatisticsNginxCustom
	}
	out := []statisticsNginxToken{}
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
	for at := 0; at < len(source); {
		if space(source[at]) {
			at++
			continue
		}
		if source[at] == '#' {
			for at < len(source) && source[at] != '\n' {
				at++
			}
			continue
		}
		start := at
		c := source[at]
		if c == '{' || c == '}' || c == ';' {
			at++
			out = append(out, statisticsNginxToken{value: string(c), start: start, end: at})
		} else if c == '\'' || c == '"' {
			quote := c
			at++
			value := []byte{}
			closed := false
			for at < len(source) {
				c = source[at]
				at++
				if c == quote {
					closed = true
					break
				}
				if c == '\\' {
					if at >= len(source) {
						return nil, errStatisticsNginxCustom
					}
					c = source[at]
					at++
				}
				value = append(value, c)
			}
			if !closed {
				return nil, errStatisticsNginxCustom
			}
			out = append(out, statisticsNginxToken{value: string(value), start: start, end: at, quoted: true})
		} else {
			for at < len(source) {
				c = source[at]
				if space(c) || c == '#' || c == '{' || c == '}' || c == ';' {
					break
				}
				if c == '\'' || c == '"' {
					return nil, errStatisticsNginxCustom
				}
				if c == '$' && at+1 < len(source) && source[at+1] == '{' {
					end := bytes.IndexByte(source[at+2:], '}')
					if end < 0 {
						return nil, errStatisticsNginxCustom
					}
					at += end + 3
					continue
				}
				if c == '\\' {
					if at+1 >= len(source) {
						return nil, errStatisticsNginxCustom
					}
					at += 2
				} else {
					at++
				}
			}
			if at == start {
				return nil, errStatisticsNginxCustom
			}
			out = append(out, statisticsNginxToken{value: string(source[start:at]), start: start, end: at})
		}
		if len(out) > 65536 {
			return nil, errStatisticsNginxCustom
		}
	}
	return out, nil
}
func statisticsNginxTokenValues(tokens []statisticsNginxToken) string {
	values := make([]string, len(tokens))
	for i, t := range tokens {
		values[i] = t.value
	}
	raw, _ := json.Marshal(values)
	return string(raw)
}
func statisticsRequestIDNginxConfig(source []byte) ([]byte, bool, error) {
	tokens, err := statisticsNginxTokens(source)
	if err != nil {
		return nil, false, err
	}
	pathTokens, _ := statisticsNginxTokens([]byte(statisticsNginxPathMap))
	refererTokens, _ := statisticsNginxTokens([]byte(statisticsNginxRefererMap))
	type block struct {
		name  string
		start int
	}
	stack := []block{}
	pending := []statisticsNginxToken{}
	pendingStart := 0
	formats := []statisticsNginxToken{}
	httpCount, pathCount, refererCount := 0, 0, 0
	for i, t := range tokens {
		if !t.quoted && t.value == "{" {
			if len(pending) == 0 {
				return nil, false, errStatisticsNginxCustom
			}
			if len(stack) == 0 && pending[0].value == "http" {
				if len(pending) != 1 || pending[0].quoted {
					return nil, false, errStatisticsNginxCustom
				}
				httpCount++
			}
			stack = append(stack, block{name: pending[0].value, start: pendingStart})
			pending = nil
			continue
		}
		if !t.quoted && t.value == "}" {
			if len(stack) == 0 || len(pending) != 0 {
				return nil, false, errStatisticsNginxCustom
			}
			closing := stack[len(stack)-1]
			if len(stack) == 2 && stack[0].name == "http" && closing.name == "map" {
				body := tokens[closing.start : i+1]
				if len(body) > 3 && body[2].value == "$panel_log_path" {
					pathCount++
					if statisticsNginxTokenValues(body) != statisticsNginxTokenValues(pathTokens) {
						return nil, false, errStatisticsNginxCustom
					}
				}
				if len(body) > 3 && body[2].value == "$panel_log_referer" {
					refererCount++
					if statisticsNginxTokenValues(body) != statisticsNginxTokenValues(refererTokens) {
						return nil, false, errStatisticsNginxCustom
					}
				}
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if !t.quoted && t.value == ";" {
			if len(pending) == 0 {
				return nil, false, errStatisticsNginxCustom
			}
			if pending[0].value == "log_format" && len(pending) > 1 && pending[1].value == "panel_site" {
				if len(stack) != 1 || stack[0].name != "http" || len(pending) != 4 || pending[0].quoted || pending[2].value != "escape=json" || !pending[3].quoted {
					return nil, false, errStatisticsNginxCustom
				}
				formats = append(formats, pending[3])
			}
			pending = nil
			continue
		}
		if len(pending) == 0 {
			pendingStart = i
		}
		pending = append(pending, t)
	}
	if len(pending) != 0 || len(stack) != 0 || httpCount != 1 || len(formats) != 1 || pathCount != 1 || refererCount != 1 {
		return nil, false, errStatisticsNginxCustom
	}
	format := formats[0]
	if format.value != statisticsNginxLegacyFormat && format.value != statisticsNginxRequestFormat {
		return nil, false, errStatisticsNginxCustom
	}
	if format.value == statisticsNginxRequestFormat {
		return append([]byte(nil), source...), false, nil
	}
	result := make([]byte, 0, len(source)+64)
	result = append(result, source[:format.start]...)
	result = append(result, '\'')
	result = append(result, statisticsNginxRequestFormat...)
	result = append(result, '\'')
	result = append(result, source[format.end:]...)
	if strings.Count(string(result), "'"+statisticsNginxRequestFormat+"'") < 1 {
		return nil, false, errStatisticsNginxCustom
	}
	return result, true, nil
}
