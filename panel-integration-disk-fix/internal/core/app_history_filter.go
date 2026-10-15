package core

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

var historyResourceID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

func ValidateModuleHistoryInput(in AppModuleInput) error {
	if in.Limit < 0 || in.Limit > 100 || in.Offset < 0 || in.Offset > 100000 || len(in.Search) > 128 || !utf8.ValidString(in.Search) || in.SiteID != "" && !ValidID(in.SiteID) || in.ResourceID != "" && !historyResourceID.MatchString(in.ResourceID) {
		return errors.New("历史筛选参数无效；每页最多 100 条")
	}
	var start, end time.Time
	var err error
	if in.FromTime != "" {
		start, err = time.Parse(time.RFC3339, in.FromTime)
		if err != nil {
			return errors.New("开始时间无效")
		}
	}
	if in.ToTime != "" {
		end, err = time.Parse(time.RFC3339, in.ToTime)
		if err != nil {
			return errors.New("结束时间无效")
		}
	}
	if !start.IsZero() && !end.IsZero() && end.Before(start) {
		return errors.New("结束时间不能早于开始时间")
	}
	return nil
}

func ParseModuleHistoryQuery(values url.Values) (AppModuleInput, error) {
	in := AppModuleInput{SiteID: values.Get("site_id"), ResourceID: values.Get("resource_id"), FromTime: values.Get("from_time"), ToTime: values.Get("to_time"), Search: values.Get("search")}
	for key, entries := range values {
		if len(entries) != 1 {
			return in, errors.New("历史筛选参数不能重复")
		}
		switch key {
		case "site_id", "resource_id", "from_time", "to_time", "search":
		case "limit", "offset":
			n, err := strconv.Atoi(entries[0])
			if err != nil {
				return in, errors.New("分页参数无效")
			}
			if key == "limit" {
				in.Limit = n
			} else {
				in.Offset = n
			}
		default:
			return in, errors.New("历史筛选字段不受支持")
		}
	}
	return in, ValidateModuleHistoryInput(in)
}
