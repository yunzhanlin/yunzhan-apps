package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const analyticsNJSHeaderSourceSHA = "3c27dd9c9c2be34d2f9f8f992136dddf79c804f13d43d2779b46d11fee4a7728"

// njs 1.0.1's QuickJS delete handler clears the Last-Modified header pointer,
// but leaves nginx's parsed timestamp behind. nginx's final header filter then
// recreates the deleted validator. Fix only deletion, preserving normal writes.
// This exact, reviewed change is applied to the fully pinned source before any
// non-privileged compiler receives it; no API/catalog input chooses a patch.
const analyticsNJSHeaderBefore = `    if (!(flags & NJS_HEADER_GET)) {
        r->headers_out.last_modified = h;
    }

    return ret;
}
`

const analyticsNJSHeaderAfter = `    if (!(flags & NJS_HEADER_GET)) {
        r->headers_out.last_modified = h;
        if (h == NULL) {
            r->headers_out.last_modified_time = -1;
        }
    }

    return ret;
}
`

func patchAnalyticsNJSHeaders(source []byte) ([]byte, error) {
	sha := sha256.Sum256(source)
	if hex.EncodeToString(sha[:]) != analyticsNJSHeaderSourceSHA || bytes.Count(source, []byte(analyticsNJSHeaderBefore)) != 1 {
		return nil, errors.New("QuickJS 缓存标识修复的原始源码或唯一目标不匹配，拒绝编译")
	}
	return bytes.Replace(source, []byte(analyticsNJSHeaderBefore), []byte(analyticsNJSHeaderAfter), 1), nil
}
