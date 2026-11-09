package appcatalog

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"local/panel/internal/geodata"
)

// A signed asset supplies ONLY a two-letter code, count, hash and length. Its
// URL is built from the trusted registry origin and immutable manifest digest;
// no manifest/request URL, caller cookie, redirect or resume is accepted.
func (c *Client) DownloadCountryAssetFile(ctx context.Context, a CountryDataAuthority, code string, destination *os.File) error {
	bad := errors.New("country data transfer not independently verified; no installation accepted")
	if ctx == nil || c == nil || c.HTTP == nil || destination == nil || !a.verified || a.keySHA != hashRuleFeedFile(c.PublicKey) {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	selected, err := a.data.Select([]string{code})
	if err != nil {
		return err
	}
	asset := selected[0]
	initial, err := destination.Stat()
	if err != nil || !initial.Mode().IsRegular() || initial.Mode().Perm() != 0600 || initial.Size() != 0 {
		return bad
	}
	position, err := destination.Seek(0, io.SeekCurrent)
	if err != nil || position != 0 {
		return bad
	}
	m := a.data.Manifest()
	url := c.BaseURL + "/data/geodata/" + geodata.CountryChannel + "/releases/" + m.Release + "-r" + strconv.Itoa(m.Revision) + "-" + a.data.SHA256() + "/" + code + ".cidr"
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, url, nil)
	if err != nil {
		return bad
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Accept", "text/plain")
	client := *c.HTTP
	client.Timeout = 60 * time.Second
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return bad
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Uncompressed || len(response.Header.Values("Content-Encoding")) > 1 || len(response.Header.Values("Content-Length")) > 1 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" || response.ContentLength >= 0 && response.ContentLength != asset.Bytes {
		return bad
	}
	buffer := bufio.NewWriterSize(destination, 64<<10)
	if _, err := geodata.VerifyCountryAsset(bounded, a.data, code, io.TeeReader(io.LimitReader(response.Body, asset.Bytes+1), buffer)); err != nil {
		return err
	}
	if err := buffer.Flush(); err != nil {
		return err
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	final, err := destination.Stat()
	if err != nil || !final.Mode().IsRegular() || !os.SameFile(initial, final) || final.Mode().Perm() != 0600 || final.Size() != asset.Bytes {
		return bad
	}
	return bounded.Err()
}
