package importer

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUrlReturnsValidUrl(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl("https://example.com/api/%s/", "test", []RequestOptionsFunc{})
	require.NoError(err, "unexpected error")

	require.NotEmpty(result)

	parsedUrl, err := url.Parse(result)
	require.NoError(err)
	require.Equal("example.com", parsedUrl.Host)
	require.Equal("/api/test/", parsedUrl.Path)
	require.Equal("https", parsedUrl.Scheme)
}

func TestBuildUrlNoRejected(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl("https://example.com/api/%s/", "test", []RequestOptionsFunc{NoRejected()})
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()

	require.Contains(query, "noRejected", "Query parementer noRejected should be present")
}

func TestBuildUrlPubStart(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl(
		"https://example.com/api/%s/",
		"test",
		[]RequestOptionsFunc{PubStart(time.Date(2023, 8, 1, 0, 0, 0, 0, time.UTC))},
	)
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()
	pubStart := query.Get("pubStartDate")

	require.Equal("2023-08-01T00:00:00Z", pubStart)
}

func TestBuildUrlPubStartSetsPubEndIfMissing(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl(
		"https://example.com/api/%s/",
		"test",
		[]RequestOptionsFunc{PubStart(time.Date(2023, 8, 1, 0, 0, 0, 0, time.UTC))},
	)
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()
	pubEnd := query.Get("pubEndDate")

	require.Equal("2023-08-02T00:00:00Z", pubEnd)
}

func TestBuildUrlPubStartDoesNotOverwriteExistingPubEnd(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl(
		"https://example.com/api/%s/",
		"test",
		[]RequestOptionsFunc{
			PubEnd(time.Date(2023, 8, 7, 0, 0, 0, 0, time.UTC)),
			PubStart(time.Date(2023, 8, 1, 0, 0, 0, 0, time.UTC)),
		},
	)
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()
	pubEnd := query.Get("pubEndDate")

	require.Equal("2023-08-07T00:00:00Z", pubEnd)
}

func TestBuildUrlPubEnd(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl(
		"https://example.com/api/%s/",
		"test",
		[]RequestOptionsFunc{PubEnd(time.Date(2023, 8, 2, 0, 0, 0, 0, time.UTC))},
	)
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()
	pubStart := query.Get("pubEndDate")

	require.Equal("2023-08-02T00:00:00Z", pubStart)
}

func TestBuildUrlPubEndSetsPubEndIfMissing(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl(
		"https://example.com/api/%s/",
		"test",
		[]RequestOptionsFunc{PubEnd(time.Date(2023, 8, 2, 0, 0, 0, 0, time.UTC))},
	)
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()
	pubEnd := query.Get("pubStartDate")

	require.Equal("2023-08-01T00:00:00Z", pubEnd)
}

func TestBuildUrlPubEndDoesNotOverwriteExistingPubEnd(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl(
		"https://example.com/api/%s/",
		"test",
		[]RequestOptionsFunc{
			PubStart(time.Date(2023, 8, 1, 0, 0, 0, 0, time.UTC)),
			PubEnd(time.Date(2023, 8, 5, 0, 0, 0, 0, time.UTC)),
		},
	)
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()
	pubEnd := query.Get("pubStartDate")

	require.Equal("2023-08-01T00:00:00Z", pubEnd)
}

func TestBuildUrlStartIndex(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl("https://example.com/api/%s/", "test", []RequestOptionsFunc{StartIndex(1)})
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()

	startIndex := query.Get("startIndex")

	require.Equal("1", startIndex)
}

func TestBuildUrlResultsPerPage(t *testing.T) {
	require := require.New(t)

	result, err := buildUrl("https://example.com/api/%s/", "test", []RequestOptionsFunc{ResultsPerPage(200)})
	require.NoError(err)

	url, err := url.Parse(result)
	require.NoError(err)
	query := url.Query()

	resultsPerPage := query.Get("resultsPerPage")

	require.Equal("200", resultsPerPage)
}

func TestCPEUri(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	uri := "cpe:2.3:a:b:c:d:e:f:g:h:i:j:k"
	cpeuri, err := NewCPEUri(uri)

	require.NoError(err)

	assert.Equal("a", cpeuri.Part, "part")
	assert.Equal("b", cpeuri.Vendor, "vendor")
	assert.Equal("c", cpeuri.Product, "product")
	assert.Equal("d", cpeuri.Version, "version")
	assert.Equal("e", cpeuri.Update, "update")
	assert.Equal("f", cpeuri.Edition, "edition")
	assert.Equal("g", cpeuri.Language, "language")
	assert.Equal("h", cpeuri.SwEdition, "sw_edition")
	assert.Equal("i", cpeuri.TargetSw, "target_sw")
	assert.Equal("j", cpeuri.TargetHw, "target_hw")
	assert.Equal("k", cpeuri.Other, "other")
}

func TestCPEUriUnmarshalJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cpeuri := CPE23Uri{}

	data := []byte(`"cpe:2.3:a:b:c:d:e:f:g:h:i:j:k"`)
	err := json.Unmarshal(data, &cpeuri)

	require.NoError(err)

	assert.Equal("a", cpeuri.Part, "part")
	assert.Equal("b", cpeuri.Vendor, "vendor")
	assert.Equal("c", cpeuri.Product, "product")
	assert.Equal("d", cpeuri.Version, "version")
	assert.Equal("e", cpeuri.Update, "update")
	assert.Equal("f", cpeuri.Edition, "edition")
	assert.Equal("g", cpeuri.Language, "language")
	assert.Equal("h", cpeuri.SwEdition, "sw_edition")
	assert.Equal("i", cpeuri.TargetSw, "target_sw")
	assert.Equal("j", cpeuri.TargetHw, "target_hw")
	assert.Equal("k", cpeuri.Other, "other")
}
