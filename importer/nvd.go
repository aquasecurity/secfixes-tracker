package importer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moznion/go-optional"
)

const NVDEndpoint = "https://services.nvd.nist.gov/rest/json/%s/2.0"

type NVDCVEResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID               string          `json:"id"`
	SourceIdentifier string          `json:"sourceIdentifier"`
	Published        string          `json:"published"`
	VulnStatus       string          `json:"vulnStatus"`
	Descriptions     Descriptions    `json:"descriptions"`
	Metrics          Metric          `json:"metrics"`
	Configurations   []Configuration `json:"configurations"`
	Weaknesses       []Weakness      `json:"weakness"`
	References       []Reference     `json:"references"`
}

type Descriptions []Description

func (d Descriptions) SelectLang(lang string) optional.Option[Description] {
	for _, description := range d {
		if description.Lang == lang {
			return optional.Some(description)
		}
	}
	return optional.None[Description]()
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CvssMetricsV31 []CvssMetricV31

func (c CvssMetricsV31) SelectByType(typ string) optional.Option[CvssMetricV31] {
	for _, metric := range c {
		if metric.Type == typ {
			return optional.Some(metric)
		}
	}
	return optional.None[CvssMetricV31]()
}

type Metric struct {
	CvssMetricV31 CvssMetricsV31 `json:"cvssMetricV31"`
}

type CvssMetricV31 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CvssData CvssData `json:"cvssData"`
}

type CvssData struct {
	Version               string      `json:"version"`
	VectorString          string      `json:"vectorString"`
	AttackVector          string      `json:"attackVector"`
	AttackComplexity      string      `json:"attackComplexity"`
	PrivilegeRequired     string      `json:"privilegeRequired"`
	UserInteraction       string      `json:"userInteraction"`
	Scope                 string      `json:"scope"`
	ConfidentialityImpact string      `json:"confidentialityImpact"`
	IntegrityImpact       string      `json:"integrityImpact"`
	AvailabilityImpact    string      `json:"availabilityImpact"`
	BaseScore             json.Number `json:"baseScore"`
	BaseSeverity          string      `json:"baseSeverity"`
}

type Configuration struct {
	Operator string `json:"operator"`
	Nodes    []Node `json:"nodes"`
}

type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type CPE23Uri struct {
	Uri       string
	Part      string
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SwEdition string
	TargetSw  string
	TargetHw  string
	Other     string
}

var _ json.Unmarshaler = (*CPE23Uri)(nil)

func (c *CPE23Uri) fromUri(uri string) error {
	c.Uri = uri

	if !strings.HasPrefix(uri, "cpe:2.3:") {
		return fmt.Errorf("invalid format, must start with 'cpe:2.3:', received: '%s;", uri)
	}
	parts := strings.Split(uri, ":")

	if len(parts) < 13 {
		return fmt.Errorf("invalid format, must have 13 components, found %d components", len(parts))
	}

	c.Part = unquote(parts[2])
	c.Vendor = unquote(parts[3])
	c.Product = unquote(parts[4])
	c.Version = unquote(parts[5])
	c.Update = unquote(parts[6])
	c.Edition = unquote(parts[7])
	c.Language = unquote(parts[8])
	c.SwEdition = unquote(parts[9])
	c.TargetSw = unquote(parts[10])
	c.TargetHw = unquote(parts[11])
	c.Other = unquote(parts[12])

	return nil
}

func NewCPEUri(uri string) (c CPE23Uri, err error) {
	err = c.fromUri(uri)
	return c, err
}

func (c *CPE23Uri) UnmarshalJSON(data []byte) error {
	var uri string
	err := json.Unmarshal(data, &uri)
	if err != nil {
		return err
	}

	if c == nil {
		c = &CPE23Uri{}
	}
	c.fromUri(uri)

	return nil
}

type CPEMatch struct {
	Vulnerable            bool                    `json:"vulnerable"`
	Criteria              CPE23Uri                `json:"criteria"`
	VersionStartExcluding optional.Option[string] `json:"versionStartExcluding"`
	VersionStartIncluding optional.Option[string] `json:"versionStartIncluding"`
	VersionEndExcluding   optional.Option[string] `json:"versionEndExcluding"`
	VersionEndIncluding   optional.Option[string] `json:"versionEndIncluding"`
	MatchCriteriaId       string                  `json:"matchCriteriaId"`
}

func (c CPEMatch) UsesVersionRanges() bool {
	if c.VersionStartExcluding.IsSome() {
		return true
	}
	if c.VersionStartIncluding.IsSome() {
		return true
	}
	if c.VersionEndExcluding.IsSome() {
		return true
	}
	if c.VersionEndIncluding.IsSome() {
		return true
	}
	return false
}

type Weakness struct {
	Source       string       `json:"source"`
	Type         string       `json:"type"`
	Descriptions Descriptions `json:"descriptions"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `jons:"tags"`
}

type APIv2 struct {
	once     sync.Once
	Endpoint string
}

func (a *APIv2) init() {
	a.once.Do(func() {
		if a.Endpoint == "" {
			a.Endpoint = NVDEndpoint
		}
	})
}

type RequestOptionsFunc func(url.Values) error

func NoRejected() RequestOptionsFunc {
	return func(q url.Values) error {
		q.Set("noRejected", "")
		return nil
	}
}

func StartIndex(index int) RequestOptionsFunc {
	return func(q url.Values) error {
		q.Set("startIndex", strconv.Itoa(index))
		return nil
	}
}

func ResultsPerPage(nr int) RequestOptionsFunc {
	return func(q url.Values) error {
		q.Set("resultsPerPage", strconv.Itoa(nr))
		return nil
	}
}

func PubStart(date time.Time) RequestOptionsFunc {
	return func(q url.Values) error {
		q.Set("pubStartDate", date.Format(time.RFC3339))
		if q.Get("pubEndDate") == "" {
			q.Set("pubEndDate", date.Add(24*time.Hour).Format(time.RFC3339))
		}
		return nil
	}
}

func PubEnd(date time.Time) RequestOptionsFunc {
	return func(q url.Values) error {
		q.Set("pubEndDate", date.Format(time.RFC3339))
		if q.Get("pubStartDate") == "" {
			q.Set("pubStartDate", date.Add(-24*time.Hour).Format(time.RFC3339))
		}
		return nil
	}
}

func buildUrl(endpoint, api string, options []RequestOptionsFunc) (string, error) {
	apiUrl, err := url.Parse(fmt.Sprintf(endpoint, api))
	if err != nil {
		return "", fmt.Errorf("failed to parse endpoint: %w", err)
	}

	query := url.Values{}
	for _, option := range options {
		err = option(query)
		if err != nil {
			return "", fmt.Errorf("failed to apply option: %w", err)
		}
	}

	apiUrl.RawQuery = query.Encode()
	return apiUrl.String(), nil
}

func (a *APIv2) GetCVEs(options ...RequestOptionsFunc) (*NVDCVEResponse, error) {
	a.init()

	requestUrl, err := buildUrl(a.Endpoint, "cves", options)
	if err != nil {
		return nil, fmt.Errorf("failed to build url: %w", err)
	}

	resp, err := http.Get(requestUrl)
	if err != nil {
		return nil, fmt.Errorf("failure in HTTP request: %w", err)
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	nvdResp := &NVDCVEResponse{}
	err = decoder.Decode(nvdResp)

	return nvdResp, err
}

func unquote(v string) string {
	var unquoted strings.Builder

	for _, r := range v {
		if r == '\\' {
			continue
		}
		unquoted.WriteRune(r)
	}

	return unquoted.String()
}
