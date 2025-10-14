package vulnrich

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/moznion/go-optional"
)

//go:generate go run github.com/abice/go-enum@v0.6.0 --marshal

type Stringable string

var _ json.Unmarshaler = (*Stringable)(nil)

func (s *Stringable) UnmarshalJSON(b []byte) error {
	var value string
	err := json.Unmarshal(b, &value)
	if err == nil {
		*s = Stringable(value)
		return nil
	}

	var valueInt int
	err = json.Unmarshal(b, &valueInt)
	if err != nil {
		return fmt.Errorf("stringable: cannot interpret version as string or int: %w", err)
	}

	*s = Stringable(strconv.Itoa(valueInt))
	return nil
}

func (s Stringable) String() string {
	return string(s)
}

type RejectedReasons struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type ProviderMetadata struct {
	DateUpdated DateTime `json:"dateUpdated"`
	OrgID       string   `json:"orgId"`
	ShortName   string   `json:"shortName"`
}

// ENUM(affected, unaffected, unknown)
type AffectedStatus string

type Version struct {
	LessThan        optional.Option[string]         `json:"lessThan"`
	LessThanOrEqual optional.Option[string]         `json:"lessThanOrEqual"`
	Status          optional.Option[AffectedStatus] `json:"status"`
	Version         Stringable                      `json:"version"`
	VersionType     optional.Option[string]         `json:"versionType"`
}

type Affected struct {
	CPEs          []string                        `json:"cpes"`
	Product       string                          `json:"product"`
	Vendor        string                          `json:"vendor"`
	DefaultStatus optional.Option[AffectedStatus] `json:"defaultStatus"`
	Versions      []Version                       `json:"versions"`
}

type CveDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CveDescriptions []CveDescription

func (c CveDescriptions) ForLang(lang string) optional.Option[CveDescription] {
	for _, descr := range c {
		if descr.Lang == lang {
			return optional.Some(descr)
		}
	}
	return optional.None[CveDescription]()
}

type ProblemTypeDescription struct {
	Description string `json:"description"`
	Lang        string `json:"lang"`
	Type        string `json:"type"`
	CweID       string `json:"cwiId"`
}

type ProblemType struct {
	Descriptions []ProblemTypeDescription `json:"descriptions"`
}

type Reference struct {
	URL  string   `json:"url"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags"`
}

type CVEDataMeta struct {
	Assigner string `json:"ASSIGNER"`
	ID       string `json:"ID"`
	State    string `json:"STATE"`
}

type DescriptionData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Description struct {
	DescriptionData []DescriptionData `json:"description_data"`
}

type ProblemDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type ProblemtypeData struct {
	Description []ProblemDescription `json:"description"`
}

type Problemtype struct {
	ProblemtypeData []ProblemtypeData `json:"problemtype_data"`
}

type Options struct {
	Exploitation    string `json:"Exploitation,omitempty"`
	Automatable     string `json:"Automatable,omitempty"`
	TechnicalImpact string `json:"Technical Impact,omitempty"`
}

type Content struct {
	Timestamp Timestamp `json:"timestamp"`
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	Version   string    `json:"version"`
	Options   []Options `json:"options"`
}

// ENUM(NONE, LOW, MEDIUM, HIGH, CRITICAL)
type CvssSeverity string

type CvssMetric struct {
	Version      string       `json:"version"`
	VectorString string       `json:"vectorString"`
	BaseScore    json.Number  `json:"baseScore"`
	BaseSeverity CvssSeverity `json:"baseSeverity"`
}

type Metric struct {
	Format  string                           `json:"format"`
	CvssV20 optional.Option[CvssMetric]      `json:"cvssV2_0"`
	CvssV30 optional.Option[CvssMetric]      `json:"cvssV3_0"`
	CvssV31 optional.Option[CvssMetric]      `json:"cvssV3_1"`
	CvssV40 optional.Option[CvssMetric]      `json:"cvssV4_0"`
	Other   optional.Option[json.RawMessage] `json:"other"`
}

type CveContainer struct {
	ProviderMetadata ProviderMetadata        `json:"providerMetadata"`
	DateAssigned     DateTime                `json:"dateAssigned"`
	DatePublic       DateTime                `json:"datePublic"`
	Title            optional.Option[string] `json:"title"`
	Descriptions     CveDescriptions         `json:"descriptions"`
	Affected         []Affected              `json:"affected"`
	ProblemTypes     []ProblemType           `json:"problemTypes"`
	References       []Reference             `json:"references"`
	Metrics          []Metric                `json:"metrics"`
	RejectedReasons  CveDescriptions         `json:"rejectedReasons"`
}

type Containers struct {
	Cna CveContainer   `json:"cna"`
	Adp []CveContainer `json:"adp"`
}

// ENUM(PUBLISHED, REJECTED)
type CveState string

type CveMetadata struct {
	DateUpdated       DateTime `json:"dateUpdated"`
	DateReserved      DateTime `json:"dateReserved"`
	DatePublished     DateTime `json:"datePublished"`
	DateRejected      DateTime `json:"dateRejected"`
	CveID             string   `json:"cveId"`
	AssignerOrgID     string   `json:"assignerOrgId"`
	AssignerShortName string   `json:"assignerShortName"`
	RequesterUserID   string   `json:"requesterUserId"`
	State             CveState `json:"state"`
	Serial            int      `json:"serial"`
}

type Record struct {
	CveMetadata CveMetadata `json:"cveMetadata"`
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
	Containers  Containers  `json:"containers"`
}

type Records []Record

func (r Records) Filter(predicate func(Record) bool) (result Records) {
	for _, record := range r {
		if predicate(record) {
			result = append(result, record)
		}
	}
	return
}
