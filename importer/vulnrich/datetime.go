package vulnrich

import (
	"encoding/json"
	"time"
)

func UnmarshalJsonTimeFormat(b []byte, formats ...string) (t time.Time, err error) {
	var timeUnmarshalled string
	err = json.Unmarshal(b, &timeUnmarshalled)
	if err != nil {
		return time.Time{}, err
	}

	var parsed time.Time

	for _, format := range formats {
		parsed, err = time.Parse(format, timeUnmarshalled)
		if err == nil {
			break
		}
	}

	if err != nil {
		return time.Time{}, err
	}

	return parsed, nil
}

type DateTime struct {
	time.Time
}

var _ json.Unmarshaler = (*DateTime)(nil)

func (t *DateTime) UnmarshalJSON(b []byte) error {
	formats := []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z07:00",
	}
	tm, err := UnmarshalJsonTimeFormat(b, formats...)
	if err != nil {
		return err
	}

	*t = DateTime{tm}
	return nil
}

type Timestamp struct {
	time.Time
}

var _ json.Unmarshaler = (*Timestamp)(nil)

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	tm, err := UnmarshalJsonTimeFormat(b, "2006-01-02T15:04:05.999999Z07:00")
	if err != nil {
		return err
	}

	*t = Timestamp{tm}
	return nil
}
