package support

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseLogDate(t *testing.T) {
	data := "I0817 06:55:10.804384       1 shared_informer.go:270] caches populated"
	ts, err := parseTimeFromLogLine(data, "2021")
	assert.Nil(t, err)
	assert.Equal(t, ts.String(), "2021-08-17 06:55:10 +0000 UTC")
}

func TestTimestampFilter(t *testing.T) {
	result := timestampFilter("1w")
	t.Log(result.String())
}