package libprobe_test

import (
	"testing"
	"time"

	"github.com/blho/libprobe"

	"github.com/stretchr/testify/require"
)

func TestHTTPProber(t *testing.T) {
	result, err := libprobe.NewHTTPProber().Probe(libprobe.Target{
		Address: "https://baidu.com",
		Timeout: 3 * time.Second,
	})
	require.NoError(t, err)
	t.Logf("Result: \n%v", result)

	result, err = libprobe.NewHTTPProber().Probe(libprobe.Target{
		Address: "https://google.com",
		Timeout: 3 * time.Second,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Error(t, result.(*libprobe.HTTPResult).Error)
}
