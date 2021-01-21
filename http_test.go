package libprobe_test

import (
	"testing"

	"github.com/oif/libprobe"

	"github.com/stretchr/testify/require"
)

func TestHTTPProber(t *testing.T) {
	result, err := libprobe.NewHTTPProber().Probe(libprobe.Target{
		Address: "https://baidu.com",
		Timeout: 0,
	})
	require.NoError(t, err)
	t.Logf("Result: \n%v", result)
}
