package libprobe_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/blho/libprobe"

	"github.com/stretchr/testify/require"
)

func TestHTTPProber(t *testing.T) {
	result, err := libprobe.NewHTTPProber().Probe(libprobe.Target[libprobe.HTTPExtention]{
		Address: "https://baidu.com",
		Timeout: 3 * time.Second,
		Extention: libprobe.HTTPExtention{
			Method: "GET",
			Headers: http.Header{
				"User-Agent": []string{"Probe/1.0"},
			},
		},
	})
	require.NoError(t, err)
	t.Logf("Result: \n%v", result)

	result, err = libprobe.NewHTTPProber().Probe(libprobe.Target[libprobe.HTTPExtention]{
		Address: "https://google.com",
		Timeout: 3 * time.Second,
		Extention: libprobe.HTTPExtention{
			Method: "GET",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Error(t, result.Error())
}
