package libprobe_test

import (
	"testing"
	"time"

	"github.com/blho/libprobe"

	"github.com/stretchr/testify/require"
)

func TestTCPPing(t *testing.T) {
	p := libprobe.NewTCPProber()
	r, err := p.Probe(libprobe.Target[libprobe.TCPExtention]{
		Address: "223.5.5.5:80",
		Timeout: 5 * time.Second,
		Extention: libprobe.TCPExtention{
			Port: 80,
		},
	})
	require.NoError(t, err)
	require.True(t, r.IsSuccess(), "TCP probe should succeed")
	t.Logf("RTT: %s", r.RTT())
}
