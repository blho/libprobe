package libprobe_test

import (
	"testing"

	"github.com/blho/libprobe"

	"github.com/stretchr/testify/require"
)

func TestTCPPing(t *testing.T) {
	p := libprobe.NewTCPProber()
	r, err := p.Probe(libprobe.Target{
		Address: "1.1.1.1:80",
	})
	require.NoError(t, err)
	t.Logf("RTT: %s", r.RTT())
}
