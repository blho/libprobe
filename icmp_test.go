package libprobe_test

import (
	"testing"

	"github.com/oif/libprobe"

	"github.com/stretchr/testify/require"
)

func TestICMP(t *testing.T) {
	prober := libprobe.NewICMPProber()
	r, err := prober.Probe(libprobe.Target{
		Address: "1.1.1.1",
		Count:   3,
	})
	require.NoError(t, err)
	t.Logf("RTT: %s\n%s", r.RTT(), r.String())
}
