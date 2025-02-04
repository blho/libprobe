package libprobe_test

import (
	"testing"
	"time"

	"github.com/blho/libprobe"

	"github.com/stretchr/testify/require"
)

func TestICMP(t *testing.T) {
	prober := libprobe.NewICMPProber()
	r, err := prober.Probe(libprobe.Target[libprobe.ICMPExtention]{
		Address: "223.5.5.5",
		Count:   3,
		Timeout: 5 * time.Second,
		Extention: libprobe.ICMPExtention{
			TTL:      64,
			Size:     56,
			SourceIP: "",
			EnableV6: false,
			Sequence: 1,
		},
	})
	require.NoError(t, err)
	require.True(t, r.IsSuccess(), "ICMP probe should succeed")
	icmpResult := r.(*libprobe.ICMPResult)
	t.Logf("RTT: %s, Size: %d bytes\n%s", r.RTT(), icmpResult.Size, r.String())
}
