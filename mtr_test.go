package libprobe_test

import (
	"testing"
	"time"

	"github.com/blho/libprobe"
	"github.com/stretchr/testify/require"
)

func TestMTR(t *testing.T) {
	prober := libprobe.NewMTRProber()
	r, err := prober.Probe(libprobe.Target[libprobe.MTRExtention]{
		Address: "8.8.8.8",
		Timeout: 5 * time.Second,
		Count:   3,
		Extention: libprobe.MTRExtention{
			ICMPExtention: libprobe.ICMPExtention{
				TTL:      64,
				Size:     56,
				SourceIP: "",
				EnableV6: false,
			},
			MaxHops:    30,
			ResolvePtr: true,
		},
	})
	require.NoError(t, err)
	require.True(t, r.IsSuccess(), "MTR probe should succeed")

	mtrResult := r.(*libprobe.MTRResult)
	require.NotEmpty(t, mtrResult.Hops, "Should have at least one hop")
	t.Logf("\n%s", r.String())
}
