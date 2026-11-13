package satoken_test

import (
	"testing"

	"github.com/joshwrightcodes/cell-identity-poc/internal/clusterjwt"
	"github.com/joshwrightcodes/cell-identity-poc/internal/satoken"
)

// clusterjwt imports satoken, so satoken repeats the four variable names of the M2 pod. This test
// keeps the two sets equal.
func TestEnvNamesMatchClusterjwt(t *testing.T) {
	for _, p := range [][2]string{
		{satoken.EnvPodName, clusterjwt.EnvPodName}, {satoken.EnvPodUID, clusterjwt.EnvPodUID},
		{satoken.EnvPodNamespace, clusterjwt.EnvPodNamespace}, {satoken.EnvServiceAccount, clusterjwt.EnvServiceAccount},
	} {
		if p[0] != p[1] {
			t.Errorf("satoken %q differs from clusterjwt %q", p[0], p[1])
		}
	}
}
