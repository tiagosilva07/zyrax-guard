package selfupdate

import "testing"

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.8.2", "0.8.2", 0},
		{"v0.8.2", "0.8.2", 0},     // leading v ignored
		{"0.8.2", "0.8.10", -1},    // numeric, not lexical
		{"0.9.0", "0.8.99", 1},
		{"1.0.0", "0.9.9", 1},
		{"0.8.2-rc1", "0.8.2", 0},  // pre-release suffix dropped
		{"garbage", "0.8.2", -1},   // unparsable treated as oldest
		{"0.8.2", "garbage", 1},
	}
	for _, c := range cases {
		if got := compareSemver(c.a, c.b); got != c.want {
			t.Errorf("compareSemver(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
