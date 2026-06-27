package selfupdate

import "testing"

func TestDetectInstall(t *testing.T) {
	cases := []struct {
		path string
		want Method
	}{
		{"/usr/lib/node_modules/zyrax-guard/bin/zyrax-guard", MethodNPM},
		{"/opt/homebrew/Cellar/zyrax-guard/0.8.2/bin/zyrax-guard", MethodBrew},
		{"/usr/local/Cellar/zyrax-guard/0.8.2/bin/zyrax-guard", MethodBrew},
		{"/home/u/go/bin/zyrax-guard", MethodGo},
		{"/usr/local/bin/zyrax-guard", MethodBinary},
		{"/home/u/.local/bin/zyrax-guard", MethodBinary},
	}
	for _, c := range cases {
		if got := DetectInstall(c.path, "/home/u/go"); got != c.want {
			t.Errorf("DetectInstall(%q)=%v want %v", c.path, got, c.want)
		}
	}
}
