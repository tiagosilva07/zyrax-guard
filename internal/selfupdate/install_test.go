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
		// scoop shims resolve into <root>\scoop\apps\zyrax-guard\<version-or-current>\.
		{`C:\Users\u\scoop\apps\zyrax-guard\current\zyrax-guard.exe`, MethodScoop},
		{`C:\Users\u\scoop\apps\zyrax-guard\0.11.0\zyrax-guard.exe`, MethodScoop},
		{`D:\tools\scoop\apps\zyrax-guard\current\zyrax-guard.exe`, MethodScoop},
		// A scoop dir for a DIFFERENT app must not claim the binary.
		{`C:\Users\u\scoop\apps\other-tool\current\zyrax-guard.exe`, MethodBinary},
	}
	for _, c := range cases {
		if got := DetectInstall(c.path, "/home/u/go"); got != c.want {
			t.Errorf("DetectInstall(%q)=%v want %v", c.path, got, c.want)
		}
	}
}
