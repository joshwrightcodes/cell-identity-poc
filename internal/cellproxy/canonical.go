package cellproxy

import (
	"net/url"
	"path"
	"strings"
)

// CanonicalPath returns the path of u when it is in canonical form, so that an allow-list can
// match it by exact segments. It is false when u holds an escaped path (RawPath), an opaque
// part, a "%", a byte outside printable ASCII, an empty segment ("//" or a trailing "/"), a "."
// or ".." segment, or any other form that path.Clean would change. Matching stays
// case-sensitive.
func CanonicalPath(u *url.URL) (string, bool) {
	p := u.Path
	if u.RawPath != "" || u.Opaque != "" || !strings.HasPrefix(p, "/") || p == "/" {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if b := p[i]; b < 0x21 || b > 0x7e || b == '%' {
			return "", false
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	if path.Clean(p) != p {
		return "", false
	}
	return p, true
}
