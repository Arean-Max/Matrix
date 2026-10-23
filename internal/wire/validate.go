package wire

import "encoding/base64"

func ValidHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func ValidFingerprint(s string) bool { return ValidHex(s, 32) }

func ValidCode(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func ValidPackageID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func ValidB64(s string, n int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == n
}

func ValidB64Max(s string, min, max int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) >= min && len(b) <= max
}
