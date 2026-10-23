package licensing

import "strconv"

func pageArgs(limit, offset int) (int, int) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func plural(n int64, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.FormatInt(n, 10) + " " + what + "s"
}
