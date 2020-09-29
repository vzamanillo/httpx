package sliceutils

import (
	"strconv"
	"strings"
)

// ToStringSlice creates a slice with all string keys from a map
func ToStringSlice(m map[string]struct{}) (s []string) {
	for k := range m {
		s = append(s, k)
	}

	return
}

// ToIntSlice converts string to slice of ints
func ToIntSlice(s string) ([]int, error) {
	var r []int
	if s == "" {
		return r, nil
	}
	for _, v := range strings.Split(s, ",") {
		vTrim := strings.TrimSpace(v)
		if i, err := strconv.Atoi(vTrim); err == nil {
			r = append(r, i)
		} else {
			return r, err
		}
	}

	return r, nil
}

// IntSliceContains check if a slice contains the specified int value
func IntSliceContains(sl []int, v int) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}
