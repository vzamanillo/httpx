package stringutils

import "strings"

// SplitAndTrimSpaces splits string by a character and remove spaces
func SplitAndTrimSpaces(s, splitchar string) (result []string) {
	for _, token := range strings.Split(s, splitchar) {
		result = append(result, strings.TrimSpace(token))
	}
	return
}
