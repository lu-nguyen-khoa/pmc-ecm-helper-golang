package context_handler

import "strings"

const (
	baseContentType = "application"
)

func ContentType(subtype string) string {
	return strings.Join([]string{baseContentType, subtype}, "/")
}
