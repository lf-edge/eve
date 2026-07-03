package partitionresizer

import "strings"

const (
	alternateLabelSuffix = "_resized2"
)

// getAlternateName returns an alternate label for a partition.
// It must be predictable, so that we can go away, come back, and connect them.
func getAlternateLabel(original string) string {
	return original + alternateLabelSuffix
}

//nolint:unused // getOriginalLabel returns the original label from an alternate label.
func getOriginalLabel(alternate string) string {
	return strings.TrimSuffix(alternate, alternateLabelSuffix)
}
