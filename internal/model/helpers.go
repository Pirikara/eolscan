package model

import (
	"sort"
)

// DatedSignal is evaluated against its recorded date. Other maintenance
// conditions describe live publisher/repository state only.
func DatedSignal(kind string) bool {
	return kind == "STALE_RELEASE" || kind == "RELEASE_SERIES_EOL"
}

func SortedStrings(a []string) []string { sort.Strings(a); return a }

// SecuritySupportLabel accepts explicit upstream security phases from API v1.
func SecuritySupportLabel(label string) bool {
	return label == "Security Support" || label == "Maintenance & Security Support"
}
