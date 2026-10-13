package model

import (
	"sort"
)

func SortedStrings(a []string) []string { sort.Strings(a); return a }

// SecuritySupportLabel accepts explicit upstream security phases from API v1.
func SecuritySupportLabel(label string) bool {
	return label == "Security Support" || label == "Maintenance & Security Support"
}
