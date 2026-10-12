package provider

import (
	"sort"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
)

// latestRelease needs a complete available index to prove inactivity. A
// sufficiently recent, fully dated release can prove activity independently
// of missing publication dates for other versions. Unassigned PyPI artifacts
// can hide an older first upload for that release, so they block that proof.
func latestRelease(versions map[string][]release, complete, unassignedArtifacts bool, asOf string, now time.Time, threshold int) (time.Time, string) {
	reason := ""
	if !complete || len(versions) == 0 {
		reason = "INCOMPLETE_VERSION_LIST"
	}
	keys := make([]string, 0, len(versions))
	for version := range versions {
		keys = append(keys, version)
	}
	sort.Strings(keys)
	var latest time.Time
	for _, version := range keys {
		var first time.Time
		fullyDated := len(versions[version]) > 0
		for _, artifact := range versions[version] {
			at, err := time.Parse(time.RFC3339Nano, artifact.PublishedAt)
			if err != nil {
				fullyDated = false
				if reason == "" {
					reason = "MISSING_PUBLICATION_DATE"
				}
				continue
			}
			if at.After(now) {
				return time.Time{}, "PUBLICATION_IN_FUTURE"
			}
			if first.IsZero() || at.Before(first) {
				first = at
			}
		}
		if !fullyDated && reason == "" {
			reason = "MISSING_PUBLICATION_DATE"
		}
		if fullyDated && model.UTCDate(first) <= asOf && first.After(latest) {
			latest = first
		}
	}
	if !latest.IsZero() && !unassignedArtifacts && releaseAge(latest, asOf) <= threshold {
		return latest, ""
	}
	if reason != "" {
		return time.Time{}, reason
	}
	if latest.IsZero() {
		return time.Time{}, "NO_RELEASE_AS_OF"
	}
	return latest, ""
}

func releaseAge(published time.Time, asOf string) int {
	evaluation, _ := time.Parse("2006-01-02", asOf)
	day, _ := time.Parse("2006-01-02", model.UTCDate(published))
	return int(evaluation.Sub(day).Hours() / 24)
}
