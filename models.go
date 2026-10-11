package main

import "time"

const toolVersion = "0.1.0"

type Component struct {
	SourceRef    string
	Name         string
	Version      string
	PURL         string
	PURLConflict bool
}

type SBOM struct {
	Components []Component
	Excluded   int
	SHA256     string
}

type VersionVerification struct {
	Status      string  `json:"status"`
	ProviderID  *string `json:"provider_id"`
	SourceURL   *string `json:"source_url"`
	CheckedAt   *string `json:"checked_at"`
	PublishedAt *string `json:"published_at"`
	ReasonCode  *string `json:"reason_code"`
}

type VersionAssertion struct {
	PackagePURL string `json:"package_purl"`
	PublishedAt string `json:"published_at"`
	SourceURL   string `json:"source_url"`
	ReviewedAt  string `json:"reviewed_at"`
	ValidUntil  string `json:"valid_until"`
}

type GeneralEolReview struct {
	ID           string `json:"id"`
	ProductSlug  string `json:"product_slug"`
	PackagePURL  string `json:"package_purl"`
	MatchedCycle string `json:"matched_cycle"`
	SupportScope string `json:"support_scope"`
	EvidenceURL  string `json:"evidence_url"`
	ReviewedAt   string `json:"reviewed_at"`
	ValidUntil   string `json:"valid_until"`
}

type CatalogEntry struct {
	ID                    string   `json:"id"`
	PackagePURL           string   `json:"package_purl"`
	MatchedCycle          string   `json:"matched_cycle"`
	Match                 string   `json:"match"`
	Versions              []string `json:"versions"`
	Claim                 string   `json:"claim"`
	SupportScope          string   `json:"support_scope"`
	SupportStartDate      *string  `json:"support_start_date"`
	EOLEffectiveDate      string   `json:"eol_effective_date"`
	EvidenceURL           string   `json:"evidence_url"`
	SupportAuthority      string   `json:"support_authority"`
	ReviewedAt            string   `json:"reviewed_at"`
	ValidUntil            string   `json:"valid_until"`
	SupersededBy          *string  `json:"superseded_by"`
	SupersessionSourceURL *string  `json:"supersession_source_url"`
}

type Catalog struct {
	SchemaVersion     int                `json:"schema_version"`
	Entries           []CatalogEntry     `json:"entries"`
	VerifiedVersions  []VersionAssertion `json:"verified_versions"`
	GeneralEolReviews []GeneralEolReview `json:"general_eol_reviews"`
}

type Exception struct {
	PackagePURL string   `json:"package_purl"`
	Suppress    []string `json:"suppress"`
	Reason      string   `json:"reason"`
	Owner       string   `json:"owner"`
	ExpiresOn   string   `json:"expires_on"`
}

type Exceptions struct {
	SchemaVersion int         `json:"schema_version"`
	Exceptions    []Exception `json:"exceptions"`
}

type LifecycleEvidence struct {
	ID                    string            `json:"id"`
	ProviderID            string            `json:"provider_id"`
	SourceClass           string            `json:"source_class"`
	Claim                 string            `json:"claim"`
	PackagePURL           string            `json:"package_purl"`
	ProductSlug           *string           `json:"product_slug"`
	MatchedCycle          string            `json:"matched_cycle"`
	SupportScope          string            `json:"support_scope"`
	SupportStartDate      *string           `json:"support_start_date"`
	EOLEffectiveDate      string            `json:"eol_effective_date"`
	SourceURL             string            `json:"source_url"`
	SourceField           string            `json:"source_field"`
	ObservedAt            string            `json:"observed_at"`
	SourceUpdatedAt       *string           `json:"source_updated_at"`
	ReviewedAt            *string           `json:"reviewed_at"`
	ValidUntil            *string           `json:"valid_until"`
	RawPayloadHash        *string           `json:"raw_payload_hash"`
	Confidence            string            `json:"confidence"`
	RuleID                string            `json:"rule_id"`
	GeneralEolReview      *GeneralEolReview `json:"general_eol_review"`
	SupersededBy          *string           `json:"superseded_by"`
	SupersessionSourceURL *string           `json:"supersession_source_url"`
}

type SignalEvidence struct {
	Type       string         `json:"type"`
	ProviderID string         `json:"provider_id"`
	SourceURL  *string        `json:"source_url"`
	ObservedAt string         `json:"observed_at"`
	Details    map[string]any `json:"details"`
}
type SignalEvaluation struct {
	Type       string  `json:"type"`
	Status     string  `json:"status"`
	ProviderID *string `json:"provider_id"`
	SourceURL  *string `json:"source_url"`
	CheckedAt  *string `json:"checked_at"`
	ReasonCode *string `json:"reason_code"`
}
type Notice struct {
	Type          string `json:"type"`
	DaysRemaining int    `json:"days_remaining"`
	EvidenceID    string `json:"evidence_id"`
	RuleID        string `json:"rule_id"`
}
type Diagnostic struct {
	Code       string  `json:"code"`
	ProviderID *string `json:"provider_id"`
	HTTPStatus *int    `json:"http_status"`
	Retryable  bool    `json:"retryable"`
	Message    string  `json:"message"`
}

type ComponentResult struct {
	SourceRef           string              `json:"source_ref"`
	PURL                *string             `json:"purl"`
	Name                string              `json:"name"`
	Version             *string             `json:"version"`
	VersionVerification VersionVerification `json:"version_verification"`
	Lifecycle           string              `json:"lifecycle"`
	Confidence          *string             `json:"confidence"`
	EOLEffectiveDate    *string             `json:"eol_effective_date"`
	MatchedCycle        *string             `json:"matched_cycle"`
	Signals             []SignalEvidence    `json:"signals"`
	SignalEvaluations   []SignalEvaluation  `json:"signal_evaluations"`
	SelectedEvidenceIDs []string            `json:"selected_evidence_ids"`
	Notices             []Notice            `json:"notices"`
	UnknownReasons      []string            `json:"unknown_reasons"`
	RuleIDs             []string            `json:"rule_ids"`
	Evidence            []LifecycleEvidence `json:"evidence"`
	Diagnostics         []Diagnostic        `json:"diagnostics"`
	Incomplete          bool                `json:"incomplete"`
	CIFailure           bool                `json:"ci_failure"`
	ExceptionApplied    bool                `json:"exception_applied"`
}
type Summary struct {
	InScope            int     `json:"in_scope"`
	Excluded           int     `json:"excluded"`
	EOL                int     `json:"eol"`
	Supported          int     `json:"supported"`
	Unknown            int     `json:"unknown"`
	AssessmentCoverage float64 `json:"assessment_coverage"`
	ProviderErrorCount int     `json:"provider_error_count"`
	CIFailureCount     int     `json:"ci_failure_count"`
}
type CIGate struct {
	Passed         bool     `json:"passed"`
	ViolationCodes []string `json:"violation_codes"`
	Incomplete     bool     `json:"incomplete"`
}
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	ToolVersion   string            `json:"tool_version"`
	AsOf          string            `json:"as_of"`
	Projection    bool              `json:"projection"`
	GeneratedAt   string            `json:"generated_at"`
	InputSHA256   string            `json:"input_sha256"`
	PolicyHash    string            `json:"policy_hash"`
	Summary       Summary           `json:"summary"`
	CIGate        CIGate            `json:"ci_gate"`
	Results       []ComponentResult `json:"results"`
}

func ptr[T any](v T) *T { return &v }
func textOf(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return ptr(s)
}
func utcDay(t time.Time) string                 { return t.UTC().Format("2006-01-02") }
func stamp(t time.Time) string                  { return t.UTC().Format(time.RFC3339Nano) }
func active(reviewed, until, today string) bool { return reviewed <= today && today <= until }
func has[T comparable](items []T, want T) bool {
	for _, v := range items {
		if v == want {
			return true
		}
	}
	return false
}
func addUnique(items []string, v string) []string {
	if !has(items, v) {
		return append(items, v)
	}
	return items
}
func diag(code, provider, message string) Diagnostic {
	return Diagnostic{Code: code, ProviderID: nullable(provider), Message: message}
}
