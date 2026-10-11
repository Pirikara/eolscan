package model

type InputPolicy struct {
	IncludeComponentTypes    []string `json:"include_component_types"`
	IncludeMetadataComponent bool     `json:"include_metadata_component"`
	MaxInputBytes            int64    `json:"max_input_bytes"`
	MaxComponents            int      `json:"max_components"`
	MaxJSONDepth             int      `json:"max_json_depth"`
}

type SourcePolicy struct {
	OfficialCatalog struct {
		Enabled bool    `json:"enabled"`
		Path    *string `json:"path"`
	} `json:"official_catalog"`
	EndoflifeDate struct {
		Enabled          bool   `json:"enabled"`
		BaseURL          string `json:"base_url"`
		MatchPURLExactly bool   `json:"match_purl_exactly"`
	} `json:"endoflife_date"`
	DepsDev struct {
		Enabled bool   `json:"enabled"`
		BaseURL string `json:"base_url"`
	} `json:"deps_dev"`
}

type Policy struct {
	SchemaVersion       int          `json:"schema_version"`
	Input               InputPolicy  `json:"input"`
	Sources             SourcePolicy `json:"sources"`
	VersionVerification struct {
		Mode    string   `json:"mode"`
		Sources []string `json:"sources"`
	} `json:"version_verification"`
	Signals struct {
		Deprecated       bool `json:"deprecated"`
		StaleReleaseDays *int `json:"stale_release_days"`
	} `json:"signals"`
	Notices struct {
		EOLSoonDays int `json:"eol_soon_days"`
	} `json:"notices"`
	Decision struct {
		SupportScope       string `json:"support_scope"`
		MaxEvidenceAgeDays int    `json:"max_evidence_age_days"`
	} `json:"decision"`
	Network struct {
		AllowedHosts   []string `json:"allowed_hosts"`
		TimeoutSeconds float64  `json:"timeout_seconds"`
		Retries        int      `json:"retries"`
		MaxConcurrency int      `json:"max_concurrency"`
	} `json:"network"`
	Cache struct {
		Enabled          bool    `json:"enabled"`
		PositiveTTLHours float64 `json:"positive_ttl_hours"`
		NegativeTTLHours float64 `json:"negative_ttl_hours"`
	} `json:"cache"`
	CI struct {
		FailOnStatuses       []string `json:"fail_on_statuses"`
		MinConfidence        string   `json:"min_confidence"`
		FailOnSignals        []string `json:"fail_on_signals"`
		FailOnIncompleteScan bool     `json:"fail_on_incomplete_scan"`
		MaxUnknownRatio      *float64 `json:"max_unknown_ratio"`
	} `json:"ci"`
	Exceptions struct {
		Path *string `json:"path"`
	} `json:"exceptions"`
	Output struct {
		IncludeUnknown  bool `json:"include_unknown"`
		IncludeEvidence bool `json:"include_evidence"`
	} `json:"output"`
}

type PolicyBundle struct {
	Policy      Policy
	Catalog     *Catalog
	Exceptions  *Exceptions
	Hash        string
	CatalogHash string
}
