package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

type ProductRef struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type EolIndexRow struct {
	Identifier string     `json:"identifier"`
	Product    ProductRef `json:"product"`
}

type eolRelease struct {
	Name         string  `json:"name"`
	EOLFrom      *string `json:"eolFrom"`
	IsEOL        *bool   `json:"isEol"`
	IsMaintained *bool   `json:"isMaintained"`
}

type eolProduct struct {
	Name        string `json:"name"`
	Identifiers *[]struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"identifiers"`
	Releases *[]eolRelease `json:"releases"`
	Links    struct {
		HTML string `json:"html"`
	} `json:"links"`
}

type EOLProvider struct {
	t         *transport.Transport
	bundle    model.PolicyBundle
	once      sync.Once
	index     map[string][]ProductRef
	indexData transport.HTTPData
	indexErr  error
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

func eolHeader(schema, generated string) bool {
	_, err := time.Parse(time.RFC3339Nano, generated)
	return strings.HasPrefix(schema, "1.") && err == nil
}

func (p *EOLProvider) loadIndex(ctx context.Context) {
	p.once.Do(func() {
		raw := config.CleanBase(p.t.Policy().Sources.EndoflifeDate.BaseURL) + "/identifiers/purl/"
		p.index = map[string][]ProductRef{}
		p.indexData, p.indexErr = p.t.Get(ctx, raw)
		if p.indexErr != nil {
			return
		}
		if p.indexData.Status == 404 {
			return
		}
		var response struct {
			SchemaVersion string         `json:"schema_version"`
			GeneratedAt   string         `json:"generated_at"`
			Result        *[]EolIndexRow `json:"result"`
		}
		bad := contract.InspectJSON(p.indexData.Body, 256) != nil || json.Unmarshal(p.indexData.Body, &response) != nil ||
			response.Result == nil || !eolHeader(response.SchemaVersion, response.GeneratedAt)
		if !bad {
			for _, row := range *response.Result {
				if !strings.HasPrefix(row.Identifier, "pkg:") || row.Product.Name == "" || row.Product.URI == "" {
					bad = true
					break
				}
				parsed, inScope, err := identity.IndexPackage(row.Identifier)
				// The public index also contains OCI/OS/SWID identities and
				// qualified registry identities outside this adapter's scope.
				// They must not invalidate unrelated supported public packages.
				if !inScope {
					continue
				}
				if err != nil {
					bad = true
					break
				}
				if !p.validProductURI(row.Product) {
					bad = true
					break
				}
				base := parsed.ToString()
				if !model.Contains(p.index[base], row.Product) {
					p.index[base] = append(p.index[base], row.Product)
				}
			}
		}
		if bad {
			p.indexErr = &transport.LookupError{Code: "PROVIDER_SCHEMA_MISMATCH", Status: 200}
			p.t.Invalidate(raw)
		}
	})
}

func (p *EOLProvider) validProductURI(r ProductRef) bool {
	if !slugPattern.MatchString(r.Name) || r.Name == "." || r.Name == ".." {
		return false
	}
	base, err := url.Parse(config.CleanBase(p.t.Policy().Sources.EndoflifeDate.BaseURL))
	if err != nil {
		return false
	}
	u, err := url.Parse(r.URI)
	if err != nil || !transport.AllowedURL(u, p.t.Policy()) || u.Host != base.Host {
		return false
	}
	want := config.CleanBase(base.Path) + "/products/" + r.Name
	return u.EscapedPath() == want || u.EscapedPath() == want+"/"
}

func (p *EOLProvider) Evidence(ctx context.Context, id identity.Identity) ([]model.LifecycleEvidence, []model.Diagnostic, string, bool) {
	out := []model.LifecycleEvidence{}
	ds := []model.Diagnostic{}
	p.loadIndex(ctx)
	ds = append(ds, ProviderDiagnostics("endoflife_date", p.indexData.Diagnostics)...)
	if p.indexErr != nil {
		return out, append(ds, transport.ErrorDiagnostic("endoflife_date", p.indexErr)), "SOURCE_ERROR", true
	}
	refs := p.index[id.BasePURL]
	if len(refs) == 0 {
		return out, ds, "", false
	}
	if len(refs) > 1 {
		return out, ds, "AMBIGUOUS_IDENTITY", false
	}
	ref := refs[0]
	// Reconstruct from trusted base + validated slug, never fetch an SBOM URL.
	raw := config.CleanBase(p.t.Policy().Sources.EndoflifeDate.BaseURL) + "/products/" + ref.Name + "/"
	data, err := p.t.Get(ctx, raw)
	ds = append(ds, ProviderDiagnostics("endoflife_date", data.Diagnostics)...)
	if err != nil {
		return out, append(ds, transport.ErrorDiagnostic("endoflife_date", err)), "SOURCE_ERROR", true
	}
	if data.Status == 404 {
		return out, ds, "", false
	}
	var response struct {
		SchemaVersion string      `json:"schema_version"`
		GeneratedAt   string      `json:"generated_at"`
		LastModified  *string     `json:"last_modified"`
		Result        *eolProduct `json:"result"`
	}
	if contract.InspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &response) != nil || response.Result == nil ||
		!eolHeader(response.SchemaVersion, response.GeneratedAt) || response.Result.Identifiers == nil || response.Result.Releases == nil ||
		!slugPattern.MatchString(response.Result.Name) {
		p.t.Invalidate(raw)
		return out, append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Product details are malformed")), "SOURCE_ERROR", true
	}
	product := response.Result
	if response.LastModified != nil {
		if modified, err := time.Parse(time.RFC3339Nano, *response.LastModified); err == nil {
			response.LastModified = model.Ptr(model.Timestamp(modified))
		} else {
			response.LastModified = nil
		}
	}
	matches := false
	for _, i := range *product.Identifiers {
		if i.Type == "purl" {
			base, err := identity.Base(i.ID)
			if err == nil && base == id.BasePURL {
				matches = true
			}
		}
	}
	if !matches {
		return out, append(ds, model.NewDiagnostic("PROVIDER_IDENTITY_MISMATCH", "endoflife_date", "Product details do not contain the requested PURL")), "SOURCE_ERROR", true
	}
	source := product.Links.HTML
	if !config.SafeEvidenceURL(source) {
		return out, append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Product evidence link is not a safe HTTPS URL")), "SOURCE_ERROR", true
	}
	best := -1
	chosen := []eolRelease{}
	for _, r := range *product.Releases {
		if r.Name == "" || r.IsEOL == nil || r.IsMaintained == nil {
			return out, append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Release is missing required fields")), "SOURCE_ERROR", true
		}
		if identity.NumericCycleMatches(id.Version, r.Name) {
			n := len(strings.Split(r.Name, "."))
			if n > best {
				best = n
				chosen = []eolRelease{r}
			} else if n == best {
				chosen = append(chosen, r)
			}
		}
	}
	if len(chosen) > 1 {
		for _, r := range chosen[1:] {
			if r.Name != chosen[0].Name || model.Text(r.EOLFrom) != model.Text(chosen[0].EOLFrom) {
				return out, ds, "AMBIGUOUS_CYCLE", false
			}
		}
		chosen = chosen[:1]
	}
	for _, r := range chosen {
		if r.EOLFrom == nil {
			continue
		}
		if _, err := time.Parse("2006-01-02", *r.EOLFrom); err != nil {
			return out, append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Invalid EOL date")), "SOURCE_ERROR", true
		}
		var review *model.GeneralEolReview
		if p.bundle.Catalog != nil {
			for _, candidate := range p.bundle.Catalog.GeneralEolReviews {
				if candidate.ProductSlug == product.Name && candidate.PackagePURL == id.BasePURL && candidate.MatchedCycle == r.Name && candidate.SupportScope == "upstream_security" {
					review = model.Ptr(candidate)
					break
				}
			}
		}
		hash := contract.Digest(data.Body)
		out = append(out, model.LifecycleEvidence{
			ID: "endoflife_date:" + product.Name + ":" + r.Name, ProviderID: "endoflife_date", SourceClass: "CURATED_DATABASE", Claim: "GENERAL_EOL_END",
			PackagePURL: id.BasePURL, ProductSlug: model.Ptr(product.Name), MatchedCycle: r.Name, SupportScope: "general_eol", EOLEffectiveDate: *r.EOLFrom,
			SourceURL: source, SourceField: "releases[].eolFrom", ObservedAt: data.ObservedAt, SourceUpdatedAt: response.LastModified,
			RawPayloadHash: model.Ptr(hash), Confidence: "MEDIUM", RuleID: "R-003", GeneralEolReview: review,
		})
		if *r.IsMaintained && *r.EOLFrom <= model.UTCDate(p.t.Now()) {
			ds = append(ds, model.NewDiagnostic("SUPPORT_SCOPE_DIFFERENCE", "endoflife_date", "isMaintained may include extended support; upstream EOL date is retained"))
		}
	}
	return out, ds, "", false
}
