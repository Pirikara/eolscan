package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

const maxDeclarationBytes = 256 << 10

// Reflow publisher prose while excluding common Markdown/RST example blocks
// and quotations. Matching never executes or renders this content.
func declarationProse(raw string) string {
	lines := []string{}
	var paragraph strings.Builder
	flush := func() {
		if paragraph.Len() > 0 {
			lines = append(lines, paragraph.String())
			paragraph.Reset()
		}
	}
	boundary := func() { flush(); lines = append(lines, "") }
	fence := ""
	htmlEnd := ""
	literal := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			marker := trimmed[:3]
			if fence == "" {
				fence = marker
			} else if fence == marker {
				fence = ""
			}
			boundary()
			continue
		}
		if fence != "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if htmlEnd == "" {
			if strings.HasPrefix(lower, "<!--") {
				htmlEnd = "-->"
			} else if block := htmlExampleBlock.FindStringSubmatch(lower); len(block) > 1 {
				htmlEnd = "</" + block[1] + ">"
			}
		}
		if htmlEnd != "" {
			if strings.Contains(lower, htmlEnd) {
				htmlEnd = ""
			}
			boundary()
			continue
		}
		if strings.HasPrefix(trimmed, ">") {
			quoted := strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(trimmed, ">")), "**", "")
			quoted = trimNoticeDecoration(quoted)
			if !noticePrefix.MatchString(quoted) {
				continue
			}
			trimmed = quoted
		}
		if strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
			boundary()
			continue
		}
		if literal && trimmed != "" && strings.HasPrefix(line, " ") {
			continue
		}
		if trimmed != "" {
			literal = strings.HasSuffix(trimmed, "::")
		}
		heading := strings.HasPrefix(trimmed, "#")
		if html := htmlDeclarationHeading.FindStringSubmatch(trimmed); len(html) > 3 && html[1] == html[3] {
			trimmed, heading = html[2], true
		}
		if heading {
			boundary()
		}
		trimmed = strings.TrimLeft(trimmed, "#* ")
		trimmed = strings.ReplaceAll(trimmed, "**", "")
		trimmed = strings.ReplaceAll(trimmed, "`", "")
		trimmed = trimNoticeDecoration(trimmed)
		trimmed = noticePrefix.ReplaceAllString(trimmed, "")
		if trimmed == "" {
			boundary()
			continue
		}
		if paragraph.Len() > 0 {
			paragraph.WriteByte(' ')
		}
		paragraph.WriteString(trimmed)
		if heading {
			boundary()
		}
	}
	flush()
	return strings.Join(lines, "\n")
}

var noticePrefix = regexp.MustCompile(`(?i)^(?:warning|notice|note|attention|deprecated)\s*:\s*`)
var htmlDeclarationHeading = regexp.MustCompile(`(?i)^<h([1-6])(?:\s+[^>]*)?>(.*?)</h([1-6])>\s*$`)
var htmlExampleBlock = regexp.MustCompile(`(?i)^<(pre|code|script|style)(?:\s+[^>]*)?>`)

func trimNoticeDecoration(text string) string {
	return strings.TrimLeftFunc(text, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsSymbol(r) || unicode.IsMark(r) })
}

func declaration(kind, source, field, text string, classifiers []string, id identity.Identity, data transport.HTTPData, p model.Policy) (model.SignalEvaluation, *model.SignalEvidence) {
	e := model.SignalEvaluation{Type: "DECLARED_UNMAINTAINED", Status: "ABSENT", ProviderID: model.Ptr(kind), SourceURL: model.Ptr(source), CheckedAt: model.Nullable(data.ObservedAt)}
	details := map[string]any{"source_field": field, "raw_payload_hash": contract.Digest(data.Body), "scope": "publisher_declaration"}
	for _, classifier := range classifiers {
		if classifier == "Development Status :: 7 - Inactive" {
			e.Status = "PRESENT"
			details["source_field"], details["classifier"] = "info.classifiers", classifier
			return e, &model.SignalEvidence{Type: e.Type, ProviderID: kind, SourceURL: model.Ptr(source), ObservedAt: data.ObservedAt, Details: details}
		}
	}
	if len(text) > maxDeclarationBytes {
		e.Status, e.ReasonCode = "UNKNOWN", model.Ptr("DECLARATION_TOO_LARGE")
		return e, nil
	}
	prose := declarationProse(text)
	for index, pattern := range config.UnmaintainedPatterns(p) {
		expression, err := regexp.Compile(strings.ReplaceAll(pattern, "{package}", regexp.QuoteMeta(id.Name)))
		if err != nil {
			continue
		} // Validated when loading policy.
		if matched := expression.FindString(prose); matched != "" {
			e.Status = "PRESENT"
			details["pattern_index"], details["pattern"] = index, pattern
			words := strings.Fields(matched)
			if len(words) > 20 {
				words = words[:20]
			}
			details["matched_text"] = strings.Join(words, " ")
			// The pattern, content hash and field retain proof without copying
			// whole READMEs or package descriptions into reports.
			return e, &model.SignalEvidence{Type: e.Type, ProviderID: kind, SourceURL: model.Ptr(source), ObservedAt: data.ObservedAt, Details: details}
		}
	}
	return e, nil
}

func (r *registry) declaredUnmaintained(ctx context.Context, id identity.Identity) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
	providerID, raw := "", ""
	switch id.Type {
	case "npm":
		providerID = "npm"
		raw = config.CleanBase(r.t.Policy().Sources.NPM.BaseURL) + "/" + url.PathEscape(id.Name) + "/" + url.PathEscape(id.Version)
	case "pypi":
		providerID = "pypi"
		raw = config.CleanBase(r.t.Policy().Sources.PyPI.BaseURL) + "/pypi/" + url.PathEscape(id.Name) + "/" + url.PathEscape(id.Version) + "/json"
	case "gem":
		providerID = "rubygems"
		raw = config.CleanBase(r.t.Policy().Sources.RubyGems.BaseURL) + "/api/v2/rubygems/" + url.PathEscape(id.Name) + "/versions/" + url.PathEscape(id.Version) + ".json"
	default:
		return UnknownSignal("DECLARED_UNMAINTAINED", "NO_CAPABILITY"), nil, nil
	}
	data, err := r.t.Get(ctx, raw)
	ds := ProviderDiagnostics(providerID, data.Diagnostics)
	e := model.SignalEvaluation{Type: "DECLARED_UNMAINTAINED", Status: "UNKNOWN", ProviderID: model.Ptr(providerID), SourceURL: model.Ptr(raw), CheckedAt: model.Nullable(data.ObservedAt)}
	if err != nil {
		e.ReasonCode = model.Ptr("SOURCE_ERROR")
		return e, nil, append(ds, transport.ErrorDiagnostic(providerID, err))
	}
	if data.Status != 200 {
		e.ReasonCode = model.Ptr("VERSION_NOT_FOUND_IN_INDEX")
		return e, nil, ds
	}
	var doc struct {
		Name        string          `json:"name"`
		Version     string          `json:"version"`
		Description *string         `json:"description"`
		Info        json.RawMessage `json:"info"`
	}
	var description *string
	classifiers := []string{}
	classifiersKnown := id.Type != "pypi"
	field := "description"
	bad := contract.InspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &doc) != nil
	name, version := doc.Name, doc.Version
	if !bad && id.Type == "pypi" {
		var info struct {
			Name        string    `json:"name"`
			Version     string    `json:"version"`
			Description *string   `json:"description"`
			Classifiers *[]string `json:"classifiers"`
		}
		bad = json.Unmarshal(doc.Info, &info) != nil
		name, version, description, field = info.Name, info.Version, info.Description, "info.description"
		if info.Classifiers != nil {
			classifiers = *info.Classifiers
			classifiersKnown = true
		}
	} else if !bad && id.Type == "gem" {
		bad = json.Unmarshal(doc.Info, &description) != nil
		field = "info"
	} else {
		description = doc.Description
	}
	if bad || identity.NormalizeName(id.System, name) != id.Name || version != id.Version {
		r.t.Invalidate(raw)
		e.ReasonCode = model.Ptr("PROVIDER_SCHEMA_MISMATCH")
		return e, nil, append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", providerID, "Publisher declaration metadata does not identify the requested version"))
	}
	inactive := model.Contains(classifiers, "Development Status :: 7 - Inactive")
	if description == nil && !inactive {
		e.ReasonCode = model.Ptr("MISSING_DECLARATION_METADATA")
		return e, nil, ds
	}
	e, evidence := declaration(providerID, raw, field, model.Text(description), classifiers, id, data, r.t.Policy())
	if e.Status == "ABSENT" && !classifiersKnown {
		e.Status, e.ReasonCode = "UNKNOWN", model.Ptr("MISSING_DECLARATION_METADATA")
	}
	return e, evidence, ds
}
