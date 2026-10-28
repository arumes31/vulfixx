package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var regexCache sync.Map

func getKeywordRegex(keyword string) *regexp.Regexp {
	pattern := `(?i)\b` + regexp.QuoteMeta(keyword) + `\b`
	if val, ok := regexCache.Load(pattern); ok {
		return val.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	regexCache.Store(pattern, re)
	return re
}

const maxPatternLen = 2000

func getPatternRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxPatternLen {
		return nil, fmt.Errorf("regex pattern too long (%d chars, max %d)", len(pattern), maxPatternLen)
	}
	// Validate the syntax tree to reject patterns with excessive nesting/quantifiers (ReDoS)
	sre, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}
	if hasNestedQuantifiers(sre) {
		return nil, fmt.Errorf("regex pattern has nested quantifiers (ReDoS risk): %s", pattern)
	}
	if val, ok := regexCache.Load(pattern); ok {
		return val.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err == nil {
		regexCache.Store(pattern, re)
	}
	return re, err
}

// hasNestedQuantifiers returns true if the syntax tree contains quantifiers (Star/Plus/Repeat)
// nested inside other quantifiers, a common ReDoS pattern.
func hasNestedQuantifiers(re *syntax.Regexp) bool {
	return checkNested(re, false)
}

func checkNested(re *syntax.Regexp, inQuantifier bool) bool {
	isQ := isQuantifier(re.Op)
	if inQuantifier && isQ {
		return true
	}
	for _, sub := range re.Sub {
		if checkNested(sub, inQuantifier || isQ) {
			return true
		}
	}
	return false
}

func isQuantifier(op syntax.Op) bool {
	return op == syntax.OpStar || op == syntax.OpPlus || op == syntax.OpRepeat || op == syntax.OpQuest
}

func (w *Worker) processAlerts(ctx context.Context) {
	for {
		result, err := w.Redis.BRPop(ctx, 1*time.Second, "cve_alerts_queue").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !errors.Is(err, redis.Nil) {
				slog.Error("Error reading from alerts queue", "error", err)
			}
			continue
		}
		var cve models.CVE
		if err := json.Unmarshal([]byte(result[1]), &cve); err != nil {
			slog.Error("Error unmarshaling alert job", "error", err)
			continue
		}
		w.evaluateSubscriptions(ctx, &cve)
	}
}

func (w *Worker) evaluateSubscriptions(ctx context.Context, cve *models.CVE) {
	notifiedUsers := make(map[int]bool)
	// Pre-fetch all users who have already been notified about this CVE to avoid N+1 queries
	historyRows, err := w.Pool.Query(ctx, "SELECT user_id FROM alert_history WHERE cve_id = $1", cve.ID)
	if err != nil {
		slog.Error("Error fetching alert history for CVE", "id", cve.ID, "cve_id", cve.CVEID, "error", err)
		notifiedUsers = nil
	} else {
		defer historyRows.Close()
		for historyRows.Next() {
			var uid int
			if err := historyRows.Scan(&uid); err == nil {
				notifiedUsers[uid] = true
			}
		}
	}

	rows, err := w.Pool.Query(ctx, `
		SELECT s.id, s.user_id, s.keyword, s.min_severity, s.webhook_url, s.slack_webhook_url, s.teams_webhook_url, 
		       s.enable_email, s.enable_webhook, s.enable_slack, s.enable_teams, s.enable_browser_push,
		       s.filter_logic, s.aggregation_mode, u.email
		FROM user_subscriptions s
		JOIN users u ON s.user_id = u.id
		WHERE u.is_email_verified = TRUE
		  AND s.min_severity <= $1
		  AND (
		      s.keyword = '' OR 
		      EXISTS (
		          SELECT 1 FROM unnest(string_to_array(s.keyword, ',')) AS kw 
		          WHERE $2 ILIKE '%' || REPLACE(REPLACE(REPLACE(TRIM(kw), '\', '\\'), '%', '\%'), '_', '\_') || '%' ESCAPE '\'
		      )
		  )
	`, cve.CVSSScore, cve.Description)
	if err != nil {
		slog.Error("Error fetching subscriptions", "error", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sub models.UserSubscription
		var email string
		var slackURL, teamsURL string
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.Keyword, &sub.MinSeverity,
			&sub.WebhookURL, &slackURL, &teamsURL,
			&sub.EnableEmail, &sub.EnableWebhook, &sub.EnableSlack, &sub.EnableTeams, &sub.EnableBrowserPush,
			&sub.FilterLogic, &sub.AggregationMode, &email); err != nil {
			slog.Error("Error scanning subscription row", "error", err)
			continue
		}
		sub.SlackWebhookURL, _ = models.DecryptWebhook(slackURL)
		sub.TeamsWebhookURL, _ = models.DecryptWebhook(teamsURL)
		if notifiedUsers[sub.UserID] {
			continue
		}
		if matchCVE(cve, sub) {
			if w.notifyIfNewWithCache(ctx, sub.UserID, cve, sub, email, "", notifiedUsers) {
				notifiedUsers[sub.UserID] = true
			}
		}
	}

	assetRows, err := w.Pool.Query(ctx, `
		SELECT ak.keyword, a.user_id, u.email, a.name
		FROM asset_keywords ak
		JOIN assets a ON ak.asset_id = a.id
		JOIN users u ON a.user_id = u.id
		WHERE u.is_email_verified = TRUE
		  AND $1 ILIKE '%' || REPLACE(REPLACE(REPLACE(ak.keyword, '\', '\\'), '%', '\%'), '_', '\_') || '%' ESCAPE '\'
	`, cve.Description)
	if err != nil {
		slog.Error("Error fetching asset keywords", "error", err)
		return
	}
	defer assetRows.Close()
	for assetRows.Next() {
		var keyword, email, assetName string
		var userID int
		if err := assetRows.Scan(&keyword, &userID, &email, &assetName); err != nil {
			slog.Error("Error scanning asset keyword row", "error", err)
			continue
		}
		if notifiedUsers[userID] {
			continue
		}
		if getKeywordRegex(keyword).MatchString(cve.Description) {
			sub := models.UserSubscription{EnableEmail: true, EnableWebhook: true}
			if w.notifyIfNewWithCache(ctx, userID, cve, sub, email, assetName, notifiedUsers) {
				notifiedUsers[userID] = true
			}
		}
	}
}

func matchCVE(cve *models.CVE, sub models.UserSubscription) bool {
	if sub.Keyword != "" {
		matched := slices.ContainsFunc(strings.Split(sub.Keyword, ","), func(kw string) bool {
			kw = strings.TrimSpace(kw)
			return kw != "" && getKeywordRegex(kw).MatchString(cve.Description)
		})
		if !matched {
			return false
		}
	}
	if sub.MinSeverity > 0 && cve.CVSSScore < sub.MinSeverity {
		return false
	}
	if sub.FilterLogic != "" {
		return evaluateComplexFilter(sub.FilterLogic, cve)
	}
	return true
}

// evaluateComplexFilter evaluates a boolean filter expression against a CVE.
//
// Supported variables: epss, buzz (github_poc_count), severity / cvss, cisa, and
// a trailing "regex: <pattern>" term matched against the description. Comparisons
// support >, >=, <, <=, ==, = and != operators. Terms can be combined with the
// logical operators && (AND) and || (OR); AND binds tighter than OR, e.g.
// "cisa = true && epss > 0.1 || severity >= 9" is read as
// "(cisa = true && epss > 0.1) || (severity >= 9)".
//
// The evaluator fails closed: any malformed term, unknown variable/operator, or
// invalid regex causes the whole filter to reject the CVE.
func evaluateComplexFilter(logic string, cve *models.CVE) bool {
	logic = strings.TrimSpace(strings.ToLower(logic))
	if logic == "" {
		return true
	}
	tokens := strings.Fields(logic)
	result, ok := evalFilterTokens(tokens, cve)
	if !ok {
		return false // fail closed on any parse error
	}
	return result
}

// ValidateComplexFilter checks that a filter expression is well-formed so the web
// layer can reject malformed input at write time. It returns nil for an empty
// filter. A non-nil error describes the first structural problem found.
func ValidateComplexFilter(logic string) error {
	logic = strings.TrimSpace(strings.ToLower(logic))
	if logic == "" {
		return nil
	}
	if len(logic) > maxPatternLen {
		return fmt.Errorf("filter expression too long (%d chars, max %d)", len(logic), maxPatternLen)
	}
	tokens := strings.Fields(logic)
	dummy := &models.CVE{}
	expectTerm := true
	for i := 0; i < len(tokens); {
		switch tokens[i] {
		case "&&", "||":
			if expectTerm {
				return fmt.Errorf("unexpected operator %q", tokens[i])
			}
			expectTerm = true
			i++
			continue
		}
		if !expectTerm {
			return fmt.Errorf("expected && or || before %q", tokens[i])
		}
		_, consumed, ok := parseFilterTerm(tokens, i, dummy)
		if !ok {
			return fmt.Errorf("invalid filter term near %q", tokens[i])
		}
		expectTerm = false
		i += consumed
	}
	if expectTerm {
		return fmt.Errorf("filter expression ends with a dangling operator")
	}
	return nil
}

// evalFilterTokens evaluates the token stream as an OR of AND-groups.
func evalFilterTokens(tokens []string, cve *models.CVE) (bool, bool) {
	var orResult bool // accumulated value across completed AND-groups
	andResult := true // accumulated value within the current AND-group
	haveTermInAnd := false
	haveOrResult := false

	closeAndGroup := func() {
		if !haveTermInAnd {
			return
		}
		if haveOrResult {
			orResult = orResult || andResult
		} else {
			orResult = andResult
			haveOrResult = true
		}
		andResult = true
		haveTermInAnd = false
	}

	for i := 0; i < len(tokens); {
		switch tokens[i] {
		case "&&":
			i++
			continue
		case "||":
			closeAndGroup()
			i++
			continue
		}
		val, consumed, ok := parseFilterTerm(tokens, i, cve)
		if !ok {
			return false, false
		}
		if haveTermInAnd {
			andResult = andResult && val
		} else {
			andResult = val
			haveTermInAnd = true
		}
		i += consumed
	}
	closeAndGroup()

	if !haveOrResult {
		// No evaluable terms at all: impose no constraint.
		return true, true
	}
	return orResult, true
}

// parseFilterTerm parses a single term starting at index i and returns its
// boolean value, the number of tokens consumed, and whether parsing succeeded.
func parseFilterTerm(tokens []string, i int, cve *models.CVE) (value bool, consumed int, ok bool) {
	tok := tokens[i]

	// A "regex:" term greedily consumes the remainder of the expression as the
	// pattern (patterns may contain spaces), so it must be the final term.
	if strings.HasPrefix(tok, "regex:") {
		consumed = len(tokens) - i
		var pattern string
		if tok == "regex:" {
			pattern = strings.Join(tokens[i+1:], " ")
		} else {
			pattern = strings.TrimPrefix(tok, "regex:")
			if i+1 < len(tokens) {
				pattern += " " + strings.Join(tokens[i+1:], " ")
			}
		}
		if pattern == "" {
			return true, consumed, true // empty pattern imposes no constraint
		}
		re, err := getPatternRegex(pattern)
		if err != nil {
			slog.Error("Complex filter regex error", "pattern", pattern, "error", err)
			return false, consumed, false // fail closed
		}
		return re.MatchString(cve.Description), consumed, true
	}

	// All other terms are "<variable> <operator> <value>".
	if i+2 >= len(tokens) {
		return false, len(tokens) - i, false // malformed / truncated term
	}
	op := tokens[i+1]
	valTok := tokens[i+2]
	consumed = 3

	switch tok {
	case "epss":
		v, err := strconv.ParseFloat(valTok, 64)
		if err != nil {
			return false, consumed, false
		}
		res, ok := compareFloat(cve.EPSSScore, op, v)
		return res, consumed, ok
	case "severity", "cvss":
		v, err := strconv.ParseFloat(valTok, 64)
		if err != nil {
			return false, consumed, false
		}
		res, ok := compareFloat(cve.CVSSScore, op, v)
		return res, consumed, ok
	case "buzz":
		v, err := strconv.Atoi(valTok)
		if err != nil {
			return false, consumed, false
		}
		res, ok := compareFloat(float64(cve.GitHubPoCCount), op, float64(v))
		return res, consumed, ok
	case "cisa":
		want := valTok == "true"
		switch op {
		case "==", "=":
			return cve.CISAKEV == want, consumed, true
		case "!=":
			return cve.CISAKEV != want, consumed, true
		default:
			return false, consumed, false
		}
	default:
		return false, consumed, false // unknown variable: fail closed
	}
}

// compareFloat applies a comparison operator. The second return value is false
// for unrecognized operators so the caller can fail closed.
func compareFloat(actual float64, op string, want float64) (bool, bool) {
	switch op {
	case ">":
		return actual > want, true
	case ">=":
		return actual >= want, true
	case "<":
		return actual < want, true
	case "<=":
		return actual <= want, true
	case "==", "=":
		return actual == want, true
	case "!=":
		return actual != want, true
	default:
		return false, false
	}
}

// notifyIfNewWithCache allows bypassing the DB existence check if a pre-fetched cache is available.
func (w *Worker) notifyIfNewWithCache(ctx context.Context, userID int, cve *models.CVE, sub models.UserSubscription, email, assetName string, notifiedCache map[int]bool) bool {
	if notifiedCache != nil && notifiedCache[userID] {
		return false
	}
	// Note: We don't do an EXISTS check here because we assume the cache is authoritative or
	// we will rely on the ON CONFLICT DO NOTHING during insertion if cache is nil.
	// However, for safety when cache is nil, we should still check.
	if notifiedCache == nil {
		var exists bool
		_ = w.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM alert_history WHERE user_id = $1 AND cve_id = $2)", userID, cve.ID).Scan(&exists)
		if exists {
			return false
		}
	}

	// 21. Alert Flood Protection (Rate limiting per user/hour)
	floodKey := fmt.Sprintf("flood_protection:%d", userID)
	count, _ := w.Redis.Incr(ctx, floodKey).Result()
	if count == 1 {
		w.Redis.Expire(ctx, floodKey, 1*time.Hour)
	}
	if count > 50 { // Max 50 alerts per hour
		if count == 51 {
			slog.Warn("Flood Protection: Throttling alerts for user", "user_id", userID)
		}
		return false
	}

	// Ensure we have full details if the job only provided minimal data
	// If the job unmarshaled from Redis has CVEID, we assume it's full.
	if cve.CVEID == "" {
		err := w.Pool.QueryRow(ctx, `
			SELECT cve_id, COALESCE(description, ''), COALESCE(cvss_score, 0), COALESCE(vector_string, ''), cisa_kev, COALESCE(epss_score, 0), COALESCE(cwe_id, ''), COALESCE(github_poc_count, 0), published_date, "references"
			FROM cves WHERE id = $1
		`, cve.ID).Scan(&cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.VectorString, &cve.CISAKEV, &cve.EPSSScore, &cve.CWEID, &cve.GitHubPoCCount, &cve.PublishedDate, &cve.References)
		if err != nil {
			w.Redis.Decr(ctx, floodKey)
			slog.Error("Failed to fetch full CVE details for alert", "id", cve.ID, "error", err)
			return false
		}
	}

	// OSINT data depends only on the CVE, not the recipient. This runs once per
	// subscriber for the same *models.CVE, so reuse whatever an earlier iteration
	// already fetched.
	if cve.OSINTData == nil {
		cve.OSINTData = w.fetchOSINTLinks(ctx, cve.CVEID)
	}

	if !w.bufferAlert(ctx, userID, cve, sub, email, assetName) {
		w.Redis.Decr(ctx, floodKey)
		return false
	}

	_, err := w.Pool.Exec(ctx, "INSERT INTO alert_history (user_id, cve_id, sent_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING", userID, cve.ID)
	if err != nil {
		slog.Error("Failed to record alert history", "user_id", userID, "cve_id", cve.CVEID, "error", err)
	}

	return true
}
