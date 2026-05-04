package worker

import (
	"context"
	"cve-tracker/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"time"
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
			log.Println("Error reading from alerts queue:", err)
			time.Sleep(1 * time.Second)
			continue
		}
		var cve models.CVE
		if err := json.Unmarshal([]byte(result[1]), &cve); err != nil {
			log.Printf("Error unmarshaling alert job: %v", err)
			continue
		}
		w.evaluateSubscriptions(ctx, &cve)
	}
}

func (w *Worker) evaluateSubscriptions(ctx context.Context, cve *models.CVE) {
	rows, err := w.Pool.Query(ctx, `
		SELECT s.id, s.user_id, s.keyword, s.min_severity, s.webhook_url, s.slack_webhook_url, s.teams_webhook_url, 
		       s.enable_email, s.enable_webhook, s.enable_slack, s.enable_teams, s.enable_browser_push,
		       s.filter_logic, s.aggregation_mode, u.email
		FROM user_subscriptions s
		JOIN users u ON s.user_id = u.id
		WHERE u.is_email_verified = TRUE
		  AND s.min_severity <= $1
		  AND (s.keyword = '' OR $2 ILIKE '%' || REPLACE(REPLACE(REPLACE(s.keyword, '\', '\\'), '%', '\%'), '_', '\_') || '%' ESCAPE '\')
	`, cve.CVSSScore, cve.Description)
	if err != nil {
		log.Println("Error fetching subscriptions:", err)
		return
	}
	defer rows.Close()

	notifiedUsers := make(map[int]bool)
	for rows.Next() {
		var sub models.UserSubscription
		var email string
		var slackURL, teamsURL string
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.Keyword, &sub.MinSeverity, 
			&sub.WebhookURL, &slackURL, &teamsURL,
			&sub.EnableEmail, &sub.EnableWebhook, &sub.EnableSlack, &sub.EnableTeams, &sub.EnableBrowserPush,
			&sub.FilterLogic, &sub.AggregationMode, &email); err != nil {
			log.Printf("Error scanning subscription row: %v", err)
			continue
		}
		sub.SlackWebhookURL = models.DecryptWebhook(slackURL)
		sub.TeamsWebhookURL = models.DecryptWebhook(teamsURL)
		if matchCVE(cve, sub) {
			if w.notifyIfNew(ctx, sub.UserID, cve, sub, email, "") {
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
		log.Println("Error fetching asset keywords:", err)
		return
	}
	defer assetRows.Close()
	for assetRows.Next() {
		var keyword, email, assetName string
		var userID int
		if err := assetRows.Scan(&keyword, &userID, &email, &assetName); err != nil {
			log.Printf("Error scanning asset keyword row: %v", err)
			continue
		}
		if notifiedUsers[userID] {
			continue
		}
		if getKeywordRegex(keyword).MatchString(cve.Description) {
			sub := models.UserSubscription{EnableEmail: true, EnableWebhook: true}
			if w.notifyIfNew(ctx, userID, cve, sub, email, assetName) {
				notifiedUsers[userID] = true
			}
		}
	}
}

func matchCVE(cve *models.CVE, sub models.UserSubscription) bool {
	if sub.Keyword != "" && !getKeywordRegex(sub.Keyword).MatchString(cve.Description) {
		return false
	}
	if sub.MinSeverity > 0 && cve.CVSSScore < sub.MinSeverity {
		return false
	}
	if sub.FilterLogic != "" {
		return evaluateComplexFilter(sub.FilterLogic, cve)
	}
	return true
}

func evaluateComplexFilter(logic string, cve *models.CVE) bool {
	logic = strings.TrimSpace(strings.ToLower(logic))
	if logic == "" {
		return true
	}

	// Simple whitespace-based tokenizer
	tokens := strings.Fields(logic)
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "epss":
			if i+2 < len(tokens) {
				val, err := strconv.ParseFloat(tokens[i+2], 64)
				if err != nil {
					return false
				}
				if tokens[i+1] == ">" && cve.EPSSScore <= val {
					return false
				}
				if tokens[i+1] == ">=" && cve.EPSSScore < val {
					return false
				}
				i += 2
			}
		case "cisa":
			if i+2 < len(tokens) && (tokens[i+1] == "==" || tokens[i+1] == "=") {
				if tokens[i+2] == "true" && !cve.CISAKEV {
					return false
				}
				i += 2
			}
		case "buzz":
			if i+2 < len(tokens) {
				val, err := strconv.Atoi(tokens[i+2])
				if err != nil {
					return false
				}
				if tokens[i+1] == ">" && cve.GitHubPoCCount <= val {
					return false
				}
				if tokens[i+1] == ">=" && cve.GitHubPoCCount < val {
					return false
				}
				i += 2
			}
		default:
			if strings.HasPrefix(tokens[i], "regex:") {
				var pattern string
				if tokens[i] == "regex:" {
					if i+1 < len(tokens) {
						pattern = strings.Join(tokens[i+1:], " ")
					}
				} else {
					pattern = strings.TrimPrefix(tokens[i], "regex:")
					if i+1 < len(tokens) {
						pattern += " " + strings.Join(tokens[i+1:], " ")
					}
				}
				if pattern != "" {
					re, err := getPatternRegex(pattern)
					if err != nil {
						log.Printf("Complex filter regex error: %v", err)
						return false // Fail closed
					}
					if !re.MatchString(cve.Description) {
						return false
					}
					i = len(tokens) - 1
				}
			}
		}
	}

	return true
}

func (w *Worker) notifyIfNew(ctx context.Context, userID int, cve *models.CVE, sub models.UserSubscription, email, assetName string) bool {
	// Check if already notified
	var exists bool
	_ = w.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM alert_history WHERE user_id = $1 AND cve_id = $2)", userID, cve.ID).Scan(&exists)
	if exists {
		return false
	}

	// 21. Alert Flood Protection (Rate limiting per user/hour)
	floodKey := fmt.Sprintf("flood_protection:%d", userID)
	count, _ := w.Redis.Incr(ctx, floodKey).Result()
	if count == 1 {
		w.Redis.Expire(ctx, floodKey, 1*time.Hour)
	}
	if count > 50 { // Max 50 alerts per hour
		if count == 51 {
			log.Printf("Flood Protection: Throttling alerts for user %d", userID)
		}
		return false
	}

	// Ensure we have full details if the job only provided minimal data
	// If the job unmarshaled from Redis has CVEID, we assume it's full.
	if cve.CVEID == "" {
		err := w.Pool.QueryRow(ctx, `
			SELECT cve_id, description, cvss_score, vector_string, cisa_kev, epss_score, cwe_id, github_poc_count, published_date, "references" 
			FROM cves WHERE id = $1
		`, cve.ID).Scan(&cve.CVEID, &cve.Description, &cve.CVSSScore, &cve.VectorString, &cve.CISAKEV, &cve.EPSSScore, &cve.CWEID, &cve.GitHubPoCCount, &cve.PublishedDate, &cve.References)
		if err != nil {
			w.Redis.Decr(ctx, floodKey)
			log.Printf("Failed to fetch full CVE details for alert: %v", err)
			return false
		}
	}

	cve.OSINTData = w.fetchOSINTLinks(ctx, cve.CVEID)

	if !w.bufferAlert(ctx, userID, cve, sub, email, assetName) {
		w.Redis.Decr(ctx, floodKey)
		return false
	}

	_, err := w.Pool.Exec(ctx, "INSERT INTO alert_history (user_id, cve_id, sent_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING", userID, cve.ID)
	if err != nil {
		log.Printf("Failed to record alert history: %v", err)
	}

	return true
}
