package sitegoose

// Crawlers module: counts the search engines and AI bots that fetch the site
// and sends one row a minute per bot, page and status to POST /events/crawlers
// (sdk/protocols/crawlers.md). This traffic is invisible to the browser
// tracker, because crawlers don't run JavaScript: the server is the only
// place it can be counted.
//
// Only requests whose user agent names a known crawler are counted, so
// visitors are never counted twice. Nothing about a visitor is sent; bot
// addresses go with the batch only so the collector can check a crawler is
// itself, and are not stored.

import (
	"context"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	crawlersFlush  = 60 * time.Second
	maxIPsPerBot   = 5
	maxCrawlerPath = 400
)

// The catalogue of the protocol, most specific first: "ChatGPT-User" must be
// tried before "GPTBot", "Claude-User" before "ClaudeBot". Keep in step with
// the collector (expresscollect/Analytics/crawlers.js CATALOGUE).
var botCatalogue = [][2]string{
	// Fetched because a person asked an AI about the page.
	{"ChatGPT-User", `ChatGPT-User`},
	{"OAI-SearchBot", `OAI-SearchBot`},
	{"Perplexity-User", `Perplexity-User`},
	{"Claude-User", `Claude-User`},
	{"Claude-SearchBot", `Claude-SearchBot`},
	{"MistralAI-User", `MistralAI-User`},
	{"MistralAI-SearchBot", `MistralAI-SearchBot`},
	{"Meta-ExternalFetcher", `meta-externalfetcher`},
	// Bulk collection, for training or a dataset.
	{"GPTBot", `GPTBot`},
	{"ClaudeBot", `ClaudeBot|Claude-Web`},
	{"anthropic-ai", `anthropic-ai`},
	{"CCBot", `CCBot`},
	{"Bytespider", `Bytespider`},
	{"Meta-ExternalAgent", `meta-externalagent|facebookbot`},
	{"Amazonbot", `Amazonbot`},
	{"Diffbot", `Diffbot`},
	{"omgili", `omgili`},
	{"AI2Bot", `AI2Bot`},
	{"Timpibot", `Timpibot`},
	{"Webzio-Extended", `Webzio-Extended`},
	{"PerplexityBot", `PerplexityBot`},
	{"DuckAssistBot", `DuckAssistBot`},
	{"YouBot", `YouBot`},
	// Search engines. Google's tools before Googlebot itself.
	{"Google-InspectionTool", `Google-InspectionTool`},
	{"Storebot-Google", `Storebot-Google`},
	{"AdsBot-Google", `AdsBot-Google`},
	{"Googlebot", `Googlebot|Google-Site-Verification`},
	{"bingbot", `bingbot|BingPreview|adidxbot`},
	{"YandexBot", `Yandex(Bot|Mobile|Images|Webmaster)?`},
	{"Baiduspider", `Baiduspider`},
	{"DuckDuckBot", `DuckDuckBot|DuckDuckGo-Favicons`},
	{"Applebot", `Applebot`},
	{"PetalBot", `PetalBot|AspiegelBot`},
	{"SeznamBot", `SeznamBot`},
	{"Yeti", `Yeti/`},
	{"MojeekBot", `MojeekBot`},
	{"Qwantbot", `Qwantbot|Qwantify`},
	// SEO and backlink tools.
	{"AhrefsBot", `AhrefsBot|AhrefsSiteAudit`},
	{"SemrushBot", `SemrushBot|SiteAuditBot`},
	{"DotBot", `DotBot`},
	{"MJ12bot", `MJ12bot`},
	{"BLEXBot", `BLEXBot`},
	{"DataForSeoBot", `DataForSeoBot`},
	{"Barkrowler", `Barkrowler`},
	{"ScreamingFrog", `Screaming\s?Frog`},
	{"ZoominfoBot", `ZoominfoBot`},
	// Link previews.
	{"facebookexternalhit", `facebookexternalhit`},
	{"Twitterbot", `Twitterbot`},
	{"LinkedInBot", `LinkedInBot`},
	{"Slackbot", `Slackbot|Slack-ImgProxy`},
	{"Discordbot", `Discordbot`},
	{"TelegramBot", `TelegramBot`},
	{"WhatsApp", `WhatsApp`},
	{"Pinterestbot", `Pinterest(bot)?/`},
	{"redditbot", `redditbot`},
	// Uptime and speed checks.
	{"UptimeRobot", `UptimeRobot`},
	{"Pingdom", `Pingdom`},
	{"BetterUptime", `Better\s?Uptime|betteruptime`},
	{"Lighthouse", `Chrome-Lighthouse|Google Page Speed`},
	{"GTmetrix", `GTmetrix`},
	// Archives.
	{"ia_archiver", `ia_archiver`},
	{"archive.org_bot", `archive\.org_bot|Wayback`},
}

type compiledBot struct {
	name    string
	pattern *regexp.Regexp
}

var bots = func() []compiledBot {
	out := make([]compiledBot, len(botCatalogue))
	for i, b := range botCatalogue {
		out[i] = compiledBot{b[0], regexp.MustCompile(`(?i)` + b[1])}
	}
	return out
}()

// Anything else that names itself a bot: counted as "Other bot", so a new
// crawler shows up as traffic instead of disappearing.
var genericBot = regexp.MustCompile(`(?i)bot\b|crawler|crawling|spider|scrapy|curl/|wget/|python-requests|headlesschrome|http-client|okhttp|java/|go-http-client`)

// DetectCrawler is the crawler's catalogue name, or "" when the user agent isn't one.
func DetectCrawler(userAgent string) string {
	if userAgent == "" {
		return ""
	}
	for _, b := range bots {
		if b.pattern.MatchString(userAgent) {
			return b.name
		}
	}
	if genericBot.MatchString(userAgent) {
		return "Other bot"
	}
	return ""
}

// CrawlersOptions configure Health -> Crawlers.
type CrawlersOptions struct {
	// ServerName names this service; default Options.ServerName, else the host name.
	ServerName string
}

type crawlerKey struct {
	minute int64
	bot    string
	path   string
	status int
}

type crawlerRow struct{ count, bytes, sumMS int64 }

type crawlers struct {
	core       *core
	serverName string
	mu         sync.Mutex
	rows       map[crawlerKey]*crawlerRow
	agents     map[string][]string
	order      []string
	job        *periodic
	now        func() time.Time
}

func newCrawlers(c *core, o CrawlersOptions) *crawlers {
	k := &crawlers{core: c, serverName: truncate(firstNonEmpty(o.ServerName, hostname()), 100),
		rows: map[crawlerKey]*crawlerRow{}, agents: map[string][]string{}, now: time.Now}
	k.job = c.every(crawlersFlush, func() time.Duration {
		k.flush(context.Background(), false)
		return crawlersFlush
	})
	return k
}

// record counts one finished request from a crawler. bot: DetectCrawler(userAgent).
func (k *crawlers) record(bot, path string, status int, ms float64, size int64, ip string) {
	if bot == "" || !k.core.isOn(ModuleCrawlers) {
		return
	}
	clean := path
	if loc := queryOrFragment.FindStringIndex(clean); loc != nil {
		clean = clean[:loc[0]]
	}
	clean = truncate(firstNonEmpty(clean, "/"), maxCrawlerPath)
	minute := k.now().Unix() / 60 * 60
	key := crawlerKey{minute, bot, clean, statusCode(status)}
	k.mu.Lock()
	defer k.mu.Unlock()
	// Past maxRouteKeys a crawler asking for thousands of URLs becomes one
	// row, and past that the status folds to its class.
	if _, ok := k.rows[key]; !ok && len(k.rows) >= maxRouteKeys {
		key.path = "(other)"
		if _, ok := k.rows[key]; !ok && len(k.rows) >= maxRouteKeys+maxFoldedKeys {
			key.status = key.status / 100 * 100
		}
	}
	row := k.rows[key]
	if row == nil {
		row = &crawlerRow{}
		k.rows[key] = row
	}
	row.count++
	if size > 0 {
		row.bytes += size
	}
	if ms > 0 {
		row.sumMS += int64(ms)
	}
	if ip != "" {
		seen, known := k.agents[bot]
		if !known {
			k.order = append(k.order, bot)
		}
		if len(seen) < maxIPsPerBot && !containsString(seen, ip) {
			seen = append(seen, ip)
		}
		k.agents[bot] = seen
	}
}

func (k *crawlers) flush(ctx context.Context, everything bool) {
	current := k.now().Unix() / 60 * 60
	k.mu.Lock()
	var rows []map[string]any
	sent := map[string]bool{}
	for key, v := range k.rows {
		if !everything && key.minute >= current {
			continue
		}
		delete(k.rows, key)
		sent[key.bot] = true
		rows = append(rows, map[string]any{
			"minute": isoMinute(time.Unix(key.minute, 0)), "bot": key.bot, "path": key.path, "status": key.status,
			"count": v.count, "bytes": v.bytes, "sum_ms": v.sumMS,
		})
	}
	agents := []map[string]any{}
	for _, bot := range k.order {
		if sent[bot] {
			agents = append(agents, map[string]any{"bot": bot, "ips": append([]string{}, k.agents[bot]...)})
		}
	}
	if len(rows) > 0 {
		// A bot with rows still waiting (this minute isn't over) keeps its
		// addresses, so the next batch can be checked as well.
		waiting := map[string]bool{}
		for key := range k.rows {
			waiting[key.bot] = true
		}
		var order []string
		for _, bot := range k.order {
			if waiting[bot] {
				order = append(order, bot)
			} else {
				delete(k.agents, bot)
			}
		}
		k.order = order
	}
	k.mu.Unlock()
	for i := 0; i < len(rows); i += maxRows {
		end := i + maxRows
		if end > len(rows) {
			end = len(rows)
		}
		batchAgents := agents
		if i > 0 {
			batchAgents = []map[string]any{}
		}
		k.core.send(ctx, "crawlers", "/events/crawlers", http.MethodPost, map[string]any{
			"server_name": k.serverName, "runtime": runtimeName(), "rows": rows[i:end], "agents": batchAgents,
		}, authBody, nil)
	}
}

func (k *crawlers) close(ctx context.Context) {
	k.job.halt(ctx)
	k.flush(ctx, true)
}
