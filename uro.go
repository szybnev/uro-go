// Package uro provides URL deduplication for security testing.
//
// uro removes duplicate and uninteresting URLs from lists without making HTTP requests.
// It filters out incremental URLs, blog posts, duplicate query parameters, and static files.
//
// # Basic Usage
//
//	p := uro.NewProcessor(nil)
//	p.Process("https://example.com/api/users")
//	p.Process("https://example.com/api/users/123")
//	p.Process("https://example.com/api/users/456") // filtered (same pattern as 123)
//	p.Process("https://example.com/style.css")     // filtered (blacklisted extension)
//
//	for _, url := range p.Results() {
//	    fmt.Println(url)
//	}
//
// # With Options
//
//	p := uro.NewProcessor(&uro.Options{
//	    Whitelist: []string{"php", "html"},
//	    Filters:   []string{"hasparams", "vuln"},
//	})
//
// # Processing from io.Reader
//
//	p := uro.NewProcessor(nil)
//	p.ProcessReader(os.Stdin)
//	p.WriteResults(os.Stdout)
package uro

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// Version is the current version of uro
const Version = "1.0.2"

// Options configures the URL processor behavior
type Options struct {
	// Whitelist contains extensions to keep (e.g., []string{"php", "html"}).
	// If set, only URLs with these extensions (or no extension) are kept.
	Whitelist []string

	// Blacklist contains extensions to remove (e.g., []string{"css", "png"}).
	// If empty, the default blacklist is used.
	// Ignored if Whitelist is set.
	Blacklist []string

	// Filters contains active filters. Available filters:
	//   - "hasparams": only URLs with query parameters
	//   - "noparams": only URLs without parameters
	//   - "hasext": only URLs with file extensions
	//   - "noext": only URLs without extensions
	//   - "allexts": don't filter by extension
	//   - "keepcontent": keep human-written content (blogs)
	//   - "keepslash": keep trailing slash in URLs
	//   - "vuln": only URLs with potentially vulnerable parameters
	Filters []string

	// KeepSlash preserves trailing slashes in URLs.
	// Can also be enabled via Filters: []string{"keepslash"}
	KeepSlash bool
}

// Processor handles URL deduplication
type Processor struct {
	opts            *Options
	urlMap          map[string]map[string][]map[string]string
	paramsSeen      map[string]struct{}
	patternsSeen    map[string]struct{}
	contentPrefixes []string
	extList         []string
	filters         []string
	strict          bool
	keepSlash       bool
	reInt           *regexp.Regexp
	reContent       *regexp.Regexp
}

// NewProcessor creates a new URL processor with the given options.
// If opts is nil, default options are used.
func NewProcessor(opts *Options) *Processor {
	if opts == nil {
		opts = &Options{}
	}

	p := &Processor{
		opts:         opts,
		urlMap:       make(map[string]map[string][]map[string]string),
		paramsSeen:   make(map[string]struct{}),
		patternsSeen: make(map[string]struct{}),
		reInt:        regexp.MustCompile(`/\d+([?/]|$)`),
		reContent:    regexp.MustCompile(`(post|blog)s?|docs|support/|/(\d{4}|pages?)/\d+/`),
	}

	p.setupFilters()
	return p
}

// Process adds a URL to the processor for deduplication.
// Returns true if the URL was kept, false if it was filtered out.
func (p *Processor) Process(rawURL string) bool {
	// Normalize
	rawURL = strings.ToValidUTF8(rawURL, "")
	rawURL = strings.TrimSpace(rawURL)
	if !p.keepSlash {
		rawURL = strings.TrimSuffix(rawURL, "/")
	}

	if rawURL == "" {
		return false
	}

	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}

	return p.processURL(u)
}

// ProcessReader reads URLs from an io.Reader (one per line) and processes them.
// Returns the number of URLs that were kept.
func (p *Processor) ProcessReader(r io.Reader) int {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	count := 0
	for scanner.Scan() {
		if p.Process(scanner.Text()) {
			count++
		}
	}
	return count
}

// Results returns all deduplicated URLs as a slice.
func (p *Processor) Results() []string {
	var results []string
	for host, paths := range p.urlMap {
		for path, paramsList := range paths {
			if len(paramsList) > 0 {
				for _, params := range paramsList {
					results = append(results, host+path+mapToQuery(params))
				}
			} else {
				results = append(results, host+path)
			}
		}
	}
	return results
}

// WriteResults writes all deduplicated URLs to an io.Writer.
func (p *Processor) WriteResults(w io.Writer) error {
	for host, paths := range p.urlMap {
		for path, paramsList := range paths {
			if len(paramsList) > 0 {
				for _, params := range paramsList {
					if _, err := fmt.Fprintln(w, host+path+mapToQuery(params)); err != nil {
						return err
					}
				}
			} else {
				if _, err := fmt.Fprintln(w, host+path); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Count returns the number of unique URLs currently stored.
func (p *Processor) Count() int {
	count := 0
	for _, paths := range p.urlMap {
		for _, paramsList := range paths {
			if len(paramsList) > 0 {
				count += len(paramsList)
			} else {
				count++
			}
		}
	}
	return count
}

// Reset clears all processed URLs and resets the processor state.
func (p *Processor) Reset() {
	p.urlMap = make(map[string]map[string][]map[string]string)
	p.paramsSeen = make(map[string]struct{})
	p.patternsSeen = make(map[string]struct{})
	p.contentPrefixes = nil
}

// --- Internal methods ---

func (p *Processor) setupFilters() {
	// Normalize filters
	filters := cleanArgs(p.opts.Filters)

	// Check for special filters
	keepContent := false
	allExts := false
	for _, f := range filters {
		switch f {
		case "keepcontent":
			keepContent = true
		case "allexts":
			allExts = true
		case "keepslash":
			p.keepSlash = true
		}
	}

	// Also check explicit KeepSlash option
	if p.opts.KeepSlash {
		p.keepSlash = true
	}

	// Build active filters list
	activeFilters := []string{}

	// Add removecontent by default (unless keepcontent)
	if !keepContent {
		activeFilters = append(activeFilters, "removecontent")
	}

	// Add extension filter (unless allexts)
	if !allExts {
		if len(p.opts.Whitelist) > 0 {
			activeFilters = append(activeFilters, "whitelist")
			p.extList = cleanArgs(p.opts.Whitelist)
		} else {
			activeFilters = append(activeFilters, "blacklist")
			if len(p.opts.Blacklist) > 0 {
				p.extList = cleanArgs(p.opts.Blacklist)
			} else {
				p.extList = defaultBlacklist
			}
		}
	}

	// Add user filters
	for _, f := range filters {
		if f == "keepcontent" || f == "keepslash" || f == "allexts" {
			continue
		}
		normalized := normalizeFilterName(f)
		if isValidFilter(normalized) {
			activeFilters = append(activeFilters, normalized)
		}
	}

	p.filters = activeFilters

	// Set strict mode
	for _, f := range filters {
		if f == "hasext" || f == "noext" {
			p.strict = true
			break
		}
	}
}

func (p *Processor) processURL(u *url.URL) bool {
	host := u.Scheme + "://" + u.Host
	path := u.Path
	params := paramsToMap(u.RawQuery)

	// Find new params
	newParams := []string{}
	for param := range params {
		if _, seen := p.paramsSeen[param]; !seen {
			newParams = append(newParams, param)
		}
	}

	// Apply filters
	if !p.applyFilters(path, params) {
		return false
	}

	// Update seen params
	for _, param := range newParams {
		p.paramsSeen[param] = struct{}{}
	}

	// Initialize host map if needed
	if _, ok := p.urlMap[host]; !ok {
		p.urlMap[host] = make(map[string][]map[string]string)
	}

	// Check if path exists
	_, pathExists := p.urlMap[host][path]

	if !pathExists {
		// Check numeric pattern
		if p.reInt.MatchString(path) {
			pattern := p.createPattern(path)
			if _, seen := p.patternsSeen[pattern]; seen {
				return false
			}
			p.patternsSeen[pattern] = struct{}{}
		}

		// Add new path
		p.urlMap[host][path] = []map[string]string{}
		if len(params) > 0 {
			p.urlMap[host][path] = append(p.urlMap[host][path], params)
		}
		return true
	}

	// Path exists, check params
	if len(newParams) > 0 {
		p.urlMap[host][path] = append(p.urlMap[host][path], params)
		return true
	} else if len(params) > 0 && compareParams(p.urlMap[host][path], params) {
		p.urlMap[host][path] = append(p.urlMap[host][path], params)
		return true
	}

	return false
}

func (p *Processor) applyFilters(path string, params map[string]string) bool {
	for _, f := range p.filters {
		if !p.applyFilter(f, path, params) {
			return false
		}
	}
	return true
}

func (p *Processor) applyFilter(name, path string, params map[string]string) bool {
	switch name {
	case "hasext":
		return hasExtension(path)
	case "noext":
		return !hasExtension(path)
	case "hasparams":
		return len(params) > 0
	case "noparams":
		return len(params) == 0
	case "whitelist":
		return p.checkWhitelist(path)
	case "blacklist":
		return p.checkBlacklist(path)
	case "removecontent":
		return p.checkContent(path)
	case "vuln":
		return p.checkVuln(params)
	default:
		return true
	}
}

func (p *Processor) checkWhitelist(path string) bool {
	ext := getExtension(path)
	if ext == "" {
		return !p.strict // Keep extensionless unless strict
	}
	for _, e := range p.extList {
		if ext == e {
			return true
		}
	}
	return false
}

func (p *Processor) checkBlacklist(path string) bool {
	ext := getExtension(path)
	if ext == "" {
		return true // Keep extensionless
	}
	for _, e := range p.extList {
		if ext == e {
			return false
		}
	}
	return true
}

func (p *Processor) checkContent(path string) bool {
	// Check hyphen count
	for _, part := range strings.Split(path, "/") {
		if strings.Count(part, "-") > 3 {
			return false
		}
	}

	// Check cached prefixes
	for _, prefix := range p.contentPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}

	// Check regex
	match := p.reContent.FindStringIndex(path)
	if match != nil {
		p.contentPrefixes = append(p.contentPrefixes, path[:match[1]])
	}

	return true
}

func (p *Processor) checkVuln(params map[string]string) bool {
	for param := range params {
		if _, ok := vulnParams[param]; ok {
			return true
		}
	}
	return false
}

func (p *Processor) createPattern(path string) string {
	parts := strings.Split(path, "/")
	newParts := make([]string, 0, len(parts))
	lastIndex := 0

	for i, part := range parts {
		if isDigit(part) {
			lastIndex = i
			newParts = append(newParts, `\d+`)
		} else {
			newParts = append(newParts, regexp.QuoteMeta(part))
		}
	}

	return strings.Join(newParts[:lastIndex+1], "/")
}

// --- Helper functions ---

func paramsToMap(query string) map[string]string {
	result := make(map[string]string)
	if query == "" {
		return result
	}
	for _, pair := range strings.Split(query, "&") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			result[parts[0]] = parts[1]
		} else if len(parts) == 1 && parts[0] != "" {
			result[parts[0]] = ""
		}
	}
	return result
}

func mapToQuery(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(params))
	for k, v := range params {
		pairs = append(pairs, k+"="+v)
	}
	return "?" + strings.Join(pairs, "&")
}

func compareParams(existing []map[string]string, new map[string]string) bool {
	seen := make(map[string]struct{})
	for _, params := range existing {
		for key := range params {
			seen[key] = struct{}{}
		}
	}
	for key := range new {
		if _, ok := seen[key]; !ok {
			return true
		}
	}
	return false
}

func cleanArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	result := make(map[string]struct{})
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if strings.Contains(arg, ",") {
			for _, part := range strings.Split(arg, ",") {
				part = strings.TrimSpace(strings.ToLower(part))
				if part != "" {
					result[part] = struct{}{}
				}
			}
		} else {
			result[strings.ToLower(arg)] = struct{}{}
		}
	}
	output := make([]string, 0, len(result))
	for k := range result {
		output = append(output, k)
	}
	return output
}

func hasExtension(path string) bool {
	lastSlash := strings.LastIndex(path, "/")
	lastPart := path
	if lastSlash >= 0 {
		lastPart = path[lastSlash+1:]
	}
	return strings.Contains(lastPart, ".")
}

func getExtension(path string) string {
	lastSlash := strings.LastIndex(path, "/")
	lastPart := path
	if lastSlash >= 0 {
		lastPart = path[lastSlash+1:]
	}
	lastDot := strings.LastIndex(lastPart, ".")
	if lastDot < 0 {
		return ""
	}
	return strings.ToLower(lastPart[lastDot+1:])
}

func isDigit(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func normalizeFilterName(name string) string {
	switch name {
	case "hasparam":
		return "hasparams"
	case "noparam":
		return "noparams"
	case "hasexts":
		return "hasext"
	case "noexts":
		return "noext"
	default:
		return name
	}
}

func isValidFilter(name string) bool {
	switch name {
	case "hasext", "noext", "hasparams", "noparams", "whitelist", "blacklist", "removecontent", "vuln":
		return true
	default:
		return false
	}
}

// Default blacklist of extensions to filter out
var defaultBlacklist = []string{
	"css", "png", "jpg", "jpeg", "svg", "ico", "webp", "scss",
	"tif", "tiff", "ttf", "otf", "woff", "woff2", "gif",
	"pdf", "bmp", "eot", "mp3", "mp4", "avi",
}

// Vulnerable parameter names
var vulnParams = map[string]struct{}{
	"file": {}, "document": {}, "folder": {}, "root": {}, "path": {},
	"pg": {}, "style": {}, "pdf": {}, "template": {}, "php_path": {},
	"doc": {}, "page": {}, "name": {}, "cat": {}, "dir": {}, "action": {},
	"board": {}, "date": {}, "detail": {}, "download": {}, "prefix": {},
	"include": {}, "inc": {}, "locate": {}, "show": {}, "site": {},
	"type": {}, "view": {}, "content": {}, "layout": {}, "mod": {},
	"conf": {}, "daemon": {}, "upload": {}, "log": {}, "ip": {}, "cli": {},
	"cmd": {}, "exec": {}, "command": {}, "execute": {}, "ping": {},
	"query": {}, "jump": {}, "code": {}, "reg": {}, "do": {}, "func": {},
	"arg": {}, "option": {}, "load": {}, "process": {}, "step": {},
	"read": {}, "function": {}, "req": {}, "feature": {}, "exe": {},
	"module": {}, "payload": {}, "run": {}, "print": {},
	"callback": {}, "checkout": {}, "checkout_url": {}, "continue": {},
	"data": {}, "dest": {}, "destination": {}, "domain": {}, "feed": {},
	"file_name": {}, "file_url": {}, "folder_url": {}, "forward": {},
	"from_url": {}, "go": {}, "goto": {}, "host": {}, "html": {},
	"image_url": {}, "img_url": {}, "load_file": {}, "load_url": {},
	"login_url": {}, "logout": {}, "navigation": {}, "next": {},
	"next_page": {}, "Open": {}, "out": {}, "page_url": {}, "port": {},
	"redir": {}, "redirect": {}, "redirect_to": {}, "redirect_uri": {},
	"redirect_url": {}, "reference": {}, "return": {}, "return_path": {},
	"return_to": {}, "returnTo": {}, "return_url": {}, "rt": {}, "rurl": {},
	"target": {}, "to": {}, "uri": {}, "url": {}, "val": {}, "validate": {},
	"window": {}, "q": {}, "s": {}, "search": {}, "lang": {}, "keyword": {},
	"keywords": {}, "year": {}, "email": {}, "p": {}, "jsonp": {}, "api_key": {},
	"api": {}, "password": {}, "emailto": {}, "token": {}, "username": {},
	"csrf_token": {}, "unsubscribe_token": {}, "id": {}, "item": {}, "page_id": {},
	"month": {}, "immagine": {}, "list_type": {}, "terms": {}, "categoryid": {},
	"key": {}, "l": {}, "begindate": {}, "enddate": {}, "select": {}, "report": {},
	"role": {}, "update": {}, "user": {}, "sort": {}, "where": {}, "params": {},
	"row": {}, "table": {}, "from": {}, "sel": {}, "results": {}, "sleep": {},
	"fetch": {}, "order": {}, "column": {}, "field": {}, "delete": {}, "string": {},
	"number": {}, "filter": {}, "access": {}, "admin": {}, "dbg": {}, "debug": {},
	"edit": {}, "grant": {}, "test": {}, "alter": {}, "clone": {}, "create": {},
	"disable": {}, "enable": {}, "make": {}, "modify": {}, "rename": {},
	"reset": {}, "shell": {}, "toggle": {}, "adm": {}, "cfg": {},
	"open": {}, "img": {}, "filename": {}, "preview": {}, "activity": {},
}
