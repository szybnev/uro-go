# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

### Git Conventions

- Commit messages пишутся на **русском языке**
- Группировать изменения в разные коммиты по смыслу
- **НЕ добавлять** "Generated with Claude Code" в commit messages
- Main branch для PR: `main`

### Documentation Tools

- **ALWAYS** используйте Ref (mcp__Ref__ref_search_documentation) при работе с библиотеками для проверки актуальной документации

## Project Overview

uro is a CLI tool for decluttering URL lists used in security testing and web crawling. It removes duplicate/uninteresting URLs without making HTTP requests.

**This is the Go version** of the original Python tool.

## Build & Install

```bash
# Build
make build

# Install globally
make install

# Run tests
make test

# Cross-compile for all platforms
make build-all
```

## Usage

```bash
# Stdin input
cat urls.txt | uro

# File input/output
uro -i input.txt -o output.txt

# Whitelist extensions (comma-separated or multiple flags)
uro -w php,html,asp < urls.txt
uro -w php -w html -w asp < urls.txt

# Blacklist extensions
uro -b jpg,png,js,pdf < urls.txt

# Filters
uro -f hasparams -f vuln < urls.txt
```

### Available Filters

| Filter | Description |
|--------|-------------|
| `hasparams` | Only URLs with query parameters |
| `noparams` | Only URLs without parameters |
| `hasext` | Only URLs with file extensions |
| `noext` | Only URLs without extensions |
| `allexts` | Don't filter by extension |
| `keepcontent` | Keep human-written content (blogs, posts) |
| `keepslash` | Keep trailing slash in URLs |
| `vuln` | Only URLs with potentially vulnerable parameters |

## Architecture

```
cmd/uro/main.go           # CLI entry point, flag parsing, I/O
internal/
├── config/
│   ├── config.go         # Config struct
│   └── defaults.go       # Default blacklist, vuln_params (163 params)
├── filter/
│   ├── filter.go         # Filter interface + Registry
│   ├── extension.go      # HasExt, NoExt, Whitelist, Blacklist filters
│   ├── params.go         # HasParams, NoParams, VulnParam filters
│   └── content.go        # RemoveContent filter (blog detection)
└── processor/
    └── processor.go      # URLProcessor - main deduplication logic
pkg/urlutil/
    └── urlutil.go        # URL parsing utilities
```

### Core Components

**processor.URLProcessor** - Main URL processing logic:
- `ProcessLine()`: Parses and processes a single URL line
- `processURL()`: Deduplicates URLs by host/path/params using `urlMap`
- `createPattern()`: Generates regex patterns for numeric path segments
- `applyFilters()`: Runs filter chain on each URL
- Three-level deduplication: params_seen → urlMap → patternsSeen

**filter.Filter interface** - All filters implement:
- `Name() string`
- `Apply(path string, params map[string]string, meta *Meta) bool`

### Key Data Structures

```go
urlMap        map[string]map[string][]map[string]string  // host → path → []params
paramsSeen    map[string]struct{}                        // global param names seen
patternsSeen  map[string]struct{}                        // numeric path patterns
```

### Regex Patterns

- `reInt`: `/\d+([?/]|$)` — detects numeric IDs in paths
- `reContent`: `(post|blog)s?|docs|support/|/(\d{4}|pages?)/\d+/` — content detection

## Library API

The package can be used as a Go library:

```go
import "github.com/szybnev/uro-go"

// Create processor
p := uro.NewProcessor(&uro.Options{
    Whitelist: []string{"php", "html"},
    Filters:   []string{"hasparams", "vuln"},
})

// Process URLs
p.Process("https://example.com/page?id=1")
p.ProcessReader(os.Stdin)

// Get results
urls := p.Results()
p.WriteResults(os.Stdout)
p.Count()
p.Reset()
```

**Public API** (uro.go):
- `NewProcessor(opts *Options) *Processor` — create processor
- `Process(rawURL string) bool` — add URL, returns true if kept
- `ProcessReader(r io.Reader) int` — process from reader
- `Results() []string` — get all URLs
- `WriteResults(w io.Writer) error` — write to writer
- `Count() int` — number of unique URLs
- `Reset()` — clear state

## Differences from Python Version

1. **CLI syntax**: Use `-w php,html` or `-w php -w html` instead of `-w php html`
2. **Output mode**: `-o` overwrites file (Python version appends)
3. **Bug fix**: `strict` flag now correctly checks for `hasext`/`noext` filters
