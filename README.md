# uro

Using a URL list for security testing can be painful as there are a lot of URLs that have uninteresting/duplicate content; **uro** aims to solve that.

It doesn't make any HTTP requests to the URLs and removes:
- incremental URLs e.g. `/page/1/` and `/page/2/`
- blog posts and similar human written content e.g. `/posts/a-brief-history-of-time`
- URLs with same path but parameter value difference e.g. `/page.php?id=1` and `/page.php?id=2`
- images, js, css and other "useless" files

> This is a Go rewrite of the original [Python uro](https://github.com/s0md3v/uro).

## Installation

### CLI Tool
```bash
go install github.com/szybnev/uro-go/cmd/uro@latest
```

### As Library
```bash
go get github.com/szybnev/uro-go
```

### Build locally
```bash
git clone https://github.com/szybnev/uro-go
cd uro
make build
# Binary will be in ./bin/uro
```

## CLI Usage

```bash
cat urls.txt | uro
uro -i input.txt -o output.txt
uro -w php,html,asp < urls.txt
uro -f hasparams -f vuln < urls.txt
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-i <file>` | Input file (default: stdin) |
| `-o <file>` | Output file (default: stdout) |
| `-w` | Whitelist extensions (comma-separated or multiple flags) |
| `-b` | Blacklist extensions |
| `-f` | Add filter |
| `-j <num>` | Number of parallel workers (0=sequential, -1=NumCPU) |
| `--stream` | Output URLs immediately as they are processed |
| `-h` | Show help |
| `--version` | Show version |

### Filters

| Filter | Description |
|--------|-------------|
| `hasparams` | Only URLs with query parameters |
| `noparams` | Only URLs without parameters |
| `hasext` | Only URLs with file extensions |
| `noext` | Only URLs without extensions |
| `allexts` | Don't filter by extension |
| `keepcontent` | Keep human-written content (blogs) |
| `keepslash` | Keep trailing slash in URLs |
| `vuln` | Only URLs with potentially vulnerable parameters |

---

## Library Usage

### Basic Example

```go
package main

import (
    "fmt"
    "github.com/szybnev/uro-go"
)

func main() {
    p := uro.NewProcessor(nil)

    p.Process("https://example.com/api/users")
    p.Process("https://example.com/api/users/123")
    p.Process("https://example.com/api/users/456") // filtered (same pattern)
    p.Process("https://example.com/style.css")     // filtered (blacklisted)

    for _, url := range p.Results() {
        fmt.Println(url)
    }
}
```

### With Options

```go
p := uro.NewProcessor(&uro.Options{
    Whitelist: []string{"php", "html"},
    Filters:   []string{"hasparams", "vuln"},
    KeepSlash: true,
})
```

### Process from io.Reader

```go
p := uro.NewProcessor(nil)

file, _ := os.Open("urls.txt")
defer file.Close()

count := p.ProcessReader(file)
fmt.Printf("Kept %d URLs\n", count)

// Write results
p.WriteResults(os.Stdout)
```

### API Reference

#### Types

```go
// Options configures the URL processor
type Options struct {
    Whitelist    []string      // Extensions to keep (e.g., []string{"php", "html"})
    Blacklist    []string      // Extensions to remove
    Filters      []string      // Active filters: hasparams, noparams, hasext, noext, etc.
    KeepSlash    bool          // Preserve trailing slashes
    Workers      int           // Parallel workers (0=sequential, -1=NumCPU)
    StreamOutput func(string)  // Callback for streaming output
}

// Processor handles URL deduplication
type Processor struct { ... }
```

#### Functions

```go
// NewProcessor creates a new URL processor
func NewProcessor(opts *Options) *Processor

// Process adds a URL for deduplication, returns true if kept
func (p *Processor) Process(rawURL string) bool

// ProcessReader reads URLs from io.Reader, returns count of kept URLs
func (p *Processor) ProcessReader(r io.Reader) int

// Results returns all deduplicated URLs as a slice
func (p *Processor) Results() []string

// WriteResults writes URLs to io.Writer
func (p *Processor) WriteResults(w io.Writer) error

// Count returns number of unique URLs stored
func (p *Processor) Count() int

// Reset clears all processed URLs
func (p *Processor) Reset()
```

### Options Reference

| Option | Type | Description |
|--------|------|-------------|
| `Whitelist` | `[]string` | Keep only these extensions + extensionless URLs |
| `Blacklist` | `[]string` | Remove these extensions (default: common static files) |
| `Filters` | `[]string` | Active filters (see Filters table above) |
| `KeepSlash` | `bool` | Don't strip trailing slashes |
| `Workers` | `int` | Number of parallel workers (0=sequential, -1=NumCPU) |
| `StreamOutput` | `func(string)` | Callback for streaming mode (URLs output immediately) |

### Streaming Mode

```go
p := uro.NewProcessor(&uro.Options{
    StreamOutput: func(url string) {
        fmt.Println(url)  // Output immediately
    },
})
p.ProcessReader(os.Stdin)
```

### Parallel Processing

```go
p := uro.NewProcessor(&uro.Options{
    Workers: 4,  // Use 4 workers, or -1 for NumCPU
    StreamOutput: func(url string) {
        fmt.Println(url)
    },
})
p.ProcessReader(os.Stdin)
```

### Full Example

```go
package main

import (
    "os"
    "github.com/szybnev/uro-go"
)

func main() {
    // Create processor with vuln filter
    p := uro.NewProcessor(&uro.Options{
        Filters: []string{"vuln", "hasparams"},
    })

    // Process from stdin
    p.ProcessReader(os.Stdin)

    // Output results
    p.WriteResults(os.Stdout)
}
```

## License

Apache-2.0
