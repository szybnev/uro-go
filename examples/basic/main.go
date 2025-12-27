package main

import (
	"fmt"
	"strings"

	"github.com/szybnev/uro-go"
)

func main() {
	// Example 1: Basic usage
	fmt.Println("=== Basic Usage ===")
	p := uro.NewProcessor(nil)

	urls := []string{
		"https://example.com/api/users",
		"https://example.com/api/users/123",
		"https://example.com/api/users/456", // filtered (same pattern)
		"https://example.com/style.css",     // filtered (blacklisted)
		"https://example.com/page?id=1",
		"https://example.com/page?id=2", // filtered (same params)
		"https://example.com/page?id=3&role=admin",
	}

	for _, u := range urls {
		p.Process(u)
	}

	for _, u := range p.Results() {
		fmt.Println(u)
	}

	// Example 2: With options
	fmt.Println("\n=== With Whitelist ===")
	p2 := uro.NewProcessor(&uro.Options{
		Whitelist: []string{"php", "html"},
	})

	urls2 := []string{
		"https://example.com/index.php",
		"https://example.com/style.css",
		"https://example.com/about.html",
		"https://example.com/api/users", // kept (no extension)
	}

	for _, u := range urls2 {
		p2.Process(u)
	}

	for _, u := range p2.Results() {
		fmt.Println(u)
	}

	// Example 3: Vuln filter
	fmt.Println("\n=== Vuln Filter ===")
	p3 := uro.NewProcessor(&uro.Options{
		Filters: []string{"vuln"},
	})

	urls3 := []string{
		"https://example.com/page?foo=bar",              // filtered (not vuln param)
		"https://example.com/page?id=5",                 // kept
		"https://example.com/page?cmd=whoami",           // kept
		"https://example.com/page?redirect=http://evil", // kept
	}

	for _, u := range urls3 {
		p3.Process(u)
	}

	for _, u := range p3.Results() {
		fmt.Println(u)
	}

	// Example 4: Process from reader
	fmt.Println("\n=== From Reader ===")
	p4 := uro.NewProcessor(nil)

	input := `https://example.com/api/v1
https://example.com/api/v2
https://example.com/image.png`

	p4.ProcessReader(strings.NewReader(input))
	fmt.Printf("Kept %d URLs\n", p4.Count())
}
