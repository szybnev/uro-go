package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/szybnev/uro-go/internal/config"
	"github.com/szybnev/uro-go/internal/processor"
	"github.com/szybnev/uro-go/pkg/urlutil"
)

const version = "1.0.2"

// arrayFlags позволяет передавать несколько значений через один флаг
type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ", ")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func main() {
	var (
		inputFile  string
		outputFile string
		whitelist  arrayFlags
		blacklist  arrayFlags
		filters    arrayFlags
		showHelp   bool
		showVer    bool
	)

	flag.StringVar(&inputFile, "i", "", "file containing urls")
	flag.StringVar(&outputFile, "o", "", "output file")
	flag.Var(&whitelist, "w", "only keep these extensions (can be specified multiple times)")
	flag.Var(&whitelist, "whitelist", "only keep these extensions")
	flag.Var(&blacklist, "b", "remove these extensions (can be specified multiple times)")
	flag.Var(&blacklist, "blacklist", "remove these extensions")
	flag.Var(&filters, "f", "additional filters (can be specified multiple times)")
	flag.Var(&filters, "filters", "additional filters")
	flag.BoolVar(&showHelp, "h", false, "show help")
	flag.BoolVar(&showHelp, "help", false, "show help")
	flag.BoolVar(&showVer, "version", false, "show version")

	flag.Parse()

	if showVer {
		fmt.Println("uro version", version)
		return
	}

	if showHelp {
		printHelp()
		return
	}

	// Проверяем keepslash в фильтрах
	keepSlash := false
	cleanFilters := urlutil.CleanArgs(filters)
	for _, f := range cleanFilters {
		if f == "keepslash" {
			keepSlash = true
			break
		}
	}

	// Создаём конфигурацию
	cfg := &config.Config{
		InputFile:  inputFile,
		OutputFile: outputFile,
		Whitelist:  urlutil.CleanArgs(whitelist),
		Blacklist:  urlutil.CleanArgs(blacklist),
		Filters:    cleanFilters,
		KeepSlash:  keepSlash,
	}

	// Создаём процессор
	proc, err := processor.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}

	// Определяем источник ввода
	var input *os.File
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Cannot open input file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		input = f
	} else {
		// Проверяем, есть ли данные в stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Fprintln(os.Stderr, "[ERROR] No input file or stdin.")
			os.Exit(1)
		}
		input = os.Stdin
	}

	// Читаем и обрабатываем строки
	scanner := bufio.NewScanner(input)
	// Увеличиваем буфер для длинных строк
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		proc.ProcessLine(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Error reading input: %v\n", err)
		os.Exit(1)
	}

	// Определяем вывод
	var output *os.File
	if outputFile != "" {
		f, err := os.Create(outputFile) // Overwrite mode (не append)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Cannot create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		output = f
	} else {
		output = os.Stdout
	}

	// Выводим результаты
	proc.Output(output)
}

func printHelp() {
	fmt.Println(`uro - URL deduplication tool for security testing

Usage:
  uro [options]
  cat urls.txt | uro
  uro -i input.txt -o output.txt

Options:
  -i <file>        Input file containing URLs (default: stdin)
  -o <file>        Output file (default: stdout)
  -w, -whitelist   Only keep these extensions
  -b, -blacklist   Remove these extensions
  -f, -filters     Additional filters (see below)
  -h, -help        Show this help
  --version        Show version

Filters:
  hasparams     Only URLs with query parameters
  noparams      Only URLs without parameters
  hasext        Only URLs with file extensions
  noext         Only URLs without extensions
  allexts       Don't filter by extension
  keepcontent   Keep human-written content (blogs, posts)
  keepslash     Keep trailing slash in URLs
  vuln          Only URLs with potentially vulnerable parameters

Examples:
  cat urls.txt | uro
  uro -i urls.txt -o clean.txt
  uro -w php,html,asp < urls.txt
  uro -w php -w html -w asp < urls.txt
  uro -f hasparams -f vuln < urls.txt`)
}
