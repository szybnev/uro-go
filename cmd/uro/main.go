package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/szybnev/uro-go"
)

const version = "1.1.0"

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
		workers    int
		stream     bool
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
	flag.IntVar(&workers, "j", 0, "number of parallel workers (0=sequential, -1=NumCPU)")
	flag.BoolVar(&stream, "stream", false, "streaming mode (output URLs as they are processed)")
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
	cleanFilters := cleanArgs(filters)
	for _, f := range cleanFilters {
		if f == "keepslash" {
			keepSlash = true
			break
		}
	}

	// Определяем вывод
	var output *os.File
	if outputFile != "" {
		f, err := os.Create(outputFile) // Overwrite mode
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Cannot create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		output = f
	} else {
		output = os.Stdout
	}

	// Создаём опции для процессора
	opts := &uro.Options{
		Whitelist: cleanArgs(whitelist),
		Blacklist: cleanArgs(blacklist),
		Filters:   cleanFilters,
		KeepSlash: keepSlash,
		Workers:   workers,
	}

	// Настраиваем streaming режим
	var streamMu sync.Mutex
	if stream {
		opts.StreamOutput = func(url string) {
			streamMu.Lock()
			fmt.Fprintln(output, url)
			streamMu.Unlock()
		}
	}

	// Создаём процессор
	proc := uro.NewProcessor(opts)

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

	// Обрабатываем URL
	proc.ProcessReader(input)

	// Выводим результаты (если не streaming режим)
	if !stream {
		proc.WriteResults(output)
	}
}

// cleanArgs очищает и нормализует аргументы
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
  -j <num>         Number of parallel workers (0=sequential, -1=NumCPU)
  --stream         Output URLs immediately as they are processed
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
  uro -f hasparams -f vuln < urls.txt
  uro -j 4 < urls.txt                  # 4 parallel workers
  uro -j -1 --stream < urls.txt        # NumCPU workers, streaming output`)
}
