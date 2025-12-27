# uro

[English](README.md)

Использование списка URL для тестирования безопасности может быть болезненным, так как многие URL содержат неинтересный/дублирующийся контент; **uro** решает эту проблему.

Инструмент не делает HTTP-запросов к URL и удаляет:
- инкрементные URL, например `/page/1/` и `/page/2/`
- блог-посты и подобный контент, например `/posts/a-brief-history-of-time`
- URL с одинаковым путём, но разными значениями параметров, например `/page.php?id=1` и `/page.php?id=2`
- изображения, js, css и другие "бесполезные" файлы

> Это Go-версия оригинального [Python uro](https://github.com/s0md3v/uro).

## Установка

### CLI-инструмент
```bash
go install github.com/szybnev/uro-go/cmd/uro@latest
```

### Как библиотека
```bash
go get github.com/szybnev/uro-go
```

### Сборка локально
```bash
git clone https://github.com/szybnev/uro-go
cd uro
make build
# Бинарник будет в ./bin/uro
```

## Использование CLI

```bash
cat urls.txt | uro
uro -i input.txt -o output.txt
uro -w php,html,asp < urls.txt
uro -f hasparams -f vuln < urls.txt
```

### Опции CLI

| Опция | Описание |
|-------|----------|
| `-i <файл>` | Входной файл (по умолчанию: stdin) |
| `-o <файл>` | Выходной файл (по умолчанию: stdout) |
| `-w` | Белый список расширений (через запятую или несколько флагов) |
| `-b` | Чёрный список расширений |
| `-f` | Добавить фильтр |
| `-j <число>` | Количество параллельных воркеров (0=последовательно, -1=NumCPU) |
| `--stream` | Выводить URL сразу по мере обработки |
| `-h` | Показать справку |
| `--version` | Показать версию |

### Фильтры

| Фильтр | Описание |
|--------|----------|
| `hasparams` | Только URL с query-параметрами |
| `noparams` | Только URL без параметров |
| `hasext` | Только URL с расширениями файлов |
| `noext` | Только URL без расширений |
| `allexts` | Не фильтровать по расширению |
| `keepcontent` | Сохранять контент (блоги) |
| `keepslash` | Сохранять trailing slash в URL |
| `vuln` | Только URL с потенциально уязвимыми параметрами |

---

## Использование как библиотеки

### Базовый пример

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
    p.Process("https://example.com/api/users/456") // отфильтрован (тот же паттерн)
    p.Process("https://example.com/style.css")     // отфильтрован (в чёрном списке)

    for _, url := range p.Results() {
        fmt.Println(url)
    }
}
```

### С опциями

```go
p := uro.NewProcessor(&uro.Options{
    Whitelist: []string{"php", "html"},
    Filters:   []string{"hasparams", "vuln"},
    KeepSlash: true,
})
```

### Обработка из io.Reader

```go
p := uro.NewProcessor(nil)

file, _ := os.Open("urls.txt")
defer file.Close()

count := p.ProcessReader(file)
fmt.Printf("Сохранено %d URL\n", count)

// Запись результатов
p.WriteResults(os.Stdout)
```

### Справочник API

#### Типы

```go
// Options настраивает процессор URL
type Options struct {
    Whitelist    []string      // Расширения для сохранения (например, []string{"php", "html"})
    Blacklist    []string      // Расширения для удаления
    Filters      []string      // Активные фильтры: hasparams, noparams, hasext, noext и т.д.
    KeepSlash    bool          // Сохранять trailing slash
    Workers      int           // Параллельные воркеры (0=последовательно, -1=NumCPU)
    StreamOutput func(string)  // Callback для потокового вывода
}

// Processor обрабатывает дедупликацию URL
type Processor struct { ... }
```

#### Функции

```go
// NewProcessor создаёт новый процессор URL
func NewProcessor(opts *Options) *Processor

// Process добавляет URL для дедупликации, возвращает true если сохранён
func (p *Processor) Process(rawURL string) bool

// ProcessReader читает URL из io.Reader, возвращает количество сохранённых URL
func (p *Processor) ProcessReader(r io.Reader) int

// Results возвращает все дедуплицированные URL как slice
func (p *Processor) Results() []string

// WriteResults записывает URL в io.Writer
func (p *Processor) WriteResults(w io.Writer) error

// Count возвращает количество уникальных URL
func (p *Processor) Count() int

// Reset очищает все обработанные URL
func (p *Processor) Reset()
```

### Справочник опций

| Опция | Тип | Описание |
|-------|-----|----------|
| `Whitelist` | `[]string` | Сохранять только эти расширения + URL без расширений |
| `Blacklist` | `[]string` | Удалять эти расширения (по умолчанию: статические файлы) |
| `Filters` | `[]string` | Активные фильтры (см. таблицу фильтров выше) |
| `KeepSlash` | `bool` | Не удалять trailing slash |
| `Workers` | `int` | Количество параллельных воркеров (0=последовательно, -1=NumCPU) |
| `StreamOutput` | `func(string)` | Callback для потокового режима (URL выводятся сразу) |

### Потоковый режим

```go
p := uro.NewProcessor(&uro.Options{
    StreamOutput: func(url string) {
        fmt.Println(url)  // Вывод сразу
    },
})
p.ProcessReader(os.Stdin)
```

### Параллельная обработка

```go
p := uro.NewProcessor(&uro.Options{
    Workers: 4,  // Использовать 4 воркера, или -1 для NumCPU
    StreamOutput: func(url string) {
        fmt.Println(url)
    },
})
p.ProcessReader(os.Stdin)
```

### Полный пример

```go
package main

import (
    "os"
    "github.com/szybnev/uro-go"
)

func main() {
    // Создание процессора с фильтром vuln
    p := uro.NewProcessor(&uro.Options{
        Filters: []string{"vuln", "hasparams"},
    })

    // Обработка из stdin
    p.ProcessReader(os.Stdin)

    // Вывод результатов
    p.WriteResults(os.Stdout)
}
```

## Лицензия

Apache-2.0
