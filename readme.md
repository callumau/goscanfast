
# goscanfast

High-throughput TCP port scanner written in Go. Designed for large CIDR ranges with bounded concurrency and a live TUI.

## Features

- Fast, parallel TCP connect scanning
- Top 10 management ports by default
- Comma-separated port list or JSON port list
- CIDR exclude list via JSON
- Streaming CSV or JSON output
- Live TUI with progress, rate, ETA, and recent finds

## Install

```bash
go build -o goscanfast .
```

## Build for Multiple Platforms

To build for different operating systems and architectures, creating binaries in the `build/` folder:

### Linux
```bash
GOOS=linux GOARCH=amd64 go build -o build/goscanfast-linux-amd64 .
```

### Windows
```bash
GOOS=windows GOARCH=amd64 go build -o build/goscanfast-windows-amd64.exe .
```

### macOS (Intel)
```bash
GOOS=darwin GOARCH=amd64 go build -o build/goscanfast-darwin-amd64 .
```

### macOS (Apple Silicon)
```bash
GOOS=darwin GOARCH=arm64 go build -o build/goscanfast-darwin-arm64 .
```


### Windows
```bash
GOOS=windows GOARCH=amd64 go build -o goscanfast-windows-amd64.exe .
```

### macOS (Apple Silicon)
```bash
GOOS=darwin GOARCH=arm64 go build -o goscanfast-darwin-arm64 .
```

## Usage

```bash
sudo ./goscanfast 10.0.0.0/8 --output results.csv
sudo ./goscanfast 10.0.0.0/8 10.1.0.0/16 --output results.csv
sudo ./goscanfast --targets targets.json --output results.csv
sudo ./goscanfast 10.0.0.0/8 --format json --output results.json
sudo ./goscanfast 10.0.0.0/8 --ports 22,80,443 --output results.csv
sudo ./goscanfast 10.0.0.0/8 --exclude excludes.json --ports ports.json --output results.csv
```

## Reliability Tips

Default settings prioritize speed. On large ranges, some hosts can be missed if timeouts are too tight or rate is too high for your network path.

If results look unexpectedly low:

```bash
sudo ./goscanfast 10.0.0.0/8 --ports 22,80,443 --timeout 2s --retries 2 --rate 256 --output results.csv
```

Also try a small slice (e.g., a /24) first to confirm consistency before scaling up.

## Flags

- `--exclude`: Path to JSON file with CIDR strings to skip.
- `--ports`: Comma-separated list or JSON file with integer ports.
- `--format`: `csv` (default) or `json`.
- `--output`: Output file (required for TUI).
- `--concurrency`: Max concurrent workers (default 1024).
- `--rate`: Max scans per second (default 1024).
- `--timeout`: Per-port timeout (default 0.5s).
- `--retries`: Retries per port (default 1).
- `--port-concurrency`: Max concurrent ports per host (default auto).
- `--tui`: Enable/disable TUI (default true).
- `--targets`: JSON file with CIDR targets.

## JSON Formats

Targets list:

```json
["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
```

Exclude list:

```json
["10.0.0.0/16", "10.5.0.0/24"]
```

Ports list:

```json
[21, 22, 23, 25, 80, 135, 139, 161, 389, 443, 445, 636, 3389, 5985, 5986, 8080]
```


## CSV Output

Columns:

- `ip`
- `hostname` (rDNS)
- `ports` (semicolon-delimited)

## TUI

The TUI shows:

- Completed hosts
- Open ports found
- Average rate (hosts/sec)
- ETA
- Recent port findings

Quit with `q` or `Ctrl+C`.

## Tests

```bash
go test ./...
```

## Synthetic Benchmark (/16)

This benchmark is synthetic: it measures IP generation and a lightweight scan loop without network I/O. It is intended as a baseline throughput indicator only.

```bash
go test ./pkg/scanner -bench=.
```

Look for `BenchmarkSyntheticScan16` in the output.

The realistic benchmark scans a /24 against local TCP listeners and reports an extrapolated `sec_per_/8` metric.
Targets list:

```json
["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
```
