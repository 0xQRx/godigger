# Combined Domain Intelligence Query Tool

## Overview
This is a multithreaded Go-based tool that queries multiple domain intelligence sources to fetch information about subdomains, IP addresses, or URLs related to a given domain. It supports concurrent execution with adjustable thread limits and optional debugging output.

## Features
- Supports querying domain intelligence from:
  - AlienVault
  - Common Crawl
  - urlscan.io
  - VirusTotal
  - WebArchive
- Multithreaded execution with configurable concurrency (`-t` flag)
- Debug mode for detailed output (`-debug true`)
- Supports proxy usage (`-proxy true`)

## Requirements
- Go 1.17+
- Environment variable `VIRUSTOTAL_API_KEY` must be set to use VirusTotal
- Environment variable `URLSCAN_API_KEY` must be set to use URLScan

## Installation
Clone the repository and build the binary:
```bash
$ go install github.com/0xQRx/godigger@main
```

## Usage
Run the tool with the required parameters:
```bash
$ ./godigger -domain example.com -search ips -proxy false -debug true -t 5
```

### Command-Line Options
| Option      | Description |
|------------|-------------|
| `-domain`  | Target domain for the query (required) |
| `-search`  | Search type: `ips`, `urls`, or `subdomains` (required) |
| `-proxy`   | Use proxy (`true` or `false`, default: `false`) |
| `-debug`   | Enable debug mode (`true` or `false`, default: `false`) |
| `-t`       | Number of concurrent threads (default: `5`) |

## Example Outputs
### Fetching IPs
```bash
$ godigger -domain example.com -search ips -debug true
[DEBUG] AlienVault: Fetching IPs for example.com
192.168.1.1 : example.com
```

### Fetching Subdomains
```bash
$ godigger.go -domain example.com -search subdomains -t 20
```

### Fetching URLs
```bash
$ godigger -domain example.com -search urls -t 10
http://example.com/page1
http://example.com/page2
```

