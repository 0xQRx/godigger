package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var (
	debug      bool
	userAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0"
	httpClient *http.Client
)

// debugPrint prints messages only if debug is enabled.
func debugPrint(msg string) {
	if debug {
		fmt.Println("[DEBUG]", msg)
	}
}

func main() {
	// Parse command-line flags.
	var domain, searchType string
	var useProxy bool
	var threads int
	flag.StringVar(&domain, "domain", "", "Domain to query")
	flag.StringVar(&searchType, "search", "", "Search type: ips, urls, or subdomains")
	flag.BoolVar(&useProxy, "proxy", false, "Use proxy")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.IntVar(&threads, "t", 5, "Number of threads to use")
	flag.Parse()

	if domain == "" || searchType == "" {
		fmt.Println("Usage: -domain <domain> -search <ips|urls|subdomains> [-proxy true|false] [-debug true|false] [-t <threads>]")
		os.Exit(1)
	}

	// Set up HTTP client with optional proxy and skip TLS certificate verification.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if useProxy {
		proxyURL, err := url.Parse("https://127.0.0.1:8080")
		if err != nil {
			log.Fatal("Invalid proxy URL:", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	httpClient = &http.Client{Transport: transport}

	// Get VirusTotal API key from environment.
	virusTotalAPIKey := os.Getenv("VIRUSTOTAL_API_KEY")
	urlScanAPIKey := os.Getenv("URLSCAN_API_KEY")

	// Define which engines to run based on the search type.
	var engines []string
	switch searchType {
	case "urls":
		engines = []string{"AlienVault", "CommonCrawl", "urlscan", "VirusTotal", "WebArchive"}
	case "ips":
		engines = []string{"AlienVault", "urlscan", "VirusTotal"}
	case "subdomains":
		engines = []string{"AlienVault", "VirusTotal"}
	default:
		fmt.Println("Unknown search type. Use ips, urls, or subdomains.")
		os.Exit(1)
	}

	// Structure to hold each engine's results.
	type EngineResult struct {
		Engine  string
		Results []string
		Err     error
	}

	resultsMap := make(map[string]EngineResult)
	var wg sync.WaitGroup
	resultCh := make(chan EngineResult, len(engines))
	sem := make(chan struct{}, threads)

	// Launch concurrent queries.
	for _, engine := range engines {
		sem <- struct{}{}
		wg.Add(1)
		go func(engine string) {
			defer wg.Done()
			defer func() { <-sem }()
			var res []string
			var err error
			switch engine {
			case "AlienVault":
				res, err = alienvaultSearch(domain, searchType)
			case "CommonCrawl":
				res, err = commoncrawlSearch(domain)
			case "urlscan":
				res, err = urlscanSearch(domain, searchType, urlScanAPIKey)
			case "VirusTotal":
				res, err = virustotalSearch(domain, searchType, virusTotalAPIKey)
			case "WebArchive":
				res, err = webarchiveSearch(domain)
			}
			resultCh <- EngineResult{Engine: engine, Results: res, Err: err}
		}(engine)
	}

	// Wait for all queries to finish and close the channel.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results.
	for result := range resultCh {
		resultsMap[result.Engine] = result
	}

	// Print results (dividers printed only in debug mode).
	for _, engine := range engines {
		header := ""
		switch searchType {
		case "urls":
			switch engine {
			case "AlienVault":
				header = "===== AlienVault URLs ====="
			case "CommonCrawl":
				header = "===== Common Crawl URLs ====="
			case "urlscan":
				header = "===== urlscan URLs ====="
			case "VirusTotal":
				header = "===== VirusTotal URLs ====="
			case "WebArchive":
				header = "===== WebArchive URLs ====="
			}
		case "ips":
			switch engine {
			case "AlienVault":
				header = "===== AlienVault IP Results ====="
			case "urlscan":
				header = "===== urlscan IP Results ====="
			case "VirusTotal":
				header = "===== VirusTotal IP Results ====="
			}
		case "subdomains":
			switch engine {
			case "AlienVault":
				header = "===== AlienVault Subdomains ====="
			case "VirusTotal":
				header = "===== VirusTotal Subdomains ====="
			}
		}
		if debug && header != "" {
			fmt.Println(header)
		}
		if res, ok := resultsMap[engine]; ok {
			if res.Err != nil {
				fmt.Printf("Error: %v\n", res.Err)
			} else {
				for _, line := range res.Results {
					fmt.Println(line)
				}
			}
		}
	}
}

// alienvaultSearch queries the AlienVault API.
func alienvaultSearch(domain, searchType string) ([]string, error) {
	results := []string{}
	baseURL := "https://otx.alienvault.com/otxapi/indicators/domain/"
	client := httpClient

	// For subdomains and IP mappings.
	if searchType == "subdomains" || searchType == "ips" {
		url := baseURL + "passive_dns/" + domain
		debugPrint(fmt.Sprintf("AlienVault: Fetching data for %s", domain))
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return results, err
		}
		req.Header.Set("Host", "otx.alienvault.com")
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			return results, err
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return results, err
		}
		debugPrint("AlienVault response: " + string(body))
		var data struct {
			PassiveDNS []map[string]interface{} `json:"passive_dns"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return results, err
		}
		for _, entry := range data.PassiveDNS {
			if searchType == "subdomains" {
				if hostname, ok := entry["hostname"].(string); ok && hostname != "" {
					results = append(results, hostname)
				}
			} else if searchType == "ips" {
				if address, ok := entry["address"].(string); ok && address != "" {
					// Validate that address is a proper IP.
					if netIP := net.ParseIP(address); netIP != nil {
						hostname := ""
						if h, ok := entry["hostname"].(string); ok {
							hostname = h
						}
						results = append(results, fmt.Sprintf("%s : %s", address, hostname))
					}
				}
			}
		}
	} else if searchType == "urls" {
		// For URLs: paginate through results.
		page := 1
		for {
			url := fmt.Sprintf("%surl_list/%s?limit=500&page=%d", baseURL, domain, page)
			debugPrint(fmt.Sprintf("AlienVault: Fetching URLs for %s, page %d", domain, page))
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return results, err
			}
			req.Header.Set("Host", "otx.alienvault.com")
			req.Header.Set("User-Agent", userAgent)
			resp, err := httpClient.Do(req)
			if err != nil {
				return results, err
			}
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return results, err
			}
			debugPrint("AlienVault response: " + string(body))
			var data struct {
				URLList []map[string]interface{} `json:"url_list"`
			}
			if err := json.Unmarshal(body, &data); err != nil {
				return results, err
			}
			if len(data.URLList) == 0 {
				break
			}
			for _, entry := range data.URLList {
				if urlField, ok := entry["url"].(string); ok && urlField != "" {
					results = append(results, urlField)
				}
			}
			page++
		}
	}
	return results, nil
}

// commoncrawlSearch queries the Common Crawl API (only for URLs).
func commoncrawlSearch(domain string) ([]string, error) {
	results := []string{}
	indexURL := "https://index.commoncrawl.org/collinfo.json"
	queryParam := "*." + domain + "/*"
	debugPrint("Common Crawl: Fetching index data from " + indexURL)
	req, err := http.NewRequest("GET", indexURL, nil)
	if err != nil {
		return results, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return results, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return results, err
	}
	debugPrint("Common Crawl: Successfully fetched index data.")
	var indexes []map[string]interface{}
	if err := json.Unmarshal(body, &indexes); err != nil {
		return results, err
	}
	// Collect available endpoints.
	endpoints := []string{}
	for _, idx := range indexes {
		if endpoint, ok := idx["cdx-api"].(string); ok && endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
	}
	if len(endpoints) == 0 {
		return results, fmt.Errorf("Common Crawl: No endpoints found")
	}
	encodedQuery := url.QueryEscape(queryParam)
	// Query each endpoint.
	for _, endpoint := range endpoints {
		queryURL := fmt.Sprintf("%s?output=json&fl=timestamp,url,mime,status,digest&url=%s", endpoint, encodedQuery)
		debugPrint("Common Crawl: Querying endpoint: " + endpoint)
		debugPrint("Common Crawl: Query URL: " + queryURL)
		req, err := http.NewRequest("GET", queryURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				continue
			}
			if urlField, ok := entry["url"].(string); ok && urlField != "" {
				results = append(results, urlField)
			}
		}
		resp.Body.Close()
	}
	return results, nil
}

// urlscanSearch queries the urlscan.io API (supports IPs and URLs).
func urlscanSearch(domain, searchType string, apiKey string) ([]string, error) {
	results := []string{}
	// Skip processing if searchType is subdomains.
	if searchType == "subdomains" {
		return results, nil
	}
	if apiKey == "" {
		return results, fmt.Errorf("URLScan: URLSCAN_API_KEY not set. Skipping URLScan.")
	}
	baseURL := "https://urlscan.io/api/v1/search/?q=domain:" + url.QueryEscape(domain)
	currentURL := baseURL
	for {
		debugPrint("urlscan: Fetching data from " + currentURL)
		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return results, err
		}
		req.Header.Set("Host", "urlscan.io")
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Api-Key", apiKey)
		resp, err := httpClient.Do(req)
		if err != nil {
			return results, err
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return results, err
		}
		debugPrint("urlscan response: " + string(body))
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			return results, err
		}
		resultsArray, ok := data["results"].([]interface{})
		if !ok || resultsArray == nil {
			return results, fmt.Errorf("urlscan: No results found")
		}
		// Process each result.
		for _, item := range resultsArray {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if searchType == "urls" {
				if task, ok := m["task"].(map[string]interface{}); ok {
					// Only add the URL if the apexDomain matches the target domain.
					if apex, ok := task["apexDomain"].(string); ok && apex == domain {
						if urlField, ok := task["url"].(string); ok && urlField != "" {
							results = append(results, urlField)
						}
					}
				}
			} else if searchType == "ips" {
				if page, ok := m["page"].(map[string]interface{}); ok {
					if ip, ok := page["ip"].(string); ok && ip != "" {
						results = append(results, ip)
					}
				}
			}
		}
		// Check pagination.
		hasMore, _ := data["has_more"].(bool)
		debugPrint(fmt.Sprintf("urlscan: Has more pages: %v", hasMore))
		if !hasMore {
			break
		}
		if len(resultsArray) > 0 {
			lastItem := resultsArray[len(resultsArray)-1]
			m, ok := lastItem.(map[string]interface{})
			if !ok {
				break
			}
			sortField, ok := m["sort"].([]interface{})
			if !ok || len(sortField) < 2 {
				break
			}
			sortTimestamp := fmt.Sprintf("%v", sortField[0])
			sortUUID := fmt.Sprintf("%v", sortField[1])
			sortParam := sortTimestamp + "," + sortUUID
			debugPrint("urlscan: Next page sort: " + sortParam)
			currentURL = baseURL + "&size=10000&search_after=" + url.QueryEscape(sortParam)
		} else {
			break
		}
	}
	return results, nil
}

// virustotalSearch queries the VirusTotal API.
func virustotalSearch(domain, searchType, apiKey string) ([]string, error) {
	results := []string{}
	if apiKey == "" {
		return results, fmt.Errorf("VirusTotal: VIRUSTOTAL_API_KEY not set. Skipping VirusTotal.")
	}
	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain)
	debugPrint("VirusTotal: Fetching data for " + domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return results, err
	}
	req.Header.Set("Host", "www.virustotal.com")
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return results, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return results, err
	}
	debugPrint("VirusTotal response: " + string(body))
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return results, err
	}
	if searchType == "subdomains" {
		if subs, ok := data["subdomains"].([]interface{}); ok {
			for _, s := range subs {
				if sub, ok := s.(string); ok && sub != "" {
					results = append(results, sub)
				}
			}
		}
	} else if searchType == "ips" {
		if resolutions, ok := data["resolutions"].([]interface{}); ok {
			for _, r := range resolutions {
				if m, ok := r.(map[string]interface{}); ok {
					if ip, ok := m["ip_address"].(string); ok && ip != "" {
						results = append(results, ip)
					}
				}
			}
		}
	} else if searchType == "urls" {
		if detected, ok := data["detected_urls"].([]interface{}); ok {
			for _, item := range detected {
				if m, ok := item.(map[string]interface{}); ok {
					if urlField, ok := m["url"].(string); ok && urlField != "" {
						results = append(results, urlField)
					}
				}
			}
		}
		if undetected, ok := data["undetected_urls"].([]interface{}); ok {
			for _, item := range undetected {
				if arr, ok := item.([]interface{}); ok && len(arr) > 0 {
					if urlField, ok := arr[0].(string); ok && urlField != "" {
						results = append(results, urlField)
					}
				}
			}
		}
	}
	return results, nil
}

// webarchiveSearch queries the WebArchive API (only for URLs).
func webarchiveSearch(domain string) ([]string, error) {
	results := []string{}
	subsPrefix := "*."
	apiURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsPrefix, domain)
	debugPrint("WebArchive: Fetching data from " + apiURL)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return results, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return results, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return results, err
	}
	var data [][]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return results, err
	}
	// Skip header (first element) and extract the URL from each subsequent record.
	for i, entry := range data {
		if i == 0 {
			continue
		}
		if len(entry) > 2 {
			if urlField, ok := entry[2].(string); ok && urlField != "" {
				results = append(results, urlField)
			}
		}
	}
	return results, nil
}
