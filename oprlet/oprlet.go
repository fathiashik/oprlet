package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "strings"
    "time"
)

type Config struct {
    Vulnerabilities []string `json:"vulnerabilities"`
}

type ScanResult struct {
    URL           string `json:"url"`
    Vulnerability string `json:"vulnerability"`
    Status        string `json:"status"`
}

var config Config
var results []ScanResult
var targetURLs []string

func main() {
    fmt.Println(`
     ____             _      _      
    / __ \           | |    | |     
   | |  | |_ __  _ __| | ___| |_    
   | |  | | '_ \| '__| |/ _ \ __|   
   | |__| | |_) | |  | |  __/ |_    
    \____/| .__/|_|  |_|\___|\__|   
          | |                       
          |_|                       

     Oprlet - Vulnerability Scanner by Ashik
    `)

    loadConfig("config.json")
    getInput()

    for _, url := range targetURLs {
        fmt.Printf("Scanning %s...\n", url)
        for _, vulnerability := range config.Vulnerabilities {
            checkVulnerability(url, vulnerability)
        }
    }

    saveResults("results.json")
}

func loadConfig(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        fmt.Printf("Error opening config file: %s\n", err)
        os.Exit(1)
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    err = decoder.Decode(&config)
    if err != nil {
        fmt.Printf("Error decoding config file: %s\n", err)
        os.Exit(1)
    }
}

func getInput() {
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter a target URL or the path to a file containing URLs: ")
    input, _ := reader.ReadString('\n')
    input = strings.TrimSpace(input)

    if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
        targetURLs = append(targetURLs, input)
    } else {
        file, err := os.Open(input)
        if err != nil {
            fmt.Printf("Error opening file: %s\n", err)
            os.Exit(1)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            targetURLs = append(targetURLs, scanner.Text())
        }

        if err := scanner.Err(); err != nil {
            fmt.Printf("Error reading file: %s\n", err)
            os.Exit(1)
        }
    }
}

func checkVulnerability(url string, vulnerability string) {
    switch vulnerability {
    case "sql-injection":
        testSQLInjection(url)
    case "xss":
        testXSS(url)
    case "directory-traversal":
        testDirTraversal(url)
    default:
        fmt.Printf("Unknown vulnerability: %s\n", vulnerability)
    }
}

func testSQLInjection(url string) {
    payloads := loadPayloads("sql_payloads.txt")
    for _, payload := range payloads {
        scanURL(url, payload, "sql-injection")
    }
}

func testXSS(url string) {
    payloads := loadPayloads("xss_payloads.txt")
    for _, payload := range payloads {
        scanURL(url, payload, "xss")
    }
}

func testDirTraversal(url string) {
    payloads := loadPayloads("dir_payloads.txt")
    for _, payload := range payloads {
        scanURL(url, payload, "directory-traversal")
    }
}

func loadPayloads(filename string) []string {
    file, err := os.Open(filename)
    if err != nil {
        fmt.Printf("Error opening payload file: %s\n", err)
        os.Exit(1)
    }
    defer file.Close()

    var payloads []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        payloads = append(payloads, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading payload file: %s\n", err)
        os.Exit(1)
    }

    return payloads
}

func scanURL(url string, payload string, vulnerability string) {
    client := &http.Client{Timeout: 10 * time.Second}
    fullURL := fmt.Sprintf("%s%s", url, payload)

    resp, err := client.Get(fullURL)
    if err != nil {
        fmt.Printf("Request failed: %s\n", err)
        return
    }
    defer resp.Body.Close()

    status := "No vulnerabilities found"
    if resp.StatusCode == http.StatusOK {
        status = fmt.Sprintf("Potential %s vulnerability found", vulnerability)
    }
    fmt.Printf("%s on %s\n", status, url)

    result := ScanResult{
        URL:           url,
        Vulnerability: vulnerability,
        Status:        status,
    }
    results = append(results, result)
}

func saveResults(filename string) {
    file, err := os.Create(filename)
    if err != nil {
        fmt.Printf("Error creating results file: %s\n", err)
        return
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    err = encoder.Encode(results)
    if err != nil {
        fmt.Printf("Error encoding results: %s\n", err)
    }
}
