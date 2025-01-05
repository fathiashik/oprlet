package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "github.com/jung-kurt/gofpdf/v2"
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
var configPath = "configuration/config.json"
var sqlPayloadPath = "payloads/sql_payloads.txt"
var xssPayloadPath = "payloads/xss_payloads.txt"
var dirPayloadPath = "payloads/dir_payloads.txt"

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

    loadConfig(configPath)
    getInput()

    for _, url := range targetURLs {
        fmt.Printf("Scanning %s...\n", url)
        for _, vulnerability := range config.Vulnerabilities {
            checkVulnerability(url, vulnerability)
        }
    }

    saveResults("results.json")
    generatePDFReport("scan_report.pdf")
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
    payloads := loadPayloads(sqlPayloadPath)
    for _, payload := range payloads {
        scanURL(url, payload, "sql-injection")
    }
}

func testXSS(url string) {
    payloads := loadPayloads(xssPayloadPath)
    for _, payload := range payloads {
        scanURL(url, payload, "xss")
    }
}

func testDirTraversal(url string) {
    payloads := loadPayloads(dirPayloadPath)
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

func generatePDFReport(filename string) {
    pdf := gofpdf.New("P", "mm", "A4", "")
    pdf.AddPage()
    pdf.SetFont("Arial", "B", 16)
    pdf.Cell(40, 10, "Oprlet - Vulnerability Scan Report")
    pdf.Ln(20)

    pdf.SetFont("Arial", "", 12)
    for _, result := range results {
        pdf.Cell(0, 10, fmt.Sprintf("URL: %s", result.URL))
        pdf.Ln(8)
        pdf.Cell(0, 10, fmt.Sprintf("Vulnerability: %s", result.Vulnerability))
        pdf.Ln(8)
        pdf.Cell(0, 10, fmt.Sprintf("Status: %s", result.Status))
        pdf.Ln(12)
    }

    err := pdf.OutputFileAndClose(filename)
    if err != nil {
        fmt.Printf("Error creating PDF report: %s\n", err)
    }
}

func checkForUpdates() {
    fmt.Println("Checking for updates...")

    originalConfig, _ := ioutil.ReadFile("original_config.json")
    currentConfig, _ := ioutil.ReadFile(configPath)

    if string(originalConfig) != string(currentConfig) {
        fmt.Println("Configuration file has been updated.")
        loadConfig(configPath)
    } else {
        fmt.Println("Configuration file is up-to-date.")
    }

    originalSQLPayloads, _ := ioutil.ReadFile("original_sql_payloads.txt")
    currentSQLPayloads, _ := ioutil.ReadFile(sqlPayloadPath)

    if string(originalSQLPayloads) != string(currentSQLPayloads) {
        fmt.Println("SQL payload file has been updated.")
    } else {
        fmt.Println("SQL payload file is up-to-date.")
    }

    originalXSSPayloads, _ := ioutil.ReadFile("original_xss_payloads.txt")
    currentXSSPayloads, _ := ioutil.ReadFile(xssPayloadPath)

    if string(originalXSSPayloads) != string(currentXSSPayloads) {
        fmt.Println("XSS payload file has been updated.")
    } else {
        fmt.Println("XSS payload file is up-to-date.")
    }

    originalDirPayloads, _ := ioutil.ReadFile("original_dir_payloads.txt")
    currentDirPayloads, _ := ioutil.ReadFile(dirPayloadPath)

    if string(originalDirPayloads) != string(currentDirPayloads) {
        fmt.Println("Directory traversal payload file has been updated.")
    } else {
        fmt.Println("Directory traversal payload file is up-to-date.")
    }
}
