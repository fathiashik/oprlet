# Oprlet - Vulnerability Scanner by Ashik

## Welcome to Oprlet! 🚀
Oprlet is a powerful and flexible tool designed to perform automated vulnerability checks on websites, helping you identify potential security weaknesses. The scanner supports SQL Injection, XSS, and Directory Traversal vulnerabilities, utilizing comprehensive payloads for thorough scanning.

## Features
• Automated Scanning: Easily scan single or   multiple target URLs.

• Configurable Payloads: Customize your       scans with external payload files.

• Detailed Reporting: Save scan results in a structured JSON and PDF format.

• User-Friendly: Simple and intuitive         command-line interface.

## Getting Started
# Prerequisites

• Kali Linux

• Go (Golang) installed
## Installation

1. Install Go:
Open your terminal and run the following commands:

      ```sh
   sudo apt update
   sudo apt install golang-go

**2. Clone the Repository:**

Clone the Oprlet repository to your local machine:

        ```sh
    git clone https://github.com/fathiashik/oprlet.git 
    cd oprlet
    chmod +x oprlet.py

**3. Initialize the Go Module:**

Initialize a new Go module to manage dependencies:

    ```bash
     go mod init oprlet

**4. Install the Required Package:**

Install the gofpdf package:

     ```sh
     go get github.com/jung-kurt/gofpdf/v2

**5. Build the Script:**

Compile the Go script to create an executable:

      ```sh
     go build oprlet.go

**6. Run the Script:**

After the script is compiled, you can run the executable. When prompted, enter either a single target URL or the path to your text file containing multiple URLs:

      ```sh
    ./oprlet

## Example Usage

   To scan a single URL:

      ```sh
      ./oprlet

When prompted, enter: http://example.com

To scan multiple URLs from a file:

    ```sh
    ./oprlet

    When prompted, enter: /path/to/your/targets.txt


## Generating PDF Report

The script will automatically generate a detailed PDF report named scan_report.pdf in the current directory after the scan is complete.

## Contributing

Feel free to contribute to this project by forking the repository, making changes, and submitting a pull request. All contributions are welcome!

    







