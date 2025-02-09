# PortSwigger vulnerabilities scraper

## Disclaimer
Written almost entirely by AI, including this doc.

## **Overview**
This project is designed to scrape and maintain an up-to-date JSON file containing structured data about vulnerabilities detected by **Burp Suite** from PortSwigger's website.

The script fetches vulnerability information, including:
- **Vulnerability Name**
- **Default Severity Level**
- **Vulnerability IDs (Hex & Decimal)**
- **CWE Identifiers**
- **Description** (raw HTML)
- **Remediation Guidance** (raw HTML)

The data is automatically updated daily using GitHub Actions to help security professionals and developers access the latest vulnerability information without manual effort. The old records are not removed from the JSON even if they are removed from the website.

---

## **Script Logic**

### **Fetching Data**
- **Vulnerability List**: Scraped from [PortSwigger's Vulnerability List](https://portswigger.net/burp/documentation/scanner/vulnerabilities-list).
- **Detailed Vulnerability Pages**: Direct links are extracted from the table on the vulnerability list page, like [this one](https://portswigger.net/kb/issues/00100200_sql-injection).

### **Parsing Process**
- Extracts vulnerability **Name**, **Severity**, **IDs**, **CWEs**, and **links** from the table.
- Uses **asyncio queues** for concurrency:
  - Vulnerabilities are added to an **input queue**.
  - **Worker tasks** fetch and process vulnerability details concurrently (default: 10 workers).
  - Processed data is placed into an **output queue**.

### **Maintaining Data**
- Reads the existing `vulnerabilities.json` file.
- **Adds new vulnerabilities only**
- **Sorts records** by `id_dec` in ascending order.
- **Rewrites the file** only if new vulnerabilities are found.
- **Commits and pushes** the updated JSON file to the repository.

---

## **Environment Variables** (Optional)
| Variable                   | Default Value                                                                                   | Description                        |
|----------------------------|-------------------------------------------------------------------------------------------------|------------------------------------|
| `VULNERABILITIES_LIST_URL` | `https://portswigger.net/burp/documentation/scanner/vulnerabilities-list`                      | URL to the main vulnerabilities list |
| `OUTPUT_FILE`              | `vulnerabilities.json`                                                                         | Output JSON file path               |
| `MAX_WORKERS`              | `10`                                                                                           | Maximum number of concurrent workers |

You can override these by exporting environment variables:
```bash
export VULNERABILITIES_LIST_URL="https://custom-url.com/vuln-list"
export OUTPUT_FILE="custom_vulnerabilities.json"
export MAX_WORKERS=5
```
