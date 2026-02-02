# Regex Data Extraction & Secure Validation

## Overview
This project simulates a real-world system that processes raw text data returned from an external API.  
The goal is to **extract structured data using regex**, while also demonstrating **validation, security awareness, and defensive handling of untrusted input**.

The program reads realistic mixed-format text, extracts multiple data types, validates them against real-world rules, and outputs structured JSON.

---

## Data Types Extracted
The program extracts and validates the following data types:

- **Email addresses**  
  Example: `jane.doe@company.co.uk`  
  Invalid formats such as `admin@localhost` or `test@@example.com` are ignored.

- **URLs**  
  Only `http://` and `https://` URLs are accepted.  
  Unsafe schemes such as `javascript:` and `data:` are rejected.

- **Phone numbers**  
  Supports multiple real-world formats:  
  `(415) 555-0132`, `415-555-0132`, `415.555.0132`, `+1 415 555 0199`

- **Credit card numbers**  
  Extracted using regex and **validated with the Luhn algorithm**.  
  Invalid or fake card numbers are rejected.

- **Time values**  
  Supports both 24-hour and 12-hour formats:  
  `14:30`, `2:30 PM`, `02:30 pm`  
  Invalid times such as `24:01` or `9:70 AM` are rejected.

- **Currency amounts**  
  Examples: `$19.99`, `$1,234.56`, `$12`

- **Hashtags**  
  Examples: `#LaunchDay`, `#ThisIsAHashtag`  
  Invalid hashtags starting with numbers (e.g. `#123start`) are ignored.

- **HTML tags**  
  Tags are extracted and **classified as safe or unsafe** based on content.

---

## Security Considerations
This project assumes that **input is not trustworthy** and applies multiple defensive techniques:

- **URL validation**  
  Only `http` and `https` schemes are allowed to prevent XSS-style attacks.

- **Credit card protection**  
  - Numbers must pass the Luhn check  
  - Output is masked (only last 4 digits shown)

- **Email protection**  
  Email addresses are masked in output to prevent unnecessary exposure.

- **HTML safety awareness**  
  HTML tags are flagged as unsafe if they contain:
  - `<script>` tags  
  - Event-handler attributes such as `onclick=` or `onerror=`  
  - `javascript:` in attributes

- **Malformed input handling**  
  Invalid, incomplete, or malicious patterns are safely ignored rather than processed.

---

## Input Design
The sample input file (`samples/input.txt`) is intentionally **messy and realistic**, resembling:
- API logs
- User-generated content
- Payment attempts
- Tracking URLs
- Mixed valid and invalid data

This reflects how data appears in real production systems.

---

## Output
- Results are printed as **structured JSON**
- A copy is saved to `samples/output.json`
- Sensitive data (emails and credit cards) is masked in outputs

---

## How to Run
Make sure Python 3 is installed, then run:

```bash
python src/main.py
