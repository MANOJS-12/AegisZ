# AegisZ
A URL Inspection Framework for Early Threat Identification
# Features
1. Asynchronous HTTP Requests: Uses aiohttp for efficient, non-blocking network requests.
2. Comprehensive Checks:
    - Domain age (flags domains under 6 months).
    - Google Safe Browsing API integration for malware and phishing detection.
    - Google indexing check to identify unindexed sites.
    - SSL certificate validation, including expiry checks.
    - Detection of URL shorteners.
    - Suspicious URL format analysis (e.g., excessive hyphens or subdomains).
    - Webpage content analysis for phishing-related keywords.
3. Configurable: Uses a YAML configuration file for API keys and settings.
4. Rich CLI Interface: Powered by the rich library for colorful, formatted output.
5. Robust Error Handling: Gracefully handles network errors, timeouts, and invalid inputs.
6. Logging: Detailed logging for debugging and tracking issues.
# Requirements
1. Python 3.8 or higher
2. Required Python packages:
    - aiohttp
    - validators
    - pyyaml
    - python-whois
    - beautifulsoup4
    - rich
# Installation
## Clone the repository
    git clone https://github.com/MANOJS-12/aegisz.git
    cd aegisz
## Install Dependencies
    pip install aiohttp validators pyyaml python-whois beautifulsoup4 rich
## API Key Configuration
    google_safe_browsing_api_key: "your_api_key_here"
Obtain a Google Safe Browsing API key from the Google Cloud Console and replace your_api_key_here with your key.
## Run the Script
    python aegisz.py
# Usage
## Launch the script
    python aegisz.py
1. Choose an option from the menu
        - Check a URL: Enter a URL to analyze for phishing risks.
        - Exit: Close the program.
2. View the results
        - The tool performs multiple checks and displays results in a table.
        - A risk score is calculated, categorizing the URL as:
            High Risk (Score ≥ 7): Likely a phishing site.
            Warning (Score ≥ 4): Suspicious site.
            Caution (Score ≥ 2): Some risk factors detected.
            Safe (Score < 2): No major issues detected.


