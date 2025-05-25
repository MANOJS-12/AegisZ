import re
import socket
import asyncio
import aiohttp
import whois
import time
import datetime
import ssl
import json
import logging
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from bs4 import BeautifulSoup
import yaml
import validators

# Initialize console and logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Load configuration from YAML file
def load_config(config_file="config.yaml"):
    try:
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logger.error("Configuration file not found. Using default settings.")
        return {"google_safe_browsing_api_key": "your_api_key_here"}

CONFIG = load_config()

def print_banner():
    banner = """
    █████╗ ███████╗ ██████╗ ██╗███████╗███████╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝╚════██║
  ███████║█████╗  ██║  ███╗██║███████╗ █████║
 ██╔══██║██╔══╝  ██║   ██║██║╚════██║██╔═══╝ 
██║  ██║███████╗╚██████╔╝██║███████║███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝
    """
    console.print(Panel(banner, title="AegisZ", style="bold blue"))

def progress_task(task_name):
    with Progress() as progress:
        task = progress.add_task(f"[cyan]{task_name}...", total=10)
        for _ in range(10):
            time.sleep(0.1)
            progress.update(task, advance=1)

async def check_google_safe_browsing(url, session):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={CONFIG['google_safe_browsing_api_key']}"
    payload = {
        "client": {"clientId": "AegisZ", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        async with session.post(api_url, json=payload, timeout=10) as response:
            response.raise_for_status()
            result = await response.json()
            return bool(result.get("matches", []))
    except aiohttp.ClientError as e:
        logger.error(f"Google Safe Browsing check failed: {e}")
        return False

def check_domain_age(url):
    try:
        domain = urlparse(url).hostname
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return False
        age_days = (datetime.datetime.utcnow() - creation_date).days
        return age_days < 180
    except Exception as e:
        logger.error(f"Domain age check failed: {e}")
        return False

def check_ssl_certificate(url):
    try:
        domain = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                return (expiry - datetime.datetime.utcnow()).days < 30  # Check if cert is near expiry
    except Exception as e:
        logger.error(f"SSL certificate check failed: {e}")
        return True

async def check_google_index(url, session):
    search_url = f"https://www.google.com/search?q=site:{url}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        async with session.get(search_url, headers=headers, timeout=10) as response:
            response.raise_for_status()
            text = await response.text()
            return "did not match any documents" in text.lower()
    except aiohttp.ClientError as e:
        logger.error(f"Google index check failed: {e}")
        return False

async def check_page_content(url, session):
    try:
        async with session.get(url, timeout=10) as response:
            response.raise_for_status()
            soup = BeautifulSoup(await response.text(), "html.parser")
            text = soup.get_text().lower()
            suspicious_keywords = ["login", "password", "credit card", "bank account", "verify your account"]
            return any(keyword in text for keyword in suspicious_keywords)
    except aiohttp.ClientError as e:
        logger.error(f"Page content check failed: {e}")
        return False

def check_shortened_url(url):
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'shorte.st', 'adf.ly', 'cutt.ly', 'v.gd', 'rb.gy', 'soo.gd']
    return urlparse(url).hostname in shorteners

def check_url_format(url):
    """Check if URL has suspicious characteristics (e.g., excessive hyphens, subdomains, or length)."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return (
        len(hostname) > 50 or  # Long domain names
        hostname.count("-") > 3 or  # Excessive hyphens
        hostname.count(".") > 3  # Too many subdomains
    )

async def phishing_detection(url):
    if not validators.url(url):
        console.print("[bold red]Invalid URL format![/bold red]")
        return

    console.print("\n[bold yellow]Running Phishing Detection Checks...[/bold yellow]")
    progress_task("Analyzing URL")

    async with aiohttp.ClientSession() as session:
        checks = {
            "Young domain (under 6 months)": check_domain_age(url),
            "Flagged by Google Safe Browsing": await check_google_safe_browsing(url, session),
            "Not indexed in Google": await check_google_index(url, session),
            "Shortened URL": check_shortened_url(url),
            "No or expiring SSL Certificate": check_ssl_certificate(url),
            "Suspicious page content": await check_page_content(url, session),
            "Suspicious URL format": check_url_format(url),
        }

        table = Table(title="Phishing Check Report", show_header=True, header_style="bold magenta")
        table.add_column("Check", justify="left")
        table.add_column("Result", justify="center")

        risk_score = 0
        risk_weights = {
            "Flagged by Google Safe Browsing": 5,
            "Shortened URL": 3,
            "Young domain (under 6 months)": 2,
            "Not indexed in Google": 1,
            "No or expiring SSL Certificate": 2,
            "Suspicious page content": 3,
            "Suspicious URL format": 2,
        }

        for check, result in checks.items():
            table.add_row(check, "[green]No[/green]" if not result else "[red]Yes[/red]")
            if result:
                risk_score += risk_weights.get(check, 0)

        console.print(table)

        if risk_score >= 7:
            console.print("\n[bold red]⛔ HIGH RISK: Phishing site detected![/bold red]")
        elif risk_score >= 4:
            console.print("\n[bold yellow]🚨 WARNING: This site looks suspicious.[/bold yellow]")
        elif risk_score >= 2:
            console.print("\n[bold cyan]⚠️ CAUTION: Some risk factors detected.[/bold cyan]")
        else:
            console.print("\n[bold green]✅ SAFE: No major issues detected.[/bold green]")

def main():
    print_banner()
    loop = asyncio.get_event_loop()
    while True:
        console.print("\n[bold cyan]1. Check a URL[/bold cyan]")
        console.print("[bold cyan]2. Exit[/bold cyan]")
        choice = input("Select an option: ").strip()
        if choice == "1":
            user_url = input("Enter URL to check: ").strip()
            loop.run_until_complete(phishing_detection(user_url))
        elif choice == "2":
            console.print("[bold green]Exiting...[/bold green]")
            break
        else:
            console.print("[bold red]Invalid option! Try again.[/bold red]")

if __name__ == "__main__":
    main()
