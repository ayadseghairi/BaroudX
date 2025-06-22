import os
import json
import socket
import whois
import shodan
import dns.resolver
import requests
import ssl
import builtwith
import re
import logging
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# Configure logging
logging.basicConfig(
    filename="logs/cyber_vuln_analyzer.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_whois(domain):
    """
    Retrieve WHOIS information for a given domain.
    """
    try:
        info = whois.whois(domain)
        return {
            "domain_name": info.domain_name,
            "registrar": info.registrar,
            "creation_date": str(info.creation_date),
            "expiration_date": str(info.expiration_date),
            "emails": info.emails,
        }
    except Exception as e:
        logging.error(f"WHOIS error for {domain}: {e}")
        return {"error": f"WHOIS error: {e}"}


def get_dns(domain):
    """
    Retrieve DNS records (A, MX, TXT, NS) for a given domain.
    """
    records = {}
    try:
        records['A'] = [r.to_text() for r in dns.resolver.resolve(domain, 'A', lifetime=5)]
        records['MX'] = [r.to_text() for r in dns.resolver.resolve(domain, 'MX', lifetime=5)]
        records['TXT'] = [r.to_text() for r in dns.resolver.resolve(domain, 'TXT', lifetime=5)]
        records['NS'] = [r.to_text() for r in dns.resolver.resolve(domain, 'NS', lifetime=5)]
    except Exception as e:
        logging.error(f"DNS error for {domain}: {e}")
        records["error"] = str(e)
    return records


def get_shodan(domain):
    """
    Retrieve Shodan information for a given domain.
    """
    try:
        ip = socket.gethostbyname(domain)
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        return {
            "ip": ip,
            "org": result.get("org"),
            "os": result.get("os"),
            "ports": result.get("ports"),
            "vulns": result.get("vulns", [])
        }
    except Exception as e:
        logging.error(f"Shodan error for {domain}: {e}")
        return {"error": f"Shodan error: {e}"}


def get_web_info(domain):
    """
    Analyze web information of the domain including headers, cookies, and links.
    """
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(response.text, "lxml")
        links = [link.get("href") for link in soup.find_all("a") if link.get("href")]

        headers = response.headers
        return {
            "status_code": response.status_code,
            "server": headers.get("Server"),
            "content_type": headers.get("Content-Type"),
            "x_powered_by": headers.get("X-Powered-By"),
            "security_headers": {
                "Content-Security-Policy": headers.get("Content-Security-Policy"),
                "X-Frame-Options": headers.get("X-Frame-Options"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security")
            },
            "cookies": response.cookies.get_dict(),
            "links_found": links[:10]  # Limit to first 10 links for performance
        }
    except Exception as e:
        logging.error(f"Web analysis error for {domain}: {e}")
        return {"error": f"Web analysis error: {e}"}


def get_subdomains(domain):
    """
    Discover common subdomains for the given domain.
    """
    common = ["www", "mail", "ftp", "dev", "test", "api", "blog", "shop"]
    found = []
    for sub in common:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found.append({"subdomain": subdomain, "ip": ip})
        except Exception as e:
            logging.info(f"Subdomain not found: {subdomain} -> {e}")
            continue
    return found


def get_ssl_info(domain):
    """
    Retrieve SSL certificate information for the given domain.
    """
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "subject": dict(cert.get("subject", [])),
                "issuer": dict(cert.get("issuer", [])),
                "valid_from": cert.get("notBefore"),
                "valid_to": cert.get("notAfter"),
            }
    except Exception as e:
        logging.error(f"SSL error for {domain}: {e}")
        return {"error": f"SSL error: {e}"}


def get_tech_stack(domain):
    """
    Identify the technology stack used by the website using BuiltWith.
    """
    try:
        return builtwith.parse(f"https://{domain}")
    except Exception as e:
        logging.error(f"BuiltWith error for {domain}: {e}")
        return {"error": f"BuiltWith error: {e}"}


def get_emails_from_site(domain):
    """
    Extract email addresses from the website content.
    """
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        emails = re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}", response.text)
        return list(set(emails))
    except Exception as e:
        logging.error(f"Email parsing error for {domain}: {e}")
        return {"error": f"Email parsing error: {e}"}


def get_robots_txt(domain):
    """
    Retrieve and parse the robots.txt file of the domain.
    """
    try:
        response = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return response.text.splitlines()
    except Exception as e:
        logging.error(f"robots.txt error for {domain}: {e}")
        return {"error": f"robots.txt error: {e}"}


def get_javascript_secrets(domain):
    """
    Scan a subset of JavaScript files for API keys or secrets.
    """
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(response.text, "lxml")
        scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
        findings = []
        for script_url in scripts[:5]:  # Limit to first 5 scripts for performance
            if script_url.startswith("/"):
                script_url = f"http://{domain}{script_url}"
            if not script_url.startswith("http"):
                continue
            try:
                js_response = requests.get(script_url, timeout=5)
                js_code = js_response.text
                # Search for potential API keys in JavaScript code
                secrets = re.findall(r'API_KEY\s*=\s*[\'"]([A-Za-z0-9_\-]+)[\'"]', js_code)
                if secrets:
                    findings.append({"script": script_url, "api_keys": secrets})
            except Exception as js_e:
                logging.warning(f"JS script error {script_url}: {js_e}")
                continue
        return findings
    except Exception as e:
        logging.error(f"JavaScript analysis error for {domain}: {e}")
        return {"error": f"JavaScript analysis error: {e}"}


def run(domain):
    """
    Run the reconnaissance modules and save the results in a JSON file.
    """
    logging.info(f"Starting recon for: {domain}")
    result = {
        "whois": get_whois(domain),
        "dns": get_dns(domain),
        "shodan": get_shodan(domain),
        "web": get_web_info(domain),
        "subdomains": get_subdomains(domain),
        "ssl": get_ssl_info(domain),
        "tech_stack": get_tech_stack(domain),
        "emails": get_emails_from_site(domain),
        "robots_txt": get_robots_txt(domain),
        "javascript_secrets": get_javascript_secrets(domain),
    }

    os.makedirs("output", exist_ok=True)
    output_path = f"output/recon-{domain}.json"
    try:
        with open(output_path, "w") as f:
            json.dump(result, f, indent=4)
        logging.info(f"Recon complete. Output saved to {output_path}")
        print(f"[+] Recon complete. Output saved to {output_path}")
    except Exception as e:
        logging.error(f"Error writing output file for {domain}: {e}")
        print(f"[!] Error writing output file: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cyber Vulnerability Analyzer")
    parser.add_argument("--target", required=True, help="Target domain to analyze")
    args = parser.parse_args()

    run(args.target)
