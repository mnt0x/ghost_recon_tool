#!/usr/bin/env python3
# Ghost Recon Tool - Passive Domain Reconnaissance
# ASCII logo:
#    ________  __  ___    ___      ____   ____  ________  ________  ______  __
#   / ___/ _ \/ / / / |  / _ \    / __/  / __ \/ ___/ _ \/ ___/ _ \/ __/ _ \/ /
#  /__  / , _/ /_/ /| | / , _/   _\ \   / /_/ / /__/ , _/ /__/ , _/ _// , _/ /
# /____/_/|_|\____/ |___/_/|_|  /___/   \____/\___/_/|_|\___/_/|_/___/_/|_/_/
# For authorized penetration testing and bug bounty engagements only.
# Author: mnt0x

import asyncio
import aiohttp
import aiofiles
import json
import re
import os
import sys
import time
import socket
import random
import hashlib
import base64
import ipaddress
import csv
import io
import logging
import traceback as _traceback
from collections import Counter
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urlparse, quote, urlencode
import argparse
import ssl
import webbrowser
import threading
from aiohttp import web as aio_web

# ── WINDOWS UTF-8 TERMINAL FIX ───────────────────────────────────────────────
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
from rich.live import Live
from rich.columns import Columns
from rich.markup import escape

from bs4 import BeautifulSoup
import tldextract
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from jinja2 import Template

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ghost_recon")

console = Console(
    force_terminal=True,
    legacy_windows=False,
    safe_box=True,
)

# ── MODULE-LEVEL CACHES ───────────────────────────────────────────────────────
_DOH_CACHE: Dict[Tuple[str, str], Tuple[list, float]] = {}
_DOH_CACHE_TTL = 300  # 5 minutes
_CLOUD_RANGES: Dict[str, List[Tuple[Any, str]]] = {}
_CLOUD_RANGES_LOADED = False
_IP_API_SEM: Optional[asyncio.Semaphore] = None  # rate limit: 15 req/s


def _get_ip_api_sem() -> asyncio.Semaphore:
    global _IP_API_SEM
    if _IP_API_SEM is None:
        _IP_API_SEM = asyncio.Semaphore(15)
    return _IP_API_SEM

# ── CREDENTIAL PATTERNS ───────────────────────────────────────────────────────
CRED_PATTERNS = {
    "AWS_KEY":       re.compile(r'AKIA[0-9A-Z]{16}'),
    "Google_API":    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Slack_Token":   re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
    "Stripe_Live":   re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "Stripe_Test":   re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
    "JWT":           re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*'),
    "Private_Key":   re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "Generic_Secret":re.compile(r'(?i)(?:password|passwd|secret|token|api_key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']'),
}

# ── USER AGENTS ───────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.39",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/1.61",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

TIMEOUTS   = {"fast": 10, "balanced": 20, "deep": 45, "turbo": 8}
DELAYS     = {"fast": 0.1, "balanced": 0.5, "deep": 1.0, "turbo": 0.0}
SEMAPHORES = {"fast": 30, "balanced": 50, "deep": 30, "turbo": 100}

# ── DATACLASSES ───────────────────────────────────────────────────────────────
@dataclass
class SubdomainRecord:
    name: str
    sources: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    cname: list = field(default_factory=list)
    takeover_status: str = "UNKNOWN"
    takeover_evidence: str = ""
    wildcard_candidate: bool = False

@dataclass
class EmailRecord:
    email: str
    sources: list = field(default_factory=list)
    role_category: str = "generic"

@dataclass
class TechnologyFinding:
    name: str
    category: str
    evidence: str
    confidence: str
    sources: list = field(default_factory=list)

@dataclass
class DNSRecord:
    type: str
    name: str
    value: str
    source: str = "doh"

@dataclass
class IPRecord:
    ip: str
    asn: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    rdns: str = ""
    cloud_provider: str = ""
    cdn: bool = False

@dataclass
class BreachRecord:
    name: str
    date: str = ""
    data_types: list = field(default_factory=list)
    description: str = ""

@dataclass
class TakeoverRecord:
    subdomain: str
    cname_chain: list = field(default_factory=list)
    provider: str = ""
    status: str = "INVESTIGATE"
    evidence: str = ""
    severity: str = "LOW"

@dataclass
class CloudAsset:
    asset_type: str
    name: str
    url: str = ""
    region: str = ""
    public: bool = False

@dataclass
class WaybackURL:
    url: str
    timestamp: str = ""
    status_code: int = 0
    mime_type: str = ""

@dataclass
class SSLInfo:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san_entries: list = field(default_factory=list)
    expired: bool = False
    days_left: int = 0
    ct_sources: list = field(default_factory=list)

@dataclass
class ReconResult:
    domain: str
    scan_id: str
    scan_date: str
    mode: str
    subdomains: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    dns_records: list = field(default_factory=list)
    ip_records: list = field(default_factory=list)
    ssl_info: list = field(default_factory=list)
    breach_records: list = field(default_factory=list)
    takeover_records: list = field(default_factory=list)
    cloud_assets: list = field(default_factory=list)
    wayback_urls: list = field(default_factory=list)
    whois_data: dict = field(default_factory=dict)
    reputation_data: dict = field(default_factory=dict)
    scores: dict = field(default_factory=dict)
    typosquats: list = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    social_footprint: dict = field(default_factory=dict)
    asn_intelligence: dict = field(default_factory=dict)
    vulnerabilities: list = field(default_factory=list)
    duration_seconds: float = 0.0

# ── TECH SIGNATURES ───────────────────────────────────────────────────────────
TECH_SIGNATURES = {
    "Apache":       {"category": "web_server",   "patterns": [r"Apache[/ ][\d.]+", r"<address>Apache"]},
    "Nginx":        {"category": "web_server",   "patterns": [r"nginx[/ ][\d.]+", r"<hr><center>nginx"]},
    "IIS":          {"category": "web_server",   "patterns": [r"Microsoft-IIS[/ ][\d.]+", r"X-Powered-By: ASP\.NET"]},
    "LiteSpeed":    {"category": "web_server",   "patterns": [r"LiteSpeed"]},
    "Caddy":        {"category": "web_server",   "patterns": [r"Caddy"]},
    "OpenResty":    {"category": "web_server",   "patterns": [r"openresty[/ ][\d.]+"]},
    "Tomcat":       {"category": "web_server",   "patterns": [r"Apache Tomcat", r"Coyote"]},
    "Gunicorn":     {"category": "web_server",   "patterns": [r"gunicorn[/ ][\d.]+"]},
    "Cloudflare":   {"category": "cdn_waf",      "patterns": [r"cloudflare", r"CF-Cache-Status", r"cf-ray"]},
    "Akamai":       {"category": "cdn_waf",      "patterns": [r"akamai", r"AkamaiGHost", r"X-Check-Cacheable"]},
    "Fastly":       {"category": "cdn_waf",      "patterns": [r"Fastly", r"fastly-restarts"]},
    "CloudFront":   {"category": "cdn_waf",      "patterns": [r"CloudFront", r"X-Amz-Cf-Id"]},
    "Incapsula":    {"category": "cdn_waf",      "patterns": [r"incapsula", r"visid_incap_"]},
    "Sucuri":       {"category": "cdn_waf",      "patterns": [r"Sucuri", r"X-Sucuri-ID"]},
    "Imperva":      {"category": "cdn_waf",      "patterns": [r"Imperva", r"X-Iinfo"]},
    "F5-BIG-IP":    {"category": "cdn_waf",      "patterns": [r"BIG-IP", r"TS\w{8}="]},
    "ModSecurity":  {"category": "cdn_waf",      "patterns": [r"Mod_Security"]},
    "WordPress":    {"category": "cms",          "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"WordPress"]},
    "Drupal":       {"category": "cms",          "patterns": [r"Drupal", r"/sites/default/files/"]},
    "Joomla":       {"category": "cms",          "patterns": [r"Joomla", r"/media/jui/"]},
    "Magento":      {"category": "cms",          "patterns": [r"Magento", r"mage/", r"Mage\.Cookies"]},
    "Shopify":      {"category": "cms",          "patterns": [r"cdn\.shopify\.com", r"shopify\.com/s/files"]},
    "Wix":          {"category": "cms",          "patterns": [r"wix\.com", r"X-Wix-"]},
    "Squarespace":  {"category": "cms",          "patterns": [r"Squarespace", r"squarespace\.com"]},
    "Ghost":        {"category": "cms",          "patterns": [r"ghost\.io", r"content/themes/ghost"]},
    "Webflow":      {"category": "cms",          "patterns": [r"Webflow", r"webflow\.com"]},
    "Next.js":      {"category": "framework",    "patterns": [r"__NEXT_DATA__", r"_next/static"]},
    "Nuxt.js":      {"category": "framework",    "patterns": [r"__NUXT__", r"_nuxt/"]},
    "Gatsby":       {"category": "framework",    "patterns": [r"___gatsby", r"gatsby-"]},
    "Hugo":         {"category": "framework",    "patterns": [r"Hugo"]},
    "React":        {"category": "js_framework", "patterns": [r"react\.js", r"ReactDOM", r"__REACT"]},
    "Angular":      {"category": "js_framework", "patterns": [r"ng-version", r"ng-app", r"\[ng-"]},
    "Vue":          {"category": "js_framework", "patterns": [r"vue\.js", r"__vue__", r"v-bind:"]},
    "Svelte":       {"category": "js_framework", "patterns": [r"__svelte"]},
    "jQuery":       {"category": "js_library",   "patterns": [r"jquery[.-][\d.]+\.js", r"jQuery v[\d.]+"]},
    "Bootstrap":    {"category": "css_framework", "patterns": [r"bootstrap\.min\.css", r"bootstrap\.js"]},
    "Tailwind":     {"category": "css_framework", "patterns": [r"tailwindcss", r"tailwind"]},
    "PHP":          {"category": "backend",      "patterns": [r"X-Powered-By: PHP", r"PHPSESSID"]},
    "Node.js":      {"category": "backend",      "patterns": [r"X-Powered-By: Express", r"Express"]},
    "Django":       {"category": "backend",      "patterns": [r"csrfmiddlewaretoken", r"django"]},
    "Flask":        {"category": "backend",      "patterns": [r"Werkzeug"]},
    "Laravel":      {"category": "backend",      "patterns": [r"laravel_session", r"XSRF-TOKEN"]},
    "Ruby-Rails":   {"category": "backend",      "patterns": [r"Phusion Passenger", r"_rails_"]},
    "ASP.NET":      {"category": "backend",      "patterns": [r"ASP\.NET", r"__VIEWSTATE", r"X-AspNet-Version"]},
    "Spring":       {"category": "backend",      "patterns": [r"X-Application-Context"]},
    "GA4":          {"category": "analytics",    "patterns": [r"G-[A-Z0-9]{10}", r"gtag\("]},
    "UA-Analytics": {"category": "analytics",    "patterns": [r"UA-\d{4,}-\d+"]},
    "GTM":          {"category": "tag_manager",  "patterns": [r"GTM-[A-Z0-9]+", r"googletagmanager\.com"]},
    "Hotjar":       {"category": "analytics",    "patterns": [r"hotjar", r"hjid"]},
    "Mixpanel":     {"category": "analytics",    "patterns": [r"mixpanel"]},
    "Segment":      {"category": "analytics",    "patterns": [r"segment\.com"]},
    "HubSpot":      {"category": "marketing",    "patterns": [r"hubspot\.com", r"hs-scripts\.com"]},
    "Intercom":     {"category": "marketing",    "patterns": [r"intercom\.com", r"intercomSettings"]},
    "Zendesk":      {"category": "marketing",    "patterns": [r"zendesk\.com", r"zopim"]},
    "Drift":        {"category": "marketing",    "patterns": [r"drift\.com"]},
    "Mailchimp":    {"category": "marketing",    "patterns": [r"mailchimp\.com", r"list-manage\.com"]},
    "Salesforce":   {"category": "crm",          "patterns": [r"salesforce\.com", r"force\.com"]},
    "Stripe":       {"category": "payments",     "patterns": [r"js\.stripe\.com", r"Stripe\("]},
    "PayPal":       {"category": "payments",     "patterns": [r"paypalobjects\.com"]},
    "AWS-S3":       {"category": "cloud",        "patterns": [r"s3\.amazonaws\.com", r"s3-[a-z]+-[0-9]+\.amazonaws"]},
    "Google-Cloud": {"category": "cloud",        "patterns": [r"storage\.googleapis\.com", r"appspot\.com"]},
    "Azure":        {"category": "cloud",        "patterns": [r"azurewebsites\.net", r"blob\.core\.windows"]},
    "Heroku":       {"category": "cloud",        "patterns": [r"herokuapp\.com"]},
    "Vercel":       {"category": "cloud",        "patterns": [r"vercel\.app", r"now\.sh"]},
    "Netlify":      {"category": "cloud",        "patterns": [r"netlify\.app", r"netlify\.com"]},
    "Okta":         {"category": "auth_sso",     "patterns": [r"okta\.com", r"oktacdn\.com"]},
    "Auth0":        {"category": "auth_sso",     "patterns": [r"auth0\.com", r"cdn\.auth0\.com"]},
    "Google-SSO":   {"category": "auth_sso",     "patterns": [r"accounts\.google\.com", r"gsi/client"]},
    "Azure-AD":     {"category": "auth_sso",     "patterns": [r"login\.microsoftonline\.com"]},
    "Sentry":       {"category": "monitoring",   "patterns": [r"sentry\.io", r"Sentry\.init"]},
    "Datadog":      {"category": "monitoring",   "patterns": [r"datadoghq\.com", r"DD_CLIENT_TOKEN"]},
    "New-Relic":    {"category": "monitoring",   "patterns": [r"newrelic\.com", r"NREUM"]},
    "Dynatrace":    {"category": "monitoring",   "patterns": [r"dynatrace\.com", r"dtrum"]},
    "Google-WS":    {"category": "email_infra",  "patterns": [r"aspmx\.l\.google", r"google\.com\."]},
    "M365":         {"category": "email_infra",  "patterns": [r"mail\.protection\.outlook", r"outlook\.com"]},
    "Proofpoint":   {"category": "email_sec",    "patterns": [r"pphosted\.com", r"proofpoint"]},
    "Mimecast":     {"category": "email_sec",    "patterns": [r"mimecast\.com"]},
    "Sendgrid":     {"category": "email_infra",  "patterns": [r"sendgrid\.net"]},
    "Mailgun":      {"category": "email_infra",  "patterns": [r"mailgun\.org"]},
    "Amazon-SES":   {"category": "email_infra",  "patterns": [r"amazonses\.com"]},
    "Atlassian":    {"category": "devops",       "patterns": [r"atlassian-domain-verification"]},
    "HackerOne":    {"category": "security",     "patterns": [r"hackerone\.com"]},
    "Bugcrowd":     {"category": "security",     "patterns": [r"bugcrowd\.com"]},
}

# ── TAKEOVER FINGERPRINTS ─────────────────────────────────────────────────────
TAKEOVER_FINGERPRINTS = {
    "github_pages":   {"cname": [".github.io", ".github.com"],              "content": ["There isn't a GitHub Pages site here", "For root URLs"],           "severity": "HIGH"},
    "heroku":         {"cname": [".herokudns.com", ".herokuapp.com"],        "content": ["No such app", "herokucdn.com/error-pages/no-such-app"],             "severity": "HIGH"},
    "shopify":        {"cname": [".myshopify.com", ".shopifycloud.com"],     "content": ["Sorry, this shop is currently unavailable"],                         "severity": "HIGH"},
    "tumblr":         {"cname": [".tumblr.com"],                             "content": ["Whatever you were looking for doesn't live here"],                    "severity": "HIGH"},
    "wordpress_com":  {"cname": [".wordpress.com"],                          "content": ["Do you want to register"],                                            "severity": "HIGH"},
    "ghost":          {"cname": [".ghost.io"],                               "content": ["The thing you were looking for is no longer here"],                   "severity": "HIGH"},
    "fastly":         {"cname": [".fastly.net", ".fastlylb.net"],            "content": ["Fastly error: unknown domain"],                                      "severity": "HIGH"},
    "pantheon":       {"cname": [".pantheonsite.io"],                        "content": ["404 error unknown site"],                                             "severity": "HIGH"},
    "azure_websites": {"cname": [".azurewebsites.net", ".trafficmanager.net"], "content": ["404 Web Site not found"],                                          "severity": "HIGH"},
    "aws_s3":         {"cname": [".s3.amazonaws.com", ".s3-website"],        "content": ["NoSuchBucket", "The specified bucket does not exist"],               "severity": "CRITICAL"},
    "aws_cloudfront": {"cname": [".cloudfront.net"],                         "content": ["Bad request", "ERROR: The request could not be satisfied"],          "severity": "HIGH"},
    "zendesk":        {"cname": [".zendesk.com"],                            "content": ["Help Center Closed"],                                                 "severity": "HIGH"},
    "sendgrid":       {"cname": [".sendgrid.net"],                           "content": ["The domain you are looking for is not configured"],                   "severity": "HIGH"},
    "hubspot":        {"cname": [".hubspot.net", ".hs-sites.com"],           "content": ["This page isn't available", "does not exist in our system"],         "severity": "HIGH"},
    "acquia":         {"cname": [".acquia-sites.com"],                       "content": ["If you are an Acquia Cloud customer"],                                "severity": "HIGH"},
    "netlify":        {"cname": [".netlify.app", ".netlify.com"],            "content": ["Not Found - Request ID"],                                             "severity": "HIGH"},
    "vercel":         {"cname": [".vercel.app", ".now.sh"],                  "content": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],         "severity": "HIGH"},
    "surge":          {"cname": [".surge.sh"],                               "content": ["project not found"],                                                  "severity": "HIGH"},
    "bitbucket":      {"cname": [".bitbucket.io"],                           "content": ["Repository not found"],                                               "severity": "HIGH"},
    "read_the_docs":  {"cname": [".readthedocs.io"],                         "content": ["unknown to Read the Docs"],                                           "severity": "HIGH"},
    "intercom":       {"cname": [".custom.intercom.help"],                   "content": ["This page is reserved for artistic dogs"],                            "severity": "HIGH"},
    "freshdesk":      {"cname": [".freshdesk.com"],                          "content": ["We couldn't find the site you're looking for"],                       "severity": "HIGH"},
    "uservoice":      {"cname": [".uservoice.com"],                          "content": ["This UserVoice subdomain is currently available"],                    "severity": "HIGH"},
    "helpscout":      {"cname": [".helpscoutdocs.com"],                      "content": ["No settings were found for this company"],                            "severity": "HIGH"},
    "fly_io":         {"cname": [".fly.dev"],                                "content": ["404 Not Found"],                                                      "severity": "MEDIUM"},
    "canny":          {"cname": [".canny.io"],                               "content": ["There is no such company"],                                           "severity": "HIGH"},
    "webflow":        {"cname": [".webflow.io"],                             "content": ["The page you are looking for doesn't exist"],                         "severity": "MEDIUM"},
    "wix":            {"cname": [".wixdns.net"],                             "content": ["Error ConnectYourDomain"],                                            "severity": "MEDIUM"},
    "squarespace":    {"cname": [".squarespace.com"],                        "content": ["No Such Account"],                                                    "severity": "MEDIUM"},
    "strikingly":     {"cname": [".strikingly.com"],                         "content": ["page not found"],                                                     "severity": "MEDIUM"},
    "tilda":          {"cname": [".tilda.ws"],                               "content": ["Please renew your subscription"],                                     "severity": "MEDIUM"},
    "feedpress":      {"cname": [".feedpress.me"],                           "content": ["The feed has not been found"],                                        "severity": "MEDIUM"},
    "unbounce":       {"cname": [".unbouncepages.com"],                      "content": ["The requested URL was not found"],                                    "severity": "MEDIUM"},
    "agilecrm":       {"cname": [".agilecrm.com"],                           "content": ["Sorry, this page is no longer available"],                            "severity": "MEDIUM"},
    "kajabi":         {"cname": [".kajabi.com"],                             "content": ["The page you were looking for doesn't exist"],                        "severity": "MEDIUM"},
    "desk_com":       {"cname": [".desk.com"],                               "content": ["Please try again or try Desk.com free"],                              "severity": "HIGH"},
    "statuspage":     {"cname": [".statuspage.io"],                          "content": ["You are being redirected"],                                           "severity": "MEDIUM"},
    "landingi":       {"cname": [".landingi.com"],                           "content": ["It looks like you're lost"],                                          "severity": "MEDIUM"},
    "cargo":          {"cname": [".cargocollective.com"],                    "content": ["If you're moving your domain away from Cargo"],                       "severity": "MEDIUM"},
    "launchrock":     {"cname": [".launchrock.com"],                         "content": ["It looks like you may have taken a wrong turn"],                      "severity": "MEDIUM"},
    "simplebooklet":  {"cname": [".simplebooklet.com"],                      "content": ["We can't find this flipbook"],                                        "severity": "MEDIUM"},
    "pingdom":              {"cname": [".pingdom.com"],                      "content": ["pingdom"],                                                 "severity": "LOW"},
    "uptimerobot":          {"cname": [".uptimerobot.com"],                  "content": ["page not found"],                                          "severity": "LOW"},
    "aws_elastic_beanstalk":{"cname": [".elasticbeanstalk.com"],             "content": ["NoSuchApplication", "404 Not Found"],                      "severity": "HIGH"},
    "aws_s3_website":       {"cname": [".s3-website-", ".s3-website."],      "content": ["NoSuchBucket", "403 Forbidden"],                           "severity": "CRITICAL"},
    "digitalocean_spaces":  {"cname": [".digitaloceanspaces.com"],           "content": ["NoSuchBucket"],                                            "severity": "HIGH"},
    "kinsta":               {"cname": [".kinsta.cloud"],                     "content": ["No Site For Domain"],                                      "severity": "HIGH"},
    "wpengine":             {"cname": [".wpengine.com"],                     "content": ["No Site Configured"],                                      "severity": "HIGH"},
    "flywheel":             {"cname": [".getflywheel.com"],                  "content": ["We're sorry"],                                             "severity": "MEDIUM"},
    "render":               {"cname": [".onrender.com"],                     "content": ["No web service found"],                                    "severity": "HIGH"},
    "railway":              {"cname": [".railway.app"],                      "content": ["Application not found"],                                   "severity": "HIGH"},
    "cyclic":               {"cname": [".cyclic.app"],                       "content": ["not found"],                                               "severity": "MEDIUM"},
    "gitbook":              {"cname": [".gitbook.io"],                       "content": ["We could not find what you were looking for"],              "severity": "HIGH"},
    "readme_io":            {"cname": [".readme.io"],                        "content": ["The page you're looking for"],                             "severity": "MEDIUM"},
    "aftership":            {"cname": [".aftership.com"],                    "content": ["Oops"],                                                    "severity": "MEDIUM"},
    "aha":                  {"cname": [".ideas.aha.io"],                     "content": ["There is no portal here"],                                 "severity": "MEDIUM"},
    "campaign_monitor":     {"cname": [".createsend.com"],                   "content": ["Double check the URL"],                                    "severity": "MEDIUM"},
    "acquia_alt":           {"cname": [".acquia-sites.com"],                 "content": ["The site you are looking for could not be found"],         "severity": "HIGH"},
    "frontify":             {"cname": [".frontify.com"],                     "content": ["Not Found"],                                               "severity": "MEDIUM"},
    "hatenablog":           {"cname": [".hatenablog.com"],                   "content": ["404 Blog is not found"],                                   "severity": "MEDIUM"},
    "short_io":             {"cname": [".short.vu"],                         "content": ["Link does not exist"],                                     "severity": "HIGH"},
    "smugmug":              {"cname": [".smugmug.com"],                      "content": ["SmugMug Error Page"],                                      "severity": "MEDIUM"},
    "myshopify_alt":        {"cname": [".myshopify.com"],                    "content": ["Sorry, this shop is currently unavailable"],               "severity": "HIGH"},
    "tictail":              {"cname": [".tictail.com"],                      "content": ["Building beautiful stores"],                               "severity": "LOW"},
    "cloudfront_alt":       {"cname": [".cloudfront.net"],                   "content": ["ERROR: The request could not be satisfied", "Bad request"], "severity": "HIGH"},
    "azure_cdn":            {"cname": [".azureedge.net"],                    "content": ["404 Not Found"],                                           "severity": "MEDIUM"},
    "pantheon_alt":         {"cname": [".pantheon.io"],                      "content": ["404 error unknown site"],                                  "severity": "HIGH"},
    "dokku":                {"cname": [".dokku.me"],                         "content": ["no such app"],                                             "severity": "MEDIUM"},
    "smartjob":             {"cname": [".smartjobboard.com"],                "content": ["This job board website is either expired"],                 "severity": "MEDIUM"},
    "proposify":            {"cname": [".proposify.biz"],                    "content": ["If you need immediate assistance"],                        "severity": "MEDIUM"},
    "bigcartel":            {"cname": [".bigcartel.com"],                    "content": ["Oops! We couldn\\'t find that page."],                     "severity": "LOW"},
    "gemfury":              {"cname": [".fury.io"],                          "content": ["404: This page could not be found."],                      "severity": "MEDIUM"},
}

# ── WILDCARD PATTERNS ─────────────────────────────────────────────────────────
WILDCARD_PATS = [
    re.compile(r"^[a-f0-9]{32}\."),
    re.compile(r"^[a-f0-9]{20,}\."),
    re.compile(r"^\d{10,}\."),
    re.compile(r"^[a-z]{1,2}\d{8,}\."),
]

# ── CLOUD BUCKET PATTERNS ─────────────────────────────────────────────────────
CLOUD_BUCKET_PATTERNS = {
    "s3":     [r"https?://([a-z0-9][a-z0-9\-\.]{2,62})\.s3(?:[-.][\w-]+)?\.amazonaws\.com"],
    "gcs":    [r"https?://storage\.googleapis\.com/([a-z0-9\-_.]+)"],
    "azure":  [r"https?://([a-z0-9][a-z0-9\-]{2,62})\.blob\.core\.windows\.net"],
    "do":     [r"https?://([a-z0-9][a-z0-9\-\.]{2,62})\.digitaloceanspaces\.com"],
}

# ── ROLE EMAIL PATTERNS ───────────────────────────────────────────────────────
ROLE_EMAIL_PREFIXES = {
    "security":  ["security", "abuse", "ciso", "infosec", "bugbounty", "vuln", "pentest", "cert", "csirt", "soc"],
    "admin":     ["admin", "administrator", "postmaster", "webmaster", "hostmaster", "sysadmin", "root"],
    "executive": ["ceo", "cto", "coo", "cfo", "president", "founder", "vp", "director", "ciso"],
    "devops":    ["devops", "sre", "ops", "cloud", "infra", "deploy"],
    "support":   ["support", "help", "helpdesk", "service", "ticket"],
    "sales":     ["sales", "bizdev", "business", "partner", "bd", "partnerships"],
    "hr":        ["hr", "jobs", "careers", "recruiting", "talent", "people"],
    "dev":       ["dev", "developer", "engineer", "engineering", "git", "code"],
    "finance":   ["billing", "finance", "accounting", "invoice", "payment"],
    "info":      ["info", "contact", "hello", "hi", "team", "general"],
    "legal":     ["legal", "compliance", "privacy", "gdpr", "dpo"],
    "marketing": ["marketing", "press", "media", "pr", "comms"],
}

# ── DNS INTELLIGENCE CONSTANTS ────────────────────────────────────────────────
DKIM_SELECTORS = [
    "google", "selector1", "selector2", "selector3", "default", "mail",
    "smtp", "k1", "k2", "k3", "s1", "s2", "dkim", "email", "key1", "key2",
    "mailjet", "sendgrid", "mandrill", "sparkpost", "zendesk", "salesforce",
    "hubspot", "mailchimp", "amazonses", "ses", "postmark", "protonmail",
    "zoho", "yandex", "office365", "mimecast", "proofpoint", "ironport",
    "sig1", "sig2", "main", "primary", "secondary", "test", "prod", "m",
    "s", "smtpout", "dkimout", "mx", "mail2", "newsletter",
    "lists", "bounce", "em", "em1", "em2", "mailer", "outbound",
]

SRV_PREFIXES = [
    "_sip._tcp", "_sip._udp", "_xmpp-client._tcp", "_xmpp-server._tcp",
    "_ldap._tcp", "_autodiscover._tcp", "_imaps._tcp", "_pop3s._tcp",
    "_submission._tcp", "_imap._tcp", "_caldav._tcp", "_carddav._tcp",
    "_matrix._tcp", "_turn._tcp", "_stun._tcp", "_jabber._tcp",
]

SPF_PROVIDER_MAP = {
    "_spf.google.com":          "Google Workspace",
    "include.zoho.com":         "Zoho",
    "spf.protection.outlook.com": "Microsoft 365",
    "sendgrid.net":             "SendGrid",
    "mailgun.org":              "Mailgun",
    "servers.mcsv.net":         "Mailchimp",
    "amazonses.com":            "Amazon SES",
    "_spf.salesforce.com":      "Salesforce",
    "spf.mandrillapp.com":      "Mandrill/Mailchimp",
    "mktomail.com":             "Marketo",
}

TXT_TOKEN_MAP = {
    r"google-site-verification":   "Google Search Console",
    r"MS=":                        "Microsoft/Office 365",
    r"atlassian-domain-verification": "Atlassian",
    r"slack-domain-verification":  "Slack",
    r"stripe-verification":        "Stripe",
    r"apple-domain-verification":  "Apple",
    r"dropbox-domain-verification":"Dropbox",
    r"zoom-domain-verification":   "Zoom",
    r"facebook-domain-verification":"Facebook",
    r"have-i-been-pwned-validation":"HIBP",
    r"docusign":                   "DocuSign",
    r"adobe-idp-site-verification":"Adobe",
    r"cisco-site-verification":    "Cisco",
    r"keybase-site-verification":  "Keybase",
    r"brave-ledger-verification":  "Brave",
}

def categorize_email(email: str) -> str:
    prefix = email.split("@")[0].lower()
    for cat, patterns in ROLE_EMAIL_PREFIXES.items():
        if any(p in prefix for p in patterns):
            return cat
    return "generic"

# ── HTTP HELPERS ────────────────────────────────────────────────────────────────────────────
def _headers(extra: dict = None) -> dict:
    h = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    if extra:
        h.update(extra)
    return h

async def _safe_get(session: aiohttp.ClientSession, url: str, timeout: int = 20, **kwargs) -> Optional[aiohttp.ClientResponse]:
    try:
        extra_h = kwargs.pop("headers", {})
        merged_h = _headers(extra_h if isinstance(extra_h, dict) else {})
        resp = await session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                  headers=merged_h, ssl=False, allow_redirects=True, **kwargs)
        return resp
    except Exception:
        return None


async def _doh_query(session: aiohttp.ClientSession, name: str, qtype: str, timeout: int = 15) -> list:
    """Cached DoH query — Cloudflare primary, Google fallback."""
    cache_key = (name.lower(), qtype.upper())
    now = time.time()
    if cache_key in _DOH_CACHE:
        records, expiry = _DOH_CACHE[cache_key]
        if now < expiry:
            return records
    endpoints = [
        f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={qtype}",
        f"https://dns.google/resolve?name={quote(name)}&type={qtype}",
        f"https://doh.opendns.com/dns-query?name={quote(name)}&type={qtype}",
    ]
    for endpoint in endpoints:
        try:
            resp = await session.get(
                endpoint,
                headers={"Accept": "application/dns-json", "User-Agent": random.choice(USER_AGENTS)},
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False,
            )
            if resp.status == 200:
                data = await resp.json(content_type=None)
                answers = data.get("Answer", [])
                _DOH_CACHE[cache_key] = (answers, now + _DOH_CACHE_TTL)
                return answers
        except Exception:
            continue
    _DOH_CACHE[cache_key] = ([], now + 30)
    return []


async def _load_cloud_ranges(session: aiohttp.ClientSession):
    """Download and cache cloud provider IP ranges once."""
    global _CLOUD_RANGES, _CLOUD_RANGES_LOADED
    if _CLOUD_RANGES_LOADED:
        return
    # AWS
    try:
        resp = await _safe_get(session, "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=15)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for p in data.get("prefixes", []):
                try:
                    nets.append((ipaddress.ip_network(p["ip_prefix"], strict=False), p.get("service", "AWS")))
                except Exception:
                    pass
            _CLOUD_RANGES["aws"] = nets
    except Exception:
        pass
    # Cloudflare
    try:
        resp = await _safe_get(session, "https://www.cloudflare.com/ips-v4", timeout=10)
        if resp and resp.status == 200:
            text = await resp.text()
            nets = []
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        nets.append((ipaddress.ip_network(line, strict=False), "CDN"))
                    except Exception:
                        pass
            _CLOUD_RANGES["cloudflare"] = nets
    except Exception:
        pass
    # GCP
    try:
        resp = await _safe_get(session, "https://www.gstatic.com/ipranges/cloud.json", timeout=10)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for p in data.get("prefixes", []):
                ipv4 = p.get("ipv4Prefix", "")
                if ipv4:
                    try:
                        nets.append((ipaddress.ip_network(ipv4, strict=False), "GCP"))
                    except Exception:
                        pass
            _CLOUD_RANGES["gcp"] = nets
    except Exception:
        pass
    # Azure
    try:
        azure_url = (
            "https://download.microsoft.com/download/7/1/D/"
            "71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public.json"
        )
        resp = await _safe_get(session, azure_url, timeout=20)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for value in data.get("values", []):
                for prefix in value.get("properties", {}).get("addressPrefixes", []):
                    if ":" not in prefix:  # IPv4 only
                        try:
                            svc = value.get("name", "Azure")
                            nets.append((ipaddress.ip_network(prefix, strict=False), svc))
                        except Exception:
                            pass
            _CLOUD_RANGES["azure"] = nets
    except Exception:
        pass
    # Fastly
    try:
        resp = await _safe_get(session, "https://api.fastly.com/public-ip-list", timeout=10)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for prefix in data.get("addresses", []):
                if ":" not in prefix:
                    try:
                        nets.append((ipaddress.ip_network(prefix, strict=False), "CDN"))
                    except Exception:
                        pass
            _CLOUD_RANGES["fastly"] = nets
    except Exception:
        pass
    _CLOUD_RANGES_LOADED = True


def _check_cloud_provider(ip_str: str) -> Tuple[str, str]:
    """Returns (provider_name, service_name) for a given IP."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        provider_map = {
            "aws": "AWS", "cloudflare": "Cloudflare", "gcp": "Google Cloud",
            "azure": "Azure", "fastly": "Fastly",
        }
        for key, nets in _CLOUD_RANGES.items():
            for net, svc in nets:
                if ip_obj in net:
                    return provider_map.get(key, key.upper()), svc
    except Exception:
        pass
    return "", ""

# ── SUBDOMAIN ENUMERATOR ──────────────────────────────────────────────────────────
class SubdomainEnumerator:
    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession, api_keys: dict):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]
        self._domain_re = re.compile(
            rf"(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_\-]{{0,61}}[a-zA-Z0-9_])?\.)+{re.escape(domain)}",
            re.I
        )

    def _extract(self, text: str) -> set:
        found = set(m.lower() for m in self._domain_re.findall(text))
        cleaned = set()
        for s in found:
            s = s.strip(".")
            if s.endswith("." + self.domain) or s == self.domain:
                cleaned.add(s)
        return cleaned
    async def _crtsh(self) -> set:
        subs = set()
        def parse_crtsh(data):
            found = set()
            for entry in data if isinstance(data, list) else []:
                for field in ("name_value", "common_name"):
                    val = entry.get(field, "")
                    for line in re.split(r'[\n,]', val):
                        line = line.strip().lstrip("*.")
                        if line and line.endswith(self.domain):
                            found.add(line.lower())
            return found
        queries = [
            f"https://crt.sh/?q=%25.{self.domain}&output=json",
            f"https://crt.sh/?q={self.domain}&output=json",
            f"https://crt.sh/?q=%25.%25.{self.domain}&output=json",
        ]
        for url in queries:
            try:
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    subs.update(parse_crtsh(data))
                await asyncio.sleep(0.5)
            except Exception:
                pass
        return subs

    async def _certspotter(self) -> set:
        subs = set()
        after_id = None
        max_pages = 20 if self.mode == "deep" else 10
        for _ in range(max_pages):
            try:
                url = (f"https://api.certspotter.com/v1/issuances?domain={self.domain}"
                       f"&include_subdomains=true&expand=dns_names")
                if after_id:
                    url += f"&after_id={after_id}"
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    if not data:
                        break
                    for entry in data:
                        for name in entry.get("dns_names", []):
                            name = name.strip().lstrip("*.")
                            if name.endswith(self.domain):
                                subs.add(name.lower())
                        after_id = entry.get("id")
                    await asyncio.sleep(0.2)
                else:
                    break
            except Exception:
                break
        return subs

    async def _hackertarget(self) -> set:
        subs = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                if "API count exceeded" not in text and "error" not in text.lower():
                    subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _rapiddns(self) -> set:
        subs = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _threatcrowd(self) -> set:
        subs = set()
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("subdomains", []):
                    sub = sub.strip()
                    if sub.endswith(self.domain):
                        subs.add(sub.lower())
        except Exception:
            pass
        return subs

    async def _urlscan(self) -> set:
        subs = set()
        try:
            headers = {"API-Key": self.api_keys.get("urlscan", "")} if self.api_keys.get("urlscan") else {}
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=200"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for result in data.get("results", []):
                    page = result.get("page", {})
                    for key in ("domain", "ptr"):
                        val = page.get(key, "")
                        if val and val.endswith(self.domain):
                            subs.add(val.lower())
                    subs.update(self._extract(str(result)))
        except Exception:
            pass
        return subs

    async def _otx(self) -> set:
        subs = set()
        try:
            key = self.api_keys.get("otx", "")
            headers = {"X-OTX-API-KEY": key} if key else {}
            page = 1
            while True:
                url = (f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}"
                       f"/passive_dns?limit=500&page={page}")
                resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    entries = data.get("passive_dns", [])
                    for entry in entries:
                        host = entry.get("hostname", "")
                        if host and host.endswith(self.domain):
                            subs.add(host.lower())
                    if not data.get("has_next", False) or not entries:
                        break
                    page += 1
                    await asyncio.sleep(0.3)
                else:
                    break
        except Exception:
            pass
        return subs
    async def _wayback_subs(self) -> set:
        subs = set()
        limit = 100000 if self.mode in ("balanced", "deep") else 10000
        cdx_urls = [
            (f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*"
             f"&output=json&fl=original&collapse=urlkey&limit={limit}"),
            (f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}"
             f"&output=text&fl=original&collapse=urlkey&limit={limit}"),
        ]
        for cdx_url in cdx_urls:
            try:
                resp = await _safe_get(self.session, cdx_url, timeout=max(self.timeout, 45))
                if resp and resp.status == 200:
                    if "&output=json" in cdx_url:
                        try:
                            data = await resp.json(content_type=None)
                            for row in data[1:]:
                                if row:
                                    parsed = urlparse(row[0] if isinstance(row, list) else row)
                                    host = parsed.hostname or ""
                                    if host.endswith(self.domain):
                                        subs.add(host.lower())
                        except Exception:
                            pass
                    else:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                parsed = urlparse(line)
                                host = parsed.hostname or ""
                                if not host:
                                    ext = tldextract.extract(line)
                                    if ext.subdomain and ext.domain and ext.suffix:
                                        host = f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
                                if host.endswith(self.domain) and host != self.domain:
                                    subs.add(host.lower())
                            except Exception:
                                pass
            except Exception:
                pass
        return subs

    async def _commoncrawl(self) -> set:
        subs = set()
        indexes = ["CC-MAIN-2024-10"]
        if self.mode in ("balanced", "deep"):
            indexes = ["CC-MAIN-2024-10", "CC-MAIN-2023-50", "CC-MAIN-2023-23", "CC-MAIN-2022-49"]
        for idx in indexes:
            try:
                url = (f"https://index.commoncrawl.org/{idx}-index?"
                       f"url=*.{self.domain}&output=json&limit=10000")
                resp = await _safe_get(self.session, url, timeout=max(self.timeout, 30))
                if resp and resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        try:
                            obj = json.loads(line)
                            raw_url = obj.get("url", "")
                            host = urlparse(raw_url).hostname or ""
                            if not host:
                                ext = tldextract.extract(raw_url)
                                if ext.subdomain and ext.domain and ext.suffix:
                                    host = f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
                            if host.endswith(self.domain) and host != self.domain:
                                subs.add(host.lower())
                        except Exception:
                            pass
                await asyncio.sleep(0.2)
            except Exception:
                pass
        return subs

    async def _securitytrails(self) -> set:
        subs = set()
        key = self.api_keys.get("securitytrails", "")
        if not key:
            return subs
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                    headers={"APIKEY": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("subdomains", []):
                    subs.add(f"{sub}.{self.domain}".lower())
        except Exception:
            pass
        return subs

    async def _virustotal_subs(self) -> set:
        subs = set()
        key = self.api_keys.get("virustotal", "")
        if not key:
            return subs
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=40"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                    headers={"x-apikey": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("data", []):
                    sub = item.get("id", "")
                    if sub.endswith(self.domain):
                        subs.add(sub.lower())
        except Exception:
            pass
        return subs

    async def _fullhunt(self) -> set:
        subs = set()
        key = self.api_keys.get("fullhunt", "")
        if not key:
            return subs
        try:
            url = f"https://fullhunt.io/api/v1/domain/{self.domain}/subdomains"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                    headers={"X-API-KEY": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("hosts", []):
                    if sub.endswith(self.domain):
                        subs.add(sub.lower())
        except Exception:
            pass
        return subs

    async def _chaos(self) -> set:
        subs = set()
        key = self.api_keys.get("chaos", "")
        if not key:
            return subs
        try:
            url = f"https://dns.projectdiscovery.io/dns/{self.domain}/subdomains"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                    headers={"Authorization": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("subdomains", []):
                    subs.add(f"{sub}.{self.domain}".lower())
        except Exception:
            pass
        return subs

    async def _bufferover(self) -> set:
        subs = set()
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data.get("FDNS_A", []) + data.get("RDNS", []):
                    parts = entry.split(",")
                    for part in parts:
                        part = part.strip()
                        if part.endswith(self.domain):
                            subs.add(part.lower())
        except Exception:
            pass
        return subs

    async def _jldc(self) -> set:
        subs = set()
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in (data if isinstance(data, list) else []):
                    sub = str(sub).strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _anubisdb(self) -> set:
        subs = set()
        try:
            url = f"https://jonlu.ca/anubis/subdomains/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in (data if isinstance(data, list) else []):
                    sub = str(sub).strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _shrewdeye(self) -> set:
        subs = set()
        try:
            url = f"https://shrewdeye.app/domains/{self.domain}.json"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                items = data if isinstance(data, list) else data.get("domains", [])
                for sub in items:
                    sub = str(sub).strip().lower().lstrip("*.")
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _sublist3r_api(self) -> set:
        subs = set()
        try:
            url = f"https://api.sublist3r.com/search.php?domain={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in (data if isinstance(data, list) else []):
                    sub = str(sub).strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _threatminer(self) -> set:
        subs = set()
        try:
            url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("results", []):
                    sub = str(sub).strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _hackertarget_dns(self) -> set:
        subs = set()
        try:
            url = f"https://api.hackertarget.com/dnslookup/?q={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _rapiddns_pages(self) -> set:
        subs = set()
        max_pages = 20 if self.mode in ("balanced", "deep") else 5
        for page in range(1, max_pages + 1):
            try:
                url = f"https://rapiddns.io/subdomain/{self.domain}?full=1&page={page}"
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    found = self._extract(text)
                    if not found:
                        break
                    subs.update(found)
                else:
                    break
                await asyncio.sleep(0.3)
            except Exception:
                break
        return subs

    async def _dnsdumpster(self) -> set:
        subs = set()
        try:
            async with self.session.get(
                "https://dnsdumpster.com/",
                headers=_headers(),
                ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as r1:
                if r1.status != 200:
                    return subs
                html_text = await r1.text()
                # Extract CSRF from cookie first
                csrf_val = ""
                csrf_cookie = r1.cookies.get("csrftoken")
                if csrf_cookie:
                    csrf_val = csrf_cookie.value if hasattr(csrf_cookie, "value") else str(csrf_cookie)
                # Fallback: extract CSRF from HTML form (more robust)
                if not csrf_val:
                    try:
                        from lxml import html as lhtml
                        doc = lhtml.fromstring(html_text)
                        inputs = doc.xpath('//input[@name="csrfmiddlewaretoken"]/@value')
                        if inputs:
                            csrf_val = inputs[0]
                    except Exception:
                        soup_tmp = BeautifulSoup(html_text, "html.parser")
                        inp = soup_tmp.find("input", {"name": "csrfmiddlewaretoken"})
                        if inp:
                            csrf_val = inp.get("value", "")
            if not csrf_val:
                return subs
            form_data = aiohttp.FormData()
            form_data.add_field("csrfmiddlewaretoken", csrf_val)
            form_data.add_field("targetip", self.domain)
            form_data.add_field("user", "free")
            async with self.session.post(
                "https://dnsdumpster.com/",
                data=form_data,
                headers=_headers({"Referer": "https://dnsdumpster.com/", "Cookie": f"csrftoken={csrf_val}"}),
                ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as r2:
                if r2.status == 200:
                    text = await r2.text()
                    soup = BeautifulSoup(text, "html.parser")
                    for td in soup.find_all("td", class_="col-md-4"):
                        raw = td.get_text(strip=True).lower()
                        host = raw.split()[0] if raw else ""
                        if host.endswith(self.domain):
                            subs.add(host)
                    subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _virustotal_unauth(self) -> set:
        subs = set()
        try:
            cursor = ""
            for _ in range(5):
                url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40"
                if cursor:
                    url += f"&cursor={cursor}"
                resp = await _safe_get(self.session, url, timeout=self.timeout,
                                       headers={"Accept": "application/json"})
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("data", []):
                        sub = item.get("id", "")
                        if sub.endswith(self.domain):
                            subs.add(sub.lower())
                    cursor = data.get("meta", {}).get("cursor", "")
                    if not cursor or not data.get("data"):
                        break
                else:
                    break
                await asyncio.sleep(0.5)
        except Exception:
            pass
        return subs

    async def _urlscan_paginated(self) -> set:
        subs = set()
        max_pages = 10 if self.mode == "deep" else 5
        try:
            search_after = None
            for _ in range(max_pages):
                url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=10000"
                if search_after:
                    url += f"&search_after={search_after}"
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    results = data.get("results", [])
                    for r in results:
                        pg = r.get("page", {})
                        for key in ("domain", "ptr"):
                            val = pg.get(key, "")
                            if val and val.endswith(self.domain) and val != self.domain:
                                subs.add(val.lower())
                        subs.update(self._extract(str(pg)))
                    if len(results) < 100:
                        break
                    search_after = results[-1].get("sort", [None])[-1] if results else None
                    if not search_after:
                        break
                else:
                    break
                await asyncio.sleep(0.5)
        except Exception:
            pass
        return subs

    async def _github_code_subs(self) -> set:
        subs = set()
        key = self.api_keys.get("github_token", "")
        auth_h = {"Authorization": f"Bearer {key}"} if key else {}
        auth_h["Accept"] = "application/vnd.github.v3.text-match+json"
        queries = [f'"{self.domain}"', f'"site:{self.domain}"', f'"{self.domain}" subdomain']
        for query in queries:
            try:
                url = f"https://api.github.com/search/code?q={quote(query)}&per_page=100"
                resp = await _safe_get(self.session, url, timeout=self.timeout, headers=auth_h)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("items", []):
                        for match in item.get("text_matches", []):
                            subs.update(self._extract(match.get("fragment", "")))
                await asyncio.sleep(1.5)
            except Exception:
                pass
        return subs

    async def _grep_app_subs(self) -> set:
        subs = set()
        try:
            url = f"https://grep.app/api/search?q={quote(self.domain)}&per_page=100"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for hit in data.get("hits", {}).get("hits", []):
                    snippet = hit.get("content", {}).get("snippet", "")
                    raw_url = hit.get("file", {}).get("raw_url", "")
                    subs.update(self._extract(snippet))
                    subs.update(self._extract(raw_url))
        except Exception:
            pass
        return subs

    async def _zoomeye(self) -> set:
        subs = set()
        try:
            url = f"https://api.zoomeye.org/web/search?query=hostname:{self.domain}&page=1"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for match in data.get("matches", []):
                    subs.update(self._extract(str(match)))
        except Exception:
            pass
        return subs

    async def _fofa(self) -> set:
        subs = set()
        try:
            query = base64.b64encode(f'domain="{self.domain}"'.encode()).decode()
            url = f"https://fofa.info/api/v1/search/all?qbase64={query}&fields=host,domain&size=10000"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("results", []):
                    for val in item:
                        val = str(val).strip().lower().lstrip("*.")
                        if val.endswith(self.domain):
                            subs.add(val)
        except Exception:
            pass
        return subs

    async def _netcraft(self) -> set:
        subs = set()
        try:
            url = (f"https://searchdns.netcraft.com/?restriction=site+ends+with"
                   f"&host={self.domain}&position=limited")
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"Referer": "https://www.netcraft.com"})
            if resp and resp.status == 200:
                text = await resp.text()
                subs.update(self._extract(text))
                soup = BeautifulSoup(text, "html.parser")
                for a in soup.find_all("a", href=True):
                    parsed = urlparse(a["href"])
                    host = (parsed.hostname or "").lower()
                    if host.endswith(self.domain):
                        subs.add(host)
        except Exception:
            pass
        return subs

    async def _leakix(self) -> set:
        subs = set()
        try:
            url = f"https://leakix.net/domain/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"Accept": "application/json"})
            if resp and resp.status == 200:
                try:
                    data = await resp.json(content_type=None)
                    for event in (data if isinstance(data, list) else data.get("Events", [])):
                        host = str(event.get("host", "") or event.get("subdomain", "")).strip().lower()
                        if host.endswith(self.domain):
                            subs.add(host)
                except Exception:
                    text = await resp.text()
                    subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _phonebook_subs(self) -> set:
        subs = set()
        try:
            form_data = aiohttp.FormData()
            form_data.add_field("term", self.domain)
            form_data.add_field("type", "2")
            form_data.add_field("page", "1")
            async with self.session.post(
                "https://phonebook.cz/search/", data=form_data,
                headers=_headers({"Referer": "https://phonebook.cz/"}),
                ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _binaryedge(self) -> set:
        subs = set()
        key = self.api_keys.get("binaryedge", "")
        if not key:
            return subs
        try:
            url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"X-Key": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("events", []):
                    sub = str(sub).strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _riskiq(self) -> set:
        subs = set()
        user = self.api_keys.get("riskiq_user", "")
        key = self.api_keys.get("riskiq_key", "")
        if not user or not key:
            return subs
        try:
            auth = aiohttp.BasicAuth(user, key)
            url = f"https://api.riskiq.net/pt/v2/pdns/passive?query={self.domain}"
            resp = await self.session.get(url, auth=auth, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=self.timeout))
            if resp.status == 200:
                data = await resp.json(content_type=None)
                for rec in data.get("results", []):
                    host = str(rec.get("resolve", "")).strip().lower()
                    if host.endswith(self.domain):
                        subs.add(host)
        except Exception:
            pass
        return subs

    async def _censys_subs(self) -> set:
        subs = set()
        try:
            censys_id = self.api_keys.get("censys_api_id", "")
            censys_secret = self.api_keys.get("censys_api_secret", "")
            url = f"https://search.censys.io/api/v2/hosts/search?q={quote(self.domain)}&per_page=100"
            if censys_id and censys_secret:
                auth = aiohttp.BasicAuth(censys_id, censys_secret)
                resp = await self.session.get(
                    url, auth=auth, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                )
            else:
                resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for hit in data.get("result", {}).get("hits", []):
                    for name in hit.get("names", []):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(self.domain) and name != self.domain:
                            subs.add(name)
                    rdns_list = hit.get("reverse_dns", {})
                    if isinstance(rdns_list, dict):
                        rdns_list = rdns_list.get("reverse_dns", [])
                    for rname in (rdns_list if isinstance(rdns_list, list) else []):
                        rname = rname.strip().lower().rstrip(".")
                        if rname.endswith(self.domain) and rname != self.domain:
                            subs.add(rname)
        except Exception:
            pass
        return subs

    async def _dnsrepo(self) -> set:
        subs = set()
        try:
            url = f"https://dnsrepo.noc.org/?domain={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                subs.update(self._extract(text))
                soup = BeautifulSoup(text, "html.parser")
                for row in soup.find_all("tr"):
                    cells = row.find_all("td")
                    if cells:
                        val = cells[0].get_text(strip=True).lower()
                        if val.endswith(self.domain) and val != self.domain:
                            subs.add(val)
        except Exception:
            pass
        return subs

    async def _riddler(self) -> set:
        subs = set()
        try:
            url = f"https://riddler.io/search/exportcsv?q=pld:{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                for line in text.splitlines():
                    parts = line.strip().split(",")
                    for part in parts:
                        part = part.strip().strip('"').lower()
                        if part.endswith(self.domain) and part != self.domain:
                            subs.add(part)
                subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _sonar_fdns(self) -> set:
        subs = set()
        for url in [
            f"https://sonar.omnisint.io/subdomains/{self.domain}",
            f"https://sonar.omnisint.io/tlds/{self.domain}",
        ]:
            try:
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for sub in (data if isinstance(data, list) else []):
                        sub = str(sub).strip().lower().lstrip("*.")
                        if sub.endswith(self.domain) and sub != self.domain:
                            subs.add(sub)
            except Exception:
                pass
        return subs

    async def _crobat(self) -> set:
        subs = set()
        try:
            url = f"https://crobat.app/subdomains/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                items = data if isinstance(data, list) else data.get("subdomains", [])
                for sub in items:
                    sub = str(sub).strip().lower().lstrip("*.")
                    if sub.endswith(self.domain) and sub != self.domain:
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _ctsearch_entrust(self) -> set:
        subs = set()
        try:
            url = (f"https://ctsearch.entrust.com/api/v1/certificates"
                   f"?fields=subjectDN&domain={self.domain}&includeExpired=true"
                   f"&exactMatch=false&limit=5000")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                certs = data if isinstance(data, list) else data.get("certs", [])
                for cert in certs:
                    subject_dn = cert.get("subjectDN", "") if isinstance(cert, dict) else str(cert)
                    for part in subject_dn.split(","):
                        part = part.strip()
                        if part.startswith("CN="):
                            cn = part[3:].strip().lstrip("*.")
                            if cn.endswith(self.domain) and cn != self.domain:
                                subs.add(cn.lower())
        except Exception:
            pass
        return subs

    async def _bevigil(self) -> set:
        """Bevigil mobile OSINT — finds subdomains extracted from APKs."""
        subs = set()
        key = self.api_keys.get("bevigil", "")
        if not key:
            return subs
        try:
            url = f"https://osint.bevigil.com/api/{self.domain}/subdomains/"
            resp = await _safe_get(
                self.session, url, timeout=self.timeout,
                headers={"X-Access-Token": key}
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _threatbook(self) -> set:
        """ThreatBook subdomain intel."""
        subs = set()
        key = self.api_keys.get("threatbook", "")
        if not key:
            return subs
        try:
            url = f"https://api.threatbook.cn/v3/domain/sub_domains?apikey={key}&resource={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("data", {}).get("sub_domains", {}).get("data", []):
                    sub = sub.strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def enumerate(self) -> Dict[str, SubdomainRecord]:
        # All modes: fast, balanced, deep, turbo
        sources_map = {
            "crt.sh":         self._crtsh,
            "certspotter":    self._certspotter,
            "hackertarget":   self._hackertarget,
            "hackertarget_dns": self._hackertarget_dns,
            "rapiddns":       self._rapiddns,
            "rapiddns_pages": self._rapiddns_pages,
            "threatcrowd":    self._threatcrowd,
            "threatminer":    self._threatminer,
            "urlscan":        self._urlscan,
            "urlscan_pages":  self._urlscan_paginated,
            "otx":            self._otx,
            "bufferover":     self._bufferover,
            "jldc":           self._jldc,
            "anubisdb":       self._anubisdb,
            "shrewdeye":      self._shrewdeye,
            "sublist3r":      self._sublist3r_api,
            "vt_unauth":      self._virustotal_unauth,
            "grep_app":       self._grep_app_subs,
        }
        if self.mode in ("balanced", "deep", "turbo"):
            sources_map.update({
                "wayback":        self._wayback_subs,
                "commoncrawl":    self._commoncrawl,
                "github_code":    self._github_code_subs,
                "netcraft":       self._netcraft,
                "leakix":         self._leakix,
                "dnsdumpster":    self._dnsdumpster,
                "phonebook":      self._phonebook_subs,
                "zoomeye":        self._zoomeye,
                "fofa":           self._fofa,
                "censys":         self._censys_subs,
                "dnsrepo":        self._dnsrepo,
                "riddler":        self._riddler,
                "bevigil":        self._bevigil,
                "threatbook":     self._threatbook,
                "sonar_fdns":     self._sonar_fdns,
                "crobat":         self._crobat,
                "ctsearch":       self._ctsearch_entrust,
            })
        if self.mode == "deep":
            sources_map.update({
                "securitytrails": self._securitytrails,
                "virustotal":     self._virustotal_subs,
                "fullhunt":       self._fullhunt,
                "chaos":          self._chaos,
                "binaryedge":     self._binaryedge,
                "riskiq":         self._riskiq,
            })

        tasks = {name: asyncio.create_task(fn()) for name, fn in sources_map.items()}
        results: Dict[str, SubdomainRecord] = {}

        done = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), done):
            if isinstance(result, Exception):
                console.print(f"[dim]  [-] {name} -> error[/dim]")
                continue
            count = len(result) if isinstance(result, set) else 0
            if count:
                console.print(f"[dim]  [+] {name} -> {count} subdomains[/dim]")
            for sub in result:
                sub = sub.strip().lower()
                if not sub or sub == self.domain:
                    continue
                if not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', sub.replace(self.domain, "x")):
                    continue
                if sub not in results:
                    results[sub] = SubdomainRecord(name=sub)
                if name not in results[sub].sources:
                    results[sub].sources.append(name)

        # Remove exact root domain
        results.pop(self.domain, None)

        # Wildcard candidate detection from naming patterns
        for rec in results.values():
            for pat in WILDCARD_PATS:
                rel = rec.name[: -len(self.domain) - 1]
                if pat.match(rel + "."):
                    rec.wildcard_candidate = True
                    break

        # DoH resolution for each unique subdomain
        sem = asyncio.Semaphore(50)
        shodan_sem = asyncio.Semaphore(20)

        async def _shodan_idb(ip: str) -> dict:
            async with shodan_sem:
                try:
                    resp = await _safe_get(
                        self.session, f"https://internetdb.shodan.io/{ip}", timeout=8
                    )
                    if resp and resp.status == 200:
                        return await resp.json(content_type=None)
                except Exception:
                    pass
            return {}

        async def resolve_sub(sub: str, rec: SubdomainRecord):
            async with sem:
                a_answers = await _doh_query(self.session, sub, "A", self.timeout)
                ips = [a.get("data", "").strip() for a in a_answers if a.get("data", "").strip()]
                if ips:
                    rec.ips = list(set(ips))
                    # Enrich first IP with Shodan InternetDB
                    if self.mode in ("balanced", "deep"):
                        first_ip = ips[0]
                        idb = await _shodan_idb(first_ip)
                        if idb:
                            if idb.get("ports"):
                                rec.ports = idb["ports"]
                            if idb.get("hostnames") and not any(
                                h == sub for h in idb.get("hostnames", [])
                            ):
                                pass  # extra hostnames available but stored per-IP
                cname_answers = await _doh_query(self.session, sub, "CNAME", self.timeout)
                if cname_answers:
                    rec.cname = [c.get("data", "").rstrip(".") for c in cname_answers]

        resolve_tasks = [resolve_sub(sub, rec) for sub, rec in results.items()]
        await asyncio.gather(*resolve_tasks, return_exceptions=True)

        # Wildcard detection: if >30 subs resolve to same IP
        all_ips = [ip for rec in results.values() for ip in rec.ips]
        if all_ips:
            ip_counts = Counter(all_ips)
            most_common_ip, most_common_count = ip_counts.most_common(1)[0]
            if most_common_count > 30:
                for rec in results.values():
                    if most_common_ip in rec.ips:
                        rec.wildcard_candidate = True

        return results


# ── EMAIL DISCOVERY ──────────────────────────────────────────────────────────────────────────────────
class EmailDiscovery:
    _email_re = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
    _obfus_re = re.compile(
        r"[a-zA-Z0-9._%+\-]+\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\s+at\s+)\s*"
        r"[a-zA-Z0-9.\-]+\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+)\s*[a-zA-Z]{2,}",
        re.I
    )

    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession, api_keys: dict):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]
        self._domain_email_re = re.compile(
            r'\b[A-Za-z0-9._%+\-]+@' + re.escape(domain) + r'\b', re.I
        )

    def _clean_emails(self, raw: set) -> set:
        out = set()
        for e in raw:
            e = e.strip().lower().strip(".,;:")
            if re.match(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", e):
                parts = e.split("@")
                if len(parts) == 2 and (self.domain == parts[1] or parts[1].endswith("." + self.domain)):
                    out.add(e)
        return out

    def _deobfuscate(self, text: str) -> list:
        emails = []
        for m in self._obfus_re.finditer(text):
            raw = m.group(0)
            e = re.sub(r"\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\s+at\s+)\s*", "@", raw, flags=re.I)
            e = re.sub(r"\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+)\s*", ".", e, flags=re.I)
            e = e.strip().lower()
            if "@" in e:
                emails.append(e)
        return emails
    async def _from_ct_logs(self) -> set:
        emails = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data:
                    for fld in ("name_value", "common_name"):
                        val = entry.get(fld, "")
                        emails.update(self._email_re.findall(val))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_whois_html(self) -> set:
        emails = set()
        try:
            for base in [f"https://www.whois.com/whois/{self.domain}",
                         f"https://who.is/whois/{self.domain}"]:
                resp = await _safe_get(self.session, base, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    emails.update(self._email_re.findall(text))
                    emails.update(self._deobfuscate(text))
                    if emails:
                        break
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_hunter(self) -> set:
        emails = set()
        key = self.api_keys.get("hunter_io", "")
        if not key:
            return emails
        try:
            url = (f"https://api.hunter.io/v2/domain-search"
                   f"?domain={self.domain}&api_key={key}&limit=100")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("data", {}).get("emails", []):
                    addr = item.get("value", "")
                    if addr:
                        emails.add(addr.lower())
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_emailformat(self) -> set:
        emails = set()
        try:
            url = f"https://www.email-format.com/d/{self.domain}/"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                emails.update(self._email_re.findall(text))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_target_page(self) -> set:
        emails = set()
        for scheme_host in [f"https://{self.domain}", f"https://www.{self.domain}",
                             f"http://{self.domain}"]:
            try:
                resp = await _safe_get(self.session, scheme_host, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    emails.update(self._email_re.findall(text))
                    emails.update(self._deobfuscate(text))
                    for m in re.finditer(r"mailto:([^\s\"'<>?]+)", text, re.I):
                        addr = m.group(1).strip().lower()
                        if "@" in addr:
                            emails.add(addr)
                    if emails:
                        break
            except Exception:
                pass
        return self._clean_emails(emails)
    async def _from_securitytxt(self) -> set:
        emails = set()
        for path in [f"https://{self.domain}/.well-known/security.txt",
                     f"https://{self.domain}/security.txt"]:
            try:
                resp = await _safe_get(self.session, path, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    for m in re.finditer(r"Contact:\s*(.+)", text, re.I):
                        val = m.group(1).strip()
                        emails.update(self._email_re.findall(val))
                    break
            except Exception:
                pass
        return self._clean_emails(emails)

    async def _from_pgp_keyserver(self) -> set:
        emails = set()
        for base_url in [
            f"https://keyserver.ubuntu.com/pks/lookup?op=index&search={self.domain}&fingerprint=on&options=mr",
            f"https://keys.openpgp.org/search?q={self.domain}",
        ]:
            try:
                resp = await _safe_get(self.session, base_url, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    emails.update(self._email_re.findall(text))
            except Exception:
                pass
        return self._clean_emails(emails)

    async def _from_github_code(self) -> set:
        emails = set()
        key = self.api_keys.get("github_token", "")
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/vnd.github.v3.text-match+json"} if key else {"Accept": "application/vnd.github.v3.text-match+json"}
        try:
            url = f"https://api.github.com/search/code?q=%40{self.domain}&per_page=100"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("items", []):
                    for match in item.get("text_matches", []):
                        emails.update(self._email_re.findall(match.get("fragment", "")))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_github_commits(self) -> set:
        emails = set()
        key = self.api_keys.get("github_token", "")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        try:
            url = f"https://api.github.com/search/commits?q={self.domain}&per_page=100"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("items", []):
                    author_email = item.get("commit", {}).get("author", {}).get("email", "")
                    if author_email and self.domain in author_email:
                        emails.add(author_email.lower())
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_wayback_contacts(self) -> set:
        emails = set()
        for path in ["/contact", "/about", "/about-us", "/team", "/people", "/staff", "/contact-us"]:
            try:
                url = f"https://web.archive.org/web/2024*/{self.domain}{path}"
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    emails.update(self._email_re.findall(text))
            except Exception:
                pass
        return self._clean_emails(emails)

    async def _from_skymem(self) -> set:
        emails = set()
        try:
            url = f"https://www.skymem.info/srch?q={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                emails.update(self._email_re.findall(text))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_phonebook(self) -> set:
        emails = set()
        try:
            form_data = aiohttp.FormData()
            form_data.add_field("term", self.domain)
            form_data.add_field("type", "1")
            form_data.add_field("page", "1")
            async with self.session.post(
                "https://phonebook.cz/search/", data=form_data,
                headers=_headers({"Referer": "https://phonebook.cz/"}),
                ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    emails.update(self._email_re.findall(text))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_intelx(self) -> set:
        emails = set()
        key = self.api_keys.get("intelx", "")
        try:
            search_url = "https://2.intelx.io/phonebook/search"
            body = {"term": self.domain, "maxresults": 100, "media": 1, "target": 1, "terminate": []}
            headers = {"x-key": key} if key else {}
            async with self.session.post(
                search_url, json=body,
                headers=_headers(headers),
                ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    search_id = data.get("id", "")
                    if search_id:
                        await asyncio.sleep(2)
                        result_url = f"https://2.intelx.io/phonebook/search/result?id={search_id}&limit=100&offset=0"
                        async with self.session.get(
                            result_url, headers=_headers(headers),
                            ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as r2:
                            if r2.status == 200:
                                rdata = await r2.json(content_type=None)
                                for sel in rdata.get("selectors", []):
                                    val = sel.get("selectorvalue", "")
                                    if "@" in val and self.domain in val:
                                        emails.add(val.lower())
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_commoncrawl_mailto(self) -> set:
        emails = set()
        try:
            url = (f"http://index.commoncrawl.org/CC-MAIN-2024-10-index"
                   f"?url=mailto:*@{self.domain}&output=json&limit=1000")
            resp = await _safe_get(self.session, url, timeout=30)
            if resp and resp.status == 200:
                text = await resp.text()
                for line in text.splitlines():
                    try:
                        obj = json.loads(line)
                        raw_url = obj.get("url", "")
                        m = re.match(r"mailto:(.+)", raw_url, re.I)
                        if m:
                            addr = m.group(1).strip().lower()
                            if "@" in addr and self.domain in addr:
                                emails.add(addr)
                    except Exception:
                        pass
        except Exception:
            pass
        return self._clean_emails(emails)

    async def discover(self) -> Dict[str, EmailRecord]:
        sources_map = {
            "ct_logs":      self._from_ct_logs,
            "whois_html":   self._from_whois_html,
            "target_page":  self._from_target_page,
            "security_txt": self._from_securitytxt,
            "pgp_keys":     self._from_pgp_keyserver,
            "skymem":       self._from_skymem,
            "phonebook":    self._from_phonebook,
        }
        if self.mode in ("balanced", "deep", "turbo"):
            sources_map["email_format"]       = self._from_emailformat
            sources_map["github_code_emails"] = self._from_github_code
            sources_map["github_commits"]     = self._from_github_commits
            sources_map["wayback_contacts"]   = self._from_wayback_contacts
            sources_map["commoncrawl_mailto"] = self._from_commoncrawl_mailto
        if self.mode in ("deep",):
            sources_map["hunter_io"] = self._from_hunter
            sources_map["intelx"]    = self._from_intelx

        tasks = {name: asyncio.create_task(fn()) for name, fn in sources_map.items()}
        results: Dict[str, EmailRecord] = {}

        done = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), done):
            if isinstance(result, Exception):
                continue
            for email in result:
                if email not in results:
                    results[email] = EmailRecord(
                        email=email,
                        role_category=categorize_email(email)
                    )
                if name not in results[email].sources:
                    results[email].sources.append(name)

        return results


# ── TECHNOLOGY DETECTOR ───────────────────────────────────────────────────────
class TechnologyDetector:
    def __init__(self, domain, mode, session, dns_records):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.dns_records = dns_records
        self.timeout = TIMEOUTS[mode]

    async def _fetch_target(self):
        data = {"headers": {}, "html": "", "headers_server": "", "status": 0}
        for url in [f"https://{self.domain}", f"https://www.{self.domain}", f"http://{self.domain}"]:
            try:
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp:
                    data["status"] = resp.status
                    data["headers"] = dict(resp.headers)
                    data["headers_server"] = resp.headers.get("Server", "")
                    try:
                        text = await resp.text(errors="replace")
                        data["html"] = text[:80000]
                    except Exception:
                        pass
                    break
            except Exception:
                pass
        return data

    def _build_dns_text(self):
        result = {"dns_mx": "", "dns_txt": "", "dns_ns": ""}
        for rec in self.dns_records:
            rtype = rec.get("type", "") if isinstance(rec, dict) else rec.type
            rval = rec.get("value", "") if isinstance(rec, dict) else rec.value
            if rtype == "MX":
                result["dns_mx"] += rval + " "
            elif rtype == "TXT":
                result["dns_txt"] += rval + " "
            elif rtype == "NS":
                result["dns_ns"] += rval + " "
        return result

    def _match_tech(self, name, sig, target_data, dns_text):
        all_text = (
            target_data.get("html", "") +
            " ".join(f"{k}: {v}" for k, v in target_data.get("headers", {}).items()) +
            target_data.get("headers_server", "") +
            dns_text.get("dns_mx", "") +
            dns_text.get("dns_txt", "") +
            dns_text.get("dns_ns", "")
        )
        for pattern in sig["patterns"]:
            m = re.search(pattern, all_text, re.I)
            if m:
                evidence = m.group(0)[:120]
                return TechnologyFinding(
                    name=name,
                    category=sig["category"],
                    evidence=evidence,
                    confidence="high",
                    sources=["http_probe"]
                )
        return None

    async def detect(self):
        target_data = await self._fetch_target()
        dns_text = self._build_dns_text()
        findings = []
        for name, sig in TECH_SIGNATURES.items():
            finding = self._match_tech(name, sig, target_data, dns_text)
            if finding:
                findings.append(finding)
        return findings


# ── DNS INTELLIGENCE ──────────────────────────────────────────────────────────
class DNSIntelligence:
    DOH_ENDPOINTS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]
    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY", "DS"]

    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]

    async def _query_doh(self, qname, qtype):
        for endpoint in self.DOH_ENDPOINTS:
            try:
                params = {"name": qname, "type": qtype}
                resp = await self.session.get(
                    endpoint, params=params,
                    headers={"Accept": "application/dns-json", "User-Agent": random.choice(USER_AGENTS)},
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                )
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    answers = data.get("Answer", [])
                    records = []
                    for ans in answers:
                        rdata = str(ans.get("data", "")).strip()
                        records.append(DNSRecord(type=qtype, name=qname, value=rdata, source="doh"))
                    return records
            except Exception:
                continue
        return []

    async def _query_dkim_selectors(self) -> list:
        records = []
        sem = asyncio.Semaphore(20)
        async def check_selector(sel):
            async with sem:
                qname = f"{sel}._domainkey.{self.domain}"
                answers = await self._query_doh(qname, "TXT")
                if answers:
                    return answers
                return []
        tasks = [check_selector(s) for s in DKIM_SELECTORS]
        batches = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in batches:
            if isinstance(batch, list):
                records.extend(batch)
        return records

    async def _query_srv_records(self) -> list:
        records = []
        tasks = [self._query_doh(f"{srv}.{self.domain}", "SRV") for srv in SRV_PREFIXES]
        batches = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in batches:
            if isinstance(batch, list):
                records.extend(batch)
        return records

    def _parse_spf(self, spf_val: str) -> dict:
        includes = re.findall(r"include:([^\s]+)", spf_val)
        ip4s = re.findall(r"ip4:([^\s]+)", spf_val)
        ip6s = re.findall(r"ip6:([^\s]+)", spf_val)
        all_mech = re.search(r"[~\-+?]all", spf_val)
        providers = []
        for inc in includes:
            for spf_domain, provider in SPF_PROVIDER_MAP.items():
                if spf_domain in inc:
                    providers.append(provider)
        return {
            "raw": spf_val,
            "includes": includes, "ip4": ip4s, "ip6": ip6s,
            "all_mechanism": all_mech.group(0) if all_mech else "",
            "providers": providers,
        }

    async def _parse_dmarc(self) -> dict:
        answers = await self._query_doh(f"_dmarc.{self.domain}", "TXT")
        for ans in answers:
            val = ans.value if hasattr(ans, "value") else ans.get("data", "")
            if "v=DMARC1" in val:
                tags = {m.group(1): m.group(2).strip() for m in re.finditer(r"(\w+)=([^;]+)", val)}
                p = tags.get("p", "none")
                return {
                    "raw": val, "policy": p,
                    "subdomain_policy": tags.get("sp", ""),
                    "rua": tags.get("rua", ""), "ruf": tags.get("ruf", ""),
                    "pct": tags.get("pct", "100"),
                    "strength": "strong" if p == "reject" else "medium" if p == "quarantine" else "weak",
                }
        return {}

    def _identify_txt_tokens(self, txt_records: list) -> list:
        tokens = []
        for rec in txt_records:
            val = rec.value if hasattr(rec, "value") else rec.get("value", "")
            for pattern, service in TXT_TOKEN_MAP.items():
                if re.search(pattern, val, re.I):
                    tokens.append({"service": service, "value": val[:120]})
                    break
        return tokens

    async def query(self):
        record_types = self.RECORD_TYPES if self.mode != "fast" else ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

        tasks = [self._query_doh(self.domain, rtype) for rtype in record_types]
        tasks += [
            self._query_doh(f"www.{self.domain}", "A"),
            self._query_doh(f"mail.{self.domain}", "A"),
            self._query_doh(f"_dmarc.{self.domain}", "TXT"),
        ]
        if self.mode in ("balanced", "deep"):
            tasks.append(self._query_srv_records())
            tasks.append(self._query_dkim_selectors())

        results_nested = await asyncio.gather(*tasks, return_exceptions=True)
        all_records = []
        seen = set()
        spf_extra = []
        for batch in results_nested:
            if isinstance(batch, Exception):
                continue
            for rec in (batch if isinstance(batch, list) else []):
                if not hasattr(rec, "type"):
                    continue
                # Parse SPF providers from TXT
                if rec.type == "TXT" and rec.value.startswith("v=spf1"):
                    spf_data = self._parse_spf(rec.value)
                    spf_extra.append(DNSRecord(
                        type="SPF_PARSED", name=rec.name,
                        value=json.dumps(spf_data), source="doh"
                    ))
                key = (rec.type, rec.name, rec.value)
                if key not in seen:
                    seen.add(key)
                    all_records.append(rec)
        all_records.extend(spf_extra)

        # Add TXT token identification as metadata records
        txt_recs = [r for r in all_records if r.type == "TXT"]
        tokens = self._identify_txt_tokens(txt_recs)
        for tok in tokens:
            all_records.append(DNSRecord(
                type="TXT_TOKEN", name=self.domain,
                value=f"{tok['service']}: {tok['value'][:80]}", source="doh"
            ))

        return all_records


# ── WHOIS INTELLIGENCE ────────────────────────────────────────────────────────
class WhoisIntelligence:
    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]

    async def _rdap(self):
        ext = tldextract.extract(self.domain)
        apex = f"{ext.domain}.{ext.suffix}"
        try:
            url = f"https://rdap.org/domain/{apex}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                result = {
                    "registrar": "", "created": "", "expires": "",
                    "updated": "", "status": [], "nameservers": [],
                    "registrant": "", "source": "rdap"
                }
                for event in data.get("events", []):
                    action = event.get("eventAction", "")
                    date = event.get("eventDate", "")
                    if action == "registration":
                        result["created"] = date
                    elif action == "expiration":
                        result["expires"] = date
                    elif action == "last changed":
                        result["updated"] = date
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [])
                    if "registrar" in roles and vcard:
                        for vcard_item in (vcard[1] if len(vcard) > 1 else []):
                            if vcard_item[0] == "fn":
                                result["registrar"] = vcard_item[3]
                result["nameservers"] = [
                    ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])
                ]
                result["status"] = [
                    s.get("status", "") if isinstance(s, dict) else str(s)
                    for s in data.get("status", [])
                ]
                return result
        except Exception:
            pass
        return {}

    async def _whois_fallback(self):
        try:
            ext = tldextract.extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            url = f"https://who.is/whois/{apex}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                result = {}
                patterns = {
                    "registrar": r"Registrar:\s*(.+)",
                    "created": r"Creation Date:\s*(.+)",
                    "expires": r"Registry Expiry Date:\s*(.+)",
                    "updated": r"Updated Date:\s*(.+)",
                }
                for key, pat in patterns.items():
                    m = re.search(pat, text, re.I)
                    if m:
                        result[key] = m.group(1).strip()
                ns_matches = re.findall(r"Name Server:\s*(.+)", text, re.I)
                result["nameservers"] = [ns.strip().lower() for ns in ns_matches]
                result["source"] = "who.is"
                return result
        except Exception:
            pass
        return {}

    async def lookup(self):
        rdap_data, fallback_data = await asyncio.gather(
            self._rdap(), self._whois_fallback(), return_exceptions=True
        )
        if isinstance(rdap_data, Exception):
            rdap_data = {}
        if isinstance(fallback_data, Exception):
            fallback_data = {}
        merged = {**fallback_data, **{k: v for k, v in rdap_data.items() if v}}
        return merged


# ── IP INTELLIGENCE ───────────────────────────────────────────────────────────
class IPIntelligence:
    CLOUD_KEYWORDS = {
        "AWS": ["amazonaws", "amazon"],
        "Google Cloud": ["google", "googlecloud"],
        "Azure": ["microsoft", "azure"],
        "Cloudflare": ["cloudflare"],
        "Fastly": ["fastly"],
        "Akamai": ["akamai"],
        "DigitalOcean": ["digitalocean"],
        "Hetzner": ["hetzner"],
        "OVH": ["ovh"],
        "Linode": ["linode"],
        "Vultr": ["vultr"],
    }
    CDN_PROVIDERS = {"Cloudflare", "Fastly", "Akamai"}

    def __init__(self, domain, mode, session, dns_records):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.dns_records = dns_records
        self.timeout = TIMEOUTS[mode]

    def _collect_ips(self):
        ips = set()
        for rec in self.dns_records:
            rtype = rec.get("type") if isinstance(rec, dict) else rec.type
            rval = rec.get("value") if isinstance(rec, dict) else rec.value
            if rtype in ("A", "AAAA"):
                ips.add(rval.strip())
        return ips

    async def _lookup_ip(self, ip):
        rec = IPRecord(ip=ip)
        try:
            resp = await _safe_get(self.session, f"https://ipinfo.io/{ip}/json", timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                org = data.get("org", "")
                parts = org.split(" ", 1)
                rec.asn = parts[0] if parts else ""
                rec.org = parts[1] if len(parts) > 1 else ""
                rec.country = data.get("country", "")
                rec.city = data.get("city", "")
                rec.rdns = data.get("hostname", "")
        except Exception:
            try:
                async with _get_ip_api_sem():
                    resp = await _safe_get(
                        self.session,
                        f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,reverse",
                        timeout=self.timeout
                    )
                await asyncio.sleep(1.5)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("status") == "success":
                        rec.asn = data.get("as", "")
                        rec.org = data.get("org", "") or data.get("isp", "")
                        rec.country = data.get("country", "")
                        rec.city = data.get("city", "")
                        rec.rdns = data.get("reverse", "")
            except Exception:
                pass
        org_lower = rec.org.lower()
        for provider, keywords in self.CLOUD_KEYWORDS.items():
            if any(kw in org_lower for kw in keywords):
                rec.cloud_provider = provider
                break
        # Augment with cloud IP-range detection (more authoritative)
        cloud_prov, cloud_svc = _check_cloud_provider(ip)
        if cloud_prov:
            rec.cloud_provider = cloud_prov
        rec.cdn = rec.cloud_provider in self.CDN_PROVIDERS
        return rec

    async def _shodan_internetdb(self, ip: str) -> dict:
        try:
            resp = await _safe_get(self.session, f"https://internetdb.shodan.io/{ip}", timeout=10)
            if resp and resp.status == 200:
                return await resp.json(content_type=None)
        except Exception:
            pass
        return {}

    async def _bgpview_ip(self, ip: str) -> dict:
        try:
            resp = await _safe_get(self.session, f"https://api.bgpview.io/ip/{ip}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                asns = data.get("data", {}).get("asns", [])
                if asns:
                    return {
                        "asn": asns[0].get("asn", ""),
                        "asn_name": asns[0].get("name", ""),
                        "asn_desc": asns[0].get("description", ""),
                        "rir": data.get("data", {}).get("rir_allocation", {}).get("rir_name", ""),
                    }
        except Exception:
            pass
        return {}

    async def _greynoise(self, ip: str) -> dict:
        try:
            resp = await _safe_get(self.session, f"https://api.greynoise.io/v3/community/{ip}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", ""),
                    "name": data.get("name", ""),
                }
        except Exception:
            pass
        return {}

    async def _otx_ip(self, ip: str) -> dict:
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            resp = await _safe_get(self.session, url, timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name", ""),
                }
        except Exception:
            pass
        return {}

    async def _abuseipdb(self, ip: str) -> dict:
        key = self.api_keys.get("abuseipdb", "")
        if not key:
            return {}
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
            resp = await _safe_get(
                self.session, url, timeout=10,
                headers={"Key": key, "Accept": "application/json"}
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                d = data.get("data", {})
                return {
                    "abuse_score": d.get("abuseConfidenceScore", 0),
                    "total_reports": d.get("totalReports", 0),
                    "country_code": d.get("countryCode", ""),
                    "isp": d.get("isp", ""),
                    "domain": d.get("domain", ""),
                    "usage_type": d.get("usageType", ""),
                }
        except Exception:
            pass
        return {}

    async def _reverse_dns_doh(self, ip: str) -> str:
        """Reverse DNS lookup via DoH."""
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                reversed_ip = ".".join(reversed(parts))
                answers = await _doh_query(
                    self.session, f"{reversed_ip}.in-addr.arpa", "PTR", timeout=8
                )
                if answers:
                    return answers[0].get("data", "").rstrip(".")
        except Exception:
            pass
        return ""

    async def _enrich_ip_full(self, ip: str) -> IPRecord:
        rec = await self._lookup_ip(ip)
        # Run all enrichments concurrently
        shodan_task = asyncio.create_task(self._shodan_internetdb(ip))
        bgp_task    = asyncio.create_task(self._bgpview_ip(ip))
        gn_task     = asyncio.create_task(self._greynoise(ip))
        abuse_task  = asyncio.create_task(self._abuseipdb(ip))
        rdns_task   = asyncio.create_task(self._reverse_dns_doh(ip))
        shodan_data, bgp_data, gn_data, abuse_data, rdns = await asyncio.gather(
            shodan_task, bgp_task, gn_task, abuse_task, rdns_task,
            return_exceptions=True
        )
        # Shodan InternetDB
        if isinstance(shodan_data, dict) and shodan_data:
            hostnames = shodan_data.get("hostnames", [])
            if hostnames and not rec.rdns:
                rec.rdns = hostnames[0]
            rec.__dict__["open_ports"] = shodan_data.get("ports", [])
            rec.__dict__["vulns"]      = shodan_data.get("vulns", [])
            rec.__dict__["cpes"]       = shodan_data.get("cpes", [])
            rec.__dict__["tags"]       = shodan_data.get("tags", [])
        # BGPView
        if isinstance(bgp_data, dict) and bgp_data and not rec.asn:
            rec.asn = str(bgp_data.get("asn", ""))
            rec.org = bgp_data.get("asn_name", "") or bgp_data.get("asn_desc", "") or rec.org
        # GreyNoise
        if isinstance(gn_data, dict) and (gn_data.get("noise") or gn_data.get("classification")):
            rec.__dict__["greynoise"] = gn_data
        # AbuseIPDB
        if isinstance(abuse_data, dict) and abuse_data:
            rec.__dict__["abuseipdb"] = abuse_data
        # Reverse DNS (DoH)
        if isinstance(rdns, str) and rdns and not rec.rdns:
            rec.rdns = rdns
        return rec

    async def enrich(self):
        ips = self._collect_ips()
        if not ips:
            return []
        sem = asyncio.Semaphore(min(SEMAPHORES[self.mode], 20))
        async def limited(ip):
            async with sem:
                return await self._enrich_ip_full(ip)
        tasks = [limited(ip) for ip in list(ips)[:50]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, IPRecord)]


# ── SSL INTELLIGENCE ──────────────────────────────────────────────────────────
class SSLIntelligence:
    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]

    async def _crtsh_certs(self):
        certs = []
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                seen = set()
                for entry in data[:200]:
                    cn = entry.get("common_name", "")
                    issuer = entry.get("issuer_name", "")
                    not_before = entry.get("not_before", "")
                    not_after = entry.get("not_after", "")
                    sans_raw = entry.get("name_value", "")
                    sans = [s.strip().lstrip("*.") for s in sans_raw.splitlines() if s.strip()]
                    key = cn + not_before
                    if key in seen:
                        continue
                    seen.add(key)
                    expired = False
                    days_left = 0
                    try:
                        exp_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        now = datetime.now(exp_dt.tzinfo)
                        days_left = (exp_dt - now).days
                        expired = days_left < 0
                    except Exception:
                        pass
                    certs.append(SSLInfo(
                        subject=cn,
                        issuer=issuer,
                        not_before=not_before,
                        not_after=not_after,
                        san_entries=sans,
                        expired=expired,
                        days_left=days_left,
                        ct_sources=["crt.sh"]
                    ))
        except Exception:
            pass
        return certs

    async def _certspotter_certs(self):
        certs = []
        try:
            url = (f"https://api.certspotter.com/v1/issuances?domain={self.domain}"
                   f"&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data[:100]:
                    dns_names = entry.get("dns_names", [])
                    issuer = entry.get("issuer", {})
                    issuer_str = issuer.get("friendly_name", "") if isinstance(issuer, dict) else str(issuer)
                    not_before = entry.get("not_before", "")
                    not_after = entry.get("not_after", "")
                    cn = dns_names[0] if dns_names else ""
                    days_left = 0
                    expired = False
                    try:
                        exp_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        now = datetime.now(exp_dt.tzinfo)
                        days_left = (exp_dt - now).days
                        expired = days_left < 0
                    except Exception:
                        pass
                    certs.append(SSLInfo(
                        subject=cn,
                        issuer=issuer_str,
                        not_before=not_before,
                        not_after=not_after,
                        san_entries=[n.lstrip("*.") for n in dns_names],
                        expired=expired,
                        days_left=days_left,
                        ct_sources=["certspotter"]
                    ))
        except Exception:
            pass
        return certs

    async def _hsts_preload(self) -> dict:
        try:
            ext = tldextract.extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            resp = await _safe_get(self.session, f"https://hstspreload.org/api/v2/status?domain={apex}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "status": data.get("status", "unknown"),
                    "include_subdomains": data.get("includeSubDomains", False),
                }
        except Exception:
            pass
        return {}

    async def query(self):
        tasks = [self._crtsh_certs()]
        if self.mode in ("balanced", "deep"):
            tasks.append(self._certspotter_certs())
            tasks.append(self._hsts_preload())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_certs = []
        for batch in results:
            if isinstance(batch, list):
                all_certs.extend(batch)
            elif isinstance(batch, dict) and batch:
                # HSTS preload result — embed as a synthetic SSLInfo
                all_certs.append(SSLInfo(
                    subject=f"HSTS:{batch.get('status','unknown')}",
                    issuer="hstspreload.org",
                    ct_sources=["hsts_preload"]
                ))
        return all_certs


# ── WEB ARCHIVE INTELLIGENCE ──────────────────────────────────────────────────
class WebArchiveIntelligence:
    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = max(TIMEOUTS[mode], 30)

    async def _wayback(self):
        urls = []
        limit = {"fast": 300, "balanced": 800, "deep": 2000, "turbo": 200}.get(self.mode, 500)
        try:
            url = (f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*"
                   f"&output=json&fl=original,timestamp,statuscode,mimetype"
                   f"&collapse=urlkey&limit={limit}")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for row in data[1:]:
                    if len(row) >= 4:
                        urls.append(WaybackURL(
                            url=row[0],
                            timestamp=row[1],
                            status_code=int(row[2]) if row[2].isdigit() else 0,
                            mime_type=row[3]
                        ))
        except Exception:
            pass
        return urls

    async def _commoncrawl(self):
        urls = []
        try:
            limit = 300 if self.mode == "deep" else 100
            url = (f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?"
                   f"url=*.{self.domain}&output=json&limit={limit}&fl=url,timestamp,status")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                for line in text.splitlines()[:limit]:
                    try:
                        obj = json.loads(line)
                        urls.append(WaybackURL(
                            url=obj.get("url", ""),
                            timestamp=obj.get("timestamp", ""),
                            status_code=int(obj.get("status", 0)) if str(obj.get("status", "")).isdigit() else 0
                        ))
                    except Exception:
                        pass
        except Exception:
            pass
        return urls

    def _interesting_urls(self, urls):
        interesting_patterns = [
            r"\.env", r"\.git", r"admin", r"backup", r"\.bak",
            r"config", r"debug", r"test", r"dev", r"staging",
            r"api/", r"swagger", r"graphql", r"phpinfo", r"wp-admin",
            r"login", r"dashboard", r"internal", r"secret", r"password",
            r"\.sql", r"\.xml", r"\.json", r"\.yaml", r"\.yml",
            r"\.log", r"\.csv", r"\.xls", r"\.pdf"
        ]
        flagged = []
        for wu in urls:
            for pat in interesting_patterns:
                if re.search(pat, wu.url, re.I):
                    flagged.append(wu)
                    break
        return flagged

    async def _robots_txt_history(self) -> list:
        paths = []
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/robots.txt&output=json&limit=5&fl=timestamp"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for row in data[1:]:
                    ts = row[0] if row else ""
                    archive_url = f"https://web.archive.org/web/{ts}/{self.domain}/robots.txt"
                    r2 = await _safe_get(self.session, archive_url, timeout=self.timeout)
                    if r2 and r2.status == 200:
                        text = await r2.text()
                        for m in re.finditer(r"Disallow:\s*(.+)", text, re.I):
                            paths.append(m.group(1).strip())
        except Exception:
            pass
        return list(set(paths))

    async def _sitemap_history(self) -> list:
        urls = []
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/sitemap.xml&output=json&limit=3&fl=timestamp"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for row in data[1:2]:
                    ts = row[0] if row else ""
                    archive_url = f"https://web.archive.org/web/{ts}/{self.domain}/sitemap.xml"
                    r2 = await _safe_get(self.session, archive_url, timeout=self.timeout)
                    if r2 and r2.status == 200:
                        text = await r2.text()
                        urls.extend(re.findall(r"<loc>([^<]+)</loc>", text))
        except Exception:
            pass
        return urls[:200]

    def _extract_api_endpoints(self, urls: list) -> list:
        api_re = re.compile(r'/(api|v\d+|rest|graphql|gql|rpc|ws)/[^\s"\'<>]*', re.I)
        endpoints = set()
        for wu in urls:
            for m in api_re.finditer(wu.url if hasattr(wu, "url") else str(wu)):
                endpoints.add(m.group(0))
        return list(endpoints)[:100]

    def _extract_sensitive_files(self, urls: list) -> list:
        sens_re = re.compile(
            r'\.(env|git|sql|bak|backup|config|yml|yaml|json|xml|log|csv|xls|xlsx|pdf|htaccess|htpasswd)$'
            r'|/wp-admin|/admin|/dashboard|/panel|/cpanel|/phpinfo|/phpmyadmin',
            re.I
        )
        found = []
        for wu in urls:
            raw = wu.url if hasattr(wu, "url") else str(wu)
            if sens_re.search(raw):
                found.append(raw)
        return found[:100]

    async def mine(self):
        tasks = [self._wayback()]
        if self.mode in ("balanced", "deep"):
            tasks.append(self._commoncrawl())
            tasks.append(self._robots_txt_history())
            tasks.append(self._sitemap_history())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_urls = []
        robots_paths = []
        sitemap_urls = []
        for i, batch in enumerate(results):
            if isinstance(batch, list):
                if i == 2 and self.mode in ("balanced", "deep"):
                    robots_paths = batch
                elif i == 3 and self.mode in ("balanced", "deep"):
                    sitemap_urls = batch
                else:
                    all_urls.extend(batch)
        interesting = self._interesting_urls(all_urls)
        api_endpoints = self._extract_api_endpoints(all_urls)
        sensitive_files = self._extract_sensitive_files(all_urls)
        return {
            "all": all_urls[:500],
            "interesting": interesting[:200],
            "api_endpoints": api_endpoints,
            "sensitive_files": sensitive_files,
            "robots_disallow": robots_paths,
            "sitemap_urls": sitemap_urls[:100],
        }


# ── BREACH INTELLIGENCE ───────────────────────────────────────────────────────
class BreachIntelligence:
    def __init__(self, domain, mode, session, api_keys):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]

    async def _hibp(self):
        breaches = []
        key = self.api_keys.get("hibp", "")
        if not key:
            return breaches
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachesforaccounts/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"hibp-api-key": key, "User-Agent": "ghost-recon-tool"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data:
                    breaches.append(BreachRecord(
                        name=item.get("Name", ""),
                        date=item.get("BreachDate", ""),
                        data_types=item.get("DataClasses", []),
                        description=item.get("Description", "")[:200]
                    ))
        except Exception:
            pass
        return breaches

    async def _dehashed_public(self):
        breaches = []
        try:
            url = f"https://api.dehashed.com/search?query=domain:{self.domain}&size=10"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                total = data.get("total", 0)
                if total > 0:
                    breaches.append(BreachRecord(
                        name="DeHashed",
                        description=f"{total} records found in dehashed.com for {self.domain}",
                        source="dehashed"
                    ))
        except Exception:
            pass
        return breaches

    async def _hibp_domain(self):
        """HIBP breach search by domain (no key required for domain lookup)."""
        breaches = []
        key = self.api_keys.get("hibp", "")
        try:
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}"
            headers = {"hibp-api-key": key, "User-Agent": "ghost-recon-tool"} if key else {"User-Agent": "ghost-recon-tool"}
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data:
                    breaches.append(BreachRecord(
                        name=item.get("Name", ""),
                        date=item.get("BreachDate", ""),
                        data_types=item.get("DataClasses", []),
                        description=item.get("Description", "")[:200]
                    ))
        except Exception:
            pass
        return breaches

    async def _github_dorks(self):
        """Search GitHub for exposed credentials related to the domain."""
        breaches = []
        key = self.api_keys.get("github_token", "")
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/vnd.github.v3.text-match+json"} if key else {"Accept": "application/vnd.github.v3.text-match+json"}
        dork_queries = [
            f'"{self.domain}" password',
            f'"{self.domain}" secret',
            f'"{self.domain}" api_key',
            f'"{self.domain}" token',
            f'"@{self.domain}"',
        ]
        for query in dork_queries:
            try:
                url = f"https://api.github.com/search/code?q={quote(query)}&per_page=30"
                resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("items", []):
                        for match in item.get("text_matches", []):
                            fragment = match.get("fragment", "")
                            for cred_name, cred_re in CRED_PATTERNS.items():
                                if cred_re.search(fragment):
                                    repo = item.get("repository", {}).get("full_name", "")
                                    html_url = item.get("html_url", "")
                                    breaches.append(BreachRecord(
                                        name=f"GitHub Exposure: {cred_name}",
                                        date=datetime.utcnow().strftime("%Y-%m-%d"),
                                        data_types=[cred_name],
                                        description=f"Potential {cred_name} found in {repo}: {html_url}"
                                    ))
                await asyncio.sleep(2)
            except Exception:
                pass
        return breaches

    async def check(self):
        tasks = [self._dehashed_public(), self._hibp_domain()]
        if self.mode in ("balanced", "deep", "turbo"):
            tasks.append(self._github_dorks())
        if self.api_keys.get("hibp"):
            tasks.append(self._hibp())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_breaches = []
        seen_names = set()
        for batch in results:
            if isinstance(batch, list):
                for b in batch:
                    key = (b.name if hasattr(b, "name") else b.get("name", ""))
                    if key and key not in seen_names:
                        seen_names.add(key)
                        all_breaches.append(b)
        return all_breaches


# ── REPUTATION INTELLIGENCE ───────────────────────────────────────────────────
class ReputationIntelligence:
    def __init__(self, domain, mode, session, api_keys):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]

    async def _virustotal(self):
        key = self.api_keys.get("virustotal", "")
        if not key:
            return {}
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"x-apikey": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                votes = data.get("data", {}).get("attributes", {}).get("total_votes", {})
                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                    "votes_harmless": votes.get("harmless", 0),
                    "votes_malicious": votes.get("malicious", 0),
                }
        except Exception:
            pass
        return {}

    async def _otx(self):
        key = self.api_keys.get("otx", "")
        headers = {"X-OTX-API-KEY": key} if key else {}
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/general"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "source": "otx",
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "malware_families": [
                        m.get("display_name", "") for m in
                        data.get("pulse_info", {}).get("related", {}).get("malware_families", [])
                    ][:5],
                    "industries": data.get("pulse_info", {}).get("related", {}).get("industries", [])[:5],
                }
        except Exception:
            pass
        return {}

    async def _urlscan(self):
        key = self.api_keys.get("urlscan", "")
        headers = {"API-Key": key} if key else {}
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=5"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                results = data.get("results", [])
                malicious = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious", False))
                return {
                    "source": "urlscan",
                    "total_scans": data.get("total", 0),
                    "malicious_scans": malicious,
                    "recent_scans": len(results),
                }
        except Exception:
            pass
        return {}

    async def _virustotal_unauth(self):
        try:
            url = f"https://www.virustotal.com/ui/domains/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"Accept": "application/json"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "source": "virustotal_ui",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                }
        except Exception:
            pass
        return {}

    async def _phishtank(self):
        try:
            form_data = aiohttp.FormData()
            form_data.add_field("url", f"https://{self.domain}")
            form_data.add_field("format", "json")
            form_data.add_field("app_key", "")
            async with self.session.post(
                "https://checkurl.phishtank.com/checkurl/", data=form_data,
                headers=_headers(), ssl=False,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    results = data.get("results", {})
                    return {
                        "source": "phishtank",
                        "in_database": results.get("in_database", False),
                        "verified": results.get("verified", False),
                        "valid": results.get("valid", False),
                    }
        except Exception:
            pass
        return {}

    async def _spamhaus_dbl(self):
        try:
            ext = tldextract.extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            answers = await _doh_query(self.session, f"{apex}.dbl.spamhaus.org", "A", timeout=10)
            if answers:
                ip = answers[0].get("data", "")
                classification = {
                    "127.0.1.2": "spammed_domain",
                    "127.0.1.4": "phishing_domain",
                    "127.0.1.5": "malware_domain",
                }.get(ip, "listed")
                return {"source": "spamhaus_dbl", "listed": True, "classification": classification}
            return {"source": "spamhaus_dbl", "listed": False}
        except Exception:
            pass
        return {}

    async def _surbl(self):
        try:
            ext = tldextract.extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            answers = await _doh_query(self.session, f"{apex}.multi.surbl.org", "A", timeout=10)
            if answers:
                result_ip = answers[0].get("data", "")
                # SURBL return codes: https://surbl.org/faq
                classification = {
                    "127.0.0.2": "phishing",
                    "127.0.0.4": "malware",
                    "127.0.0.8": "spam",
                    "127.0.0.16": "abuse",
                }.get(result_ip, "listed")
                return {"source": "surbl", "listed": True,
                        "classification": classification, "result_ip": result_ip}
            return {"source": "surbl", "listed": False}
        except Exception:
            pass
        return {}

    async def _talos(self):
        try:
            url = f"https://talosintelligence.com/sb_api/remote_lookup?query={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"Accept": "application/json"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "source": "talos",
                    "reputation_category": data.get("category", {}).get("description", ""),
                    "email_score": data.get("email_score_name", ""),
                    "web_score": data.get("web_score_name", ""),
                }
        except Exception:
            pass
        return {}

    async def _github_org(self):
        try:
            ext = tldextract.extract(self.domain)
            org_name = ext.domain
            key = self.api_keys.get("github_token", "")
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            resp = await _safe_get(self.session, f"https://api.github.com/orgs/{org_name}",
                                   timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                org_info = {
                    "source": "github_org",
                    "org_name": org_name,
                    "public_repos": data.get("public_repos", 0),
                    "followers": data.get("followers", 0),
                    "description": data.get("description", ""),
                    "blog": data.get("blog", ""),
                    "email": data.get("email", ""),
                    "location": data.get("location", ""),
                    "created_at": data.get("created_at", ""),
                }
                # Also fetch top repos
                repos_resp = await _safe_get(
                    self.session,
                    f"https://api.github.com/orgs/{org_name}/repos?per_page=100&type=public&sort=pushed",
                    timeout=self.timeout, headers=headers
                )
                if repos_resp and repos_resp.status == 200:
                    repos_data = await repos_resp.json(content_type=None)
                    org_info["repos"] = [
                        {
                            "name": r.get("name", ""),
                            "language": r.get("language", ""),
                            "stars": r.get("stargazers_count", 0),
                            "forks": r.get("forks_count", 0),
                            "last_push": r.get("pushed_at", ""),
                            "topics": r.get("topics", []),
                            "description": (r.get("description") or "")[:100],
                        }
                        for r in repos_data
                    ]
                return org_info
        except Exception:
            pass
        return {}

    async def check(self):
        tasks = [
            self._otx(), self._urlscan(), self._virustotal_unauth(),
            self._spamhaus_dbl(), self._surbl(), self._github_org(),
        ]
        if self.api_keys.get("virustotal"):
            tasks.append(self._virustotal())
        if self.mode in ("balanced", "deep"):
            tasks.append(self._phishtank())
            tasks.append(self._talos())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        reputation = {}
        for r in results:
            if isinstance(r, dict) and r:
                source = r.get("source", "unknown")
                reputation[source] = r
        return reputation


# ── CLOUD ASSET INTELLIGENCE ──────────────────────────────────────────────────
class CloudIntelligence:
    S3_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]

    def __init__(self, domain, mode, session, api_keys=None):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys or {}
        self.timeout = TIMEOUTS[mode]
        ext = tldextract.extract(domain)
        self.apex = f"{ext.domain}.{ext.suffix}"
        self.name = ext.domain

    def _bucket_candidates(self):
        candidates = []
        base = self.name
        prefixes = ["", "www.", "static.", "assets.", "media.", "cdn.", "files.", "data.",
                    "backup.", "dev.", "staging.", "api.", "img.", "images."]
        for pfx in prefixes:
            bucket_name = f"{pfx}{base}".strip(".")
            for region in (self.S3_REGIONS if self.mode == "deep" else self.S3_REGIONS[:2]):
                candidates.append({
                    "type": "s3",
                    "name": bucket_name,
                    "url": f"https://{bucket_name}.s3.{region}.amazonaws.com",
                    "region": region
                })
            candidates.append({
                "type": "gcs",
                "name": bucket_name,
                "url": f"https://storage.googleapis.com/{bucket_name}",
                "region": "global"
            })
            candidates.append({
                "type": "azure",
                "name": bucket_name.replace(".", "").replace("-", ""),
                "url": f"https://{bucket_name.replace('.','').replace('-','')}.blob.core.windows.net",
                "region": "azure"
            })
        return candidates[:60] if self.mode != "deep" else candidates

    async def _check_bucket(self, candidate):
        try:
            resp = await self.session.get(
                candidate["url"],
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=_headers(),
                ssl=False,
                allow_redirects=False
            )
            status = resp.status
            if status in (200, 403, 301, 302):
                body = await resp.text()
                public = status == 200 and "ListBucketResult" in body
                return CloudAsset(
                    asset_type=candidate["type"],
                    name=candidate["name"],
                    url=candidate["url"],
                    region=candidate["region"],
                    public=public
                )
        except Exception:
            pass
        return None

    async def _grayhatwarfare(self) -> list:
        assets = []
        key = self.api_keys.get("grayhatwarfare", "")
        try:
            url = f"https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={self.apex}&limit=100&page=1"
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for bucket in data.get("buckets", []):
                    assets.append(CloudAsset(
                        asset_type=bucket.get("type", "bucket"),
                        name=bucket.get("bucket", ""),
                        url=bucket.get("url", ""),
                        region="",
                        public=bucket.get("keywords", "") != ""
                    ))
        except Exception:
            pass
        return assets

    async def _docker_hub(self) -> list:
        assets = []
        try:
            url = f"https://hub.docker.com/v2/search/repositories/?query={self.apex}&page_size=25"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for repo in data.get("results", []):
                    assets.append(CloudAsset(
                        asset_type="docker_image",
                        name=repo.get("repo_name", ""),
                        url=f"https://hub.docker.com/r/{repo.get('repo_name','')}",
                        region="docker.io",
                        public=True
                    ))
        except Exception:
            pass
        return assets

    async def _check_doh_bucket(self, hostname: str, asset_type: str) -> Optional[CloudAsset]:
        """Check bucket existence via DoH only (no direct HTTP to bucket)."""
        try:
            answers = await _doh_query(self.session, hostname, "A", timeout=8)
            if answers:
                return CloudAsset(
                    asset_type=asset_type,
                    name=hostname.split(".")[0],
                    url=f"https://{hostname}",
                    region="",
                    public=False
                )
        except Exception:
            pass
        return None

    async def _check_cloud_doh_permutations(self) -> list:
        assets = []
        perms = [
            self.name, self.name + "-backup", self.name + "-assets",
            self.name + "-media", self.name + "-static", self.name + "-dev",
            self.name + "-staging", self.name + "-prod", self.name + "-data",
            self.name + "-cdn", "backup-" + self.name, "dev-" + self.name,
            self.apex.replace(".", "-"),
        ]
        checks = []
        for p in perms:
            checks.append(self._check_doh_bucket(f"{p}.s3.amazonaws.com", "s3"))
            checks.append(self._check_doh_bucket(f"{p}.blob.core.windows.net", "azure_blob"))
            checks.append(self._check_doh_bucket(f"{p}.storage.googleapis.com", "gcs"))
            checks.append(self._check_doh_bucket(f"{p}.firebaseio.com", "firebase"))
            checks.append(self._check_doh_bucket(f"{p}.web.app", "firebase"))
        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, CloudAsset):
                assets.append(r)
        return assets

    async def discover(self):
        candidates = self._bucket_candidates()
        sem = asyncio.Semaphore(SEMAPHORES[self.mode])
        async def limited(c):
            async with sem:
                return await self._check_bucket(c)
        tasks = [limited(c) for c in candidates]
        extra_tasks = [
            self._grayhatwarfare(),
            self._docker_hub(),
            self._check_cloud_doh_permutations(),
        ]
        all_tasks = tasks + extra_tasks
        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        found = []
        for r in results:
            if isinstance(r, CloudAsset):
                found.append(r)
            elif isinstance(r, list):
                found.extend([x for x in r if isinstance(x, CloudAsset)])
        return found


# ── TYPOSQUAT DETECTOR ────────────────────────────────────────────────────────
class TyposquatDetector:
    COMMON_TLDS = ["com", "net", "org", "io", "co", "us", "info", "biz", "online", "site", "app"]
    HOMOGLYPHS = {
        "a": ["à","á","â","ä","@","4"],
        "e": ["è","é","ê","ë","3"],
        "i": ["ì","í","î","ï","1","l"],
        "o": ["ò","ó","ô","ö","0"],
        "u": ["ù","ú","û","ü"],
        "s": ["$","5"],
        "g": ["9"],
        "b": ["6"],
        "l": ["1","i"],
    }

    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession):
        self.domain = domain
        self.mode = mode
        self.session = session
        ext = tldextract.extract(domain)
        self.name = ext.domain
        self.tld = ext.suffix

    def _generate_variants(self) -> set:
        variants = set()
        name = self.name
        tld = self.tld

        # Missing character
        for i in range(len(name)):
            v = name[:i] + name[i+1:]
            if len(v) >= 3:
                variants.add(f"{v}.{tld}")

        # Transposed adjacent characters
        for i in range(len(name) - 1):
            v = name[:i] + name[i+1] + name[i] + name[i+2:]
            variants.add(f"{v}.{tld}")

        # Doubled character
        for i in range(len(name)):
            v = name[:i] + name[i] + name[i] + name[i+1:]
            variants.add(f"{v}.{tld}")

        # Inserted character (keyboard neighbors simplified)
        keyboard_adj = {"a":"qs","b":"vn","c":"xv","d":"sf","e":"wr","f":"dg","g":"fh",
                        "h":"gj","i":"uo","j":"hk","k":"jl","l":"k","m":"n","n":"mb",
                        "o":"ip","p":"o","q":"aw","r":"et","s":"ad","t":"ry","u":"yi",
                        "v":"cb","w":"qe","x":"zc","y":"ut","z":"x"}
        for i in range(len(name)):
            for adj in keyboard_adj.get(name[i], ""):
                v = name[:i] + adj + name[i+1:]
                variants.add(f"{v}.{tld}")

        # TLD swaps
        for alt_tld in self.COMMON_TLDS:
            if alt_tld != tld:
                variants.add(f"{name}.{alt_tld}")

        # Combosquatting (common prefixes/suffixes)
        for affix in ["app", "api", "login", "secure", "my", "web", "mail", "get", "go"]:
            variants.add(f"{affix}{name}.{tld}")
            variants.add(f"{name}{affix}.{tld}")
            variants.add(f"{affix}-{name}.{tld}")
            variants.add(f"{name}-{affix}.{tld}")

        # Bitsquatting (1-bit error in each character)
        for i in range(len(name)):
            for bit in range(8):
                flipped = chr(ord(name[i]) ^ (1 << bit))
                if flipped.isalnum() or flipped == "-":
                    v = name[:i] + flipped + name[i+1:]
                    if v != name:
                        variants.add(f"{v}.{tld}")

        # Remove self
        variants.discard(self.domain)
        return variants

    async def _check_active(self, variant: str) -> Optional[dict]:
        try:
            answers = await _doh_query(self.session, variant, "A", timeout=5)
            if answers:
                ips = [a.get("data", "") for a in answers if a.get("type") == 1]
                return {"domain": variant, "ips": ips, "active": True}
        except Exception:
            pass
        return None

    async def detect(self) -> list:
        variants = self._generate_variants()
        # Limit checks by mode
        max_variants = 200 if self.mode == "fast" else (500 if self.mode == "balanced" else 1000)
        variants = list(variants)[:max_variants]
        sem = asyncio.Semaphore(30)
        async def limited(v):
            async with sem:
                return await self._check_active(v)
        tasks = [limited(v) for v in variants]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        active = [r for r in results if isinstance(r, dict) and r.get("active")]
        return sorted(active, key=lambda x: x["domain"])


# ── SECURITY HEADERS ANALYZER ─────────────────────────────────────────────────
class SecurityHeadersAnalyzer:
    SECURITY_HEADERS = {
        "strict-transport-security":    {"weight": 25, "name": "HSTS"},
        "content-security-policy":      {"weight": 25, "name": "CSP"},
        "x-frame-options":              {"weight": 15, "name": "X-Frame-Options"},
        "x-content-type-options":       {"weight": 10, "name": "X-Content-Type-Options"},
        "referrer-policy":              {"weight": 10, "name": "Referrer-Policy"},
        "permissions-policy":           {"weight": 10, "name": "Permissions-Policy"},
        "x-xss-protection":             {"weight": 5,  "name": "X-XSS-Protection"},
    }

    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]

    async def analyze(self) -> dict:
        result = {
            "score": 0,
            "grade": "F",
            "headers_present": [],
            "headers_missing": [],
            "details": {},
            "url_checked": "",
        }
        for scheme in (f"https://{self.domain}", f"https://www.{self.domain}"):
            try:
                resp = await _safe_get(self.session, scheme, timeout=self.timeout)
                if resp:
                    result["url_checked"] = scheme
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    score = 0
                    for hdr, meta in self.SECURITY_HEADERS.items():
                        val = resp_headers.get(hdr, "")
                        if val:
                            result["headers_present"].append(meta["name"])
                            score += meta["weight"]
                            result["details"][meta["name"]] = val[:200]
                        else:
                            result["headers_missing"].append(meta["name"])
                    result["score"] = score
                    # Grade
                    if score >= 90:   result["grade"] = "A+"
                    elif score >= 75: result["grade"] = "A"
                    elif score >= 60: result["grade"] = "B"
                    elif score >= 45: result["grade"] = "C"
                    elif score >= 30: result["grade"] = "D"
                    else:             result["grade"] = "F"
                    # Extra: check HTTPS redirect
                    result["https_enforced"] = "strict-transport-security" in resp_headers
                    # Extra: cookies with Secure/HttpOnly
                    set_cookie = resp_headers.get("set-cookie", "")
                    result["cookies_secure"] = "secure" in set_cookie.lower() if set_cookie else None
                    break
            except Exception:
                continue
        return result


# ── SOCIAL FOOTPRINT DETECTOR ─────────────────────────────────────────────────
class SocialFootprintDetector:
    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession, api_keys: dict):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]
        ext = tldextract.extract(domain)
        self.brand = ext.domain

    async def _bing_search(self, query: str) -> list:
        """Search Bing for URLs matching query."""
        key = self.api_keys.get("bing_search", "")
        if not key:
            return []
        try:
            url = "https://api.bing.microsoft.com/v7.0/search"
            resp = await _safe_get(
                self.session, f"{url}?q={quote(query)}&count=5",
                timeout=self.timeout,
                headers={"Ocp-Apim-Subscription-Key": key}
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return [item.get("url", "") for item in data.get("webPages", {}).get("value", [])]
        except Exception:
            pass
        return []

    async def _itunes_app(self) -> list:
        """Find iOS apps via iTunes search."""
        apps = []
        try:
            url = f"https://itunes.apple.com/search?term={quote(self.brand)}&entity=software&limit=5"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("results", []):
                    apps.append({
                        "name": item.get("trackName", ""),
                        "url": item.get("trackViewUrl", ""),
                        "bundle_id": item.get("bundleId", ""),
                        "developer": item.get("artistName", ""),
                        "icon": item.get("artworkUrl60", ""),
                    })
        except Exception:
            pass
        return apps

    async def _find_social(self, platform: str, url_pattern: str) -> Optional[str]:
        results = await self._bing_search(f'site:{url_pattern} "{self.brand}"')
        for r in results:
            if url_pattern in r and self.brand.lower() in r.lower():
                return r
        return None

    async def detect(self) -> dict:
        tasks = {
            "linkedin":  self._find_social("linkedin", "linkedin.com/company"),
            "twitter":   self._find_social("twitter/x", "twitter.com"),
            "github":    self._find_social("github", "github.com"),
            "crunchbase":self._find_social("crunchbase", "crunchbase.com"),
            "facebook":  self._find_social("facebook", "facebook.com"),
            "youtube":   self._find_social("youtube", "youtube.com"),
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        social = {}
        for platform, result in zip(tasks.keys(), results):
            if isinstance(result, str) and result:
                social[platform] = result

        # iOS apps (no Bing key needed)
        ios_apps = await self._itunes_app()

        return {
            "profiles": social,
            "ios_apps": ios_apps,
            "brand": self.brand,
        }


# ── ASN INTELLIGENCE ──────────────────────────────────────────────────────────
class ASNIntelligence:
    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession, ip_records: list):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.ip_records = ip_records
        self.timeout = TIMEOUTS[mode]

    async def _bgpview_asn(self, asn_num: str) -> dict:
        try:
            asn_clean = asn_num.upper().lstrip("AS")
            resp = await _safe_get(self.session, f"https://api.bgpview.io/asn/{asn_clean}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                d = data.get("data", {})
                return {
                    "asn": asn_num,
                    "name": d.get("name", ""),
                    "description": d.get("description_short", ""),
                    "country": d.get("country_code", ""),
                    "rir": d.get("rir_allocation", {}).get("rir_name", "") if d.get("rir_allocation") else "",
                }
        except Exception:
            pass
        return {}

    async def _bgpview_prefixes(self, asn_num: str) -> list:
        try:
            asn_clean = asn_num.upper().lstrip("AS")
            resp = await _safe_get(self.session, f"https://api.bgpview.io/asn/{asn_clean}/prefixes", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                return [{"prefix": p.get("prefix",""), "name": p.get("name",""), "country": p.get("country_code","")} for p in prefixes[:20]]
        except Exception:
            pass
        return []

    async def enrich(self) -> dict:
        seen_asns = set()
        for rec in self.ip_records:
            asn = rec.get("asn", "") if isinstance(rec, dict) else getattr(rec, "asn", "")
            if asn:
                seen_asns.add(asn.upper())
        if not seen_asns:
            return {}
        tasks = {}
        for asn in list(seen_asns)[:5]:
            tasks[asn] = asyncio.create_task(self._bgpview_asn(asn))
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        asn_data = {}
        prefix_tasks = {}
        for asn, result in zip(tasks.keys(), results):
            if isinstance(result, dict) and result:
                asn_data[asn] = result
                if self.mode in ("balanced", "deep"):
                    prefix_tasks[asn] = asyncio.create_task(self._bgpview_prefixes(asn))
        if prefix_tasks:
            prefix_results = await asyncio.gather(*prefix_tasks.values(), return_exceptions=True)
            for asn, pr in zip(prefix_tasks.keys(), prefix_results):
                if isinstance(pr, list) and asn in asn_data:
                    asn_data[asn]["prefixes"] = pr
        return asn_data


# ── TAKEOVER DETECTOR ─────────────────────────────────────────────────────────
class TakeoverDetector:
    def __init__(self, domain, mode, session, subdomains, dns_records):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.subdomains = subdomains
        self.dns_records = dns_records
        self.timeout = TIMEOUTS[mode]

    def _get_cnames(self):
        cname_map = {}
        for rec in self.dns_records:
            rtype = rec.get("type") if isinstance(rec, dict) else rec.type
            rname = rec.get("name") if isinstance(rec, dict) else rec.name
            rval = rec.get("value") if isinstance(rec, dict) else rec.value
            if rtype == "CNAME":
                cname_map.setdefault(rname, []).append(rval.rstrip("."))
        return cname_map

    def _match_provider(self, cname_val):
        for provider, fp in TAKEOVER_FINGERPRINTS.items():
            for marker in fp["cname"]:
                if marker.lstrip(".") in cname_val:
                    return provider, fp["severity"]
        return None, None

    async def _check_takeover(self, subdomain, cname_val):
        provider, severity = self._match_provider(cname_val)
        if not provider:
            return None
        try:
            resp = await _safe_get(self.session, f"http://{subdomain}", timeout=self.timeout)
            if resp:
                body = await resp.text()
                body_lower = body.lower()
                for fingerprint_str in TAKEOVER_FINGERPRINTS[provider]["content"]:
                    if fingerprint_str.lower() in body_lower:
                        return TakeoverRecord(
                            subdomain=subdomain,
                            cname_chain=[cname_val],
                            provider=provider,
                            status="VULNERABLE",
                            evidence=f"CNAME {cname_val!r} + fingerprint {fingerprint_str!r}",
                            severity=severity
                        )
                return TakeoverRecord(
                    subdomain=subdomain,
                    cname_chain=[cname_val],
                    provider=provider,
                    status="INVESTIGATE",
                    evidence=f"CNAME points to {provider} — fingerprint not confirmed",
                    severity="LOW"
                )
        except Exception:
            return TakeoverRecord(
                subdomain=subdomain,
                cname_chain=[cname_val],
                provider=provider,
                status="INVESTIGATE",
                evidence=f"CNAME points to {provider} — host unreachable",
                severity="LOW"
            )
        return None

    async def scan(self):
        cname_map = self._get_cnames()
        tasks = []
        for sub, cnames in cname_map.items():
            for cname_val in cnames:
                tasks.append(self._check_takeover(sub, cname_val))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, TakeoverRecord)]


# ── SCORE ENGINE ──────────────────────────────────────────────────────────────
class ScoreEngine:
    RISKY_CATEGORIES = {"web_server", "backend", "cms", "framework"}
    HIGH_RISK_TECHS = {"WordPress", "Drupal", "Joomla", "Magento", "ASP.NET",
                       "PHP", "Apache", "IIS", "Tomcat"}

    def __init__(self, result):
        self.result = result

    def attack_surface_score(self):
        score = 0
        sub_count = len(self.result.subdomains)
        score += min(sub_count * 2, 35)
        email_count = len(self.result.emails)
        score += min(email_count * 3, 20)
        takeover_count = len([t for t in self.result.takeover_records
                               if (t.get("status") if isinstance(t, dict) else t.status) in ("VULNERABLE",)])
        score += min(takeover_count * 15, 30)
        cloud_public = len([c for c in self.result.cloud_assets
                            if (c.get("public") if isinstance(c, dict) else c.public)])
        score += min(cloud_public * 10, 15)
        return min(score, 100)

    def technology_risk_score(self):
        score = 0
        for tech in self.result.technologies:
            name = tech.get("name") if isinstance(tech, dict) else tech.name
            cat = tech.get("category") if isinstance(tech, dict) else tech.category
            if name in self.HIGH_RISK_TECHS:
                score += 12
            elif cat in self.RISKY_CATEGORIES:
                score += 6
            else:
                score += 2
        return min(score, 100)

    def exposure_score(self):
        score = 0
        breach_count = len(self.result.breach_records)
        score += min(breach_count * 20, 40)
        rep = self.result.reputation_data
        vt = rep.get("virustotal", {})
        if isinstance(vt, dict):
            malicious = vt.get("malicious", 0)
            score += min(malicious * 5, 30)
        otx = rep.get("otx", {})
        if isinstance(otx, dict):
            pulse_count = otx.get("pulse_count", 0)
            score += min(pulse_count * 2, 20)
        wayback = self.result.wayback_urls
        if isinstance(wayback, dict):
            interesting = wayback.get("interesting", [])
            score += min(len(interesting) * 1, 10)
        return min(score, 100)

    def vulnerability_score(self):
        sev_points = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
        score = sum(
            sev_points.get(v.get("severity", "INFO"), 0)
            for v in self.result.vulnerabilities
            if isinstance(v, dict)
        )
        return min(int(score), 100)

    def explain_scores(self):
        atk  = self.attack_surface_score()
        tech = self.technology_risk_score()
        exp  = self.exposure_score()
        vuln = self.vulnerability_score()
        overall = int((atk + tech + exp + vuln) / 4)
        if overall >= 75:
            risk_level = "CRITICAL"
            color = "red"
        elif overall >= 50:
            risk_level = "HIGH"
            color = "orange3"
        elif overall >= 25:
            risk_level = "MEDIUM"
            color = "yellow"
        else:
            risk_level = "LOW"
            color = "green"
        return {
            "attack_surface": atk,
            "technology_risk": tech,
            "exposure": exp,
            "vulnerability": vuln,
            "overall": overall,
            "risk_level": risk_level,
            "color": color,
        }


# ── VULNERABILITY INTELLIGENCE ────────────────────────────────────────────────
class VulnerabilityIntelligence:
    """Multi-source passive vulnerability detection — no direct target contact."""

    PORT_VULNS = {
        21:    {"title": "FTP Exposed",                  "severity": "MEDIUM",   "remediation": "Disable FTP or restrict access. Use SFTP instead.",
                "desc": "FTP service exposed — potential anonymous access or credential brute-force."},
        22:    {"title": "SSH Exposed",                   "severity": "LOW",      "remediation": "Restrict SSH to known IP ranges. Use key-based authentication only.",
                "desc": "SSH exposed to internet — verify strong key-based authentication is enforced."},
        23:    {"title": "Telnet Exposed (CRITICAL)",     "severity": "CRITICAL", "remediation": "Immediately disable Telnet. Replace with SSH.",
                "desc": "Telnet exposed — unencrypted protocol transmitting credentials in cleartext."},
        25:    {"title": "SMTP Exposed",                  "severity": "MEDIUM",   "remediation": "Configure SMTP to require authentication and restrict relaying.",
                "desc": "SMTP service exposed — check for open relay and credential exposure."},
        80:    {"title": "HTTP Without HTTPS",            "severity": "LOW",      "remediation": "Configure HTTPS and redirect all HTTP traffic to HTTPS.",
                "desc": "Web server running on HTTP only — data transmitted in cleartext."},
        445:   {"title": "SMB Exposed (HIGH)",            "severity": "HIGH",     "remediation": "Block SMB ports 445/139 at perimeter firewall immediately.",
                "desc": "SMB exposed — risk of EternalBlue (MS17-010) and lateral movement attacks."},
        3306:  {"title": "MySQL Database Exposed",        "severity": "CRITICAL", "remediation": "Block port 3306 via firewall. Database must not be publicly accessible.",
                "desc": "MySQL database exposed to internet — risk of data exfiltration and remote exploitation."},
        3389:  {"title": "RDP Exposed",                   "severity": "HIGH",     "remediation": "Restrict RDP access via VPN. Enable Network Level Authentication.",
                "desc": "Remote Desktop Protocol exposed — brute force and BlueKeep exploit risk."},
        4443:  {"title": "Alternative HTTPS Port",        "severity": "LOW",      "remediation": "Review necessity of alternative HTTPS port exposure.",
                "desc": "Alternative HTTPS port 4443 exposed to internet."},
        5432:  {"title": "PostgreSQL Database Exposed",   "severity": "CRITICAL", "remediation": "Block port 5432 via firewall. Database must not be publicly accessible.",
                "desc": "PostgreSQL database exposed to internet — risk of data exfiltration."},
        6379:  {"title": "Redis Exposed",                 "severity": "CRITICAL", "remediation": "Block port 6379 via firewall. Configure Redis authentication (requirepass).",
                "desc": "Redis exposed — often unauthenticated by default, allowing full data access."},
        8080:  {"title": "Alternative HTTP Port",         "severity": "LOW",      "remediation": "Review necessity of alternative HTTP port. Ensure it enforces same security controls.",
                "desc": "Alternative web port 8080 exposed — may bypass WAF or security controls."},
        8443:  {"title": "Alternative HTTPS Port",        "severity": "LOW",      "remediation": "Review necessity of alternative HTTPS port exposure.",
                "desc": "Alternative HTTPS port 8443 exposed to internet."},
        8888:  {"title": "Dev/Jupyter Port Exposed",      "severity": "MEDIUM",   "remediation": "Restrict development ports from public internet. Use VPN or SSH tunneling.",
                "desc": "Port 8888 exposed — possible Jupyter notebook or development server with no authentication."},
        9200:  {"title": "Elasticsearch Exposed",         "severity": "CRITICAL", "remediation": "Block port 9200 via firewall. Enable Elasticsearch security (X-Pack).",
                "desc": "Elasticsearch exposed to internet — risk of data exfiltration or index manipulation."},
        11211: {"title": "Memcached Exposed",             "severity": "HIGH",     "remediation": "Block port 11211 via firewall. Memcached has no authentication by default.",
                "desc": "Memcached exposed — DDoS amplification vector and unauthenticated data access."},
        27017: {"title": "MongoDB Exposed",               "severity": "CRITICAL", "remediation": "Block port 27017 via firewall. Enable MongoDB authentication and TLS.",
                "desc": "MongoDB exposed to internet — risk of data exfiltration or ransomware."},
        2375:  {"title": "Docker API Exposed (CRITICAL)", "severity": "CRITICAL", "remediation": "Immediately block port 2375. Use TLS-authenticated Docker socket (2376).",
                "desc": "Docker daemon API exposed unauthenticated — allows full host takeover via container escape."},
    }

    def __init__(self, domain, mode, session, ip_records, dns_records, ssl_info,
                 security_headers, takeover_records):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.ip_records = ip_records
        self.dns_records = dns_records
        self.ssl_info = ssl_info
        self.security_headers = security_headers
        self.takeover_records = takeover_records
        self.timeout = TIMEOUTS[mode]

    def _vuln(self, **kw) -> dict:
        return {
            "cve_id":        kw.get("cve_id", ""),
            "title":         kw.get("title", ""),
            "description":   kw.get("description", ""),
            "severity":      kw.get("severity", "INFO"),
            "cvss_score":    kw.get("cvss_score"),
            "affected_asset":kw.get("affected_asset", self.domain),
            "source":        kw.get("source", "analysis"),
            "remediation":   kw.get("remediation", ""),
            "references":    kw.get("references", []),
        }

    async def _fetch_cve_details(self, cve_id: str) -> dict:
        details: dict = {}
        try:
            resp = await _safe_get(self.session, f"https://cve.circl.lu/api/cve/{cve_id}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                details["summary"]    = (data.get("summary") or "")[:300]
                details["cvss"]       = data.get("cvss")
                details["cvss3"]      = data.get("cvss3")
                details["references"] = data.get("references", [])[:5]
        except Exception:
            pass
        return details

    def _analyze_ports(self) -> list:
        vulns = []
        for ip_rec in self.ip_records:
            ip    = ip_rec.get("ip", "")    if isinstance(ip_rec, dict) else getattr(ip_rec, "ip",    "")
            ports = ip_rec.get("open_ports", []) if isinstance(ip_rec, dict) else getattr(ip_rec, "open_ports", [])
            for port in (ports or []):
                if port in self.PORT_VULNS:
                    pv = self.PORT_VULNS[port]
                    vulns.append(self._vuln(
                        cve_id=f"GHOST-PORT-{port}",
                        title=pv["title"],
                        description=pv["desc"],
                        severity=pv["severity"],
                        affected_asset=f"{ip}:{port}",
                        source="port_analysis",
                        remediation=pv["remediation"],
                    ))
        return vulns

    def _analyze_dns(self) -> list:
        vulns = []
        has_spf = has_dmarc = has_caa = has_dnssec = False
        spf_value = ""
        for rec in self.dns_records:
            rtype = rec.get("type", "") if isinstance(rec, dict) else getattr(rec, "type", "")
            rval  = rec.get("value", "") if isinstance(rec, dict) else getattr(rec, "value", "")
            if rtype == "TXT" and "v=spf1" in rval:
                has_spf = True
                spf_value = rval
                if "+all" in rval:
                    vulns.append(self._vuln(
                        cve_id="GHOST-DNS-SPF-PLUSALL",
                        title="SPF Record Allows ALL Senders (+all)",
                        description="SPF uses +all which permits any mail server to send email on behalf of this domain — trivially bypassable.",
                        severity="CRITICAL", affected_asset=self.domain, source="dns_analysis",
                        remediation="Change SPF record to use -all (hard fail). Remove +all immediately.",
                        references=["https://www.rfc-editor.org/rfc/rfc7208"],
                    ))
                elif "~all" in rval:
                    vulns.append(self._vuln(
                        cve_id="GHOST-DNS-SPF-SOFTFAIL",
                        title="SPF Record Uses Soft Fail (~all)",
                        description="SPF ~all means unauthorized senders receive a soft fail but messages are still delivered.",
                        severity="MEDIUM", affected_asset=self.domain, source="dns_analysis",
                        remediation="Consider changing to -all (hard fail) for stronger email spoofing protection.",
                    ))
            if rtype == "TXT" and "v=DMARC1" in rval:
                has_dmarc = True
                if "p=none" in rval:
                    vulns.append(self._vuln(
                        cve_id="GHOST-DNS-DMARC-NONE",
                        title="DMARC Policy is None (Monitoring Only)",
                        description="DMARC p=none only monitors — spoofed emails are NOT rejected or quarantined.",
                        severity="MEDIUM", affected_asset=self.domain, source="dns_analysis",
                        remediation="Gradually move DMARC policy from p=none → p=quarantine → p=reject.",
                        references=["https://dmarc.org/overview/"],
                    ))
            if rtype == "CAA":
                has_caa = True
            if rtype == "DNSKEY":
                has_dnssec = True
        if not has_spf:
            vulns.append(self._vuln(
                cve_id="GHOST-DNS-NO-SPF", title="No SPF Record Found",
                description="No SPF record exists — attackers can spoof email from this domain.",
                severity="HIGH", affected_asset=self.domain, source="dns_analysis",
                remediation="Add an SPF TXT record specifying authorized mail servers ending with -all.",
                references=["https://www.rfc-editor.org/rfc/rfc7208"],
            ))
        if not has_dmarc:
            vulns.append(self._vuln(
                cve_id="GHOST-DNS-NO-DMARC", title="No DMARC Record Found",
                description="No DMARC record — no policy exists to prevent email spoofing attacks.",
                severity="HIGH", affected_asset=self.domain, source="dns_analysis",
                remediation="Add _dmarc TXT record starting with v=DMARC1;p=quarantine or p=reject.",
                references=["https://dmarc.org/overview/"],
            ))
        if not has_caa:
            vulns.append(self._vuln(
                cve_id="GHOST-DNS-NO-CAA", title="No CAA Record Found",
                description="No CAA record allows any Certificate Authority to issue SSL certs for this domain.",
                severity="LOW", affected_asset=self.domain, source="dns_analysis",
                remediation="Add CAA records to restrict which CAs can issue certificates.",
                references=["https://letsencrypt.org/docs/caa/"],
            ))
        if not has_dnssec:
            vulns.append(self._vuln(
                cve_id="GHOST-DNS-NO-DNSSEC", title="DNSSEC Not Enabled",
                description="DNSSEC is not configured — DNS responses can be spoofed (DNS cache poisoning).",
                severity="LOW", affected_asset=self.domain, source="dns_analysis",
                remediation="Enable DNSSEC via your DNS registrar to cryptographically sign DNS records.",
                references=["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"],
            ))
        return vulns

    def _analyze_ssl(self) -> list:
        vulns = []
        has_hsts = False
        if self.security_headers:
            has_hsts = "HSTS" in self.security_headers.get("headers_present", [])
        for cert in self.ssl_info:
            subject   = cert.get("subject",   "") if isinstance(cert, dict) else getattr(cert, "subject",   "")
            expired   = cert.get("expired",   False) if isinstance(cert, dict) else getattr(cert, "expired",   False)
            days_left = cert.get("days_left", 0)    if isinstance(cert, dict) else getattr(cert, "days_left", 0)
            if expired and subject and "HSTS:" not in subject:
                vulns.append(self._vuln(
                    cve_id="GHOST-SSL-EXPIRED", title=f"Expired SSL Certificate: {subject[:50]}",
                    description=f"SSL certificate has expired — browsers show security warnings and reject connections.",
                    severity="HIGH", affected_asset=subject, source="ssl_analysis",
                    remediation="Renew the expired SSL certificate immediately.",
                ))
            elif days_left and 0 < days_left < 30 and subject and "HSTS:" not in subject:
                vulns.append(self._vuln(
                    cve_id="GHOST-SSL-EXPIRING", title=f"SSL Certificate Expiring in {days_left} Days",
                    description=f"SSL certificate for {subject} will expire in {days_left} days.",
                    severity="MEDIUM", affected_asset=subject, source="ssl_analysis",
                    remediation="Renew the SSL certificate before expiry to avoid service disruption.",
                ))
        if not has_hsts:
            vulns.append(self._vuln(
                cve_id="GHOST-SSL-NO-HSTS", title="Missing HSTS Header",
                description="HTTP Strict Transport Security is not configured — SSL stripping attacks possible.",
                severity="MEDIUM", affected_asset=self.domain, source="ssl_analysis",
                remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains header.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            ))
        return vulns

    def _analyze_headers(self) -> list:
        vulns = []
        if not self.security_headers:
            return vulns
        headers_missing = self.security_headers.get("headers_missing", [])
        details         = self.security_headers.get("details", {})
        header_map = {
            "CSP": dict(cve_id="GHOST-HDR-NO-CSP", title="Missing Content Security Policy (CSP)",
                description="No CSP header — XSS attacks are unrestricted. Attackers can inject arbitrary scripts.",
                severity="MEDIUM", remediation="Implement a Content-Security-Policy header to restrict resource loading.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]),
            "X-Frame-Options": dict(cve_id="GHOST-HDR-NO-XFO", title="Missing X-Frame-Options (Clickjacking Risk)",
                description="No X-Frame-Options header — site can be embedded in iframes, enabling clickjacking.",
                severity="MEDIUM", remediation="Add X-Frame-Options: DENY or use CSP frame-ancestors directive.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"]),
            "X-Content-Type-Options": dict(cve_id="GHOST-HDR-NO-XCTO", title="Missing X-Content-Type-Options",
                description="No X-Content-Type-Options: nosniff — browsers may MIME-sniff responses.",
                severity="LOW", remediation="Add X-Content-Type-Options: nosniff to all responses."),
        }
        for hdr_name, vuln_info in header_map.items():
            if hdr_name in headers_missing:
                vulns.append(self._vuln(
                    affected_asset=self.domain, source="headers_analysis", **vuln_info))
        csp_val = details.get("CSP", "")
        if csp_val:
            if "unsafe-inline" in csp_val:
                vulns.append(self._vuln(
                    cve_id="GHOST-HDR-CSP-UNSAFE-INLINE", title="CSP Contains 'unsafe-inline'",
                    description="CSP unsafe-inline directive allows inline script/style execution, weakening XSS protection.",
                    severity="MEDIUM", affected_asset=self.domain, source="headers_analysis",
                    remediation="Remove unsafe-inline from CSP. Use nonces or hashes for inline scripts."))
            if "unsafe-eval" in csp_val:
                vulns.append(self._vuln(
                    cve_id="GHOST-HDR-CSP-UNSAFE-EVAL", title="CSP Contains 'unsafe-eval'",
                    description="CSP unsafe-eval allows dynamic code execution via eval() — increases XSS risk.",
                    severity="MEDIUM", affected_asset=self.domain, source="headers_analysis",
                    remediation="Remove unsafe-eval from CSP and refactor code to avoid eval(), Function(), etc."))
        return vulns

    def _analyze_takeovers(self) -> list:
        vulns = []
        sev_map = {"VULNERABLE": "CRITICAL", "LIKELY_VULNERABLE": "HIGH", "INVESTIGATE": "MEDIUM"}
        for t in self.takeover_records:
            status    = t.get("status",    "") if isinstance(t, dict) else getattr(t, "status",    "")
            subdomain = t.get("subdomain", "") if isinstance(t, dict) else getattr(t, "subdomain", "")
            provider  = t.get("provider",  "") if isinstance(t, dict) else getattr(t, "provider",  "")
            if status in ("VULNERABLE", "LIKELY_VULNERABLE", "INVESTIGATE"):
                slug = subdomain.replace(".", "-").upper()[:20]
                vulns.append(self._vuln(
                    cve_id=f"GHOST-TAKEOVER-{slug}",
                    title=f"Subdomain Takeover {'CONFIRMED' if status == 'VULNERABLE' else 'Possible'}: {subdomain}",
                    description=f"Subdomain {subdomain} is {'vulnerable' if status == 'VULNERABLE' else 'potentially vulnerable'} to takeover via {provider}.",
                    severity=sev_map.get(status, "LOW"),
                    affected_asset=subdomain, source="takeover",
                    remediation=f"Remove dangling CNAME for {subdomain} or claim the {provider} resource immediately.",
                ))
        return vulns

    async def _fetch_shodan_cves(self) -> list:
        vulns = []
        seen_cves: set = set()
        for ip_rec in self.ip_records:
            ip        = ip_rec.get("ip",    "") if isinstance(ip_rec, dict) else getattr(ip_rec, "ip",    "")
            cve_list  = ip_rec.get("vulns", []) if isinstance(ip_rec, dict) else getattr(ip_rec, "vulns", [])
            for cve_id in (cve_list or []):
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                try:
                    details = await self._fetch_cve_details(cve_id)
                    severity = "HIGH"
                    cvss = details.get("cvss3") or details.get("cvss")
                    if cvss:
                        try:
                            score = float(cvss)
                            if score >= 9.0:   severity = "CRITICAL"
                            elif score >= 7.0: severity = "HIGH"
                            elif score >= 4.0: severity = "MEDIUM"
                            else:              severity = "LOW"
                        except (ValueError, TypeError):
                            pass
                    vulns.append(self._vuln(
                        cve_id=cve_id,
                        title=f"{cve_id} — {(details.get('summary','') or '')[:80]}",
                        description=details.get("summary", ""),
                        severity=severity,
                        cvss_score=cvss,
                        affected_asset=ip,
                        source="shodan_internetdb",
                        references=details.get("references", [])[:3],
                        remediation="Apply the relevant vendor security patches for this CVE.",
                    ))
                    await asyncio.sleep(0.25)
                except Exception:
                    pass
        return vulns

    async def analyze(self) -> list:
        all_vulns: list = []
        all_vulns.extend(self._analyze_ports())
        all_vulns.extend(self._analyze_dns())
        all_vulns.extend(self._analyze_ssl())
        all_vulns.extend(self._analyze_headers())
        all_vulns.extend(self._analyze_takeovers())
        if self.mode in ("balanced", "deep"):
            shodan_vulns = await self._fetch_shodan_cves()
            all_vulns.extend(shodan_vulns)
        # Deduplicate
        seen: set = set()
        deduped = []
        for v in all_vulns:
            key = v.get("cve_id", "") + "|" + v.get("affected_asset", "")
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        deduped.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 99))
        return deduped


# ── RECON ENGINE ORCHESTRATOR ─────────────────────────────────────────────────
class ReconEngine:
    def __init__(self, domain, mode, api_keys, output_dir, progress_cb=None):
        self.domain = domain.lower().strip()
        self.mode = mode
        self.api_keys = api_keys
        self.output_dir = Path(output_dir)
        self.timeout = TIMEOUTS[mode]
        self.sem = asyncio.Semaphore(SEMAPHORES[mode])
        self.progress_cb = progress_cb  # async callable(event_type: str, data: dict)

    async def _emit(self, event_type: str, data: dict):
        if self.progress_cb:
            try:
                await self.progress_cb(event_type, data)
            except Exception:
                pass

    def _make_session(self):
        connector = aiohttp.TCPConnector(
            limit=200,
            limit_per_host=20,
            ssl=False,
            ttl_dns_cache=300,
            force_close=False,
        )
        return aiohttp.ClientSession(connector=connector)

    async def run(self):
        scan_id = hashlib.md5(f"{self.domain}{time.time()}".encode()).hexdigest()[:8]
        scan_date = datetime.utcnow().isoformat() + "Z"
        t_start = time.time()
        # Pre-load cloud IP ranges once
        try:
            _init_session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False, limit=20)
            )
            async with _init_session:
                await _load_cloud_ranges(_init_session)
        except Exception:
            pass

        result = ReconResult(
            domain=self.domain,
            scan_id=scan_id,
            scan_date=scan_date,
            mode=self.mode,
        )

        if not self.progress_cb:
            console.print(Panel(
                f"[bold green]Ghost Recon Tool[/bold green]\n"
                f"Target: [cyan]{self.domain}[/cyan]  |  Mode: [yellow]{self.mode}[/yellow]  |  ID: [dim]{scan_id}[/dim]",
                border_style="green"
            ))

        await self._emit("start", {"scan_id": scan_id, "domain": self.domain, "mode": self.mode})

        async with self._make_session() as session:
            _cli_prog = None
            if not self.progress_cb:
                _cli_prog = Progress(
                    SpinnerColumn(style="green"),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=30),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                )
                _cli_prog.start()
                _task_id = _cli_prog.add_task("[green]Running intelligence modules...", total=16)

            # Phase 1: DNS
            await self._emit("phase", {"name": "DNS Intelligence", "status": "running", "icon": "🔍"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]DNS Intelligence")
            dns_engine = DNSIntelligence(self.domain, self.mode, session)
            dns_records = await dns_engine.query()
            result.dns_records = [asdict(r) for r in dns_records]
            await self._emit("phase", {"name": "DNS Intelligence", "status": "done",
                                       "count": len(result.dns_records), "icon": "✅"})
            if _cli_prog:
                _cli_prog.advance(_task_id)

            # Phase 2: Parallel modules
            _parallel_modules = [
                "Subdomain Enumeration", "Email Discovery", "Technology Detection",
                "WHOIS Intelligence", "IP Intelligence", "SSL Intelligence",
                "Web Archive", "Breach Intelligence", "Reputation Intel", "Cloud Assets"
            ]
            for mod in _parallel_modules:
                await self._emit("phase", {"name": mod, "status": "running", "icon": "⚡"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]Running parallel modules")

            sub_enum   = SubdomainEnumerator(self.domain, self.mode, session, self.api_keys)
            email_disc = EmailDiscovery(self.domain, self.mode, session, self.api_keys)
            tech_det   = TechnologyDetector(self.domain, self.mode, session, result.dns_records)
            whois_int  = WhoisIntelligence(self.domain, self.mode, session)
            ip_int     = IPIntelligence(self.domain, self.mode, session, result.dns_records)
            ssl_int    = SSLIntelligence(self.domain, self.mode, session)
            archive    = WebArchiveIntelligence(self.domain, self.mode, session)
            breach     = BreachIntelligence(self.domain, self.mode, session, self.api_keys)
            rep        = ReputationIntelligence(self.domain, self.mode, session, self.api_keys)
            cloud      = CloudIntelligence(self.domain, self.mode, session, self.api_keys)

            (
                sub_results,
                email_results,
                tech_results,
                whois_data,
                ip_results,
                ssl_results,
                archive_data,
                breach_data,
                rep_data,
                cloud_data,
            ) = await asyncio.gather(
                sub_enum.enumerate(),
                email_disc.discover(),
                tech_det.detect(),
                whois_int.lookup(),
                ip_int.enrich(),
                ssl_int.query(),
                archive.mine(),
                breach.check(),
                rep.check(),
                cloud.discover(),
                return_exceptions=True
            )
            if _cli_prog:
                _cli_prog.advance(_task_id, 9)

            # Assign results safely
            result.subdomains = [asdict(v) for v in sub_results.values()] if isinstance(sub_results, dict) else []
            result.emails = [asdict(v) for v in email_results.values()] if isinstance(email_results, dict) else []
            result.technologies = [asdict(t) for t in tech_results] if isinstance(tech_results, list) else []
            result.whois_data = whois_data if isinstance(whois_data, dict) else {}
            result.ip_records = [asdict(r) for r in ip_results] if isinstance(ip_results, list) else []
            result.ssl_info = [asdict(s) for s in ssl_results] if isinstance(ssl_results, list) else []
            result.wayback_urls = archive_data if isinstance(archive_data, dict) else {}
            result.breach_records = [asdict(b) for b in breach_data] if isinstance(breach_data, list) else []
            result.reputation_data = rep_data if isinstance(rep_data, dict) else {}
            result.cloud_assets = [asdict(c) for c in cloud_data] if isinstance(cloud_data, list) else []

            # Emit parallel done events
            counts = {
                "Subdomain Enumeration": len(result.subdomains),
                "Email Discovery": len(result.emails),
                "Technology Detection": len(result.technologies),
                "WHOIS Intelligence": len(result.whois_data),
                "IP Intelligence": len(result.ip_records),
                "SSL Intelligence": len(result.ssl_info),
                "Web Archive": len((result.wayback_urls or {}).get("interesting", [])),
                "Breach Intelligence": len(result.breach_records),
                "Reputation Intel": len(result.reputation_data),
                "Cloud Assets": len(result.cloud_assets),
            }
            for mod, cnt in counts.items():
                await self._emit("phase", {"name": mod, "status": "done", "count": cnt, "icon": "✅"})

            # Phase 3: Takeover detection
            await self._emit("phase", {"name": "Takeover Detection", "status": "running", "icon": "🎯"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]Takeover Detection")
            takeover_det = TakeoverDetector(
                self.domain, self.mode, session,
                result.subdomains, result.dns_records
            )
            takeover_results = await takeover_det.scan()
            result.takeover_records = [asdict(t) for t in takeover_results] if isinstance(takeover_results, list) else []
            await self._emit("phase", {"name": "Takeover Detection", "status": "done",
                                       "count": len(result.takeover_records), "icon": "✅"})
            if _cli_prog:
                _cli_prog.advance(_task_id)

            # Phase 4: New intelligence modules (typosquat, sec headers, social, ASN) in parallel
            new_mods = ["Typosquat Detection", "Security Headers", "Social Footprint", "ASN Intelligence"]
            for mod in new_mods:
                await self._emit("phase", {"name": mod, "status": "running", "icon": "⚡"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]Extended Intelligence")

            typo_det  = TyposquatDetector(self.domain, self.mode, session)
            sec_hdrs  = SecurityHeadersAnalyzer(self.domain, self.mode, session)
            social_fp = SocialFootprintDetector(self.domain, self.mode, session, self.api_keys)
            asn_int   = ASNIntelligence(self.domain, self.mode, session, result.ip_records)

            (
                typo_results,
                sec_hdr_data,
                social_data,
                asn_data,
            ) = await asyncio.gather(
                typo_det.detect(),
                sec_hdrs.analyze(),
                social_fp.detect(),
                asn_int.enrich(),
                return_exceptions=True
            )
            if _cli_prog:
                _cli_prog.advance(_task_id, 4)

            result.typosquats      = typo_results if isinstance(typo_results, list) else []
            result.security_headers= sec_hdr_data if isinstance(sec_hdr_data, dict) else {}
            result.social_footprint= social_data if isinstance(social_data, dict) else {}
            result.asn_intelligence= asn_data if isinstance(asn_data, dict) else {}

            new_counts = {
                "Typosquat Detection": len(result.typosquats),
                "Security Headers": result.security_headers.get("score", 0),
                "Social Footprint": len(result.social_footprint.get("profiles", {})),
                "ASN Intelligence": len(result.asn_intelligence),
            }
            for mod, cnt in new_counts.items():
                await self._emit("phase", {"name": mod, "status": "done", "count": cnt, "icon": "✅"})

            # Phase 5: Vulnerability Intelligence
            await self._emit("phase", {"name": "Vulnerability Intelligence", "status": "running", "icon": "🛡️"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]Vulnerability Intelligence")
            vuln_intel = VulnerabilityIntelligence(
                domain=self.domain,
                mode=self.mode,
                session=session,
                ip_records=result.ip_records,
                dns_records=result.dns_records,
                ssl_info=result.ssl_info,
                security_headers=result.security_headers,
                takeover_records=result.takeover_records,
            )
            result.vulnerabilities = await vuln_intel.analyze()
            await self._emit("phase", {
                "name": "Vulnerability Intelligence", "status": "done",
                "count": len(result.vulnerabilities), "icon": "✅"
            })
            if _cli_prog:
                _cli_prog.advance(_task_id)

            # Phase 6: Scoring
            await self._emit("phase", {"name": "Risk Scoring", "status": "running", "icon": "📊"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]Scoring")
            scorer = ScoreEngine(result)
            result.scores = scorer.explain_scores()
            await self._emit("phase", {"name": "Risk Scoring", "status": "done", "count": 0, "icon": "✅"})
            if _cli_prog:
                _cli_prog.advance(_task_id)

            if _cli_prog:
                try:
                    _cli_prog.stop()
                except Exception:
                    pass

        result.duration_seconds = round(time.time() - t_start, 2)
        await self._emit("complete", {
            "scan_id": scan_id,
            "domain": self.domain,
            "duration": result.duration_seconds,
            "scores": result.scores,
            "summary": {
                "subdomains": len(result.subdomains),
                "emails": len(result.emails),
                "technologies": len(result.technologies),
                "dns_records": len(result.dns_records),
                "ip_records": len(result.ip_records),
                "takeover_records": len(result.takeover_records),
                "cloud_assets": len(result.cloud_assets),
                "breach_records": len(result.breach_records),
                "typosquats": len(result.typosquats),
                "vulnerabilities": len(result.vulnerabilities),
                "security_score": result.security_headers.get("score", 0),
                "social_profiles": len(result.social_footprint.get("profiles", {})),
            }
        })
        return result


# ── OUTPUT WRITERS ────────────────────────────────────────────────────────────
def write_json(result: ReconResult, out_dir: Path):
    path = out_dir / "report.json"
    data = asdict(result)
    # Add top-level meta/scores/summary for easier consumption
    output = {
        "meta": {
            "tool": "Ghost Recon Tool",
            "version": "2.0",
            "domain": result.domain,
            "scan_id": result.scan_id,
            "scan_date": result.scan_date,
            "mode": result.mode,
            "duration_seconds": result.duration_seconds,
        },
        "scores": result.scores,
        "summary": {
            "subdomains": len(result.subdomains),
            "emails": len(result.emails),
            "technologies": len(result.technologies),
            "dns_records": len(result.dns_records),
            "ip_records": len(result.ip_records),
            "ssl_certs": len(result.ssl_info),
            "takeover_candidates": len(result.takeover_records),
            "cloud_assets": len(result.cloud_assets),
            "breach_records": len(result.breach_records),
            "typosquats": len(result.typosquats),
            "security_score": result.security_headers.get("score", 0),
            "security_grade": result.security_headers.get("grade", "N/A"),
            "social_profiles": len(result.social_footprint.get("profiles", {})),
        },
        "data": data,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    return path


def write_txt(result: ReconResult, out_dir: Path):
    path = out_dir / "report.txt"
    lines = []
    sep = "=" * 72
    lines.append(sep)
    lines.append("  GHOST RECON TOOL — Passive Domain Reconnaissance Report")
    lines.append(sep)
    lines.append(f"  Domain   : {result.domain}")
    lines.append(f"  Scan ID  : {result.scan_id}")
    lines.append(f"  Date     : {result.scan_date}")
    lines.append(f"  Mode     : {result.mode}")
    lines.append(f"  Duration : {result.duration_seconds}s")
    scores = result.scores
    lines.append(f"  Risk     : {scores.get('risk_level', 'N/A')} (Overall: {scores.get('overall', 0)}/100)")
    lines.append(sep)

    lines.append("\n[SUBDOMAINS]")
    for s in result.subdomains:
        ips = ", ".join(s.get("ips", [])) or "—"
        src = ", ".join(s.get("sources", []))
        lines.append(f"  {s.get('name','')}  [{src}]  IPs: {ips}")

    lines.append("\n[DNS RECORDS]")
    for r in result.dns_records:
        lines.append(f"  {r.get('type',''):6}  {r.get('name',''):40}  {r.get('value','')}")

    lines.append("\n[EMAILS]")
    for e in result.emails:
        lines.append(f"  {e.get('email','')}  [{e.get('role_category','')}]  via {', '.join(e.get('sources',[]))}")

    lines.append("\n[TECHNOLOGIES]")
    for t in result.technologies:
        lines.append(f"  {t.get('name',''):25}  {t.get('category',''):20}  ({t.get('confidence','')})")

    lines.append("\n[IP RECORDS]")
    for ip in result.ip_records:
        lines.append(f"  {ip.get('ip',''):18}  ASN:{ip.get('asn','')}  {ip.get('org','')}  {ip.get('country','')}  CDN:{ip.get('cdn',False)}")

    lines.append("\n[TAKEOVER CANDIDATES]")
    for t in result.takeover_records:
        lines.append(f"  [{t.get('severity','')}] {t.get('subdomain','')} -> {t.get('provider','')}  ({t.get('status','')})")

    lines.append("\n[CLOUD ASSETS]")
    for c in result.cloud_assets:
        lines.append(f"  {c.get('asset_type',''):8}  {c.get('name',''):40}  public:{c.get('public',False)}")

    lines.append("\n[BREACH RECORDS]")
    for b in result.breach_records:
        lines.append(f"  {b.get('name','')}  {b.get('date','')}  {b.get('description','')[:80]}")

    lines.append("\n[WHOIS]")
    for k, v in result.whois_data.items():
        if k != "source":
            lines.append(f"  {k}: {v}")

    lines.append("\n[SCORES]")
    for k, v in scores.items():
        lines.append(f"  {k}: {v}")
    lines.append(sep)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def write_html(result: ReconResult, out_dir: Path):
    path = out_dir / "report.html"
    template_path = Path(__file__).parent / "templates" / "report.html"
    if template_path.exists():
        with open(template_path, encoding="utf-8") as f:
            tmpl_src = f.read()
    else:
        tmpl_src = "<html><body><pre>{{ data }}</pre></body></html>"

    tmpl = Template(tmpl_src)
    html = tmpl.render(
        domain=result.domain,
        scan_id=result.scan_id,
        scan_date=result.scan_date,
        mode=result.mode,
        duration=result.duration_seconds,
        scores=result.scores,
        subdomains=result.subdomains,
        emails=result.emails,
        technologies=result.technologies,
        dns_records=result.dns_records,
        ip_records=result.ip_records,
        ssl_info=result.ssl_info,
        takeover_records=result.takeover_records,
        cloud_assets=result.cloud_assets,
        breach_records=result.breach_records,
        wayback_urls=result.wayback_urls,
        whois_data=result.whois_data,
        reputation_data=result.reputation_data,
        data=json.dumps(asdict(result), indent=2, default=str),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ── RESULTS PRINTER ───────────────────────────────────────────────────────────
def print_results(result: ReconResult):
    scores = result.scores
    risk = scores.get("risk_level", "LOW")
    color_map = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
    col = color_map.get(risk, "green")

    # Score cards
    score_table = Table(show_header=False, box=None, padding=(0, 2))
    score_table.add_column(style="dim")
    score_table.add_column(style="bold")
    score_table.add_row("Attack Surface", f"[cyan]{scores.get('attack_surface',0)}/100[/cyan]")
    score_table.add_row("Technology Risk", f"[yellow]{scores.get('technology_risk',0)}/100[/yellow]")
    score_table.add_row("Exposure", f"[magenta]{scores.get('exposure',0)}/100[/magenta]")
    score_table.add_row("Overall", f"[{col}]{scores.get('overall',0)}/100 — {risk}[/{col}]")
    console.print(Panel(score_table, title="[bold]Risk Scores[/bold]", border_style=col))

    # Summary table
    summary = Table(title="Module Summary", show_header=True, header_style="bold cyan")
    summary.add_column("Module", style="dim")
    summary.add_column("Count", justify="right")
    summary.add_row("Subdomains", str(len(result.subdomains)))
    summary.add_row("Emails", str(len(result.emails)))
    summary.add_row("Technologies", str(len(result.technologies)))
    summary.add_row("DNS Records", str(len(result.dns_records)))
    summary.add_row("IP Records", str(len(result.ip_records)))
    summary.add_row("SSL Certs", str(len(result.ssl_info)))
    summary.add_row("Takeover Candidates", str(len(result.takeover_records)))
    summary.add_row("Cloud Assets", str(len(result.cloud_assets)))
    summary.add_row("Breach Records", str(len(result.breach_records)))
    wbu = result.wayback_urls
    interesting = len(wbu.get("interesting", [])) if isinstance(wbu, dict) else 0
    summary.add_row("Wayback Interesting", str(interesting))
    console.print(summary)

    # Takeover alerts
    critical_takeovers = [t for t in result.takeover_records
                          if (t.get("status") if isinstance(t, dict) else t.get("status", "")) == "VULNERABLE"]
    if critical_takeovers:
        console.print("\n[bold red]TAKEOVER VULNERABILITIES:[/bold red]")
        for t in critical_takeovers:
            sub = t.get("subdomain", "")
            prov = t.get("provider", "")
            sev = t.get("severity", "")
            console.print(f"  [red]CRITICAL[/red] {sub} -> {prov} [{sev}]")

    console.print(f"\n[dim]Scan completed in {result.duration_seconds}s[/dim]")


# ── LOAD API KEYS ─────────────────────────────────────────────────────────────
def _load_dotenv():
    """Load .env file from script directory if it exists."""
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    try:
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


def load_api_keys():
    _load_dotenv()
    env_map = {
        "virustotal":       "GRT_VIRUSTOTAL",
        "securitytrails":   "GRT_SECURITYTRAILS",
        "hunter_io":        "GRT_HUNTER_IO",
        "urlscan":          "GRT_URLSCAN",
        "github_token":     "GRT_GITHUB_TOKEN",
        "shodan":           "GRT_SHODAN",
        "otx":              "GRT_OTX",
        "hibp":             "GRT_HIBP",
        "chaos":            "GRT_CHAOS",
        "fullhunt":         "GRT_FULLHUNT",
        "binaryedge":       "GRT_BINARYEDGE",
        "riskiq_user":      "GRT_RISKIQ_USER",
        "riskiq_key":       "GRT_RISKIQ_KEY",
        "censys_api_id":    "GRT_CENSYS_ID",
        "censys_api_secret":"GRT_CENSYS_SECRET",
        "abuseipdb":        "GRT_ABUSEIPDB",
        "grayhatwarfare":   "GRT_GRAYHATWARFARE",
        "crunchbase":       "GRT_CRUNCHBASE",
        "intelx":           "GRT_INTELX",
        "bevigil":          "GRT_BEVIGIL",
        "threatbook":       "GRT_THREATBOOK",
        "bing_search":      "GRT_BING_SEARCH",
    }
    return {k: os.environ.get(v, "") for k, v in env_map.items()}


# ── CLI ───────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Ghost Recon Tool — Passive Domain Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python recon.py                          -> Web UI on http://localhost:5000\n"
            "  python recon.py --port 8080              -> Web UI on custom port\n"
            "  python recon.py -d example.com           -> CLI scan\n"
            "  python recon.py -d example.com --mode deep --output all\n"
        )
    )
    p.add_argument("-d", "--domain", default=None, help="Target domain — omit to start web UI")
    p.add_argument(
        "--mode", choices=["fast", "balanced", "deep"],
        default="balanced",
        help="Scan mode [default: balanced]"
    )
    p.add_argument("--turbo", action="store_true", help="Turbo mode (max concurrency)")
    p.add_argument(
        "--output", choices=["json", "txt", "html", "all"],
        default="all", help="Output format [default: all]"
    )
    p.add_argument("--out-dir", default="./results", help="Output base directory")
    p.add_argument("--port", type=int, default=5000, help="Web UI port [default: 5000]")
    p.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return p


# ── WEB SERVER ────────────────────────────────────────────────────────────────
class WebServer:
    """aiohttp web server providing the Ghost Recon Tool web interface."""

    def __init__(self, port: int, results_dir: str):
        self.port = port
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.active_scans: Dict[str, dict] = {}   # scan_id -> {queue, result, domain, mode}
        self.api_keys = load_api_keys()

    # ── route setup ──────────────────────────────────────────────────────────
    def make_app(self) -> aio_web.Application:
        app = aio_web.Application()
        app.router.add_get("/",                                    self.handle_home)
        app.router.add_get("/history",                             self.handle_history)
        app.router.add_get("/scan/stream",                         self.handle_sse)
        app.router.add_get("/results/{scan_id}",                   self.handle_results)
        app.router.add_get("/api/result/{scan_id}",                self.handle_api_result)
        app.router.add_get("/api/result-fragment/{scan_id}",       self.handle_result_fragment)
        app.router.add_get("/api/download/{scan_id}/{fmt}",        self.handle_download)
        app.router.add_get("/api/debug/{scan_id}",                 self.handle_debug)
        app.router.add_get("/logo.png",                            self.handle_logo)
        return app

    # ── helpers ───────────────────────────────────────────────────────────────
    def _load_web_template(self) -> str:
        tpl = Path(__file__).parent / "templates" / "web.html"
        if tpl.exists():
            return tpl.read_text(encoding="utf-8")
        return "<html><body><h1>Template missing</h1></body></html>"

    @staticmethod
    def _normalize_scan_data(raw: dict) -> dict:
        """Normalize JSON to flat dict regardless of old/new format."""
        if "meta" in raw and "data" in raw:
            # New format: { meta, scores, summary, data }
            flat = raw["data"]
            # Ensure scores are at top-level in flat for compat
            if not flat.get("scores") and raw.get("scores"):
                flat["scores"] = raw["scores"]
            return flat
        return raw  # old format already flat

    def _scan_history(self) -> List[dict]:
        history = []
        if not self.results_dir.exists():
            return history
        for scan_dir in sorted(self.results_dir.iterdir(), reverse=True):
            if not scan_dir.is_dir():
                continue
            report_json = scan_dir / "report.json"
            if not report_json.exists():
                continue
            try:
                with open(report_json, encoding="utf-8") as f:
                    raw = json.load(f)
                data = self._normalize_scan_data(raw)
                scores = data.get("scores", {})
                history.append({
                    "scan_id": data.get("scan_id", scan_dir.name),
                    "domain": data.get("domain", ""),
                    "scan_date": data.get("scan_date", ""),
                    "mode": data.get("mode", ""),
                    "duration": data.get("duration_seconds", 0),
                    "risk_level": scores.get("risk_level", "LOW"),
                    "overall_score": scores.get("overall", 0),
                    "subdomains": len(data.get("subdomains", [])),
                    "emails": len(data.get("emails", [])),
                    "typosquats": len(data.get("typosquats", [])),
                    "dir": str(scan_dir),
                })
            except Exception:
                continue
        return history

    def _load_scan_result(self, scan_id: str) -> Optional[dict]:
        # Check in-memory first (completed scan)
        if scan_id in self.active_scans:
            info = self.active_scans[scan_id]
            if info.get("result"):
                return asdict(info["result"])
        # Search results dir
        if not self.results_dir.exists():
            return None
        for scan_dir in self.results_dir.iterdir():
            if not scan_dir.is_dir():
                continue
            report_json = scan_dir / "report.json"
            if not report_json.exists():
                continue
            try:
                with open(report_json, encoding="utf-8") as f:
                    raw = json.load(f)
                data = self._normalize_scan_data(raw)
                if data.get("scan_id") == scan_id:
                    return data
            except Exception:
                continue
        return None

    # ── render helper ─────────────────────────────────────────────────────────
    def _render(self, page: str, **ctx) -> str:
        """Render web template with full error context on failure."""
        try:
            tmpl = Template(self._load_web_template())
            return tmpl.render(page=page, **ctx)
        except Exception as exc:
            tb = _traceback.format_exc()
            logging.error("Template render error [page=%s]: %s\n%s", page, exc, tb)
            # Return a readable error page rather than a raw 500
            escaped_tb = tb.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return (
                "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                "<title>Ghost Recon — Render Error</title>"
                "<style>body{background:#070b14;color:#e2e8f0;font-family:monospace;"
                "padding:32px;max-width:900px}h2{color:#ef4444;margin-bottom:16px}"
                "pre{background:#0d1526;border:1px solid #1e2d4a;border-radius:8px;"
                "padding:16px;overflow-x:auto;font-size:12px;white-space:pre-wrap}"
                "a{color:#3b82f6}</style></head><body>"
                f"<h2>&#128683; Template Render Error — page=<code>{page}</code></h2>"
                f"<p>The results page crashed while rendering. "
                f"Use <a href='/api/debug/{ctx.get('scan_id','')}'>Debug JSON</a> to inspect raw data.</p>"
                f"<pre>{escaped_tb}</pre>"
                "</body></html>"
            )

    # ── route handlers ────────────────────────────────────────────────────────
    async def handle_home(self, request: aio_web.Request) -> aio_web.Response:
        try:
            history = self._scan_history()
            html = self._render("home", history=history, history_json=json.dumps(history))
            return aio_web.Response(text=html, content_type="text/html")
        except Exception as exc:
            logging.error("handle_home error: %s\n%s", exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text=str(exc))

    async def handle_history(self, request: aio_web.Request) -> aio_web.Response:
        try:
            history = self._scan_history()
            html = self._render("history", history=history, history_json=json.dumps(history))
            return aio_web.Response(text=html, content_type="text/html")
        except Exception as exc:
            logging.error("handle_history error: %s\n%s", exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text=str(exc))

    async def handle_results(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = request.match_info["scan_id"]
        try:
            data = self._load_scan_result(scan_id)
            if not data:
                raise aio_web.HTTPNotFound(text=f"Scan {scan_id!r} not found")
            html = self._render(
                "results",
                result=data,
                result_json=json.dumps(data, default=str),
                scan_id=scan_id,
            )
            return aio_web.Response(text=html, content_type="text/html")
        except aio_web.HTTPException:
            raise
        except Exception as exc:
            tb = _traceback.format_exc()
            logging.error("handle_results error [%s]: %s\n%s", scan_id, exc, tb)
            escaped_tb = tb.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html = (
                "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                "<title>Ghost Recon — Error</title>"
                "<style>body{background:#070b14;color:#e2e8f0;font-family:monospace;"
                "padding:32px;max-width:900px}h2{color:#ef4444;margin-bottom:16px}"
                "pre{background:#0d1526;border:1px solid #1e2d4a;border-radius:8px;"
                "padding:16px;overflow-x:auto;font-size:12px;white-space:pre-wrap}"
                "a{color:#3b82f6}</style></head><body>"
                f"<h2>&#128683; Error loading results for scan <code>{scan_id}</code></h2>"
                f"<p><a href='/api/debug/{scan_id}'>View raw JSON debug</a> &nbsp;|&nbsp; "
                f"<a href='/history'>Back to History</a> &nbsp;|&nbsp; <a href='/'>Home</a></p>"
                f"<pre>{escaped_tb}</pre>"
                "</body></html>"
            )
            return aio_web.Response(text=html, content_type="text/html", status=500)

    async def handle_api_result(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = request.match_info["scan_id"]
        data = self._load_scan_result(scan_id)
        if not data:
            raise aio_web.HTTPNotFound()
        return aio_web.Response(
            text=json.dumps(data, default=str),
            content_type="application/json"
        )

    async def handle_logo(self, request: aio_web.Request) -> aio_web.Response:
        logo_path = Path(__file__).parent / "logo.png"
        if not logo_path.exists():
            raise aio_web.HTTPNotFound()
        data = logo_path.read_bytes()
        return aio_web.Response(
            body=data,
            content_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    async def handle_result_fragment(self, request: aio_web.Request) -> aio_web.Response:
        """Return just the rendered results section as an HTML fragment for inline injection."""
        scan_id = request.match_info["scan_id"]
        try:
            data = self._load_scan_result(scan_id)
            if not data:
                raise aio_web.HTTPNotFound(text=f"Scan {scan_id!r} not found")
            html = self._render(
                "results_fragment",
                result=data,
                result_json=json.dumps(data, default=str),
                scan_id=scan_id,
            )
            return aio_web.Response(text=html, content_type="text/html")
        except aio_web.HTTPException:
            raise
        except Exception as exc:
            logging.error("handle_result_fragment error [%s]: %s\n%s",
                          scan_id, exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text=str(exc))

    async def handle_debug(self, request: aio_web.Request) -> aio_web.Response:
        """Dump raw scan data as JSON for debugging template crashes."""
        scan_id = request.match_info["scan_id"]
        data = self._load_scan_result(scan_id)
        if not data:
            raise aio_web.HTTPNotFound(text=f"Scan {scan_id!r} not found")
        # Build a diagnostic report
        diag = {
            "scan_id": scan_id,
            "keys_present": list(data.keys()),
            "field_types": {k: type(v).__name__ for k, v in data.items()},
            "list_lengths": {k: len(v) for k, v in data.items() if isinstance(v, list)},
            "null_fields": [k for k, v in data.items() if v is None],
            "data": data,
        }
        return aio_web.Response(
            text=json.dumps(diag, indent=2, default=str),
            content_type="application/json",
        )

    async def handle_download(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = request.match_info["scan_id"]
        fmt = request.match_info["fmt"]
        data = self._load_scan_result(scan_id)
        if not data:
            raise aio_web.HTTPNotFound()

        if fmt == "json":
            body = json.dumps(data, indent=2, default=str)
            ct = "application/json"
            fn = f"ghost_recon_{scan_id}.json"
        elif fmt == "txt":
            # Rebuild ReconResult-like object from dict for write_txt
            result_obj = ReconResult(**{k: data.get(k, v)
                                        for k, v in asdict(ReconResult(
                                            domain="", scan_id="", scan_date="", mode="")).items()})
            for field_name in asdict(result_obj).keys():
                setattr(result_obj, field_name, data.get(field_name,
                        getattr(result_obj, field_name)))
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                p = write_txt(result_obj, Path(td))
                body = p.read_text(encoding="utf-8")
            ct = "text/plain"
            fn = f"ghost_recon_{scan_id}.txt"
        elif fmt == "html":
            template_path = Path(__file__).parent / "templates" / "report.html"
            if template_path.exists():
                tmpl = Template(template_path.read_text(encoding="utf-8"))
                body = tmpl.render(
                    domain=data.get("domain", ""),
                    scan_id=data.get("scan_id", ""),
                    scan_date=data.get("scan_date", ""),
                    mode=data.get("mode", ""),
                    duration=data.get("duration_seconds", 0),
                    scores=data.get("scores", {}),
                    subdomains=data.get("subdomains", []),
                    emails=data.get("emails", []),
                    technologies=data.get("technologies", []),
                    dns_records=data.get("dns_records", []),
                    ip_records=data.get("ip_records", []),
                    ssl_info=data.get("ssl_info", []),
                    takeover_records=data.get("takeover_records", []),
                    cloud_assets=data.get("cloud_assets", []),
                    breach_records=data.get("breach_records", []),
                    wayback_urls=data.get("wayback_urls", {}),
                    whois_data=data.get("whois_data", {}),
                    reputation_data=data.get("reputation_data", {}),
                    data=json.dumps(data, indent=2, default=str),
                )
            else:
                body = json.dumps(data, indent=2, default=str)
            ct = "text/html"
            fn = f"ghost_recon_{scan_id}.html"
        else:
            raise aio_web.HTTPBadRequest()

        return aio_web.Response(
            text=body,
            content_type=ct,
            headers={"Content-Disposition": f'attachment; filename="{fn}"'}
        )

    async def handle_sse(self, request: aio_web.Request) -> aio_web.StreamResponse:
        domain_raw = request.rel_url.query.get("domain", "").strip().lower()
        mode = request.rel_url.query.get("mode", "balanced")
        if mode not in ("fast", "balanced", "deep", "turbo"):
            mode = "balanced"

        # Sanitize domain
        domain = re.sub(r"^https?://", "", domain_raw).split("/")[0]
        if not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain):
            resp = aio_web.StreamResponse()
            resp.headers.update({
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            })
            await resp.prepare(request)
            err = json.dumps({"message": f"Invalid domain: {domain_raw!r}"})
            await resp.write(f"event: error\ndata: {err}\n\n".encode())
            return resp

        # Prepare SSE response
        response = aio_web.StreamResponse()
        response.headers.update({
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        })
        await response.prepare(request)

        queue: asyncio.Queue = asyncio.Queue()

        async def progress_cb(event_type: str, data: dict):
            await queue.put((event_type, data))

        # Create output dir for this scan
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = self.results_dir / f"{domain}_{timestamp}"
        out_dir.mkdir(parents=True, exist_ok=True)

        engine = ReconEngine(
            domain=domain, mode=mode,
            api_keys=self.api_keys,
            output_dir=str(out_dir),
            progress_cb=progress_cb,
        )

        # Run scan in background task
        async def run_and_save():
            try:
                result = await engine.run()
                # Save results
                write_json(result, out_dir)
                write_txt(result, out_dir)
                # Store in memory for quick access
                scan_id = result.scan_id
                self.active_scans[scan_id] = {"result": result, "domain": domain}
                await queue.put(("saved", {"scan_id": scan_id, "out_dir": str(out_dir)}))
            except Exception as exc:
                await queue.put(("error", {"message": str(exc)}))

        scan_task = asyncio.create_task(run_and_save())

        # Stream events until complete
        try:
            while True:
                try:
                    event_type, data = await asyncio.wait_for(queue.get(), timeout=90)
                    msg = f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
                    await response.write(msg.encode())
                    if event_type in ("saved", "error"):
                        break
                except asyncio.TimeoutError:
                    await response.write(b": keepalive\n\n")
        except ConnectionResetError:
            pass
        finally:
            if not scan_task.done():
                scan_task.cancel()

        return response

    async def start(self, open_browser: bool = True):
        app = self.make_app()
        runner = aio_web.AppRunner(app)
        await runner.setup()
        site = aio_web.TCPSite(runner, "localhost", self.port)
        await site.start()

        url = f"http://localhost:{self.port}"
        console.print(Panel(
            f"[bold green]Ghost Recon Tool — Web Interface[/bold green]\n"
            f"[cyan]{url}[/cyan]\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
            border_style="green"
        ))

        if open_browser:
            # Small delay so server is ready before browser hits it
            await asyncio.sleep(0.8)
            webbrowser.open(url)

        # Run forever
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await runner.cleanup()


# ── MAIN ──────────────────────────────────────────────────────────────────────
async def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── Web UI mode (no -d argument) ──────────────────────────────────────────
    if args.domain is None:
        server = WebServer(port=args.port, results_dir=args.out_dir)
        await server.start(open_browser=not args.no_browser)
        return

    # ── CLI mode ──────────────────────────────────────────────────────────────
    domain = args.domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    mode = "turbo" if args.turbo else args.mode
    api_keys = load_api_keys()

    if not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain):
        console.print(f"[red]Invalid domain: {domain}[/red]")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out_dir) / f"{domain}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    engine = ReconEngine(domain=domain, mode=mode, api_keys=api_keys, output_dir=str(out_dir))
    result = await engine.run()
    print_results(result)

    saved = []
    if args.output in ("json", "all"):
        saved.append(str(write_json(result, out_dir)))
    if args.output in ("txt", "all"):
        saved.append(str(write_txt(result, out_dir)))
    if args.output in ("html", "all"):
        saved.append(str(write_html(result, out_dir)))

    console.print("\n[bold green]Results saved to:[/bold green]")
    for s in saved:
        console.print(f"  [cyan]{s}[/cyan]")


if __name__ == "__main__":
    asyncio.run(main())
