from flask import Flask, render_template, request
from urllib.parse import urlparse
import re


app = Flask(__name__)


URGENCY_KEYWORDS = [
	"urgent",
	"immediately",
	"verify now",
	"action required",
	"suspended",
	"account locked",
	"password expired",
	"limited time",
	"final notice",
	"confirm your identity",
]


SUSPICIOUS_TLDS = {
	"zip",
	"mov",
	"cn",
	"ru",
	"work",
	"top",
	"click",
	"country",
	"gq",
	"ml",
	"tk",
}


COMMON_BRANDS = [
	"microsoft",
	"office",
	"onedrive",
	"paypal",
	"apple",
	"google",
	"amazon",
	"netflix",
	"bank",
]


def analyze_url(url: str):
	issues = []
	try:
		parsed = urlparse(url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else f"http://{url}")
	except Exception:
		return {"valid": False, "issues": ["URL could not be parsed"]}

	if not parsed.netloc:
		issues.append("Missing domain (host)")

	# '@' symbol in URL path or netloc
	if "@" in (parsed.netloc + parsed.path):
		issues.append("'@' symbol found in URL, possible credential trick")

	# Too many subdomains
	if parsed.netloc:
		host_parts = parsed.netloc.split('.')
		if len(host_parts) >= 5:
			issues.append("Unusually many subdomains")

	# Numeric-only host or suspicious mix
	if parsed.hostname:
		if re.fullmatch(r"[0-9.]+", parsed.hostname):
			issues.append("Hostname is an IP address")
		if re.search(r"--|__|\d{5,}", parsed.hostname or ""):
			issues.append("Suspicious characters in hostname")

	# Suspicious TLDs
	if parsed.hostname and "." in parsed.hostname:
		tld = parsed.hostname.split(".")[-1].lower()
		if tld in SUSPICIOUS_TLDS:
			issues.append(f"Suspicious top-level domain: .{tld}")

	# Brand in subdomain but not in registrable domain
	if parsed.hostname:
		parts = parsed.hostname.split('.')
		registrable = ".".join(parts[-2:]) if len(parts) >= 2 else parsed.hostname
		subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
		for brand in COMMON_BRANDS:
			if brand in subdomain and brand not in registrable:
				issues.append("Brand name in subdomain but not in main domain")

	# Long URL
	if len(url) > 120:
		issues.append("URL is very long")

	# Excessive path depth
	if parsed.path.count('/') > 6:
		issues.append("Deeply nested path")

	return {"valid": True, "issues": issues}


def analyze_email_header(text: str):
	issues = []
	lower = text.lower()

	# Urgency keywords
	for kw in URGENCY_KEYWORDS:
		if kw in lower:
			issues.append(f"Urgency keyword detected: '{kw}'")

	# 'From' display name mismatch pattern like: From: "Microsoft Support" <random@unknown.com>
	if re.search(r"from:\s*\".*?\"\s*<[^>]+>", lower):
		issues.append("Display name used with different email address")

	# Multiple Received headers (can be normal but flag for teaching)
	received_count = len(re.findall(r"^received:", lower, flags=re.MULTILINE))
	if received_count > 3:
		issues.append("Many 'Received' hops in header")

	# DKIM/SPF failures
	if "spf=fail" in lower or "dkim=fail" in lower:
		issues.append("SPF or DKIM failure indicated")

	# Suspicious reply-to different domain
	reply_to = re.findall(r"reply-to:\s*([^\n\r]+)", lower)
	froms = re.findall(r"from:\s*([^\n\r]+)", lower)
	if reply_to and froms and reply_to[0].split('@')[-1] != froms[0].split('@')[-1]:
		issues.append("'Reply-To' domain differs from 'From' domain")

	return {"issues": issues}


@app.route('/', methods=['GET', 'POST'])
def index():
	result = None
	mode = request.form.get('mode', 'url')
	input_text = ''
	if request.method == 'POST':
		input_text = request.form.get('input', '').strip()
		if mode == 'url':
			result = analyze_url(input_text)
		else:
			result = analyze_email_header(input_text)
	return render_template('index.html', mode=mode, input_text=input_text, result=result)


if __name__ == '__main__':
	app.run(debug=True)


