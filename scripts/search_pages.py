"""Generate crawlable working examples from the same form as the main page."""
from html import escape
import json
import re


def render_pages(stage, tool, pages):
    source = (stage / "index.html").read_text(encoding="utf-8")
    for path, title, description, defaults in pages:
        folder = stage / path
        folder.mkdir(exist_ok=True)
        url = "https://coolcode.ca" + tool["url"] + (path + "/" if path else "")
        page = re.sub(r"<title>.*?</title>", lambda _: "<title>" + escape(title) + " · CoolCode</title>", source, count=1)
        page = re.sub(r'<meta name="description" content="[^"]*">', lambda _: '<meta name="description" content="' + escape(description) + '">', page, count=1)
        page = re.sub(r'<link rel="canonical"[^>]*>|<meta property="og:[^>]*>', "", page)
        head = '<link rel="canonical" href="' + escape(url) + '">'
        for prop, value in (("title", title), ("type", "website"), ("url", url), ("description", description)):
            head += '<meta property="og:' + prop + '" content="' + escape(value) + '">'
        schema = {"@context":"https://schema.org","@type":"WebApplication","name":title,"url":url,"description":description,"operatingSystem":"Any","applicationCategory":"UtilitiesApplication","offers":{"@type":"Offer","price":"0","priceCurrency":"CAD"}}
        page = page.replace("</head>", head + '<script type="application/ld+json">' + json.dumps(schema).replace("<", "\\u003c") + "</script></head>", 1)
        if path:
            page = re.sub(r'((?:href|src)=")\./', r'\1../', page)
            page = re.sub(r"(<h1(?: [^>]*)?>).*?</h1>", lambda m: m[1] + escape(title) + "</h1>", page, count=1, flags=re.S)
            page = page.replace("<!-- example-intro -->", '<p class="example-intro">' + escape(description) + '</p>', 1)
            attrs = "".join(' data-' + key + '="' + escape(value) + '"' for key, value in defaults.items())
            page = page.replace("<body", "<body" + attrs, 1)
        if defaults:
            page = page.replace('value="coolcode.ca" required', 'value="' + escape(defaults["host"]) + '" required')
            for key in ("mode", "resolver"):
                if key in defaults:
                    page = page.replace('value="' + defaults[key] + '">', 'value="' + defaults[key] + '" selected>', 1)
            if defaults.get("selector"):
                page = page.replace('id="dkim-selectors" class=', 'id="dkim-selectors" value="' + escape(defaults["selector"]) + '" class=')
        (folder / "index.html").write_text(page, encoding="utf-8")

PAGES = [('',
  'DNS Record Lookup & Mail Configuration Checker',
  'Check public DNS, compare Google and Cloudflare replies, and diagnose email records for a '
  'domain.',
  {}),
 ('email-dns-check',
  'SPF, DKIM, DMARC & MX Checker',
  'Read the sample mail configuration for gmail.com or enter your own domain. To check a '
  'particular DKIM key, copy its selector from the s= field of a signed message.',
  {'mode': 'mail', 'host': 'gmail.com', 'selector': '20230601'}),
 ('compare-resolvers',
  'Compare Google & Cloudflare DNS Answers',
  'Compare both resolvers for coolcode.ca and www.coolcode.ca. Differences can follow from '
  'caching, wildcard records, regional answers or resolver policies.',
  {'mode': 'web', 'host': 'coolcode.ca', 'resolver': 'both'})]
