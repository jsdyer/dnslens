# DNS Lens

[DNS Lens](https://coolcode.ca/dnslens/) is a client-side workbench for inspecting public DNS and registration records. Enter a hostname, IPv4 address, or IPv6 address and choose Google Public DNS or Cloudflare. A domain lookup includes A, AAAA, CNAME, HTTPS, NS, MX, TXT, SOA, CAA, DS and DNSKEY. IP lookups use PTR plus RDAP network registration. Internationalized hostnames are converted to DNS-compatible ASCII.

## Reading the report

- An empty NOERROR response, NXDOMAIN, a resolver error such as SERVFAIL, and a failed HTTPS request are reported separately. TTL values and HTTPS round-trip times describe the observed recursive-resolver response.
- The DNSSEC AD flag represents what the selected validating resolver reported. The DNS results also show available DS and DNSKEY records. Domain lookups include exact-name SPF, DMARC, MTA-STS and SMTP TLS reporting (TLS-RPT) TXT checks. They do not evaluate mail delivery, recursive SPF mechanisms, inherited DMARC policy, or the entire DNSSEC chain themselves.
- Enter up to three DKIM selectors from the signature header’s s= tag. The tool reports CNAME delegation, published key type and empty p= revocation. It never uploads an email or checks a signature. TLS-RPT reports published destinations without contacting them.
- When MTA-STS publishes an ID, the report links to the HTTPS policy and offers a browser fetch. Policy-host CORS determines whether the site can read its contents. The result is the returned policy text, rather than a deliverability verdict.
- RDAP follows IANA's HTTPS bootstrap records, selects the longest service match for IP addresses and checks parent names after registry 404 responses. Registration coverage, redaction and cross-origin browser access vary. A registry object is distinct from the current web host or actual origin network.
- Copy individual records, copy the report as plain text, or download a JSON record containing the query timestamp, response statuses, registration fields and direct upstream sources.

The app only sends lookups after an explicit search. The address or name goes to the chosen recursive resolver and the appropriate registration service. An optional MTA-STS request goes to the target's policy host. There is no automatic lookup history or app server. Only the theme setting is saved locally.

## Build and test

Run `python3 scripts/build.py` and serve `dist/` over HTTP, for example with `python3 -m http.server --directory dist 8080`. Run `node --test tests/model.test.mjs` for the model tests. Entrypoints use relative paths for GitHub Pages project deployment.

## Sources

- [Google Public DNS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Cloudflare DoH JSON API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [IANA RDAP Bootstrap Registries](https://www.iana.org/assignments/rdap-dns)
- [SPF RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html)
- [DMARC RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html)
- [MTA-STS RFC 8461](https://www.rfc-editor.org/rfc/rfc8461.html)

The resolver menu includes a side-by-side Google and Cloudflare comparison. Record order and TTLs are excluded from the match test. Each resolver's DNSSEC AD flag and returned TTLs are visible independently. Timeouts, DNS failures and truncated replies are marked unavailable. In this mode the separate record and mail-policy panels reflect Google Public DNS, and both resolver results are included in exports.

- [DKIM RFC 6376](https://www.rfc-editor.org/rfc/rfc6376.html)
- [SMTP TLS Reporting RFC 8460](https://www.rfc-editor.org/rfc/rfc8460.html)

## Website, mail and changes over time

Choose Website and www to look up IPv4, IPv6, aliases and HTTPS service records for both names. Mail setup focuses on delivery and authentication. Nameservers and signing returns NS, SOA, DS, DNSKEY and CAA at the exact input name, with registry information. One record at an exact name accepts service labels such as _dmarc and _sip._tcp and supports TXT, SRV, TLSA, SSHFP, SVCB and other types. IP addresses use the appropriate reverse PTR name.

<!-- coolcode:guide -->
Check MX, SPF, DMARC and supplied DKIM selectors for a domain. Save the report before changing DNS to compare the answers later.
<!-- /coolcode:guide -->

Quick starts at [Email DNS](https://coolcode.ca/dnslens/email-dns-check/) and [resolver comparison](https://coolcode.ca/dnslens/compare-resolvers/) load editable lookups for the named public example. DKIM needs the selector from a signed message. The resolver receives each lookup.

Download a DNS report before changing a domain, repeat the lookup afterwards and open the earlier JSON to see which answers changed at the same resolver.


The comparison checks matching query names and types, shows added and removed answers and aliases, and reports DNS response code and AD flag changes. TTL countdowns and record order are excluded. A missing query or failed request has its own state. Saved files are read locally.

## Saved preference compatibility

The theme preference uses coolcode:dnslens:theme. An existing coolcode-dnslens-theme preference is copied on first use; if storage is unavailable, the original preference is retained.
