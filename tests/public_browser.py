"""Check focused lookups and local report comparison on the published DNS Lens site."""
from copy import deepcopy
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from playwright.sync_api import sync_playwright, expect


def check(browser):
    page = browser.new_page()
    errors, requests = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("request", lambda request: requests.append(request.url))
    assert page.goto("https://coolcode.ca/dnslens/").status == 200

    def lookup(mode, name, record=None):
        requests.clear()
        page.locator("#mode").select_option(mode)
        page.locator("#host").fill(name)
        if record:
            page.locator("#record-type").select_option(record)
        page.get_by_role("button", name="Look up", exact=True).click()
        expect(page.locator("#report-title")).to_have_text(name, timeout=30000)
        expect(page.locator("#state")).to_contain_text("DNS lookups complete")
        expect(page.locator("#registration-panel")).to_be_hidden()
        assert not any("rdap" in url for url in requests), requests
        with page.expect_download() as pending:
            page.locator("#export").click()
        return json.loads(Path(pending.value.path()).read_text())

    web = lookup("web", "coolcode.ca")
    assert len(web["dns"]) == 8
    assert {(r["name"], r["type"]) for r in web["dns"]} == {
        (name, kind) for name in ("coolcode.ca", "www.coolcode.ca") for kind in ("A", "AAAA", "CNAME", "HTTPS")
    }
    assert all(not r.get("failed") for r in web["dns"])
    assert any(r["answers"] for r in web["dns"])
    print("Public resolver returned eight focused website replies for coolcode.ca and www.coolcode.ca.", flush=True)

    name = "_dmarc.google.com"
    current = lookup("record", name, "TXT")
    assert len(current["dns"]) == 1
    answers = current["dns"][0]["answers"]
    assert any("v=DMARC1" in answer["data"] for answer in answers)
    queries = [parse_qs(urlsplit(url).query) for url in requests if "dns.google/resolve?" in url]
    assert len(queries) == 1 and queries[0]["name"] == [name] and queries[0]["type"] == ["16"]
    page.locator("#snapshot summary").click()
    def compare(report):
        page.locator("#baseline").set_input_files(
            {"name":"baseline.json", "mimeType":"application/json", "buffer":json.dumps(report).encode()}
        )
    compare(current)
    expect(page.locator("#diff-state")).to_contain_text("0 changed, 1 unchanged")
    # Change a copy of the genuine export to exercise added/removed reporting;
    # no historical change at this domain is implied.
    prior = deepcopy(current)
    prior["dns"][0]["answers"][0]["data"] = '"earlier test value"'
    compare(prior)
    expect(page.locator("#diff-state")).to_contain_text("1 changed, 0 unchanged")
    expect(page.locator("#diff-rows")).to_contain_text("Removed")
    expect(page.locator("#diff-rows")).to_contain_text("earlier test value")
    expect(page.locator("#diff-rows")).to_contain_text("Added")
    expect(page.locator("#diff-rows")).to_contain_text("v=DMARC1")
    prior["target"]["value"] = "different.example"
    compare(prior)
    expect(page.locator("#diff-state")).to_contain_text("different names")
    print("Exact-name TXT, genuine JSON round trip, controlled added and removed values, and mismatched-target rejection passed.", flush=True)
    assert not errors, errors


if __name__ == "__main__":
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        check(browser)
        browser.close()
