#!/usr/bin/env python3
"""Read-only smoke crawl of Sqafe's public sitemap and search metadata.

This checks what the live server returns. It cannot tell whether a search
engine has indexed a URL or how that URL ranks.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
import ssl
import struct
import sys
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree


ORIGIN = "https://sqafe.com"
SITEMAP_URL = ORIGIN + "/sitemap.xml"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SITEMAP_URLS = 100
USER_AGENT = "SqafeSEO-Smoke/1.0 (+https://sqafe.com/contact)"


def verified_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    # The macOS Python.org build can have no bundled OpenSSL CA file even
    # while the operating system has a normal trust bundle at this path.
    if not ssl.get_default_verify_paths().cafile and Path("/etc/ssl/cert.pem").is_file():
        context.load_verify_locations(cafile="/etc/ssl/cert.pem")
    return context


class PageHead(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_head = False
        self.in_title = False
        self.titles: list[str] = []
        self.head_meta: list[dict[str, str | None]] = []
        self.canonicals: list[str | None] = []
        self.hrefs: list[str] = []
        self.h1_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "head":
            self.in_head = True
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "a" and values.get("href"):
            self.hrefs.append(values["href"] or "")
        if not self.in_head:
            return
        if tag == "title":
            self.in_title = True
            self.titles.append("")
        elif tag == "meta":
            self.head_meta.append(values)
        elif tag == "link" and values.get("rel") == "canonical":
            self.canonicals.append(values.get("href"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        elif tag == "head":
            self.in_head = False

    def handle_data(self, data: str) -> None:
        if self.in_head and self.in_title:
            self.titles[-1] += data

    def meta(self, attr: str, key: str) -> list[str | None]:
        return [item.get("content") for item in self.head_meta if item.get(attr) == key]


def fetch(url: str, timeout: float) -> tuple[int, str, object, bytes]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    with urlopen(request, timeout=timeout, context=verified_tls_context()) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError(f"Response exceeds {MAX_RESPONSE_BYTES} bytes: {url}")
        return response.status, response.geturl(), response.headers, body


def one(values: list[str | None], label: str, errors: list[str]) -> str:
    if len(values) != 1 or not values[0] or not values[0].strip():
        errors.append(f"expected one nonempty {label}")
        return ""
    return values[0].strip()


def site_url(url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme == "https" and parsed.netloc == "sqafe.com" and not parsed.query and not parsed.fragment


def reachable_sitemap_urls(urls: list[str], links_by_page: dict[str, set[str]], max_clicks: int = 3) -> set[str]:
    """Follow only links between sitemap pages, up to the requested depth."""
    home = ORIGIN + "/"
    reached = {home} if home in urls else set()
    frontier = set(reached)
    for _ in range(max_clicks):
        frontier = set().union(*(links_by_page.get(url, set()) for url in frontier)) - reached
        reached.update(frontier)
        if not frontier:
            break
    return reached


def markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def run(timeout: float) -> tuple[list[str], list[dict[str, object]]]:
    problems: list[str] = []
    rows: list[dict[str, object]] = []

    status, final, _, robots = fetch(ORIGIN + "/robots.txt", timeout)
    if status != 200 or final != ORIGIN + "/robots.txt":
        problems.append("robots.txt did not return directly with HTTP 200")
    if f"sitemap: {SITEMAP_URL}" not in robots.decode("utf-8", "replace").lower():
        problems.append("robots.txt does not point to the canonical sitemap")

    status, final, headers, sitemap = fetch(SITEMAP_URL, timeout)
    if status != 200 or final != SITEMAP_URL or "xml" not in headers.get("content-type", ""):
        problems.append("sitemap.xml did not return directly as XML with HTTP 200")
    root = ElementTree.fromstring(sitemap)
    if root.tag != "{http://www.sitemaps.org/schemas/sitemap/0.9}urlset":
        problems.append("sitemap.xml is not a standard sitemap urlset")
    urls = [(node.text or "").strip() for node in root.findall(".//{*}loc")]
    if not urls:
        problems.append("sitemap.xml contains no URLs")
    if len(urls) != len(set(urls)):
        problems.append("sitemap.xml contains duplicate URLs")
    if len(urls) > MAX_SITEMAP_URLS:
        raise ValueError(f"Sitemap contains {len(urls)} URLs; this smoke crawl is capped at {MAX_SITEMAP_URLS}")
    if any(not site_url(url) for url in urls):
        raise ValueError("Sitemap contains a URL outside the canonical origin or with a query/fragment")

    seen_titles: set[str] = set()
    seen_descriptions: set[str] = set()
    sitemap_urls = set(urls)
    links_by_page: dict[str, set[str]] = {}
    image_urls: set[str] = set()
    for url in urls:
        errors: list[str] = []
        try:
            page_status, page_final, page_headers, html = fetch(url, timeout)
            if page_status != 200 or page_final != url:
                errors.append("page did not return directly with HTTP 200")
            if not page_headers.get("content-type", "").startswith("text/html"):
                errors.append("response is not HTML")
            if "noindex" in page_headers.get("X-Robots-Tag", "").lower():
                errors.append("X-Robots-Tag contains noindex")
            head = PageHead()
            head.feed(html.decode("utf-8", "replace"))
            title = one(head.titles, "title", errors)
            description = one(head.meta("name", "description"), "description", errors)
            robots_meta = one(head.meta("name", "robots"), "robots meta", errors)
            canonical = one(head.canonicals, "canonical", errors)
            og_url = one(head.meta("property", "og:url"), "og:url", errors)
            image_url = one(head.meta("property", "og:image"), "og:image", errors)
            if title and title in seen_titles:
                errors.append("duplicate title")
            if description and description in seen_descriptions:
                errors.append("duplicate description")
            if title:
                seen_titles.add(title)
            if description:
                seen_descriptions.add(description)
            if "noindex" in robots_meta.lower():
                errors.append("robots meta contains noindex")
            if canonical and canonical != url:
                errors.append("canonical differs from sitemap URL")
            if og_url and og_url != url:
                errors.append("og:url differs from sitemap URL")
            if head.h1_count != 1:
                errors.append(f"expected one h1, found {head.h1_count}")
            if image_url:
                if not site_url(image_url):
                    errors.append("og:image is not a canonical-site URL")
                else:
                    image_urls.add(image_url)
            links_by_page[url] = set()
            for href in head.hrefs:
                parsed = urlsplit(urljoin(url, href))
                if parsed.scheme == "https" and parsed.netloc == "sqafe.com":
                    linked = ORIGIN + (parsed.path.rstrip("/") or "/")
                    if linked in sitemap_urls:
                        links_by_page[url].add(linked)
        except Exception as exc:
            title = ""
            errors.append(f"{type(exc).__name__}: {exc}")
        rows.append({"url": url, "title": title, "errors": errors})
        problems.extend(f"{url}: {error}" for error in errors)

    if ORIGIN + "/" not in sitemap_urls:
        problems.append("homepage is missing from the sitemap")
    reached = reachable_sitemap_urls(urls, links_by_page)
    for url in urls:
        if url not in reached:
            problems.append(f"{url}: not reachable within 3 links through sitemap pages")

    for image_url in sorted(image_urls):
        try:
            image_status, image_final, image_headers, image = fetch(image_url, timeout)
            if image_status != 200 or image_final != image_url:
                problems.append(f"{image_url}: image did not return directly with HTTP 200")
            if image_headers.get_content_type() != "image/png" or image[:8] != b"\x89PNG\r\n\x1a\n":
                problems.append(f"{image_url}: expected a PNG image")
            elif struct.unpack(">II", image[16:24]) != (1200, 630):
                problems.append(f"{image_url}: image is not 1200 x 630")
        except Exception as exc:
            problems.append(f"{image_url}: {type(exc).__name__}: {exc}")
    return problems, rows


def report(problems: list[str], rows: list[dict[str, object]]) -> str:
    checked_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Sqafe public SEO smoke check",
        "",
        f"**Checked:** {checked_at}. **Origin:** {ORIGIN}. **Result:** {'PASS' if not problems else 'FAIL'}.",
        "This is a live response check, not evidence of search-engine indexing or ranking.",
        "",
        "| Sitemap URL | Title | Page checks |",
        "| --- | --- | --- |",
    ]
    for row in rows:
        errors = row["errors"]
        result = "Pass" if not errors else "; ".join(errors)
        lines.append(f"| {markdown_cell(row['url'])} | {markdown_cell(row['title'])} | {markdown_cell(result)} |")
    lines.extend(("", "## Findings", ""))
    lines.extend(f"- {problem}" for problem in problems)
    if not problems:
        lines.append("- None in the checks above.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the Markdown report to this path")
    parser.add_argument("--timeout", type=float, default=12, help="Per-request timeout in seconds")
    args = parser.parse_args()
    try:
        problems, rows = run(args.timeout)
    except Exception as exc:
        problems, rows = [f"Crawl stopped: {type(exc).__name__}: {exc}"], []
    result = report(problems, rows)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
    print(result, end="")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
