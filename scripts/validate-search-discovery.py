#!/usr/bin/env python3
"""Validate Metrics search-verification and crawler-discovery artifacts."""

import argparse
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


GOOGLE_TAG = (
    '<meta name="google-site-verification" '
    'content="XaJCH6-K355pE6DNYj50QvpVDHrmcGT_NBUey3dXiKc">'
)
BING_TAG = (
    '<meta name="msvalidate.01" '
    'content="8B983F2DC788493BCD2FC9B8C74AAEDD">'
)
SITEMAP_NAMESPACE = "http://www.sitemaps.org/schemas/sitemap/0.9"


def fail(message):
    raise ValueError(message)


def html_attribute(tag, attribute):
    """Extract a quoted or unquoted HTML attribute from one start tag."""
    match = re.search(
        rf"(?:^|\s){re.escape(attribute)}\s*=\s*"
        r"(?:([\"'])(.*?)\1|([^\s\"'=<>`]+))",
        tag,
        re.I | re.S,
    )
    return (match.group(2) or match.group(3)) if match else None


def validate_homepage(output_dir, expected_origin):
    homepage = (output_dir / "index.html").read_text(encoding="utf-8")
    head_match = re.search(r"<head\b[^>]*>(.*?)</head>", homepage, re.I | re.S)
    if not head_match:
        fail("index.html has no complete <head>")
    head = head_match.group(1)

    for label, tag in (("Google", GOOGLE_TAG), ("Bing", BING_TAG)):
        if homepage.count(tag) != 1 or head.count(tag) != 1:
            fail(f"{label} verification tag must appear exactly once in <head>")

    for tag in re.findall(r"<meta\b[^>]*>", head, re.I):
        if (html_attribute(tag, "name") or "").lower() != "robots":
            continue
        content = html_attribute(tag, "content") or ""
        directives = {
            directive.strip().lower()
            for directive in re.split(r"[\s,]+", content)
            if directive.strip()
        }
        if directives.intersection({"noindex", "nofollow", "none"}):
            fail("homepage robots metadata blocks indexing or following")

    for tag in re.findall(r"<link\b[^>]*>", head, re.I):
        rel_tokens = (html_attribute(tag, "rel") or "").lower().split()
        if "canonical" not in rel_tokens:
            continue
        canonical = html_attribute(tag, "href") or ""
        parsed = urlsplit(canonical)
        if (parsed.scheme or parsed.netloc) and (
            parsed.scheme != "https" or parsed.netloc != expected_origin.netloc
        ):
            fail(f"homepage canonical points outside the production origin: {canonical}")


def validate_public_url(value, expected_origin, label):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.netloc != expected_origin.netloc:
        fail(f"{label} must use the production HTTPS origin: {value}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail(f"{label} must not contain credentials, a query, or a fragment: {value}")
    return parsed


def validate_sitemap_file(sitemap_path, output_dir, expected_origin, seen):
    resolved = sitemap_path.resolve()
    if resolved in seen:
        fail(f"sitemap cycle detected at {sitemap_path.name}")
    seen.add(resolved)

    root = ET.parse(sitemap_path).getroot()
    urlset_tag = f"{{{SITEMAP_NAMESPACE}}}urlset"
    index_tag = f"{{{SITEMAP_NAMESPACE}}}sitemapindex"
    if root.tag == urlset_tag:
        locations = root.findall(
            f"{{{SITEMAP_NAMESPACE}}}url/{{{SITEMAP_NAMESPACE}}}loc")
        if not locations:
            fail(f"{sitemap_path.name} contains no URLs")
        for location in locations:
            validate_public_url(location.text or "", expected_origin, "sitemap URL")
        return

    if root.tag != index_tag:
        fail(f"{sitemap_path.name} is not a sitemap urlset or sitemap index")
    locations = root.findall(
        f"{{{SITEMAP_NAMESPACE}}}sitemap/{{{SITEMAP_NAMESPACE}}}loc")
    if not locations:
        fail("sitemap index contains no child sitemaps")
    for location in locations:
        parsed = validate_public_url(
            location.text or "", expected_origin, "child sitemap URL")
        child_name = Path(parsed.path).name
        if not re.fullmatch(r"sitemap-[1-9][0-9]*\.xml", child_name):
            fail(f"unexpected child sitemap filename: {child_name}")
        child_path = output_dir / child_name
        if not child_path.is_file():
            fail(f"referenced child sitemap is missing: {child_name}")
        validate_sitemap_file(child_path, output_dir, expected_origin, seen)


def validate(output_directory, site_url):
    output_dir = Path(output_directory)
    expected_origin = urlsplit(site_url.rstrip("/"))
    if expected_origin.scheme != "https" or not expected_origin.netloc:
        fail("site URL must be an absolute HTTPS origin")

    validate_homepage(output_dir, expected_origin)
    expected_robots = (
        "User-agent: *\n"
        "Allow: /\n"
        f"Sitemap: {site_url.rstrip('/')}/sitemap.xml\n"
    )
    if (output_dir / "robots.txt").read_text(encoding="utf-8") != expected_robots:
        fail("robots.txt does not match the production policy")
    validate_sitemap_file(
        output_dir / "sitemap.xml", output_dir, expected_origin, set())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output_directory")
    parser.add_argument("site_url")
    args = parser.parse_args()
    try:
        validate(args.output_directory, args.site_url)
    except (OSError, ET.ParseError, ValueError) as error:
        print(f"search-discovery validation failed: {error}", file=sys.stderr)
        return 1
    print("search-verification tags, robots.txt, and sitemap XML are valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
