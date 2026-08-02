#!/usr/bin/env bash

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

GOOGLE='<meta name="google-site-verification" content="XaJCH6-K355pE6DNYj50QvpVDHrmcGT_NBUey3dXiKc">'
BING='<meta name="msvalidate.01" content="8B983F2DC788493BCD2FC9B8C74AAEDD">'

write_valid_files() {
    printf '<!doctype html><html><head>%s%s</head><body></body></html>\n' \
        "$GOOGLE" "$BING" > "$TMP_DIR/index.html"
    printf 'User-agent: *\nAllow: /\nSitemap: https://metrics.1aeo.com/sitemap.xml\n' \
        > "$TMP_DIR/robots.txt"
    printf '%s\n' \
        '<?xml version="1.0" encoding="UTF-8"?>' \
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' \
        '  <url><loc>https://metrics.1aeo.com/</loc></url>' \
        '</urlset>' > "$TMP_DIR/sitemap.xml"
}

write_valid_files
python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null

python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace(
        "</head>",
        '<meta name="robots" data-noindex="documentation" '
        'content="index, follow"></head>',
    ),
    encoding="utf-8",
)
PY
python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace("</head>", '<meta name="robots" content="none"></head>'),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "blocking robots none directive was accepted" >&2
    exit 1
fi

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace("</head>", '<meta content=noindex name = robots></head>'),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "reordered unquoted robots noindex directive was accepted" >&2
    exit 1
fi

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace(
        "</head>",
        '<meta name="robots" content="noindex >"></head>',
    ),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "quoted greater-than robots noindex directive was accepted" >&2
    exit 1
fi

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace(
        "</head>",
        '<meta name="robot&#x73;" content="noindex"></head>',
    ),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "character-reference robots noindex directive was accepted" >&2
    exit 1
fi

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace(
        "</head>",
        '<meta NAME="ROBOTS" name="other" CONTENT="noindex"></head>',
    ),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "uppercase first duplicate robots name was accepted" >&2
    exit 1
fi

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace(
        "</head>",
        '<meta name="robots" content="noindex </head>"></head>',
    ),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "quoted closing-head robots noindex directive was accepted" >&2
    exit 1
fi

write_valid_files
printf '<!doctype html><html><head>%s%s%s</head><body></body></html>\n' \
    "$GOOGLE" "$GOOGLE" "$BING" > "$TMP_DIR/index.html"
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "duplicate verification tag was accepted" >&2
    exit 1
fi

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace(
        "</head>",
        '<link href=//evil.example/page rel = canonical></head>',
    ),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "protocol-relative cross-host canonical was accepted" >&2
    exit 1
fi

write_valid_files
python3 - "$TMP_DIR/index.html" <<'PY'
from pathlib import Path
import sys

homepage = Path(sys.argv[1])
contents = homepage.read_text(encoding="utf-8")
homepage.write_text(
    contents.replace("</head>", '<link rel=canonical href=javascript:alert(1)></head>'),
    encoding="utf-8",
)
PY
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "non-HTTPS canonical scheme was accepted" >&2
    exit 1
fi

write_valid_files
sed 's#metrics\.1aeo\.com#internal.example#' "$TMP_DIR/sitemap.xml" \
    > "$TMP_DIR/sitemap.invalid.xml"
mv "$TMP_DIR/sitemap.invalid.xml" "$TMP_DIR/sitemap.xml"
if python3 "$REPO_DIR/scripts/validate-search-discovery.py" \
    "$TMP_DIR" https://metrics.1aeo.com >/dev/null 2>&1; then
    echo "cross-host sitemap URL was accepted" >&2
    exit 1
fi

echo "search discovery validation tests passed"
