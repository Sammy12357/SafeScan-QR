"""Local checks for deceptive QR URL hostnames.

The brand comparison uses the pinned Unicode 18 UTS #39 confusables table.
It is deliberately narrower than the full UTS #39 identifier profile: we
compare registrable labels with a small protected-brand set, and separately
warn about common mixed scripts and hidden direction controls. A legitimate
internationalized domain is not suspicious merely because it uses IDNA.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlsplit

import idna
import tldextract

from .config import PROTECTED_BRANDS
from .idna_hosts import canonical_ascii_host
from .scoring import signal


CONFUSABLES_FILE = Path(__file__).with_name("data") / "confusables-18.0.0.txt"
CONFUSABLES_SHA256 = "6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False, include_psl_private_domains=True)

_DIRECTION_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_INVISIBLE_CONTROLS = frozenset("\u00ad\u034f\u180e\u200b\u200c\u200d\u2060\ufeff")
_SENSITIVE_BRAND_WORDS = frozenset({
    "login", "signin", "sign", "in", "secure", "verify", "verification",
    "identity", "account", "support", "wallet", "payment", "pay", "help",
    "auth", "claim", "gift", "password", "reset",
})
_IDNA_DOT_SEPARATORS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


@lru_cache(maxsize=1)
def _confusables() -> dict[str, str]:
    """Load Unicode's one-code-point-to-sequence confusable mappings once."""
    mapping = {}
    with CONFUSABLES_FILE.open(encoding="utf-8") as rows:
        for row in rows:
            if not row or row.startswith("#"):
                continue
            fields = row.split("#", 1)[0].split(";")
            if len(fields) < 2:
                continue
            source = "".join(chr(int(code, 16)) for code in fields[0].split())
            target = "".join(chr(int(code, 16)) for code in fields[1].split())
            mapping[source] = target
    return mapping


def _brand_skeleton(value: str) -> str:
    """Compute the LTR UTS #39-style skeleton needed for DNS brand labels.

    IDNA host labels disallow most default-ignorable format controls; these
    are reported separately when present in the raw QR payload. The full
    UTS #39 script-restriction algorithm is intentionally out of scope.
    """
    nfd = unicodedata.normalize("NFD", value)
    mapped = "".join(_confusables().get(char, char) for char in nfd)
    return unicodedata.normalize("NFD", mapped).casefold()


def _looks_like_brand(value: str, brand: str) -> bool:
    target = _brand_skeleton(brand)
    if _brand_skeleton(value) == target:
        return True
    # UTS #39's confusables table maps some ASCII sequences (m -> rn), but
    # not the common vv -> w substitution used in phishing hostnames.
    folded_vv = re.sub(r"(?i:vv)", "w", value)
    return folded_vv != value and _brand_skeleton(folded_vv) == target


def _raw_hostname(url: str) -> str:
    """Keep QR letter case, which urlsplit(...).hostname would discard."""
    try:
        authority = urlsplit(url).netloc.rsplit("@", 1)[-1]
    except ValueError:
        return ""
    if authority.startswith("["):
        return ""
    return authority.rsplit(":", 1)[0].rstrip(".") if ":" in authority else authority.rstrip(".")


def _host_identity(url: str) -> dict[str, str] | None:
    raw = _raw_hostname(url)
    if not raw:
        return None
    try:
        ascii_host = canonical_ascii_host(raw)
        unicode_host = idna.decode(ascii_host, uts46=True)
    except (idna.IDNAError, UnicodeError):
        return None
    # Decode A-labels for visual comparison, while preserving the original
    # case of ordinary QR text (paypaI.com and paypal.com resolve differently).
    raw_labels = raw.translate(_IDNA_DOT_SEPARATORS).split(".")
    if len(raw_labels) == len(ascii_host.split(".")):
        visible_labels = []
        for label in raw_labels:
            try:
                visible_labels.append(idna.decode(label, uts46=True) if label.lower().startswith("xn--") else label)
            except idna.IDNAError:
                visible_labels.append(label)
        visible_host = ".".join(visible_labels)
    else:
        visible_host = unicode_host
    return {"unicode": unicode_host, "ascii": ascii_host, "visible": visible_host}


def host_forms(url: str) -> dict[str, str] | None:
    """Return non-clickable display forms for a scanned URL's hostname."""
    identity = _host_identity(url)
    if identity is None:
        return None
    return {"unicode": identity["unicode"], "ascii": identity["ascii"]}


def _script_family(char: str) -> str | None:
    if not char.isalpha():
        return None
    name = unicodedata.name(char, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script + " "):
            return script
    return None


def _mixed_latin_script(label: str) -> bool:
    scripts = {_script_family(char) for char in label}
    scripts.discard(None)
    return "LATIN" in scripts and len(scripts) > 1


def _brand_placement_signal(ascii_host: str, visible_host: str, registered: str):
    if not registered:
        return None
    registered_labels = registered.split(".")
    visible_labels = visible_host.split(".")
    prefix_labels = visible_labels[: -len(registered_labels)]
    words = [part for label in [*prefix_labels, visible_labels[-len(registered_labels)]] for part in label.split("-") if part]
    for brand, official in PROTECTED_BRANDS.items():
        if len(brand) < 4 or registered == official or registered_labels[0] == brand:
            continue
        # An apparent official hostname that is actually under a different
        # registrable domain, such as paypal.com.evil.net.
        if f".{official}." in f".{ascii_host}.":
            return signal(
                "Brand Impersonation", f"{official} appears inside another hostname", "high",
                f"The QR hostname contains {official}, but its actual registered domain is {registered}. This is not an official {official} link.", False,
            )
        official_labels = official.split(".")
        if any(
            _looks_like_brand(prefix_labels[index], brand)
            and [part.casefold() for part in prefix_labels[index + 1 : index + len(official_labels)]] == official_labels[1:]
            for index in range(len(prefix_labels))
        ):
            return signal(
                "Brand Impersonation", f"Looks like {official} inside another hostname", "high",
                f"The QR hostname visually contains {official}, but its actual registered domain is {registered}. This is not an official {official} link.", False,
            )
        # A brand-like word paired with login/payment language may be split
        # by hyphens or dots and may itself use confusable characters.
        if any(_looks_like_brand(word, brand) for word in words) and any(word.casefold() in _SENSITIVE_BRAND_WORDS for word in words):
            return signal(
                "Brand Impersonation", f"{brand} login or payment wording on another domain", "high",
                f"The QR hostname uses {brand} and a sensitive action word, but its actual registered domain is {registered}, not {official}.", False,
            )
    return None


def check_url_deception_signals(url: str) -> list[dict]:
    """Inspect a URL locally, without fetching it or exposing private QR data."""
    findings = []
    inspected = url
    for _ in range(2):
        decoded = unquote(inspected)
        if decoded == inspected:
            break
        inspected = decoded
    if any(char in _DIRECTION_CONTROLS for char in inspected):
        findings.append(signal(
            "Hidden Direction Control", "Text direction can be changed", "high",
            "The QR payload contains a bidirectional text control that can make its address or action appear in a misleading order.", False,
        ))
    if any(char in _INVISIBLE_CONTROLS for char in inspected):
        findings.append(signal(
            "Invisible Character", "Hidden character in QR content", "medium",
            "The QR payload contains an invisible character that can conceal a difference between the displayed text and the actual action.", False,
        ))

    identity = _host_identity(url)
    if identity is None:
        return findings
    ascii_host = identity["ascii"]
    extracted = _EXTRACT(ascii_host)
    if not extracted.domain or not extracted.suffix:
        # A deceptive Unicode top-level label might not appear in the PSL at
        # all (apple.cοm, with Greek omicron). Compare the full hostname even
        # when no registrable-domain boundary can be established.
        for brand, official in PROTECTED_BRANDS.items():
            if _brand_skeleton(identity["visible"]) == _brand_skeleton(official) and ascii_host != official:
                findings.append(signal(
                    "Brand Impersonation", f"Looks like {official}", "high",
                    f"This QR hostname visually resembles {official}, but its actual ASCII hostname is {ascii_host}.", False,
                ))
                return findings
        if any(_mixed_latin_script(label) for label in identity["visible"].split(".")):
            findings.append(signal(
                "Mixed Script Host", "Latin and other scripts in one label", "medium",
                f"The hostname mixes look-alike writing systems inside a label. Its ASCII form is {ascii_host}; verify the destination independently.", False,
            ))
        return findings
    registered = f"{extracted.domain}.{extracted.suffix}"
    placement = _brand_placement_signal(ascii_host, identity["visible"], registered)
    if placement:
        findings.append(placement)

    reg_label_count = len(registered.split("."))
    visible_labels = identity["visible"].split(".")
    if len(visible_labels) < reg_label_count:
        return findings
    visible_label = visible_labels[-reg_label_count]
    for brand, official in PROTECTED_BRANDS.items():
        if len(brand) < 4 or registered == official:
            continue
        if not _looks_like_brand(visible_label, brand):
            continue
        if visible_label.casefold() == brand and extracted.domain == brand:
            # Many protected brands own legitimate sites on other TLDs. An
            # exact brand word alone is insufficient evidence of deception.
            continue
        else:
            findings.append(signal(
                "Brand Impersonation", f"Looks like {official}", "high",
                f"This QR hostname uses look-alike characters to resemble {official}; its actual registered domain is {registered}.", False,
            ))
        break

    if not any(item["check"] == "Brand Impersonation" for item in findings):
        if any(_mixed_latin_script(label) for label in visible_labels):
            findings.append(signal(
                "Mixed Script Host", "Latin and other scripts in one label", "medium",
                f"The hostname mixes look-alike writing systems inside a label. Its ASCII form is {ascii_host}; verify the destination independently.", False,
            ))
    return findings
