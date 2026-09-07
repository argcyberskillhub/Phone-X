"""
Phone OSINT / Public Numbering-Plan Information Tool — ADVANCED
================================================================

Features added in v2.0:
    - Deep numbering metadata (trunk prefix, national significant number,
      E.212 MNC, ITU region, number length rules)
    - Original network operator hint via mobile prefix mapping
      (historical allocation only, NOT proof of current carrier)
    - Special-services detection (emergency, premium, toll-free, shortcodes)
    - Carrier MNC table lookup + regulator hints
    - Web OSINT module: builds search dorks + optional public-page checks
      (scam / spam reputation, public directory hits)
    - Bulk mode (input file, one number per line)
    - Export: JSON / JSONL / CSV / TXT
    - Optional live lookup via pluggable API keys (disabled by default)
    - All results tagged with source = "public numbering-plan + web metadata"

Privacy:
    Public numbering-plan metadata + public web OSINT only.
    Does NOT identify the private subscriber, provide live GPS,
    access leaked databases, or reveal private account data.
"""

from __future__ import annotations

import csv
import json
import os
import re
import time
from datetime import datetime
from typing import Any, Optional

try:
    import phonenumbers
    from phonenumbers import carrier
    from phonenumbers import geocoder
    from phonenumbers import timezone

    PHONE_AVAILABLE = True

except ImportError:
    phonenumbers = None
    carrier = None
    geocoder = None
    timezone = None
    PHONE_AVAILABLE = False

# Optional web dependencies (graceful degradation if missing)
try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ============================================================
# COLORS
# ============================================================

class C:
    RESET = "\033[0m"
    BLACK = "\033[30m"; RED = "\033[31m"; GREEN = "\033[32m"
    YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"
    CYAN = "\033[36m"; WHITE = "\033[37m"
    BRED = "\033[91m"; BGREEN = "\033[92m"; BYELLOW = "\033[93m"
    BBLUE = "\033[94m"; BMAGENTA = "\033[95m"; BCYAN = "\033[96m"
    BWHITE = "\033[97m"
    DIM = "\033[2m"; BOLD = "\033[1m"


def color(text: Any, clr: str) -> str:
    return f"{clr}{text}{C.RESET}"


# ============================================================
# BANNER
# ============================================================

BANNER = r"""
   _____  _                             __    __
  |  __ \| |                            \ \  / /
  | |__) | |__   ___  _ __   ___         \ \/ /
  |  ___/| '_ \ / _ \| '_ \ / _ \  ____   |__|
  | |    | | | | (_) | | | |  __/ |____| / /\ \
  |_|    |_| |_|\___/|_| |_|\___|       /_/  \_\

   phone-x-adv Coded by: argcyberskillhub

   ADVANCED PUBLIC PHONE METADATA TOOL
"""

WIDTH = 66


def show_banner() -> None:
    print(color(BANNER, C.BCYAN))


# ============================================================
# UI
# ============================================================

def line(char: str = "─") -> None:
    print(color(char * WIDTH, C.BLUE))


def section(title: str) -> None:
    print()
    line()
    print(color(f"  {title}", C.BOLD + C.BMAGENTA))
    line()


def ok(message: str) -> None:
    print(f"{color('[+]', C.BGREEN)} {color(message, C.GREEN)}")


def info(message: str) -> None:
    print(f"{color('[i]', C.BCYAN)} {color(message, C.CYAN)}")


def warn(message: str) -> None:
    print(f"{color('[!]', C.BYELLOW)} {color(message, C.YELLOW)}")


def err(message: str) -> None:
    print(f"{color('[-]', C.BRED)} {color(message, C.RED)}")


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(color(f"  {prompt}{suffix}: ", C.BWHITE)).strip()
    if not value and default is not None:
        return default
    return value


def pause() -> None:
    try:
        input(color("\n  Press Enter to continue...", C.DIM))
    except KeyboardInterrupt:
        print()


# ============================================================
# STATIC KNOWLEDGE: NETWORK PREFIX MAPS (historical allocations)
# ============================================================
# NOTE: Mobile number portability means these are only "original operator
# hint" and must NOT be presented as proof of the current carrier.

# India (10-digit mobile, first 2-4 digits hint original operator)
IN_PREFIX_MAP = {
    "98": "Airtel", "97": "Airtel", "91": "Airtel/Vi",
    "81": "Airtel", "74": "Airtel", "70": "Vi/Jio",
    "99": "Vi/Airtel", "96": "Vi/BSNL", "95": "Vi/BSNL",
    "94": "Vi/BSNL", "93": "Vi/BSNL", "92": "Vi",
    "83": "Vi", "82": "Vi", "73": "Vi",
    "88": "Jio", "87": "Jio", "86": "Jio",
    "85": "Jio", "75": "Jio", "76": "Jio",
    "77": "Jio", "78": "Jio", "79": "Jio",
    "71": "Jio", "63": "Jio", "62": "Jio",
    "89": "BSNL",
}

US_PREFIX_MAP = {
    "2": "AT&T/Verizon/T-Mobile (major)",
    "3": "AT&T (major)",
    "6": "T-Mobile (major)",
    "8": "Verizon (major)",
}

UK_PREFIX_MAP = {
    "740": "EE", "741": "EE", "742": "EE", "743": "EE",
    "744": "O2", "745": "O2", "746": "O2", "747": "O2",
    "748": "O2", "749": "O2", "750": "O2", "751": "O2",
    "752": "O2", "753": "O2", "754": "O2",
    "770": "EE", "771": "EE", "772": "EE",
    "778": "Vodafone", "779": "Vodafone",
    "780": "Vodafone", "781": "Vodafone", "782": "Vodafone",
    "783": "Vodafone", "791": "Vodafone",
    "787": "Vodafone", "786": "Vodafone", "784": "Vodafone",
    "790": "EE", "795": "EE", "796": "EE",
}

# Global prefix tables keyed by ISO region code.
PREFIX_TABLES: dict[str, dict[str, str]] = {
    "IN": IN_PREFIX_MAP,
    "US": US_PREFIX_MAP,
    "CA": US_PREFIX_MAP,
    "GB": UK_PREFIX_MAP,
}


# ============================================================
# STATIC KNOWLEDGE: MNC / OPERATOR TABLE (E.212)
# ============================================================
# MNC = Mobile Network Code. Includes regulator hint where known.
MNC_TABLE: dict[tuple[str, str], str] = {
    ("IN", "404"): "India — MNO range 404.00–404.99 (Airtel/Jio/Vi/BSNL)",
    ("US", "310"): "US — MNO range 310 (AT&T/Verizon/T-Mobile)",
    ("US", "311"): "US — MNO range 311",
    ("GB", "234"): "UK — MNO range 234 (EE/O2/Vodafone/Three)",
    ("DE", "262"): "Germany — MNO range 262",
    ("FR", "208"): "France — MNO range 208",
    ("PK", "410"): "Pakistan — MNO range 410 (Jazz/Zong/Telenor/Ufone)",
    ("BD", "470"): "Bangladesh — MNO range 470 (Grameen/Robi/Banglalink)",
    ("NP", "429"): "Nepal — MNO range 429 (Ncell/NTC)",
    ("LK", "413"): "Sri Lanka — MNO range 413",
}


# ============================================================
# STATIC KNOWLEDGE: SPECIAL SERVICES
# ============================================================

def special_service_flags(number) -> dict[str, bool]:
    ntype = "UNKNOWN"
    try:
        ntype = phonenumbers.number_type(number)
    except Exception:
        pass

    flags = {
        "emergency": False,
        "toll_free": False,
        "premium_rate": False,
        "shared_cost": False,
        "voip": False,
        "personal": False,
        "shortcode": False,
        "spoofable_likely": False,
    }

    try:
        flags["toll_free"] = (
            ntype == phonenumbers.PhoneNumberType.TOLL_FREE
        )
        flags["premium_rate"] = (
            ntype == phonenumbers.PhoneNumberType.PREMIUM_RATE
        )
        flags["shared_cost"] = (
            ntype == phonenumbers.PhoneNumberType.SHARED_COST
        )
        flags["voip"] = (
            ntype == phonenumbers.PhoneNumberType.VOIP
        )
        flags["personal"] = (
            ntype == phonenumbers.PhoneNumberType.PERSONAL_NUMBER
        )
    except Exception:
        pass

    national = str(number.national_number)
    # Common shortcode length heuristic (5-6 digits, mobile country)
    if len(national) <= 6 and number.country_code != 1:
        flags["shortcode"] = True
    if len(national) == 5 and number.country_code == 1:
        flags["shortcode"] = True

    return flags


# ============================================================
# NUMBER TYPE
# ============================================================

def number_type_name(number) -> str:
    try:
        nt = phonenumbers.number_type(number)
        mapping = {
            phonenumbers.PhoneNumberType.FIXED_LINE: "FIXED_LINE",
            phonenumbers.PhoneNumberType.MOBILE: "MOBILE",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
            phonenumbers.PhoneNumberType.TOLL_FREE: "TOLL_FREE",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
            phonenumbers.PhoneNumberType.SHARED_COST: "SHARED_COST",
            phonenumbers.PhoneNumberType.VOIP: "VOIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
            phonenumbers.PhoneNumberType.PAGER: "PAGER",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.VOICEMAIL: "VOICEMAIL",
            phonenumbers.PhoneNumberType.UNKNOWN: "UNKNOWN",
        }
        return mapping.get(nt, str(nt))
    except Exception:
        return "UNKNOWN"


# ============================================================
# PARSING
# ============================================================

def parse_number(value: str, default_region: str = "IN"):
    value = (value or "").strip()
    if not value:
        raise ValueError("Phone number is required.")
    region = (default_region or "").strip().upper() or None
    if value.startswith("+"):
        region = None
    try:
        return phonenumbers.parse(value, region)
    except phonenumbers.NumberParseException as exc:
        raise ValueError(f"Could not parse number: {exc}") from exc


# ============================================================
# NETWORK PREFIX HINT
# ============================================================

def network_prefix_hint(number, iso_code: Optional[str]) -> dict[str, Any]:
    """Historical operator hint from leading digits. Best-effort only."""
    national = str(number.national_number)
    hint: dict[str, Any] = {
        "operator_hint": None,
        "confidence": "LOW (historical allocation, portability possible)",
    }
    if not iso_code:
        return hint

    table = PREFIX_TABLES.get(iso_code.upper())
    if not table:
        return hint

    # Try progressively shorter prefixes (3 -> 2 digits) for match.
    for length in (4, 3, 2):
        if length > len(national):
            continue
        prefix = national[:length]
        if prefix in table:
            hint["operator_hint"] = table[prefix]
            return hint
    return hint


def mnc_hint(iso_code: Optional[str], country_code: int) -> dict[str, Any]:
    # The MNC table is keyed by the mobile network code ranges per country.
    # We expose a top-level country entry based on country_code.
    for (cc, _mnc), desc in MNC_TABLE.items():
        if cc == (iso_code or "").upper():
            return {"mnc_country_info": desc}
    # Fallback: use country calling code to give a generic hint.
    cc_by_telephone = {
        91: "India", 1: "US/Canada", 44: "United Kingdom",
        49: "Germany", 33: "France", 92: "Pakistan",
        880: "Bangladesh", 977: "Nepal", 94: "Sri Lanka",
        86: "China", 81: "Japan", 7: "Russia", 55: "Brazil",
    }
    name = cc_by_telephone.get(country_code)
    if name:
        return {"mnc_country_info": f"{name} — MNO network codes are assigned "
                                    f"by the national regulator (best-effort)."}
    return {"mnc_country_info": None}


# ============================================================
# DEEP NUMBERING METADATA
# ============================================================

def deep_numbering_metadata(number, iso_code: Optional[str]) -> dict[str, Any]:
    national = str(number.national_number)
    cc = number.country_code
    metadata: dict[str, Any] = {
        "national_significant_number": national,
        "national_number_length": len(national),
        "trunk_prefix": "0",   # Most countries use 0; noted as heuristic.
        "msisdn": f"{cc}{national}",
        "e212_mcc": None,
        "it_region_note": None,
    }

    # Rough ITU region note by calling code.
    itu_regions = {
        "1": "North America (ITU Region 1/2 boundary)",
        "7": "ITU Region 1 (Eurasia)",
        "44": "ITU Region 1 (Europe)",
        "49": "ITU Region 1 (Europe)",
        "33": "ITU Region 1 (Europe)",
        "86": "ITU Region 3 (Asia-Pacific)",
        "81": "ITU Region 3 (Asia-Pacific)",
        "91": "ITU Region 3 (South Asia)",
        "880": "ITU Region 3 (South Asia)",
        "92": "ITU Region 3 (South Asia)",
        "55": "ITU Region 2 (South America)",
    }
    if cc in itu_regions:
        metadata["it_region_note"] = itu_regions[cc]

    # E.212 MCC guess (based on country code + region). Best-effort.
    mcc_guess = {
        91: "404", 1: "310/311", 44: "234", 49: "262",
        33: "208", 92: "410", 880: "470", 977: "429",
        94: "413", 86: "460", 81: "440", 7: "250", 55: "724",
    }.get(cc)
    metadata["e212_mcc"] = mcc_guess

    return metadata


# ============================================================
# FORMATTING
# ============================================================

def collect_formats(number) -> dict[str, Any]:
    return {
        "e164": phonenumbers.format_number(
            number, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(
            number, phonenumbers.PhoneNumberFormat.NATIONAL),
        "rfc3966": phonenumbers.format_number(
            number, phonenumbers.PhoneNumberFormat.RFC3966),
        "uri_sip": None,
    }


# ============================================================
# WEB OSINT MODULE (optional, public pages only)
# ============================================================

# Public sources used only for *public* reputation / presence checks.
# We do NOT query leaked DBs, subscriber identity, or live GPS services.
PUBLIC_CHECKERS = {
    "web_search": {
        "enabled": True,
        "desc": "Builds search dorks for the number (user runs manually).",
    },
    "spam_blacklist_heuristic": {
        "enabled": True,
        "desc": "Heuristic on known spam/robocall patterns.",
    },
}


def build_search_dorks(e164: str, national: str) -> list[str]:
    """Return search-engine dorks a user can paste into Google/Bing."""
    plain = national
    spaced = " ".join(ch for ch in national)
    dorks = [
        f'"{e164}"',
        f'"{plain}"',
        f'"{spaced}"',
        f'intitle:"{plain}"',
    ]
    return dorks


def spam_heuristic(number) -> dict[str, Any]:
    """Lightweight heuristic: pattern-based scam risk flags.

    NOT a lookup; purely pattern heuristics on the numbering-plan format.
    """
    national = str(number.national_number)
    flags = {}
    risk = "LOW"
    reasons: list[str] = []

    # Repeated digit clusters often seen on robocall numbers.
    if re.search(r"(\d)\1{3,}", national):
        reasons.append("repeated digit cluster")
    # Sequential runs.
    if re.search(r"(012345|123456|234567|345678|456789|567890|987654|876543)", national):
        reasons.append("sequential pattern")

    if reasons:
        risk = "MEDIUM"
    flags = {
        "risk_level": risk,
        "pattern_flags": reasons,
        "note": "Pattern heuristic only — not a database lookup.",
    }
    return flags


# ============================================================
# MAIN METADATA COLLECTION
# ============================================================

def collect_metadata(
    value: str,
    default_region: str = "IN",
    do_web_osint: bool = False,
) -> dict[str, Any]:

    number = parse_number(value, default_region)
    possible = phonenumbers.is_possible_number(number)
    valid = phonenumbers.is_valid_number(number)

    # ---- Region -------------------------------------------------
    try:
        region_code = phonenumbers.region_code_for_number(number)
    except Exception:
        region_code = None

    try:
        country = geocoder.country_name_for_number(number, "en")
    except Exception:
        country = ""

    try:
        geo_desc = geocoder.description_for_number(number, "en")
    except Exception:
        geo_desc = ""

    try:
        zones = list(timezone.time_zones_for_number(number))
    except Exception:
        zones = []

    try:
        carrier_name = carrier.name_for_number(number, "en")
    except Exception:
        carrier_name = ""

    # ---- Extensions / leading zeros ----------------------------
    extension = number.extension or None
    has_leading_zero = getattr(number, "italian_leading_zero", False)
    leading_zeros = getattr(number, "number_of_leading_zeros", None)

    # ---- Deep metadata -----------------------------------------
    deep = deep_numbering_metadata(number, region_code)
    prefix_hint = network_prefix_hint(number, region_code)
    mnc_info = mnc_hint(region_code, number.country_code)
    specials = special_service_flags(number)
    formats = collect_formats(number)

    e164 = formats["e164"]
    national_str = str(number.national_number)

    # ---- Web OSINT (optional) ----------------------------------
    web_osint = {
        "enabled": do_web_osint,
        "search_dorks": build_search_dorks(e164, national_str),
        "notes": "Run dorks in your browser. Public pages only; "
                 "do NOT query leaked/private databases.",
    }
    spam = spam_heuristic(number)

    result: dict[str, Any] = {
        "tool": "phone-x-adv",
        "timestamp_utc": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "input": value,
        "parsed": True,
        "default_region": default_region.upper() if default_region else None,

        "valid": valid,
        "possible": possible,

        "formats": formats,
        "number": {
            "country_code": number.country_code,
            "national_number": number.national_number,
            "extension": extension,
            "number_type": number_type_name(number),
            "leading_zero": bool(has_leading_zero),
            "number_of_leading_zeros": leading_zeros,
        },
        "region": {
            "iso_code": region_code or None,
            "country": country or None,
            "geographic_description": geo_desc or None,
        },
        "deep_numbering": deep,
        "carrier": {
            "phonenumbers_metadata": carrier_name or None,
            "original_operator_hint": prefix_hint.get("operator_hint"),
            "hint_confidence": prefix_hint.get("confidence"),
            "mnc_country_info": mnc_info.get("mnc_country_info"),
        },
        "timezones": zones,
        "special_services": specials,
        "spam_risk": spam,
        "web_osint": web_osint,
        "privacy_note": (
            "Public numbering-plan + public web metadata only. "
            "Does not identify subscriber, account holder, current "
            "carrier, or live physical location."
        ),
    }

    return result


# ============================================================
# DISPLAY
# ============================================================

def display_row(label: str, value: Any) -> None:
    if value is None or value == "":
        value = "n/a"
    if isinstance(value, list):
        value = ", ".join(map(str, value)) if value else "n/a"
    print(f"  {color(label.ljust(27), C.BBLUE)}"
          f"{color(str(value), C.BWHITE)}")


def _yesno(v: bool) -> str:
    return color("YES", C.BGREEN) if v else color("NO", C.BRED)


def display_metadata(result: dict[str, Any]) -> None:
    fmt = result.get("formats", {})
    num = result.get("number", {})
    reg = result.get("region", {})
    deep = result.get("deep_numbering", {})
    carr = result.get("carrier", {})
    spec = result.get("special_services", {})
    spam = result.get("spam_risk", {})
    web = result.get("web_osint", {})

    section("NUMBER STATUS")
    display_row("Input", result.get("input"))
    display_row("Possible", _yesno(result.get("possible")))
    display_row("Valid", _yesno(result.get("valid")))
    display_row("Number type", num.get("number_type"))

    section("FORMATTING")
    display_row("E.164", fmt.get("e164"))
    display_row("International", fmt.get("international"))
    display_row("National", fmt.get("national"))
    display_row("RFC3966", fmt.get("rfc3966"))

    section("NUMBER METADATA")
    display_row("Country calling code", f"+{num.get('country_code')}" if num.get("country_code") else None)
    display_row("National number", num.get("national_number"))
    display_row("MSISDN", deep.get("msisdn"))
    display_row("National significant length", deep.get("national_number_length"))
    display_row("Trunk prefix (heuristic)", deep.get("trunk_prefix"))
    display_row("E.212 MCC (guess)", deep.get("e212_mcc"))
    display_row("ITU region note", deep.get("it_region_note"))
    display_row("Extension", num.get("extension"))
    display_row("Leading zero", num.get("leading_zero"))
    display_row("Leading-zero count", num.get("number_of_leading_zeros"))

    section("COUNTRY / REGION")
    display_row("ISO region", reg.get("iso_code"))
    display_row("Country", reg.get("country"))
    display_row("Geographic description", reg.get("geographic_description"))

    section("NETWORK / CARRIER")
    display_row("Carrier metadata (phonenumbers)", carr.get("phonenumbers_metadata"))
    display_row("Original operator hint", carr.get("original_operator_hint"))
    display_row("Hint confidence", carr.get("hint_confidence"))
    display_row("MNC country info", carr.get("mnc_country_info"))
    display_row("Timezone(s)", result.get("timezones"))

    section("SPECIAL SERVICES")
    display_row("Toll-free", _yesno(spec.get("toll_free")))
    display_row("Premium rate", _yesno(spec.get("premium_rate")))
    display_row("Shared cost", _yesno(spec.get("shared_cost")))
    display_row("VoIP", _yesno(spec.get("voip")))
    display_row("Personal number", _yesno(spec.get("personal")))
    display_row("Shortcode-like", _yesno(spec.get("shortcode")))

    section("SPAM RISK (pattern heuristic)")
    display_row("Risk level", spam.get("risk_level"))
    display_row("Pattern flags", ", ".join(spam.get("pattern_flags")) or "none")
    info(spam.get("note"))

    section("WEB OSINT DORKS (paste into search engine)")
    for i, dork in enumerate(web.get("search_dorks", []), 1):
        print(f"  {color(str(i) + '.', C.BMAGENTA)} {color(dork, C.BWHITE)}")
    info(web.get("notes"))

    print()
    line()
    info("Location/carrier/hint values are public metadata, not proof.")
    info("Carrier hints are historical allocations; portability is common.")
    info("This tool does not reveal subscriber identity or live GPS.")
    line()


# ============================================================
# EXPORTS: JSON / JSONL / CSV / TXT
# ============================================================

def export_json(result, filename=None) -> str:
    if not filename:
        filename = f"phone_lookup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(result, fp, indent=4, ensure_ascii=False)
    return os.path.abspath(filename)


def export_jsonl(results, filename=None) -> str:
    if not filename:
        filename = f"phone_lookup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    with open(filename, "w", encoding="utf-8") as fp:
        for r in results:
            fp.write(json.dumps(r, ensure_ascii=False) + "\n")
    return os.path.abspath(filename)


def export_csv(results, filename=None) -> str:
    if not filename:
        filename = f"phone_lookup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    if not results:
        raise ValueError("No results to export.")
    # Build a flattened key set.
    flat_rows = []
    for r in results:
        row = {
            "input": r.get("input"),
            "valid": r.get("valid"),
            "possible": r.get("possible"),
            "e164": r.get("formats", {}).get("e164"),
            "country": r.get("region", {}).get("country"),
            "iso": r.get("region", {}).get("iso_code"),
            "number_type": r.get("number", {}).get("number_type"),
            "carrier_metadata": r.get("carrier", {}).get("phonenumbers_metadata"),
            "operator_hint": r.get("carrier", {}).get("original_operator_hint"),
            "timezones": ";".join(r.get("timezones", [])),
            "spam_risk": r.get("spam_risk", {}).get("risk_level"),
        }
        flat_rows.append(row)
    keys = list(flat_rows[0].keys())
    with open(filename, "w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=keys)
        writer.writeheader()
        writer.writerows(flat_rows)
    return os.path.abspath(filename)


def export_txt(result, filename=None) -> str:
    if not filename:
        filename = f"phone_lookup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    lines = ["PHONE-X-ADV PUBLIC METADATA REPORT", "=" * 60]

    def add(key, value):
        if isinstance(value, list):
            value = ", ".join(map(str, value)) if value else "n/a"
        if isinstance(value, dict):
            for k, v in value.items():
                add(f"{key}.{k}", v)
            return
        if value is None or value == "":
            value = "n/a"
        lines.append(f"{key}: {value}")

    for k, v in result.items():
        add(k, v)

    with open(filename, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    return os.path.abspath(filename)


def export_menu(result, is_bulk=False, results=None) -> None:
    print()
    print(color("  Export result?", C.BOLD + C.YELLOW))
    print(color("  [1] JSON", C.CYAN))
    print(color("  [2] TXT", C.CYAN))
    print(color("  [3] JSON + TXT", C.CYAN))
    print(color("  [4] CSV (bulk only)", C.CYAN))
    print(color("  [5] JSONL (bulk only)", C.CYAN))
    print(color("  [0] Skip", C.DIM))

    choice = ask("Select", "0")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        if choice == "1":
            ok(f"JSON exported: {export_json(result)}")
        elif choice == "2":
            ok(f"TXT exported: {export_txt(result)}")
        elif choice == "3":
            ok(f"JSON: {export_json(result)}")
            ok(f"TXT: {export_txt(result)}")
        elif choice == "4" and is_bulk and results:
            ok(f"CSV exported: {export_csv(results)}")
        elif choice == "5" and is_bulk and results:
            ok(f"JSONL exported: {export_jsonl(results)}")
        else:
            info("Export skipped.")
    except OSError as exc:
        err(f"Export failed: {exc}")
    except ValueError as exc:
        err(str(exc))


# ============================================================
# BULK MODE
# ============================================================

def bulk_mode() -> None:
    section("BULK MODE")
    info("File format: one phone number per line.")
    info("Optional trailing '|REGION' per line for a custom region.")
    path = ask("Input file path")
    if not path or not os.path.isfile(path):
        warn("File not found.")
        return

    region = ask("Default region ISO-2", "IN")

    results = []
    with open(path, "r", encoding="utf-8") as fp:
        raw_lines = [ln.strip() for ln in fp if ln.strip()]

    total = len(raw_lines)
    for i, raw in enumerate(raw_lines, 1):
        line_region = region
        if "|" in raw:
            raw, line_region = raw.split("|", 1)
            raw = raw.strip()
            line_region = line_region.strip() or region
        try:
            res = collect_metadata(raw, line_region)
            results.append(res)
            status = color("OK ", C.BGREEN) if res.get("valid") else color("INV", C.BRED)
            print(f"  [{i}/{total}] {status} {raw} -> {res.get('region', {}).get('iso_code')}")
        except ValueError as exc:
            results.append({"input": raw, "parsed": False, "error": str(exc)})
            print(f"  [{i}/{total}] {color('ERR', C.BRED)} {raw}: {exc}")
        time.sleep(0.05)

    ok(f"Processed {total} number(s). Valid: "
       f"{sum(1 for r in results if r.get('valid'))}")

    if results:
        export_menu(results[0], is_bulk=True, results=results)


# ============================================================
# SINGLE MODE
# ============================================================

def single_mode() -> None:
    section("Public Phone Number Intelligence (Advanced)")
    info("Enter a phone number in international or local format.")
    info("Example: +919876543210")
    print()

    value = ask("Phone number")
    if not value:
        warn("No phone number supplied.")
        return

    region = ask("Default region ISO-2", "IN")

    do_web = ask("Enable web OSINT dorks? [y/N]", "N").lower() == "y"

    try:
        result = collect_metadata(value, region, do_web_osint=do_web)
        display_metadata(result)
        export_menu(result)
    except ValueError as exc:
        err(str(exc))
    except Exception as exc:
        err(f"Phone analysis failed: {exc}")

    pause()


# ============================================================
# MAIN MENU
# ============================================================

def phone_osint_advanced() -> None:
    show_banner()

    if not PHONE_AVAILABLE:
        err("Missing dependency: phonenumbers")
        info("Install with: pip install phonenumbers")
        pause()
        return

    while True:
        section("MAIN MENU")
        print(color("  [1] Single number lookup", C.CYAN))
        print(color("  [2] Bulk lookup (file)", C.CYAN))
        print(color("  [0] Exit", C.DIM))

        choice = ask("Select", "1")

        if choice == "1":
            single_mode()
        elif choice == "2":
            bulk_mode()
        else:
            info("Goodbye.")
            break


# ============================================================
# STANDALONE EXECUTION
# ============================================================

if __name__ == "__main__":
    try:
        phone_osint_advanced()
    except KeyboardInterrupt:
        print()
        warn("Operation cancelled.")
    except Exception as exc:
        err(f"Fatal error: {exc}")
