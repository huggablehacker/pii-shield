#!/usr/bin/env python3
"""
PII Shield - Local PII/PHI Anonymizer for Safe LLM Processing
============================================================
Strips sensitive info from documents before sending to Claude.
Stores a local mapping so you can restore originals later.

Usage:
  python pii_shield.py anonymize report.pdf
  python pii_shield.py anonymize spreadsheet.xlsx --output clean.txt
  python pii_shield.py restore clean.txt --session abc123
  python pii_shield.py sessions
"""

import sys
import os
import json
import re
import hashlib
import uuid
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─── Lazy imports (checked at runtime with helpful errors) ───────────────────

def require(pkg, install_name=None):
    """Import a package with a friendly error if missing."""
    import importlib
    try:
        return importlib.import_module(pkg)
    except ImportError:
        name = install_name or pkg
        print(f"\n❌  Missing package: {pkg}")
        print(f"    Run:  pip install {name}")
        sys.exit(1)


# ─── Constants ───────────────────────────────────────────────────────────────

MAPPINGS_DIR = Path.home() / ".pii_shield" / "sessions"
MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)

# Entity types to detect (Presidio built-ins + custom PHI)
DEFAULT_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "URL",
    "US_BANK_NUMBER",
    "MEDICAL_LICENSE",
    "DATE_TIME",
    "LOCATION",
    "NRP",               # Nationality, Religion, Political group
    "ORGANIZATION",
    "US_ITIN",
]

# Labels shown in the anonymized output
ENTITY_LABELS = {
    "PERSON": "PERSON",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "US_SSN": "SSN",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVER_LICENSE": "DL",
    "CREDIT_CARD": "CC",
    "IBAN_CODE": "IBAN",
    "IP_ADDRESS": "IP",
    "URL": "URL",
    "US_BANK_NUMBER": "BANK_ACCT",
    "MEDICAL_LICENSE": "MED_LIC",
    "DATE_TIME": "DATE",
    "LOCATION": "LOCATION",
    "NRP": "NRP",
    "ORGANIZATION": "ORG",
    "US_ITIN": "ITIN",
}


# ─── Document Parsers ─────────────────────────────────────────────────────────

def parse_txt(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse_pdf(path: Path) -> str:
    pdfplumber = require("pdfplumber")
    pages = []
    with pdfplumber.open(path) as pdf:
        for i, page in enumerate(pdf.pages, 1):
            text = page.extract_text() or ""
            if text.strip():
                pages.append(f"[Page {i}]\n{text}")
    return "\n\n".join(pages)


def parse_docx(path: Path) -> str:
    docx = require("docx", "python-docx")
    doc = docx.Document(str(path))
    parts = []
    for para in doc.paragraphs:
        if para.text.strip():
            parts.append(para.text)
    # Also grab tables
    for table in doc.tables:
        for row in table.rows:
            row_text = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
            if row_text:
                parts.append(row_text)
    return "\n".join(parts)


def parse_excel(path: Path) -> str:
    pd = require("pandas")
    require("openpyxl")
    xl = pd.ExcelFile(str(path))
    parts = []
    for sheet in xl.sheet_names:
        df = xl.parse(sheet)
        parts.append(f"[Sheet: {sheet}]")
        parts.append(df.to_string(index=False))
    return "\n\n".join(parts)


def parse_csv(path: Path) -> str:
    pd = require("pandas")
    df = pd.read_csv(str(path))
    return df.to_string(index=False)


def parse_document(path: Path) -> str:
    """Dispatch to the right parser based on file extension."""
    ext = path.suffix.lower()
    parsers = {
        ".txt":  parse_txt,
        ".md":   parse_txt,
        ".pdf":  parse_pdf,
        ".docx": parse_docx,
        ".doc":  parse_docx,
        ".xlsx": parse_excel,
        ".xls":  parse_excel,
        ".xlsm": parse_excel,
        ".csv":  parse_csv,
    }
    if ext not in parsers:
        print(f"⚠️  Unsupported file type: {ext}")
        print(f"   Supported: {', '.join(parsers)}")
        sys.exit(1)
    print(f"📄  Parsing {path.name} …")
    return parsers[ext](path)


# ─── PII Engine ───────────────────────────────────────────────────────────────

def build_analyzer(entities=None):
    """Build a Presidio AnalyzerEngine with spaCy NLP backend."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    # Try large model first, fall back to small
    for model in ("en_core_web_lg", "en_core_web_sm", "en_core_web_md"):
        try:
            import spacy
            spacy.load(model)
            nlp_config = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model}]}
            print(f"🧠  Using spaCy model: {model}")
            break
        except OSError:
            continue
    else:
        print("❌  No spaCy model found. Run one of:")
        print("    python -m spacy download en_core_web_lg")
        print("    python -m spacy download en_core_web_sm")
        sys.exit(1)

    provider = NlpEngineProvider(nlp_configuration=nlp_config)
    nlp_engine = provider.create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])


def anonymize_text(text: str, entities=None, score_threshold=0.4) -> tuple[str, dict]:
    """
    Detect and replace PII/PHI in text.
    Returns (anonymized_text, mapping_dict).
    """
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig

    target_entities = entities or DEFAULT_ENTITIES

    print("🔍  Analyzing for PII/PHI …")
    analyzer = build_analyzer()
    anonymizer = AnonymizerEngine()

    results = analyzer.analyze(
        text=text,
        entities=target_entities,
        language="en",
        score_threshold=score_threshold,
    )

    if not results:
        print("✅  No PII/PHI detected.")
        return text, {}

    # Sort by position (reverse) so we can replace without offset issues
    results = sorted(results, key=lambda r: r.start, reverse=True)

    # Build mapping: original_value → placeholder
    mapping = {}          # placeholder → original
    counters = {}         # entity_type → count
    anonymized = text

    for result in results:
        original = text[result.start:result.end]

        # Deduplicate: same value → same placeholder
        key = (result.entity_type, original.strip().lower())
        if key not in counters:
            label = ENTITY_LABELS.get(result.entity_type, result.entity_type)
            idx = len([v for v in mapping.values() if v["entity_type"] == result.entity_type]) + 1
            placeholder = f"[{label}_{idx}]"
            counters[key] = placeholder
            mapping[placeholder] = {
                "original": original,
                "entity_type": result.entity_type,
                "score": round(result.score, 3),
            }
        else:
            placeholder = counters[key]

        anonymized = anonymized[:result.start] + placeholder + anonymized[result.end:]

    return anonymized, mapping


# ─── Session Storage ──────────────────────────────────────────────────────────

def save_session(mapping: dict, source_file: str, session_id: str = None) -> str:
    """Persist a mapping to disk under a session ID."""
    sid = session_id or str(uuid.uuid4())[:8]
    session = {
        "session_id": sid,
        "created": datetime.now().isoformat(),
        "source_file": source_file,
        "entity_count": len(mapping),
        "mapping": mapping,
    }
    out = MAPPINGS_DIR / f"{sid}.json"
    out.write_text(json.dumps(session, indent=2))
    return sid, out


def load_session(session_id: str) -> dict:
    """Load a session from disk."""
    path = MAPPINGS_DIR / f"{session_id}.json"
    if not path.exists():
        print(f"❌  Session not found: {session_id}")
        print(f"   Sessions are stored in: {MAPPINGS_DIR}")
        sys.exit(1)
    return json.loads(path.read_text())


def list_sessions():
    """Print all stored sessions."""
    files = sorted(MAPPINGS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("No sessions stored yet.")
        return
    print(f"\n{'SESSION ID':<12} {'CREATED':<22} {'ENTITIES':<10} SOURCE FILE")
    print("─" * 70)
    for f in files:
        try:
            s = json.loads(f.read_text())
            created = s.get("created", "")[:19].replace("T", " ")
            print(f"{s['session_id']:<12} {created:<22} {s['entity_count']:<10} {s.get('source_file','?')}")
        except Exception:
            pass


# ─── Restore ─────────────────────────────────────────────────────────────────

def restore_text(anonymized: str, mapping: dict) -> str:
    """Replace placeholders back with original values."""
    result = anonymized
    for placeholder, info in mapping.items():
        result = result.replace(placeholder, info["original"])
    return result


# ─── CLI Commands ─────────────────────────────────────────────────────────────

def cmd_anonymize(args):
    path = Path(args.file)
    if not path.exists():
        print(f"❌  File not found: {path}")
        sys.exit(1)

    # Parse document
    text = parse_document(path)
    print(f"📝  Extracted {len(text):,} characters")

    # Anonymize
    anonymized, mapping = anonymize_text(
        text,
        score_threshold=args.threshold,
    )

    # Save session
    sid, session_path = save_session(mapping, str(path))

    # Determine output path
    if args.output:
        out_path = Path(args.output)
    else:
        out_path = path.parent / f"{path.stem}_anonymized.txt"

    out_path.write_text(anonymized, encoding="utf-8")

    # Summary
    print(f"\n{'─'*55}")
    print(f"✅  Anonymization complete!")
    print(f"{'─'*55}")
    print(f"  Session ID  : {sid}  (save this to restore later)")
    print(f"  Output file : {out_path}")
    print(f"  Mapping file: {session_path}")
    print(f"  Entities found: {len(mapping)}")
    if mapping:
        print(f"\n  Replacements made:")
        for ph, info in sorted(mapping.items()):
            orig = info['original']
            if len(orig) > 40:
                orig = orig[:37] + "…"
            print(f"    {ph:<20} ← \"{orig}\"  (conf: {info['score']})")
    print(f"\n  📋 The anonymized file is ready to paste into Claude.")
    print(f"  🔑 Keep your session ID to restore: {sid}")
    print()


def cmd_restore(args):
    # Load session
    session = load_session(args.session)
    mapping = session["mapping"]

    # Get anonymized text
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"❌  File not found: {path}")
            sys.exit(1)
        anonymized = path.read_text(encoding="utf-8")
    else:
        print("Paste the anonymized text below. Press Ctrl+D (or Ctrl+Z on Windows) when done:\n")
        anonymized = sys.stdin.read()

    restored = restore_text(anonymized, mapping)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(restored, encoding="utf-8")
        print(f"✅  Restored text written to: {out_path}")
    else:
        print("\n" + "─"*55)
        print("RESTORED TEXT:")
        print("─"*55)
        print(restored)


def cmd_sessions(args):
    print(f"📁 Sessions stored in: {MAPPINGS_DIR}")
    list_sessions()


def cmd_inspect(args):
    """Show what's in a session mapping."""
    session = load_session(args.session)
    print(f"\nSession: {session['session_id']}")
    print(f"Created: {session['created']}")
    print(f"Source:  {session['source_file']}")
    print(f"\n{'PLACEHOLDER':<22} {'TYPE':<22} {'CONF':<6} ORIGINAL VALUE")
    print("─" * 80)
    for ph, info in sorted(session["mapping"].items()):
        orig = info['original'].replace('\n', ' ')
        if len(orig) > 35:
            orig = orig[:32] + "…"
        print(f"{ph:<22} {info['entity_type']:<22} {info['score']:<6} {orig}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="pii_shield",
        description="🛡️  PII Shield – Anonymize documents before sending to Claude",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pii_shield.py anonymize patient_report.pdf
  python pii_shield.py anonymize data.xlsx --output clean.txt --threshold 0.5
  python pii_shield.py restore clean.txt --session abc12345
  python pii_shield.py sessions
  python pii_shield.py inspect --session abc12345
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # anonymize
    p_anon = sub.add_parser("anonymize", help="Strip PII/PHI from a document")
    p_anon.add_argument("file", help="Path to document (pdf, docx, xlsx, csv, txt)")
    p_anon.add_argument("-o", "--output", help="Output file path (default: <name>_anonymized.txt)")
    p_anon.add_argument("--threshold", type=float, default=0.4,
                        help="Confidence threshold 0-1 (default: 0.4, lower = more aggressive)")
    p_anon.set_defaults(func=cmd_anonymize)

    # restore
    p_rest = sub.add_parser("restore", help="Restore original values from a session")
    p_rest.add_argument("file", nargs="?", help="Anonymized file (omit to paste from stdin)")
    p_rest.add_argument("-s", "--session", required=True, help="Session ID from anonymization")
    p_rest.add_argument("-o", "--output", help="Output file (default: print to terminal)")
    p_rest.set_defaults(func=cmd_restore)

    # sessions
    p_sess = sub.add_parser("sessions", help="List all stored anonymization sessions")
    p_sess.set_defaults(func=cmd_sessions)

    # inspect
    p_insp = sub.add_parser("inspect", help="Show the mapping table for a session")
    p_insp.add_argument("-s", "--session", required=True, help="Session ID to inspect")
    p_insp.set_defaults(func=cmd_inspect)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
