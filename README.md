# 🛡️ PII Shield

> **Anonymize sensitive documents locally before sending to Claude or any LLM — then restore originals on demand.**

PII Shield runs entirely on your machine. It detects and replaces Personally Identifiable Information (PII) and Protected Health Information (PHI) in PDFs, Word docs, Excel spreadsheets, and plain text files — giving you a clean version safe to paste into any AI assistant, with a local session file to reverse the process later.

---

## ✨ Features

- 🔒 **100% local** — no data ever leaves your machine
- 📄 **Multi-format** — PDF, DOCX, XLSX, XLS, CSV, TXT, Markdown
- 🧠 **NLP-powered** — Microsoft Presidio + spaCy named entity recognition
- 🔁 **Reversible** — every session is saved; restore originals anytime
- 🎯 **Tunable** — adjust detection confidence threshold per run
- 🏥 **PHI-aware** — medical license numbers, NPI, insurance IDs, and more

---

## 📋 What It Detects

| Category | Entity Types |
|---|---|
| **Identity** | Names, SSN, ITIN, Passports, Driver's Licenses |
| **Contact** | Email, Phone, Physical Address |
| **Financial** | Credit Cards, Bank Accounts, IBAN |
| **Medical** | Medical License Numbers |
| **Network** | IP Addresses, URLs |
| **Org / Geo** | Organizations, Locations, Dates |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- pip

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/pii-shield.git
cd pii-shield
```

### 2. Run setup

**Mac / Linux:**
```bash
chmod +x setup.sh
./setup.sh
source .venv/bin/activate
```

**Windows:**
```bat
setup.bat
.venv\Scripts\activate.bat
```

The setup script will:
- Create a Python virtual environment
- Install all dependencies
- Download the spaCy NLP language model

### 3. Anonymize a document

```bash
python pii_shield.py anonymize my_report.pdf
```

Output:
```
📄  Parsing my_report.pdf …
🧠  Using spaCy model: en_core_web_lg
🔍  Analyzing for PII/PHI …

───────────────────────────────────────────────
✅  Anonymization complete!
───────────────────────────────────────────────
  Session ID  : a3f8b21c   ← save this!
  Output file : my_report_anonymized.txt
  Entities found: 14

  Replacements made:
    [PERSON_1]           ← "Sarah Johnson"     (conf: 0.85)
    [EMAIL_1]            ← "sarah@gmail.com"   (conf: 0.99)
    [SSN_1]              ← "523-41-8897"       (conf: 0.85)
    [PHONE_1]            ← "(704) 555-0193"    (conf: 0.75)
    ...
```

### 4. Paste into Claude (or any LLM)

Open `my_report_anonymized.txt` and paste the contents into Claude for analysis. All sensitive values are replaced with readable placeholders like `[PERSON_1]` and `[EMAIL_2]`.

### 5. Restore originals

```bash
python pii_shield.py restore my_report_anonymized.txt --session a3f8b21c
```

---

## 📖 Full Command Reference

### `anonymize` — Strip PII from a document

```bash
python pii_shield.py anonymize <file> [options]
```

| Option | Description | Default |
|---|---|---|
| `-o`, `--output` | Output file path | `<filename>_anonymized.txt` |
| `--threshold` | Detection confidence (0.0–1.0) | `0.4` |

```bash
# Basic usage
python pii_shield.py anonymize report.pdf

# Custom output path
python pii_shield.py anonymize report.pdf --output clean.txt

# More aggressive detection (catches borderline cases)
python pii_shield.py anonymize report.pdf --threshold 0.2

# Conservative — high confidence only
python pii_shield.py anonymize report.pdf --threshold 0.7
```

---

### `restore` — Put original values back

```bash
python pii_shield.py restore [file] --session <SESSION_ID> [options]
```

```bash
# Restore from file, print to terminal
python pii_shield.py restore clean.txt --session a3f8b21c

# Restore and write to a new file
python pii_shield.py restore clean.txt --session a3f8b21c --output restored.txt

# Paste anonymized text interactively (no file)
python pii_shield.py restore --session a3f8b21c
```

---

### `sessions` — List stored sessions

```bash
python pii_shield.py sessions
```

```
📁 Sessions stored in: ~/.pii_shield/sessions/

SESSION ID   CREATED                ENTITIES   SOURCE FILE
──────────────────────────────────────────────────────────────────────
a3f8b21c     2025-04-01 09:14:32    14         patient_report.pdf
c7d42f19     2025-03-28 15:03:01    9          staff_list.xlsx
```

---

### `inspect` — View a session's full mapping

```bash
python pii_shield.py inspect --session a3f8b21c
```

```
PLACEHOLDER            TYPE                   CONF   ORIGINAL VALUE
────────────────────────────────────────────────────────────────────────────────
[DATE_1]               DATE_TIME              0.85   March 15, 1982
[EMAIL_1]              EMAIL_ADDRESS          0.99   sarah.johnson@gmail.com
[LOCATION_1]           LOCATION               0.72   Mooresville, NC 28117
[PERSON_1]             PERSON                 0.85   Sarah Elizabeth Johnson
[PHONE_1]              PHONE_NUMBER           0.75   (704) 555-0193
[SSN_1]                US_SSN                 0.85   523-41-8897
```

---

## 🔧 Supported File Types

| Format | Extensions |
|---|---|
| PDF | `.pdf` |
| Word | `.docx`, `.doc` |
| Excel | `.xlsx`, `.xls`, `.xlsm` |
| Spreadsheet | `.csv` |
| Text | `.txt`, `.md` |

---

## ⚙️ How It Works

```
Document
   │
   ▼
┌─────────────┐     ┌────────────────────────┐
│   Parser    │────▶│  Raw Text Extraction   │
│ (per format)│     └──────────┬─────────────┘
└─────────────┘                │
                               ▼
                  ┌────────────────────────────┐
                  │  Presidio Analyzer Engine  │
                  │  + spaCy NLP model         │
                  │  → Detects PII/PHI spans   │
                  └──────────┬─────────────────┘
                             │
                             ▼
                  ┌────────────────────────────┐
                  │  Replacement Engine        │
                  │  → [PERSON_1], [EMAIL_2]…  │
                  │  → Deduplicates per value  │
                  └──────────┬─────────────────┘
                             │
               ┌─────────────┴──────────────┐
               │                            │
               ▼                            ▼
  ┌─────────────────────┐     ┌──────────────────────────┐
  │  Anonymized .txt    │     │  Session JSON            │
  │  (safe for LLMs)    │     │  ~/.pii_shield/sessions/ │
  └─────────────────────┘     └──────────────────────────┘
```

1. **Parse** — Extracts raw text from your document using format-specific libraries
2. **Analyze** — Presidio + spaCy scan every sentence for PII/PHI patterns (regex + ML)
3. **Replace** — Unique values get stable placeholders; duplicate occurrences reuse the same token
4. **Store** — The placeholder↔original mapping is saved locally as a JSON session file
5. **Output** — A clean text file with all sensitive data replaced, ready for Claude

---

## 🔒 Privacy & Security

| Property | Detail |
|---|---|
| **Local only** | No API calls, no telemetry, no cloud |
| **Session storage** | `~/.pii_shield/sessions/<id>.json` |
| **No model training** | Your data is never used to train anything |
| **Reversible** | Session files contain original values — keep them safe |

> ⚠️ **Note:** Session files contain the original sensitive values in plain JSON. Protect the `~/.pii_shield/` directory accordingly (e.g., FileVault / BitLocker full-disk encryption).

---

## 🧪 Try the Sample Document

A sample PHI-heavy patient intake form is included:

```bash
python pii_shield.py anonymize sample_patient.txt
```

Inspect the output and the session mapping to see the tool in action before using it on real documents.

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| [presidio-analyzer](https://microsoft.github.io/presidio/) | PII/PHI detection engine |
| [presidio-anonymizer](https://microsoft.github.io/presidio/) | Text replacement engine |
| [spaCy](https://spacy.io/) | NLP backbone (NER) |
| [pdfplumber](https://github.com/jsvine/pdfplumber) | PDF text extraction |
| [python-docx](https://python-docx.readthedocs.io/) | Word document parsing |
| [pandas](https://pandas.pydata.org/) | Excel / CSV parsing |
| [openpyxl](https://openpyxl.readthedocs.io/) | Excel file engine |

---

## 🗺️ Roadmap

- [ ] GUI wrapper (Tkinter or web UI via Gradio)
- [ ] Custom entity patterns (e.g., internal employee IDs, account codes)
- [ ] Encrypted session storage
- [ ] Batch processing of entire folders
- [ ] HIPAA entity preset vs. GDPR entity preset
- [ ] Output as redacted PDF (preserving layout)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

Built on top of [Microsoft Presidio](https://microsoft.github.io/presidio/), an open-source PII detection framework, and [spaCy](https://spacy.io/), a leading NLP library.

---

<p align="center">
  Made to keep sensitive data out of AI training pipelines.
</p>
