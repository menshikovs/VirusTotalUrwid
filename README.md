# VirusTotal TUI Scanner

A small terminal application for checking SHA-256 file hashes and URLs with the VirusTotal API v3. The interface is built with Urwid; API requests use Requests.

## Features

- Look up an existing file report by SHA-256.
- Submit a URL for analysis and wait for the result.
- Display malicious, suspicious, harmless, and undetected counts.
- Show clear status messages for missing reports, invalid input, network errors, API-key errors, and rate limits.
- Paste from the clipboard with `Ctrl+V` or `Shift+Insert`.
- Keep using the interface while a scan runs.

## Requirements

- Python 3.9 or newer
- A VirusTotal API key

## Installation

Create and activate a virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your VirusTotal API key:

```env
VT_API_KEY=your_virustotal_api_key_here
```

Start the application:

```powershell
python main.py
```

On Linux or macOS, activate the virtual environment with `source .venv/bin/activate`, then run `python main.py`.

## Usage

1. Choose **SHA-256** or **URL**.
2. Enter or paste the hash or URL into the target field.
3. Select **Scan** and wait for the report.

For URL scans, the app submits the URL and waits up to 60 seconds for the analysis. If it is still running, try the scan again later.

Use `Tab` to move between controls, `Enter` to activate the focused control, and `Ctrl+C` or `Q` to quit.

## Project files

- `main.py` — Urwid interface and input handling.
- `virustotal.py` — VirusTotal API client and response parsing.
- `requirements.txt` — Python dependencies.
- `.env.example` — API-key configuration template.
