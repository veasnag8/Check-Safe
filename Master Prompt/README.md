# Telegram Security Scanner

Defensive Telegram bot, CLI, and FastAPI service for URL and file security analysis.

## Features

- Telegram bot with `/start`, `/help`, `/check`, `/history`, and `/status`
- URL scanning with phishing heuristics
- File scanning with static analysis and hashes
- Optional VirusTotal and Google Safe Browsing integration
- SQLite by default with PostgreSQL-compatible SQLAlchemy design
- FastAPI health/status endpoints
- CLI entry point via `run.py`

## Installation

```bash
git clone <repository>
cd telegram-security-scanner

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

Set:

```env
TELEGRAM_BOT_TOKEN=YOUR_TOKEN
```

## Run

```bash
python run.py
```

CLI examples:

```bash
python run.py --url https://example.com
python run.py --file suspicious.pdf
```

## Tests

```bash
pytest
```

## Docker

```bash
docker compose up --build
```

## Security notes

- Uploaded files are never executed
- External file upload is disabled by default
- API keys are loaded from environment variables only
