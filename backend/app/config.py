import os
from pathlib import Path


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://scanner:local-development-only@localhost:5432/scanner",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CLAMD_HOST = os.getenv("CLAMD_HOST", "localhost")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))
QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "./data/quarantine")).resolve()
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
YARA_RULES_PATH = Path(
    os.getenv("YARA_RULES_PATH", "./backend/rules/basic_indicators.yar")
).resolve()

CORS_ORIGINS = [origin.strip() for origin in os.getenv('CORS_ORIGINS', 'https://funnythirat.github.io').split(',') if origin.strip()]
