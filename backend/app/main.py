import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import uuid
import ipaddress
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import CORS_ORIGINS, CLAMD_HOST, CLAMD_PORT, MAX_UPLOAD_BYTES, QUARANTINE_DIR, REDIS_URL
from app.database import Base, SessionLocal, engine
from app.models import VirusScan
from app.worker.celery_app import celery_app
from app.worker.tasks import scan_virus_file


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
STATIC_INDEX = Path(__file__).resolve().parents[2] / "index.html"
WIFI_HELPER = Path(__file__).resolve().parents[2] / "wifi-scan.ps1"
VIRUS_HELPER = Path(__file__).resolve().parents[2] / "virus-scan.ps1"
if not STATIC_INDEX.is_file():
    STATIC_INDEX = Path(__file__).resolve().parents[1] / "static" / "index.html"
if not WIFI_HELPER.is_file():
    WIFI_HELPER = Path(__file__).resolve().parents[1] / "wifi-scan.ps1"
if not VIRUS_HELPER.is_file():
    VIRUS_HELPER = Path(__file__).resolve().parents[1] / "virus-scan.ps1"

app = FastAPI(
    title="วิถีป้องกันรอบด้าน - File Scanner",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)


class UploadRequestLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        is_upload = (
            scope["type"] == "http"
            and scope["method"] == "POST"
            and scope["path"] == "/api/v1/virus-scans"
        )
        if is_upload:
            raw_length = next(
                (value for key, value in scope.get("headers", []) if key.lower() == b"content-length"),
                None,
            )
            if raw_length is None:
                status, message = 411, "Content-Length is required for file uploads"
            else:
                try:
                    request_length = int(raw_length)
                except ValueError:
                    status, message = 400, "Invalid Content-Length"
                else:
                    if request_length < 0:
                        status, message = 400, "Invalid Content-Length"
                    elif request_length > MAX_UPLOAD_BYTES + 1024 * 1024:
                        status, message = 413, "Request exceeds the upload limit"
                    else:
                        status = 0
                        message = ""
            if status:
                body = json.dumps({"detail": message}).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": status,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


app.add_middleware(UploadRequestLimitMiddleware)


def get_db():
    with SessionLocal() as db:
        yield db


def safe_filename(filename: str | None) -> str:
    candidate = (filename or "uploaded-file").replace("\\", "/").split("/")[-1]
    cleaned = "".join(char for char in candidate if char.isprintable() and char not in "\r\n")
    return (cleaned[:255] or "uploaded-file")


def scan_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_scan_token(
    scan_id: str,
    token: Annotated[str | None, Header(alias="X-Scan-Token")] = None,
    db: Session = Depends(get_db),
) -> VirusScan:
    scan = db.get(VirusScan, scan_id)
    if scan is None or token is None or not hmac.compare_digest(
        scan.token_hash, scan_token_hash(token)
    ):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def public_scan(scan: VirusScan) -> dict:
    return {
        "id": scan.id,
        "filename": scan.filename,
        "size_bytes": scan.size_bytes,
        "sha256": scan.sha256,
        "mode": scan.mode,
        "status": scan.status,
        "result": scan.result,
        "error_code": scan.error_code,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


@app.on_event("startup")
def initialize_database() -> None:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(QUARANTINE_DIR, 0o700)
    Base.metadata.create_all(bind=engine)
    cutoff = datetime.now(timezone.utc).timestamp() - 24 * 60 * 60
    for path in QUARANTINE_DIR.iterdir():
        if path.is_file() and path.stat().st_mtime < cutoff:
            try:
                path.unlink()
                logger.warning("Removed stale quarantine file %s", path.name)
            except OSError:
                logger.exception("Could not remove stale quarantine file %s", path.name)


@app.get("/", include_in_schema=False)
def index():
    if not STATIC_INDEX.is_file():
        raise HTTPException(status_code=404, detail="Frontend is not installed")
    return FileResponse(STATIC_INDEX)


@app.get("/wifi-scan.ps1", include_in_schema=False)
def download_wifi_helper():
    if not WIFI_HELPER.is_file():
        raise HTTPException(status_code=404, detail="Wi-Fi helper is not installed")
    return FileResponse(
        WIFI_HELPER,
        media_type="application/octet-stream",
        filename="wifi-scan.ps1",
    )


@app.get("/virus-scan.ps1", include_in_schema=False)
def download_virus_helper():
    if not VIRUS_HELPER.is_file():
        raise HTTPException(status_code=404, detail="Virus scan helper is not installed")
    return FileResponse(
        VIRUS_HELPER,
        media_type="application/octet-stream",
        filename="virus-scan.ps1",
    )


@app.post("/api/v1/website-headers")
def website_headers(payload: dict) -> dict:
    raw_url = payload.get("url") if isinstance(payload, dict) else None
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise HTTPException(status_code=422, detail="A valid website URL is required")
    target = urlparse(raw_url.strip())
    if target.scheme not in {"http", "https"} or target.username or target.password or not target.hostname:
        raise HTTPException(status_code=422, detail="Only http/https URLs without credentials are allowed")
    if target.port not in {None, 80, 443}:
        raise HTTPException(status_code=422, detail="Only standard HTTP/HTTPS ports are allowed")
    host = target.hostname.rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host.lower() in {"localhost", "localhost.localdomain"}:
            raise HTTPException(status_code=422, detail="Private or local targets are not allowed")
    else:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
            raise HTTPException(status_code=422, detail="Private or local targets are not allowed")
    request = urllib.request.Request(target.geturl(), method="HEAD", headers={"User-Agent": "SecurityScanner/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            required = {
                "content-security-policy": "Add Content-Security-Policy to reduce XSS risk",
                "strict-transport-security": "Add HSTS when all HTTPS subdomains are supported",
                "x-content-type-options": "Add X-Content-Type-Options: nosniff",
                "referrer-policy": "Define a suitable Referrer-Policy",
                "permissions-policy": "Define Permissions-Policy to limit browser features",
            }
            findings = [{"level": "medium", "title": "Missing " + header, "detail": advice} for header, advice in required.items() if header not in headers]
            if "server" in headers:
                findings.append({"level": "low", "title": "Server header exposed", "detail": "Consider reducing exposed version details"})
            if not findings:
                findings.append({"level": "info", "title": "No missing checked headers", "detail": "Checked with a backend HEAD request"})
            return {"url": target.geturl(), "status": response.status, "headers": headers, "findings": findings}
    except (urllib.error.URLError, TimeoutError) as error:
        raise HTTPException(status_code=502, detail="Website check failed: target did not respond or rejected HEAD") from error


@app.get("/api/v1/health")
def health(db: Session = Depends(get_db)) -> dict:
    services = {"database": False, "redis": False, "worker": False, "clamav": False}
    try:
        db.execute(text("SELECT 1"))
        services["database"] = True
    except Exception:
        logger.exception("Health check: database unavailable")

    try:
        from redis import Redis

        redis_client = Redis.from_url(REDIS_URL, socket_connect_timeout=1)
        try:
            services["redis"] = bool(redis_client.ping())
        finally:
            redis_client.close()
    except Exception:
        logger.exception("Health check: Redis unavailable")

    try:
        services["worker"] = bool(celery_app.control.ping(timeout=0.5))
    except Exception:
        logger.exception("Health check: Celery worker unavailable")

    try:
        with socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=1) as connection:
            connection.sendall(b"zPING\0")
            services["clamav"] = connection.recv(64).strip(b"\0").endswith(b"PONG")
    except OSError:
        logger.warning("Health check: ClamAV unavailable")

    return {
        "status": "ready" if all(services.values()) else "degraded",
        "services": services,
        "virus_scan_ready": all(services.values()),
    }


@app.post("/api/v1/virus-scans", status_code=202)
async def create_virus_scan(
    file: Annotated[UploadFile, File()],
    mode: Annotated[str, Form()],
    consent: Annotated[bool, Form()],
    db: Session = Depends(get_db),
) -> dict:
    if mode not in {"standard", "deep"}:
        raise HTTPException(status_code=422, detail="Mode must be standard or deep")
    if not consent:
        raise HTTPException(status_code=400, detail="Consent is required")

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    scan_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    file_path = QUARANTINE_DIR / scan_id
    digest = hashlib.sha256()
    size = 0
    try:
        with file_path.open("xb") as destination:
            os.chmod(file_path, 0o600)
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="File exceeds the 20 MiB upload limit")
                digest.update(chunk)
                destination.write(chunk)
    except HTTPException:
        file_path.unlink(missing_ok=True)
        raise
    except OSError as error:
        file_path.unlink(missing_ok=True)
        logger.exception("Could not write uploaded file into quarantine")
        raise HTTPException(status_code=500, detail="Could not store uploaded file safely") from error
    finally:
        await file.close()

    if size == 0:
        file_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Empty files cannot be scanned")

    scan = VirusScan(
        id=scan_id,
        token_hash=scan_token_hash(token),
        filename=safe_filename(file.filename),
        file_path=str(file_path),
        sha256=digest.hexdigest(),
        size_bytes=size,
        mode=mode,
        status="queued",
    )
    db.add(scan)
    try:
        db.commit()
        scan_virus_file.delay(scan_id)
    except Exception as error:
        db.rollback()
        stored_scan = db.get(VirusScan, scan_id)
        if stored_scan is not None:
            db.delete(stored_scan)
            db.commit()
        file_path.unlink(missing_ok=True)
        logger.exception("Could not enqueue virus scan")
        raise HTTPException(status_code=503, detail="The scan queue is unavailable") from error

    return {"scan": public_scan(scan), "access_token": token}


@app.get("/api/v1/virus-scans/{scan_id}")
def get_virus_scan(scan: VirusScan = Depends(require_scan_token)) -> dict:
    return public_scan(scan)
