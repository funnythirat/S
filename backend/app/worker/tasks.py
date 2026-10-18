import logging
from datetime import datetime, timezone
from pathlib import Path

from app.config import QUARANTINE_DIR
from app.database import SessionLocal
from app.models import VirusScan
from app.scanner import scan_file
from app.worker.celery_app import celery_app


logger = logging.getLogger(__name__)


@celery_app.task(name="virus_scanner.scan_file", bind=True, max_retries=1)
def scan_virus_file(self, scan_id: str) -> None:
    redelivered = bool((self.request.delivery_info or {}).get("redelivered"))
    with SessionLocal() as db:
        scan = (
            db.query(VirusScan)
            .filter(VirusScan.id == scan_id)
            .with_for_update()
            .one_or_none()
        )
        if scan is None:
            logger.error("Scan record %s is missing", scan_id)
            return
        if scan.status in {"completed", "failed"} or (
            scan.status == "running" and not redelivered
        ):
            logger.info("Ignoring duplicate scan task %s with status %s", scan_id, scan.status)
            return
        scan.status = "running"
        db.commit()
        path = Path(scan.file_path)
        mode = scan.mode

    try:
        result = scan_file(path, mode)
        with SessionLocal() as db:
            scan = db.get(VirusScan, scan_id)
            if scan is None:
                logger.error("Scan record %s disappeared before result save", scan_id)
                return
            scan.result = result
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        logger.exception("Virus scan task failed for %s", scan_id)
        with SessionLocal() as db:
            scan = db.get(VirusScan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.error_code = "scanner_failed"
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.exception("Could not remove quarantined upload for scan %s", scan_id)
