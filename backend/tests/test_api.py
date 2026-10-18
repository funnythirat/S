import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.database import Base
from app.models import VirusScan


class VirusScanApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=cls.db_engine)
        cls.TestSession = sessionmaker(
            bind=cls.db_engine, autoflush=False, expire_on_commit=False
        )

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.db_engine)
        cls.db_engine.dispose()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.quarantine = Path(self.tempdir.name)
        self.client = TestClient(main.app)

        def override_db():
            with self.TestSession() as db:
                yield db

        main.app.dependency_overrides[main.get_db] = override_db
        self.quarantine_patch = patch.object(main, "QUARANTINE_DIR", self.quarantine)
        self.enqueue_patch = patch.object(main.scan_virus_file, "delay")
        self.quarantine_patch.start()
        self.enqueue_patch.start()

    def tearDown(self):
        main.app.dependency_overrides.clear()
        self.enqueue_patch.stop()
        self.quarantine_patch.stop()
        self.tempdir.cleanup()

    def test_upload_returns_capability_token_and_status_requires_it(self):
        response = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("..\\private.txt", b"safe test content", "text/plain")},
        )

        self.assertEqual(response.status_code, 202)
        payload = response.json()
        self.assertEqual(payload["scan"]["filename"], "private.txt")
        self.assertEqual(payload["scan"]["status"], "queued")
        self.assertNotIn("file_path", payload["scan"])
        self.assertTrue(payload["access_token"])

        scan_id = payload["scan"]["id"]
        unauthorized = self.client.get(f"/api/v1/virus-scans/{scan_id}")
        self.assertEqual(unauthorized.status_code, 404)
        authorized = self.client.get(
            f"/api/v1/virus-scans/{scan_id}",
            headers={"X-Scan-Token": payload["access_token"]},
        )
        self.assertEqual(authorized.status_code, 200)
        self.assertEqual(authorized.json()["sha256"], payload["scan"]["sha256"])
        self.assertEqual(len(list(self.quarantine.iterdir())), 1)

    def test_upload_requires_consent_and_valid_scan_mode(self):
        no_consent = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "false"},
            files={"file": ("sample.txt", b"sample", "text/plain")},
        )
        self.assertEqual(no_consent.status_code, 400)

        invalid_mode = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "aggressive", "consent": "true"},
            files={"file": ("sample.txt", b"sample", "text/plain")},
        )
        self.assertEqual(invalid_mode.status_code, 422)
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_upload_rejects_empty_and_oversized_files(self):
        empty = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("empty.txt", b"", "text/plain")},
        )
        self.assertEqual(empty.status_code, 400)

        with patch.object(main, "MAX_UPLOAD_BYTES", 4):
            oversized = self.client.post(
                "/api/v1/virus-scans",
                data={"mode": "standard", "consent": "true"},
                files={"file": ("large.txt", b"12345", "text/plain")},
            )
        self.assertEqual(oversized.status_code, 413)
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_queue_failure_returns_error_and_removes_upload_and_record(self):
        with self.TestSession() as db:
            initial_count = db.query(VirusScan).count()
        self.enqueue_patch.stop()
        self.enqueue_patch = patch.object(
            main.scan_virus_file, "delay", side_effect=RuntimeError("redis down")
        )
        self.enqueue_patch.start()
        response = self.client.post(
            "/api/v1/virus-scans",
            data={"mode": "standard", "consent": "true"},
            files={"file": ("sample.txt", b"sample", "text/plain")},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(list(self.quarantine.iterdir()), [])
        with self.TestSession() as db:
            self.assertEqual(db.query(VirusScan).count(), initial_count)

    def test_website_headers_rejects_private_targets(self):
        response = self.client.post("/api/v1/website-headers", json={"url": "http://127.0.0.1:8000"})
        self.assertEqual(response.status_code, 422)

    def test_website_headers_uses_backend_request(self):
        class FakeResponse:
            status = 200
            headers = {"Content-Type": "text/html", "Server": "test"}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        with patch.object(main.urllib.request, "urlopen", return_value=FakeResponse()):
            response = self.client.post("/api/v1/website-headers", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["findings"])
    def test_health_reports_all_scanner_services(self):
        redis_client = Mock()
        redis_client.ping.return_value = True

        class FakeClamd:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def sendall(self, _data):
                pass

            def recv(self, _size):
                return b"PONG\0"

        with (
            patch.object(Redis, "from_url", return_value=redis_client),
            patch.object(
                main.celery_app.control,
                "ping",
                return_value=[{"worker": {"ok": "pong"}}],
            ),
            patch.object(main.socket, "create_connection", return_value=FakeClamd()),
        ):
            response = self.client.get("/api/v1/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ready")
        self.assertTrue(response.json()["virus_scan_ready"])
        self.assertTrue(all(response.json()["services"].values()))
        redis_client.close.assert_called_once()

    def test_root_serves_the_frontend(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("สแกนไวรัส", response.text)
        self.assertIn("ตรวจสอบ Wi-Fi", response.text)

    def test_wifi_helper_is_downloadable(self):
        response = self.client.get("/wifi-scan.ps1")

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=\"wifi-scan.ps1\"", response.headers["content-disposition"])
        self.assertIn("netsh wlan show interfaces", response.text)

    def test_local_virus_helper_is_downloadable(self):
        response = self.client.get("/virus-scan.ps1")

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=\"virus-scan.ps1\"", response.headers["content-disposition"])
        self.assertIn("Start-MpScan", response.text)

    def test_upload_middleware_rejects_missing_or_oversized_content_length(self):
        async def app_must_not_run(_scope, _receive, _send):
            self.fail("Upload limit middleware should reject the request")

        middleware = main.UploadRequestLimitMiddleware(app_must_not_run)

        async def check(headers):
            messages = []

            async def send(message):
                messages.append(message)

            await middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/api/v1/virus-scans",
                    "headers": headers,
                },
                lambda: None,
                send,
            )
            return messages[0]["status"]

        missing_length_status = asyncio.run(check([]))
        large_length_status = asyncio.run(check([(b"content-length", b"999999999")]))
        self.assertEqual(missing_length_status, 411)
        self.assertEqual(large_length_status, 413)


if __name__ == "__main__":
    unittest.main()
