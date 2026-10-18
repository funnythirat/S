import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import scanner


class FakeClamdConnection:
    def __init__(self, response: bytes):
        self.response = response
        self.sent = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, _timeout):
        pass

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, _size):
        response = self.response
        self.response = b""
        return response


class ScannerTests(unittest.TestCase):
    def test_clamav_streams_file_and_parses_clean_response(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"safe test bytes")
            connection = FakeClamdConnection(b"stream: OK\0")
            with patch.object(scanner.socket, "create_connection", return_value=connection):
                verdict = scanner._clamav_scan(path)

        self.assertEqual(verdict, ("clean", None))
        self.assertTrue(connection.sent.startswith(b"zINSTREAM\0"))
        self.assertIn(b"safe test bytes", connection.sent)
        self.assertTrue(connection.sent.endswith(b"\0\0\0\0"))

    def test_clamav_reports_detection_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"test bytes")
            connection = FakeClamdConnection(b"stream: Test-Signature FOUND\0")
            with patch.object(scanner.socket, "create_connection", return_value=connection):
                verdict = scanner._clamav_scan(path)

        self.assertEqual(verdict, ("threat_detected", "Test-Signature"))

    def test_standard_clean_scan_recommends_safe_handling(self):
        with patch.object(scanner, "_clamav_scan", return_value=("clean", None)):
            result = scanner.scan_file(Path("not-opened"), "standard")

        self.assertEqual(result["verdict"], "no_detection")
        self.assertIn("ClamAV", result["engines"])
        self.assertTrue(result["findings"][0]["recommendation"])

    def test_clamav_detection_is_high_severity_with_remediation(self):
        with patch.object(
            scanner, "_clamav_scan", return_value=("threat_detected", "Test-Signature")
        ):
            result = scanner.scan_file(Path("not-opened"), "standard")

        self.assertEqual(result["verdict"], "threat_detected")
        self.assertEqual(result["findings"][0]["level"], "high")
        self.assertIn("อย่าเปิดหรือรันไฟล์นี้", result["findings"][0]["recommendation"])

    def test_deep_mode_runs_yara_and_reports_heuristic_separately(self):
        yara_match = {
            "rule": "Heuristic_Test",
            "description": "Heuristic only",
            "recommendation": "Review the file",
        }
        with (
            patch.object(scanner, "_clamav_scan", return_value=("clean", None)),
            patch.object(scanner, "_yara_scan", return_value=[yara_match]),
        ):
            result = scanner.scan_file(Path("not-opened"), "deep")

        self.assertEqual(result["verdict"], "heuristic_review")
        self.assertIn("YARA", result["engines"])
        self.assertEqual(result["findings"][0]["level"], "medium")
        self.assertEqual(result["findings"][0]["recommendation"], "Review the file")

    def test_bundled_yara_rules_compile_and_match_heuristic_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "indicator.txt"
            path.write_text(
                "DownloadString FromBase64String Invoke-Expression", encoding="ascii"
            )
            matches = scanner._yara_scan(path)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["rule"], "Heuristic_PowerShell_Download_Decode_Execute")
        self.assertIn("heuristic", matches[0]["description"].lower())
        self.assertTrue(matches[0]["recommendation"])

    def test_yara_flags_javascript_decode_and_dynamic_execution_together(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "script.js"
            path.write_text(
                'const payload = atob("encoded"); eval(payload);', encoding="ascii"
            )
            matches = scanner._yara_scan(path)

        self.assertEqual(len(matches), 1)
        self.assertEqual(
            matches[0]["rule"], "Heuristic_JavaScript_Decode_Dynamic_Execute"
        )
        self.assertIn("dynamic", matches[0]["description"].lower())
        self.assertTrue(matches[0]["recommendation"])

    def test_yara_does_not_flag_base64_decode_without_dynamic_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "script.js"
            path.write_text('const text = atob("encoded"); console.log(text);', encoding="ascii")
            matches = scanner._yara_scan(path)

        self.assertEqual(matches, [])


if __name__ == "__main__":
    unittest.main()
