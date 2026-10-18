import socket
import struct
import time
from pathlib import Path

import yara

from app.config import CLAMD_HOST, CLAMD_PORT, YARA_RULES_PATH


MAX_CLAMD_RESPONSE_BYTES = 4096
STREAM_CHUNK_BYTES = 64 * 1024
CLAMD_TIMEOUT_SECONDS = 180


class ScannerUnavailableError(RuntimeError):
    pass


def _read_clamd_response(connection: socket.socket) -> str:
    response = bytearray()
    while len(response) < MAX_CLAMD_RESPONSE_BYTES:
        chunk = connection.recv(1024)
        if not chunk:
            break
        terminator = chunk.find(b"\0")
        response.extend(chunk if terminator < 0 else chunk[:terminator])
        if terminator >= 0:
            break
    if len(response) >= MAX_CLAMD_RESPONSE_BYTES:
        raise ScannerUnavailableError("ClamAV response exceeded the limit")
    return response.decode("utf-8", errors="replace").strip()


def _clamav_scan(path: Path) -> tuple[str, str | None]:
    connection = None
    last_error: OSError | None = None
    for attempt in range(30):
        try:
            connection = socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=5)
            break
        except OSError as error:
            last_error = error
            if attempt < 29:
                time.sleep(2)
    if connection is None:
        raise ScannerUnavailableError("ClamAV did not become available") from last_error

    try:
        with connection:
            connection.settimeout(CLAMD_TIMEOUT_SECONDS)
            connection.sendall(b"zINSTREAM\0")
            with path.open("rb") as source:
                while chunk := source.read(STREAM_CHUNK_BYTES):
                    connection.sendall(struct.pack("!I", len(chunk)))
                    connection.sendall(chunk)
            connection.sendall(struct.pack("!I", 0))
            response = _read_clamd_response(connection)
    except (OSError, TimeoutError) as error:
        raise ScannerUnavailableError("Could not complete ClamAV scan") from error

    if response.endswith(" OK"):
        return "clean", None
    if response.endswith(" FOUND"):
        signature = response.rsplit(":", 1)[-1].removesuffix(" FOUND").strip()
        return "threat_detected", signature or "ClamAV detection"
    if response.endswith(" ERROR"):
        raise ScannerUnavailableError("ClamAV could not scan the uploaded file")
    raise ScannerUnavailableError("ClamAV returned an unexpected response")


def _yara_scan(path: Path) -> list[dict[str, str]]:
    try:
        rules_source = YARA_RULES_PATH.read_text(encoding="utf-8")
        rules = yara.compile(source=rules_source)
        matches = rules.match(filepath=str(path), timeout=15)
    except (yara.Error, OSError, TimeoutError) as error:
        raise ScannerUnavailableError("YARA scan could not be completed") from error

    return [
        {
            "rule": match.rule,
            "description": str(match.meta.get("description", "Heuristic indicator")),
            "recommendation": str(
                match.meta.get(
                    "recommendation",
                    "ให้ผู้ดูแลตรวจสอบไฟล์และแหล่งที่มาก่อนอนุญาตให้ใช้งาน",
                )
            ),
        }
        for match in matches
    ]


def scan_file(path: Path, mode: str) -> dict:
    clamav_verdict, signature = _clamav_scan(path)
    findings: list[dict[str, str]] = []

    if clamav_verdict == "threat_detected":
        findings.append(
            {
                "level": "high",
                "title": "ClamAV ตรวจพบ signature",
                "detail": f"ชื่อ signature: {signature}",
                "engine": "ClamAV",
                "recommendation": (
                    "อย่าเปิดหรือรันไฟล์นี้ แยกไฟล์ไว้ใน quarantine แล้วตรวจชื่อ signature "
                    "กับผู้ดูแลระบบหรือผู้ผลิตซอฟต์แวร์ก่อนลบ หากไฟล์มาจากแหล่งที่เชื่อถือได้ "
                    "ให้ตรวจ false positive ผ่านช่องทางทางการ"
                ),
            }
        )

    yara_matches: list[dict[str, str]] = []
    if mode == "deep":
        yara_matches = _yara_scan(path)
        for match in yara_matches:
            findings.append(
                {
                    "level": "medium",
                    "title": "YARA พบ heuristic indicator: " + match["rule"],
                    "detail": match["description"],
                    "engine": "YARA",
                    "recommendation": match["recommendation"],
                }
            )

    if not findings:
        findings.append(
            {
                "level": "info",
                "title": "ไม่พบ signature หรือ indicator ตาม engine ที่ทำงาน",
                "detail": (
                    "ผลนี้ไม่ใช่การรับรองว่าไฟล์ปลอดภัย และอาจมี false negative "
                    "ตรวจสอบแหล่งที่มาและใช้การป้องกันของระบบปฏิบัติการต่อไป"
                ),
                "engine": "ClamAV" if mode == "standard" else "ClamAV + YARA",
                "recommendation": (
                    "ใช้ไฟล์เฉพาะเมื่อเชื่อถือแหล่งที่มา อัปเดตระบบและแอนติไวรัสอยู่เสมอ "
                    "และอย่าเปิดไฟล์ที่ไม่คาดหมาย"
                ),
            }
        )

    return {
        "verdict": "threat_detected" if clamav_verdict == "threat_detected" else (
            "heuristic_review" if yara_matches else "no_detection"
        ),
        "mode": mode,
        "engines": ["ClamAV"] + (["YARA"] if mode == "deep" else []),
        "archive_recursion": "ClamAV defaults; archive processing is bounded by engine limits",
        "findings": findings,
    }
