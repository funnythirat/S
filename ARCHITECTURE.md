# สถาปัตยกรรมระบบสแกนความปลอดภัย

เอกสารนี้อธิบายเว็บต้นแบบใน [index.html](./index.html), การสแกนไฟล์ในเครื่องด้วย Microsoft Defender และ backend สำหรับสแกนไฟล์ด้วย ClamAV/YARA ผ่าน FastAPI, Celery, Redis และ PostgreSQL

## 1. เป้าหมายและขอบเขต

ระบบใช้สำหรับตรวจสอบเว็บไซต์, ซอฟต์แวร์ และไฟล์ที่ผู้ใช้มีสิทธิ์ตรวจ การตรวจประกอบด้วย:

- **HTTP security headers:** ส่งคำขอ `HEAD` แบบจำกัดจำนวนครั้งและ timeout
- **TLS certificate:** ตรวจวันหมดอายุ, hostname, chain และผลการตรวจ certificate ด้วยไลบรารี TLS มาตรฐาน ไม่ทดสอบ cipher หรือโจมตี handshake
- **Dependency:** อ่านชื่อและเวอร์ชันจาก lockfile แล้วเทียบกับ OSV API หรือฐานข้อมูลช่องโหว่ที่กำหนด
- **Source code:** ตรวจแบบ static โดยไม่ execute โค้ด ใช้กฎหรือ static analysis engine ที่ทำงานใน isolated worker
- **Virus scan:** เลือกสแกนไฟล์ในเครื่องด้วย Microsoft Defender โดยไม่อัปโหลดไฟล์ หรือเลือกอัปโหลดไฟล์เข้า quarantine เพื่อสแกนด้วย ClamAV; โหมด backend แบบลึกเพิ่ม YARA heuristic rules
- **รายงาน:** จัดระดับตามข้อมูลจากแหล่งอ้างอิง หากไม่มี CVSS จากแหล่งข้อมูล ให้แสดงว่าไม่มีคะแนนแทนการคาดเดา

การสแกนในเครื่องเรียก Microsoft Defender บน Windows และบันทึกเฉพาะรายงานไว้ในเครื่อง ไม่ส่งไฟล์หรือ path ไปยังเว็บ Defender อาจกักกันหรือลบภัยคุกคามตามการตั้งค่าของ Windows โหมด backend ไม่รันไฟล์ที่อัปโหลด และลบไฟล์จาก quarantine หลัง worker จบงาน (กรณี worker หยุดผิดปกติ ระบบลบไฟล์ค้างที่เก่ากว่า 24 ชั่วโมงตอนเริ่ม API)

**ไม่รวมในขอบเขต:** การสแกนทั้งเครื่องผู้ใช้, SQL injection/XSS exploitation, fuzzing, credential testing, crawling, port scanning, brute force, การแก้ไขข้อมูลเป้าหมาย และการเรียกใช้ Nmap, Nuclei, OWASP ZAP active scan หรือ WPScan

## 2. ภาพรวมสถาปัตยกรรม

```text
┌──────────────────────┐       HTTPS / JSON       ┌──────────────────────────┐
│ Frontend             │ ◄──────────────────────► │ FastAPI                  │
│ Dashboard / Reports  │                          │ API, Validation          │
└──────────────────────┘                          └────────────┬─────────────┘
                                                              │ enqueue
                                           ┌──────────────────┴──────────────┐
                                           ▼                                 ▼
                                  ┌─────────────────┐              ┌─────────────────┐
                                  │ Redis           │              │ PostgreSQL      │
                                  │ Celery broker   │              │ Jobs / findings │
                                  └────────┬────────┘              └─────────────────┘
                                           │ consume
                                           ▼
                                  ┌───────────────────────────────┐
                                  │ Celery scanning workers       │
                                  │ HTTP/TLS | SCA | Code | AV    │
                                  └──────────────┬────────────────┘
                                                 │
                           ┌─────────────────────┴───────────────────┐
                           ▼                                         ▼
                    Uploaded file (quarantine)             OSV vulnerability API
```

### ส่วนประกอบ

| ส่วน | หน้าที่ |
|---|---|
| Frontend | ส่งคำขอสแกนที่ผ่านการยืนยันขอบเขต แสดงสถานะและผลรายงาน |
| FastAPI | รับไฟล์ขนาดจำกัด ตรวจ consent และ input สร้างงานและให้ API อ่านผล |
| Celery + Redis | รับงานที่ใช้เวลานานและประมวลผลแบบ asynchronous; Redis เป็น broker ไม่ใช่แหล่งเก็บรายงานถาวร |
| Celery workers | ทำการตรวจแยกตามชนิดงาน มี timeout, concurrency limit และ network policy |
| PostgreSQL | เก็บ metadata, งานสแกน, สถานะ และผลการตรวจ |
| OSV API | แหล่งข้อมูลภายนอกสำหรับค้นหา vulnerability ของ dependency ด้วยชื่อและเวอร์ชัน |
| ClamAV + YARA | ตรวจ signature และ heuristic indicators ของไฟล์ที่อัปโหลด; ไม่ execute ไฟล์ |
| Microsoft Defender helper | ให้ Windows สแกนไฟล์ที่ผู้ใช้เลือกในเครื่อง และนำเข้ารายงาน JSON ใน browser; ไม่อัปโหลดไฟล์ |

## 3. ลำดับการทำงาน

1. ผู้ใช้เลือกไฟล์, โหมดตรวจ และยืนยันสิทธิ์อัปโหลด
2. Frontend ส่ง `POST /api/v1/virus-scans` เป็น `multipart/form-data`
3. FastAPI จำกัดขนาด 20 MiB, สร้างชื่อไฟล์จาก UUID, คำนวณ SHA-256 และเก็บไฟล์ไว้ใน quarantine volume
4. API สร้าง scan record และส่งเฉพาะ `scan_id` ไปยัง Celery; token สำหรับอ่านผลจะส่งกลับครั้งเดียวและเก็บไว้ใน browser memory
5. Worker เปลี่ยนสถานะเป็น `running`; ClamAV ตรวจไฟล์ผ่าน INSTREAM protocol และ deep mode เรียก YARA rules เพิ่ม
6. Worker บันทึกผลและคำแนะนำลง PostgreSQL แล้วลบไฟล์ชั่วคราว
7. Frontend อ่านสถานะ/ผลผ่าน `GET /api/v1/virus-scans/{scan_id}` พร้อม `X-Scan-Token`

สำหรับการสแกนในเครื่อง ผู้ใช้ดาวน์โหลด `virus-scan.ps1`, เรียกใช้บน Windows ที่เปิด Microsoft Defender Antivirus, เลือกไฟล์ผ่านหน้าต่าง native และนำเข้ารายงาน JSON ใน browser ไฟล์ที่เลือกและ path ไม่ถูกส่งไปยัง API; การอ่านรายงานเป็น local file operation

การอัปเดตสถานะรุ่นแรกใช้ polling ทุก 2–5 วินาที โดยมี backoff; เพิ่ม Server-Sent Events ได้ภายหลังหากจำเป็น

## 4. API และข้อมูลหลัก

### Endpoints รุ่นแรก

| Method | Endpoint | หน้าที่ |
|---|---|---|
| `POST` | `/api/v1/assets` | ลงทะเบียน asset และโดเมนที่อนุญาต |
| `GET` | `/api/v1/assets` | แสดง asset ของผู้ใช้ |
| `POST` | `/api/v1/scans` | สร้างงานสแกนตาม asset และชนิดที่อนุญาต |
| `GET` | `/api/v1/scans/{scan_id}` | อ่านสถานะ, เวลา และความคืบหน้า |
| `GET` | `/api/v1/scans/{scan_id}/findings` | อ่านผลแบบแบ่งหน้า |
| `GET` | `/api/v1/scans/{scan_id}/report` | ส่งออกรายงาน JSON |
| `GET` | `/api/v1/health` | ตรวจสถานะ API, PostgreSQL, Redis และ ClamAV |
| `GET` | `/wifi-scan.ps1` | ดาวน์โหลดตัวช่วยอ่านข้อมูล Wi-Fi ในเครื่อง Windows |
| `GET` | `/virus-scan.ps1` | ดาวน์โหลดตัวช่วยสแกนไฟล์ด้วย Microsoft Defender ในเครื่อง |
| `POST` | `/api/v1/virus-scans` | อัปโหลดไฟล์, เลือกโหมด `standard`/`deep` และสร้างงาน |
| `GET` | `/api/v1/virus-scans/{scan_id}` | อ่านสถานะและผลโดยส่ง `X-Scan-Token` |

Virus scan API เป็นส่วนใช้งานจริงในต้นแบบ; endpoints สำหรับ asset/website scan ในตารางเดิมเป็นแนวทางต่อยอดและยังไม่ได้ implement

การยกเลิกงาน (`DELETE /api/v1/scans/{scan_id}`) เพิ่มได้เมื่อ worker รองรับ cancellation อย่างปลอดภัย

### Entity ที่แนะนำ

- **User:** `id`, `email`, `password_hash` หรือ external identity, `created_at`
- **Asset:** `id`, `owner_id`, `canonical_domain`, `verification_status`, `created_at`
- **Scan:** `id`, `asset_id`, `requested_by`, `scan_type`, `status`, `created_at`, `started_at`, `completed_at`, `error_code`
- **Finding:** `id`, `scan_id`, `category`, `severity`, `title`, `description`, `evidence`, `remediation`, `source`, `external_id`, `cvss_score`, `created_at`

ค่าที่อนุญาตของ `status`: `queued`, `running`, `completed`, `failed`, `cancelled`

อย่าเก็บ credential, authorization header, cookie หรือเนื้อหาที่ไม่จำเป็นจากเว็บไซต์เป้าหมายลงใน finding หรือ log

## 5. มาตรการความปลอดภัยที่ต้องมี

### ป้องกัน SSRF และจำกัดเป้าหมาย

- ห้ามรับ URL อิสระจากผู้ใช้เพื่อส่งต่อให้ worker โดยตรง ให้สแกนเฉพาะ asset ใน allowlist ที่ผูกกับบัญชีผู้ใช้
- ยืนยันการควบคุมโดเมนก่อนเปิดใช้งาน asset เช่น DNS TXT challenge หรือไฟล์ HTTP challenge
- อนุญาตเฉพาะ `http`/`https` และพอร์ตที่กำหนดไว้; ปฏิเสธ URL ที่มี username/password, IP literal หรือรูปแบบ hostname ที่กำกวม
- resolve DNS ก่อนเชื่อมต่อและปฏิเสธ loopback, private, link-local, multicast, reserved และ metadata-service IP
- ป้องกัน DNS rebinding โดยตรวจ IP ที่เชื่อมต่อจริง; หากใช้ proxy หรือ connector ต้อง pin ปลายทางตามผลที่ตรวจแล้ว
- ปิด redirect โดยค่าเริ่มต้น หากจำเป็นต้องตาม redirect ให้ตรวจ allowlist และ resolve/validate IP ใหม่ทุก hop
- บังคับ egress firewall ของ worker ให้เข้าถึงได้เฉพาะเครือข่ายเป้าหมายที่อนุมัติและ API ฐานข้อมูลช่องโหว่ที่จำเป็น
- ส่ง `HEAD` เท่านั้นสำหรับ HTTP headers; จำกัด timeout, จำนวน redirect (ศูนย์เป็นค่าเริ่มต้น), response metadata และจำนวนงานต่อ asset

### Worker และ task queue

- แยก worker ตามชนิดงาน; static analysis และการอ่านไฟล์ควรทำใน container ที่ไม่ privileged และไม่มี network โดยไม่จำเป็น
- จำกัด CPU, memory, execution time, ขนาดไฟล์, จำนวนไฟล์, จำนวน dependency และ concurrency
- Redis ไม่ควรเปิดรับจาก public network; ใช้รหัสผ่าน/ACL, network isolation และ queue แยกตามประเภทงาน
- ตั้งค่า task retry เฉพาะความผิดพลาดชั่วคราว พร้อมจำนวนครั้งสูงสุดและ exponential backoff
- ออกแบบ task ให้ idempotent เพื่อป้องกันงานซ้ำเมื่อ worker หยุดกลางทาง
- เก็บ input ชั่วคราวนอก web root และลบตาม retention policy; ไม่ execute ไฟล์ที่ผู้ใช้อัปโหลด

### การจัดการไฟล์สแกน

- จำกัดไฟล์ไม่เกิน 20 MiB ต่อไฟล์ และอัปโหลดไม่เกิน 10 ไฟล์ต่อการส่งจาก UI
- ปฏิเสธ request สแกนที่ไม่มี `Content-Length` และจำกัดขนาด body ก่อนให้ multipart parser อ่านไฟล์
- ใช้ชื่อ UUID แทนชื่อที่ผู้ใช้อัปโหลดเป็น path; เก็บชื่อเดิมเป็น metadata ที่ escape ตอนแสดงผล
- สแกนไฟล์โดยอ่านเป็น stream ผ่าน ClamAV; ไม่แตก archive ด้วยโค้ดเว็บเอง
- ClamAV ใช้การประมวลผล archive ตามค่า engine; ควรตั้ง/ทบทวน `MaxScanSize`, `MaxFileSize`, `MaxRecursion`, `MaxFiles` กับเวอร์ชันที่ใช้งาน และทดสอบ archive bomb ก่อนเปิดสู่ภายนอก
- YARA rules ที่ให้มาคือ heuristic ตัวอย่างสำหรับ PowerShell download/decode/execute และ JavaScript decode/dynamic execution; เงื่อนไขต้องพบสัญญาณที่สัมพันธ์กันมากกว่าหนึ่งกลุ่ม ไม่ใช่ signature ครบถ้วน และผลตรงกฎไม่ใช่ข้อสรุปว่าเป็นมัลแวร์
- อย่าเพิ่มตัวอย่างเงื่อนไขทั่วไป เช่น `($abc or not $abc)` หรือกฎที่จับเพียงขนาดไฟล์ลงชุด production เพราะอาจ match ไฟล์ทั่วไปจำนวนมากและสร้าง false positive
- token อ่านผลเป็น capability token แบบสุ่ม; ต้นแบบยังไม่มีบัญชีผู้ใช้, CSRF/authentication เต็มรูปแบบ จึง bind API ที่ `127.0.0.1` และห้ามเปิดพอร์ตสู่ public internet
- อย่าเก็บไฟล์ที่ตรวจพบไว้ให้ผู้ใช้ดาวน์โหลดจากเว็บ; รายงานเก็บเฉพาะ hash, metadata, findings และ remediation

## 6. การสแกนไฟล์ในเครื่องและผ่าน Backend

**ไม่อัปโหลดไฟล์:** บน Windows ที่ Microsoft Defender Antivirus เปิดใช้งาน ให้ดาวน์โหลด `virus-scan.ps1` จากหน้าเว็บ แล้วเรียก PowerShell ด้วย `-ExecutionPolicy Bypass` สำหรับการเรียกครั้งนั้น เลือกไฟล์จากหน้าต่างที่เปิดขึ้น และนำเข้า `virus-scan-report.json` ในหน้าเว็บ หาก Defender ปิดใช้งาน ตัวช่วยจะหยุดก่อนเลือกไฟล์และไม่รายงานผลว่าไฟล์สะอาด ทั้งนี้ Defender อาจกักกัน/ลบไฟล์ตามการตั้งค่าของระบบ

**สแกนผ่าน Backend:** ต้องติดตั้ง Docker Desktop พร้อม Docker Compose จากนั้นเปิด PowerShell ในโฟลเดอร์โปรเจกต์และเรียก:

```powershell
docker compose up --build
```

เปิด `http://localhost:8000` แล้วเลือกเมนู **สแกนไวรัส** และใช้เฉพาะส่วน Backend เมื่อต้องการส่งไฟล์เข้า quarantine เพื่อให้ ClamAV/YARA ตรวจ ระบบจะดาวน์โหลด image และฐานข้อมูล ClamAV ในการเริ่มครั้งแรก ซึ่งอาจใช้เวลาหลายนาที ตรวจสุขภาพบริการได้ที่ `http://localhost:8000/api/v1/health` และ API docs อยู่ที่ `http://localhost:8000/api/docs`

หยุดระบบด้วย `Ctrl+C`; ใช้ `docker compose down` เพื่อหยุดและคงข้อมูล volume ไว้ อย่าใช้ `docker compose down -v` หากต้องการเก็บฐานข้อมูลและ signature cache

ค่า `POSTGRES_PASSWORD` เริ่มต้นใน Compose มีไว้สำหรับการพัฒนาในเครื่องเท่านั้น ระบบยังไม่มี login/บัญชีผู้ใช้และการป้องกัน CSRF แบบ production อย่าเปิดให้เข้าถึงจากเครือข่ายสาธารณะ

### Deploy แบบ private บน VPS ผ่าน Tailscale

ไฟล์ `docker-compose.production.yml` เป็น override สำหรับ VPS โดยบังคับตั้ง `POSTGRES_PASSWORD` และให้ API/worker รอ PostgreSQL กับ Redis ผ่าน health check ก่อนเริ่มงาน เริ่มด้วย Linux VPS ที่ติดตั้ง Docker Engine, Compose Plugin และ Tailscale แล้ว:

1. ส่งเฉพาะ source ที่จำเป็นขึ้น VPS: `Dockerfile`, `docker-compose.yml`, `docker-compose.production.yml`, `requirements.txt`, `index.html`, `wifi-scan.ps1`, `virus-scan.ps1` และโฟลเดอร์ `backend`. ห้ามส่ง `.env` จากเครื่องพัฒนา, diagnostics bundle หรือไฟล์ secret
2. ในโฟลเดอร์โปรเจกต์บน VPS สร้าง `.env` ที่มีเฉพาะรหัสผ่านฐานข้อมูล production สุ่มแบบ hex และจำกัดสิทธิ์ไฟล์:

   ```bash
   umask 077
   printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 32)" > .env
   chmod 600 .env
   ```

   เก็บรหัสผ่านนี้ใน password manager/secret manager และอย่าเปลี่ยนค่าระหว่างใช้งานฐานข้อมูลเดิม มิฉะนั้น PostgreSQL ที่สร้างไว้แล้วจะไม่เปลี่ยนรหัสผ่านตาม environment โดยอัตโนมัติ
3. ตรวจ merged Compose โดยไม่แสดง environment values แล้วเริ่มบริการ:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.production.yml config --quiet
   docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
   docker compose -f docker-compose.yml -f docker-compose.production.yml ps
   ```
4. ตรวจสุขภาพจาก VPS เอง:

   ```bash
   curl --fail http://127.0.0.1:8000/api/v1/health
   ```

   ก่อนแชร์เว็บ ต้องเห็น `status` เป็น `ready` และทุก service เป็น `true`
5. ติดตั้ง/ล็อกอิน Tailscale บน VPS และอุปกรณ์ของผู้ใช้ จำกัด tailnet access ให้เฉพาะคนหรืออุปกรณ์ที่อนุญาต จากนั้นบน VPS รัน `tailscale serve 8000` เพื่อให้บริการผ่าน HTTPS ภายใน tailnet เท่านั้น ใช้ URL ที่ Tailscale แสดง ห้ามเปิด Tailscale Funnel, พอร์ต `8000`, PostgreSQL, Redis หรือ ClamAV สู่ public internet
6. ทดสอบจากอุปกรณ์ที่อนุญาตและเชื่อม Tailscale แล้วเปิด URL ที่ Serve แสดง ตรวจ health และทดสอบ scan ไฟล์ที่ไม่มีข้อมูลลับ จากนั้นยืนยันว่ารายงานสำเร็จและไฟล์ quarantine ชั่วคราวถูกลบ

การจำกัดด้วย Tailscale เป็นขอบเขตการเข้าถึงของ deployment ส่วนตัว ไม่ใช่ระบบบัญชีผู้ใช้ของแอป ผู้ที่อยู่ใน tailnet และมีสิทธิ์เข้าถึง URL สามารถใช้ API สแกนได้ จึงควรเชิญเฉพาะผู้ใช้ที่ไว้ใจ ตรวจ Tailscale ACL/device approval และสำรอง volume `postgres_data`, `clamav_data` และ `quarantine` อย่างปลอดภัย ก่อนเปิดให้บุคคลทั่วไปหรือกลุ่มที่ไม่ไว้ใจใช้ ต้องเพิ่ม authentication/authorization, per-user ownership, rate limits, retention controls และ production security review ก่อน

รันชุดทดสอบ backend ใน PowerShell ด้วย:

```powershell
python -m pip install -r requirements-dev.txt
$env:PYTHONPATH = "backend"
python -m unittest discover -s backend\tests -v
```

### API, ข้อมูล และการตรวจสอบ

- บังคับ HTTPS, authentication, authorization แบบตรวจเจ้าของ asset/scan ทุก request และ rate limit
- ใช้ CSRF protection หากใช้ cookie-based session; ใช้ CORS allowlist ที่แคบ
- ตรวจ input ด้วย schema และปฏิเสธค่าที่ไม่ได้ระบุ; ห้ามแสดงรายละเอียด exception หรือ stack trace ต่อผู้ใช้
- เข้ารหัสข้อมูลสำคัญเมื่อจัดเก็บ, จัดการ secret ผ่าน environment/secret manager และใช้ least privilege
- บันทึก audit event ของผู้สร้างงาน, asset, เวลา และผลสถานะ โดยไม่บันทึก token หรือข้อมูลลับ
- กำหนด retention และการลบข้อมูลให้ชัดเจน พร้อมสำรองและทดสอบการกู้คืนฐานข้อมูล

## 7. โครงสร้างโค้ดที่แนะนำ

```text
app/
  api/
    routes/
      assets.py
      scans.py
      findings.py
  core/
    config.py
    auth.py
    scope_policy.py
  db/
    models.py
    session.py
  schemas/
    asset.py
    scan.py
    finding.py
  services/
    scan_service.py
    report_service.py
  workers/
    celery_app.py
    tasks.py
    scanners/
      http_headers.py
      tls_certificate.py
      dependencies.py
      source_code.py
tests/
  api/
  workers/
  security/
```

Frontend ปัจจุบันเป็น HTML ไฟล์เดียว ยังไม่มีการเชื่อม backend; ในขั้น MVP สามารถคงหน้าเดิมไว้และเปลี่ยนจากการตรวจใน browser เป็นการเรียก API เมื่อ backend พร้อม โดยแยก JavaScript/CSS เป็นไฟล์เมื่อเริ่มเพิ่มการทดสอบและฟีเจอร์

## 8. แผนพัฒนาต่อและเกณฑ์รับงาน

### ระยะ 1 — พื้นฐานระบบ

- สร้าง FastAPI, PostgreSQL schema และ migration
- เพิ่ม authentication, ownership checks, asset allowlist และ audit log
- ตั้งค่า Docker Compose สำหรับ API, PostgreSQL, Redis และ worker ในสภาพแวดล้อมพัฒนา

**เกณฑ์รับงาน:** ผู้ใช้ไม่สามารถอ่าน asset หรือ scan ของผู้ใช้อื่นได้; API ปฏิเสธ target ที่ไม่ได้ลงทะเบียน

### ระยะ 2 — Queue และสถานะงาน

- เพิ่ม Celery task, สถานะงาน, timeout, retry policy และ polling endpoint
- เพิ่ม quota/concurrency limit และการ recover งานค้าง

**เกณฑ์รับงาน:** API ตอบกลับการสร้างงานได้โดยไม่รอ scanner; งานที่จบแล้วมีสถานะและเวลาแน่นอน; งานล้มเหลวไม่แสดงผลสำเร็จปลอม

### ระยะ 3 — Passive HTTP/TLS

- ทำ HTTP `HEAD` check และประเมิน security headers
- ตรวจ TLS certificate ด้วย hostname validation และบันทึกวันหมดอายุ/ผลตรวจ
- ใช้ DNS/IP validation, redirect policy และ egress restriction ก่อนเปิด worker

**เกณฑ์รับงาน:** ทดสอบกรณี private IP, localhost, metadata IP, DNS rebinding และ redirect ออกนอก allowlist แล้วต้องถูกปฏิเสธ

### ระยะ 4 — Dependency และ Source Code

- รองรับ lockfile ก่อน manifest เพื่อให้ได้เวอร์ชัน dependency ที่แน่นอน
- ส่งข้อมูลขั้นต่ำที่จำเป็นไปยัง OSV; ระบุแหล่งข้อมูลและเวลาที่ตรวจในรายงาน
- เพิ่ม static analysis ใน sandbox ที่ไม่ execute โค้ด และกำหนดขนาด/จำนวนไฟล์

**เกณฑ์รับงาน:** ทดสอบ package ที่รู้ว่ามี advisory และ package ที่ไม่มี advisory; ทดสอบไฟล์เสีย, ไฟล์ใหญ่ และไฟล์จำนวนมาก

### ระยะ 4A — Virus scanning

- สแกนไฟล์อัปโหลดด้วย ClamAV และเพิ่ม YARA heuristic ในโหมดลึก
- แสดง verdict, hash, engine, ข้อจำกัด และคำแนะนำตอบสนอง โดยไม่ลบไฟล์ต้นฉบับอัตโนมัติ
- ทดสอบด้วย EICAR test file ซึ่งเป็นไฟล์ทดสอบมาตรฐานที่ไม่ใช่มัลแวร์จริง รวมถึงไฟล์สะอาด, ไฟล์ใหญ่, archive เสีย และ YARA heuristic fixture

**เกณฑ์รับงาน:** ทั้งสองโหมดให้สถานะ `queued/running/completed/failed` ถูกต้อง; ไฟล์ชั่วคราวถูกลบเมื่อจบงาน; การตรวจที่ engine ไม่พร้อมต้องแสดง error ไม่แสดงผล clean

### ระยะ 5 — Dashboard และรายงาน

- เชื่อม frontend กับ API, แสดงสถานะและ severity breakdown
- เพิ่ม filter, pagination, รายละเอียด finding, remediation และ JSON export
- เพิ่ม retention, backup, monitoring และ alert สำหรับ worker ค้างหรือ queue โตผิดปกติ

**เกณฑ์รับงาน:** รายงานตรงกับข้อมูลในฐานข้อมูล, severity ไม่ถูกแต่งขึ้น, UI รองรับ loading/empty/error states และผู้ใช้เห็นเฉพาะรายงานของตน

## 9. ข้อเสนอแนะสำหรับการพัฒนาต่อ

ต้นแบบมี file-scanning backend แล้ว แต่ยังไม่มีบัญชีผู้ใช้หรือ deployment hardening ก่อนเปิดใช้กับผู้ใช้หลายคนควรเพิ่ม authentication/authorization, scan ownership, CSRF controls, retention job, migrations, rate limits และทบทวน egress/network isolation รวมทั้งค่า resource limits ของ ClamAV/YARA worker

เครื่องมือนี้เป็นตัวช่วยคัดกรอง ไม่ใช่การรับรองว่าระบบปลอดภัย การนำไปใช้งานจริงควรมีผู้รับผิดชอบด้านความปลอดภัยตรวจสอบ scope, network egress และการจัดการข้อมูลก่อนเปิดให้ผู้ใช้เข้าถึง
