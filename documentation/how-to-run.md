# คู่มือติดตั้งและใช้งาน (ติดตั้งบนเครื่องอื่น)

คู่มือนี้พาติดตั้งและรัน FlowSentry บน**เครื่องใหม่** ตั้งแต่ศูนย์ โดยไม่ต้องมีชุดข้อมูล
2.5 GB และไม่ต้องมี GPU

ทุกอย่างที่จำเป็นต่อการรันถูกเก็บไว้ใน repo แล้ว:

- **โมเดลที่ใช้งานจริง** — `artifacts/models/optuna-denoising-50/` (autoencoder + threshold)
- **preprocessing ที่จับคู่กับโมเดล** — `artifacts/preprocessing_w50/` (scaler + encoders)
- **ตัวอย่างข้อมูลเดโม** — `data/demo_sample/` (benign 2,000 แถวสำหรับ SHAP background +
  ข้อมูลทดสอบ 7,000 แถวครบ 10 คลาสสำหรับ replay) รวม ~320 KB

> ตัวอย่างข้อมูลนี้มีไว้ให้ระบบ **รันและสาธิตได้ทันทีหลัง clone** ไม่ใช่ชุดข้อมูลเต็ม
> ถ้าต้องการรันกับข้อมูลจริง/ชุดเต็ม ดูหัวข้อ [รันกับข้อมูลของคุณเอง](#รันกับข้อมูลของคุณเอง)

> ⚠️ **โมเดลที่แถมมาเป็น "ตัวอ้างอิง" ไม่ใช่ตัวที่ใช้กับเครือข่ายคุณได้เลย** —
> มันเทรนบน NF-ToN-IoT-v2 ใช้โชว์เดโม (replay ชุดนั้น) ได้แม่น แต่ autoencoder
> เรียนรู้นิยาม "ปกติ" ของเครือข่ายเดียว พอเอาไปเจอเครือข่ายอื่นคะแนนอาจพังได้
> (AUROC ตกถึง 0 จนกว่าจะเทรนใหม่) **ก่อนใช้กับทราฟฟิกจริง ต้องเทรนใหม่ด้วย
> benign ของเครือข่ายนั้นก่อน** — ดูหัวข้อ [เทรนใหม่](#เทรนใหม่เมื่อเครือข่ายเปลี่ยน-domain-shift)

มีสองวิธี เลือกอย่างใดอย่างหนึ่ง:

| วิธี | เหมาะกับ | ต้องมี |
|---|---|---|
| **A. Docker** (แนะนำ) | นำไปรันที่ไหนก็ได้ ไม่ต้องลง Python/ไลบรารีเอง | Docker + Docker Compose |
| **B. virtualenv** | เครื่องพัฒนา หรืออยากแก้โค้ดไปด้วย | Python 3.12 |

---

## เตรียมเครื่อง

```bash
git clone https://github.com/Ekkasit-Ph/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System
```

- **Docker:** ต้องมี Docker Engine + Docker Compose (`docker --version`, `docker compose version`)
- **virtualenv:** ต้องมี Python **3.12** (`python3.12 --version`) และ `pip`
- ไม่ต้องใช้ GPU — ระบบตั้งใจใช้ PyTorch รุ่น CPU (โมเดลเล็กมาก อนุมานไม่กี่มิลลิวินาที)
- RAM ~2 GB ก็พอสำหรับรันเดโม

---

## วิธี A — Docker (แนะนำ)

ไฟล์ `Dockerfile` ตั้งค่า `NIDS_MODEL_DIR` / `NIDS_PROCESSED_DIR` ให้แล้ว ชี้ไป
โมเดลจริงกับ `data/demo_sample/` ภายใน image — **ไม่ต้องตั้ง env เอง**

### 1. สร้างและสตาร์ต

```bash
docker compose up -d --build        # ครั้งแรกนานหน่อย เพราะลง torch CPU wheel
docker compose ps                   # รอจน STATUS ขึ้น (healthy)
```

เปิดเบราว์เซอร์ที่ <http://localhost:8000> — จะเห็นหน้าแดชบอร์ด (ยังว่าง เพราะยังไม่มี flow)

### 2. ป้อน flow เข้าระบบ (จำลองทราฟฟิกสด)

```bash
docker compose exec app python -m web.backend.replay_demo --reset --n-flows 400 --rate 2 --loop
```

แดชบอร์ดจะเริ่มมี flow ไหลเข้ามา และแถวที่ผิดปกติจะขึ้นสีแดง

### 3. ข้อมูลแท็บ Firewall gaps (โมดูล 6)

โมดูล 6 เทียบ alert กับไฟล์นโยบายไฟร์วอลล์ — รัน **หลัง** มี flow ในระบบแล้ว:

```bash
docker compose exec app python -m network_simulation.firewall_rules --format ryu --output /tmp/flows.json
docker compose exec app python -m source.firewall_check.ryu_log_compare --rules /tmp/flows.json --default-action allow
```

### 4. ปิด

```bash
docker compose down          # เก็บฐานข้อมูลไว้ (named volume `nids-data`)
docker compose down -v       # ล้างฐานข้อมูลด้วย
```

> **อย่าใช้** `docker stop $(docker ps -q)` — จะไปหยุด container อื่นที่ไม่เกี่ยวด้วย
> ระบุชื่อ service เสมอ เช่น `docker compose stop app`

ฐานข้อมูล SQLite เก็บอยู่ใน named volume `nids-data` จึงคงอยู่ข้าม `docker compose restart`
โดยไม่ต้องพึ่ง path บนเครื่อง host (ดู `docker-compose.yml`)

---

## วิธี B — virtualenv (ติดตั้งตรงบนเครื่อง)

### 1. สร้าง venv + ลงไลบรารี

```bash
python3.12 -m venv .venv
source .venv/bin/activate

# ลง torch รุ่น CPU ก่อน -- ไม่งั้น pip จะดึง wheel ที่ผูก CUDA (ใหญ่ ~2GB) โดยไม่จำเป็น
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
```

### 2. สตาร์ต backend + หน้าเว็บ

```bash
NIDS_MODEL_DIR=artifacts/models/optuna-denoising-50 \
NIDS_PROCESSED_DIR=data/demo_sample \
python -m uvicorn web.backend.main:app --host 0.0.0.0 --port 8000
```

เปิด <http://localhost:8000>

> **ต้องใส่ env var สองตัวนี้เสมอ** — ค่า default ในโค้ดชี้ไป `artifacts/models/default/`
> ซึ่งไม่มีจริง โมเดลที่ใช้จริงชื่อ `optuna-denoising-50`

ใช้เวลา ~25–30 วินาทีกว่าจะพร้อม (โหลด SHAP explainer) รอจนคำสั่งนี้ตอบ `200`:

```bash
curl -o /dev/null -w '%{http_code}\n' http://localhost:8000/health
```

### 3. ป้อน flow (terminal ใหม่)

```bash
source .venv/bin/activate
python -m web.backend.replay_demo --reset --n-flows 400 --rate 2 --loop \
  --processed-dir data/demo_sample \
  --artifacts-dir artifacts/models/optuna-denoising-50
```

| flag | ความหมาย |
|---|---|
| `--reset` | ล้าง flow เก่าทั้งหมดก่อนเริ่ม (ใส่เฉพาะรอบแรก) |
| `--n-flows 400` | จำนวน flow ต่อรอบ |
| `--rate 2` | 2 flow/วินาที — ความเร็วที่ดูทันตอนนำเสนอ (`0` = เร็วสุด) |
| `--loop` | วนไปเรื่อย ๆ จนกด Ctrl+C |
| `--benign-fraction` | สัดส่วน benign (default `0.98` — โจมตี 2% ให้เหมือนของจริง) |

### 4. Firewall gaps (โมดูล 6)

```bash
python -m network_simulation.firewall_rules --format ryu --output /tmp/flows.json
python -m source.firewall_check.ryu_log_compare --rules /tmp/flows.json --default-action allow
```

### 5. ปิด

Ctrl+C ทั้งสอง terminal

---

## สิ่งที่เห็นบนแดชบอร์ด

| ส่วน | ดูอะไร |
|---|---|
| **ตารางรายการ flow** | flow ล่าสุดเรียงจากใหม่ไปเก่า แถวแดง = โมเดลตัดสินว่าผิดปกติ |
| **คลิกที่ flow แดง → SHAP** | อธิบายว่า flow นั้นผิดปกติ **เพราะฟีเจอร์อะไร** (หน่วยจริง เช่น ไบต์/มิลลิวินาที) |
| **Anomaly rate** | อัตราผิดปกติในหน้าต่างเวลา พร้อมค่า calibrated — ใช้ดูว่าเมื่อไรควรเทรนใหม่ |
| **Trend** | อัตราผิดปกติตามเวลา ลากเพื่อซูมช่วง |
| **Firewall gaps** | flow ผิดปกติที่ไฟร์วอลล์ "ปล่อยผ่าน" (โมดูล 6) |

---

## รันกับข้อมูลของคุณเอง

`data/demo_sample/` เป็นแค่ตัวอย่างเล็กไว้สาธิต ถ้าต้องการใช้ปริมาณจริง:

**ก. ชุดข้อมูลเต็ม (NF-ToN-IoT-v2)** — สร้าง split เต็มด้วย pipeline แล้วชี้ env ไปที่โฟลเดอร์นั้น
(ดู "Reproducing from scratch" ใน [README หลัก](../README.md)):

```bash
python -m source.preprocessing.pipeline --input data/raw/NF-ToN-IoT-v2.csv
# ได้ data/processed_w50/ -> ใช้แทน data/demo_sample
NIDS_PROCESSED_DIR=data/processed_w50 python -m uvicorn web.backend.main:app --port 8000
```

ใน Docker ให้ mount โฟลเดอร์เข้าไปแล้วตั้ง `NIDS_PROCESSED_DIR` ชี้ไปที่ mount นั้น

**ข. ทราฟฟิกสดจริง** — ใช้ตัวเก็บ flow สด (`source/extraction/`, อิง nfstream) แทน replay
ดูรายละเอียดที่ [`source/extraction/README.md`](../source/extraction/README.md)

---

## เทรนใหม่เมื่อเครือข่ายเปลี่ยน (domain shift)

autoencoder เรียนรู้ว่า "ปกติ" ของเครือข่าย**หนึ่ง** หน้าตาเป็นอย่างไร ถ้าเอาไปใช้กับเครือข่าย
ที่นิยาม "ปกติ" ต่างออกไป (แม้แต่เพิ่มอุปกรณ์ตัวเดียว) คะแนนอาจเพี้ยนจนต้อง**เทรนใหม่ด้วย
ทราฟฟิกของเครือข่ายนั้นเอง** ขั้นตอนเต็ม (เก็บข้อมูล → preprocess → train → threshold → serve)
และวิธีดูจากแดชบอร์ดว่าเมื่อไรถึงเวลาเทรนใหม่ อยู่ใน
[guides/deployment-runbook.md](guides/deployment-runbook.md)

---

## ตัวแปรสภาพแวดล้อม (Environment variables)

| ตัวแปร | ความหมาย | ค่าที่ควรใช้ |
|---|---|---|
| `NIDS_MODEL_DIR` | โฟลเดอร์โมเดล (model.pt + threshold.json) | `artifacts/models/optuna-denoising-50` |
| `NIDS_PROCESSED_DIR` | โฟลเดอร์ข้อมูล (train.parquet สำหรับ SHAP, test.parquet สำหรับ replay, feature_columns.json) | `data/demo_sample` (เดโม) หรือ `data/processed_w50` (เต็ม) |
| `NIDS_DB_PATH` | path ไฟล์ฐานข้อมูล SQLite | default `data/nids.db` · ใน Docker ชี้ไป volume ที่ persist |

Docker image ตั้ง `NIDS_MODEL_DIR` / `NIDS_PROCESSED_DIR` ให้แล้ว ส่วน `docker-compose.yml`
ตั้ง `NIDS_DB_PATH` ให้ชี้ named volume

---

## แก้ปัญหาที่พบบ่อย

| อาการ | สาเหตุ / ทางแก้ |
|---|---|
| แดชบอร์ดว่าง / `total_flows = 0` | ยังไม่ได้ป้อน flow — รัน `replay_demo` (ขั้นที่ 2/3) |
| คลิก flow แล้ว `/explain` คืน **503** | SHAP explainer ไม่ได้โหลด — เช็กว่า `NIDS_PROCESSED_DIR` มี `train.parquet` จริง และดู log ตอนสตาร์ต |
| `port is already allocated` / 8000 ไม่ว่าง | มีบริการอื่นใช้ 8000 — เปลี่ยน port map เป็น `-p 18000:8000` (Docker) หรือ `--port 18000` (venv) |
| build ช้ามากครั้งแรก | กำลังโหลด torch CPU wheel — ปกติ ครั้งถัดไปจะ cache |
| ฐานข้อมูลหายหลังปิด | ใช้ `docker compose down` (ไม่ใส่ `-v`) — `-v` จะลบ volume ด้วย |
| อยากได้ GPU | ไม่จำเป็น โมเดลเล็ก CPU เร็วพอ — แต่ถ้าจะใช้ ข้ามการลง torch CPU wheel แล้วลง torch ปกติ |

ตรวจว่าทุก endpoint ตอบ `200`:

```bash
curl -s 'http://localhost:8000/stats?window=1h'
curl -s 'http://localhost:8000/alerts?limit=1'
curl -s 'http://localhost:8000/firewall-gaps?limit=200&gaps_only=false'
curl -s 'http://localhost:8000/stats/trend?window=1h&buckets=60'
```

---

## เครื่องมือ simulation / ชุดทดสอบ

เครือข่ายจำลอง (Mininet, GNS3), ตัวสร้างทราฟฟิก/โจมตี, ชุดทดสอบ `pytest` และสคริปต์
benchmark **ไม่ได้อยู่บน branch `main`** เพราะเป็นเครื่องมือตอนพัฒนา ไม่ใช่ส่วนที่ติดตั้งใช้งาน
อยู่บน branch `development`:

```bash
git checkout development
```
