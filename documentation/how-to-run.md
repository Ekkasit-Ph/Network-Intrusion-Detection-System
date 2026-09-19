# วิธีรันระบบ

มีสองทาง: **venv** (เครื่องพัฒนา) กับ **Docker** (วันนำเสนอ — แนะนำ เพราะไม่ต้องพึ่งว่าเครื่องนั้นลงอะไรไว้)

---

## ทาง A — venv บนเครื่องพัฒนา

### 1. Backend + หน้าเว็บ

```bash
cd ~/Workspace/Project/Network-Intrusion-Detection-System
source .venv/bin/activate

NIDS_PROCESSED_DIR=data/processed_w50 \
NIDS_MODEL_DIR=artifacts/models/optuna-denoising-50 \
python -m uvicorn web.backend.main:app --host 0.0.0.0 --port 8000
```

เปิด <http://localhost:8000>

> **ต้องใส่ env var สองตัวนี้เสมอ** — ค่า default ของโค้ดชี้ไป `artifacts/models/default/`
> ซึ่งไม่มีอยู่จริงในโปรเจกต์ (โมเดลที่ใช้จริงชื่อ `optuna-denoising-50`)

ใช้เวลา **~25–30 วินาที** กว่าจะพร้อม เพราะต้องโหลด SHAP explainer
รอจนกว่าคำสั่งนี้ตอบ `200`:

```bash
curl -o /dev/null -w '%{http_code}\n' http://localhost:8000/health
```

### 2. ป้อน flow เข้าระบบ (จำลองทราฟฟิกสด)

เปิด terminal ใหม่:

```bash
cd ~/Workspace/Project/Network-Intrusion-Detection-System
source .venv/bin/activate

python -m web.backend.replay_demo \
  --reset --n-flows 400 --rate 2 --loop \
  --processed-dir data/processed_w50 \
  --artifacts-dir artifacts/models/optuna-denoising-50
```

| flag | ความหมาย |
|---|---|
| `--reset` | ล้าง flow เก่าทั้งหมดก่อนเริ่ม (ใส่เฉพาะรอบแรก) |
| `--rate 2` | 2 flow/วินาที — ความเร็วที่ดูทันตอนอัดจอ |
| `--loop` | วนไปเรื่อย ๆ จนกด Ctrl+C |
| `--benign-fraction` | สัดส่วน benign, default `0.98` (โจมตี 2% ให้เหมือนของจริง) |

### 3. ข้อมูลของแท็บ Firewall gaps

โมดูล 6 ต้องมีไฟล์กฎก่อนถึงจะเทียบได้ — รันสองคำสั่งนี้ **หลัง** มี flow ในระบบแล้ว:

```bash
python -m network_simulation.firewall_rules --format ryu --output /tmp/flows.json
python -m source.firewall_check.ryu_log_compare --rules /tmp/flows.json --default-action allow
```

### 4. ปิด

Ctrl+C ทั้งสอง terminal

---

## ทาง B — Docker (วันนำเสนอ)

`Dockerfile` ตั้ง `NIDS_MODEL_DIR` / `NIDS_PROCESSED_DIR` ให้แล้ว ไม่ต้องใส่เอง

```bash
cd ~/Workspace/Project/Network-Intrusion-Detection-System
docker compose up -d --build          # ครั้งแรกนานหน่อย (ลง torch CPU wheel)
docker compose ps                     # รอจน STATUS ขึ้น (healthy)
```

เปิด <http://localhost:8000>

ป้อน flow:

```bash
docker compose exec app python -m web.backend.replay_demo --reset --n-flows 400 --rate 2 --loop
```

Firewall gaps:

```bash
docker compose exec app python -m network_simulation.firewall_rules --format ryu --output /tmp/flows.json
docker compose exec app python -m source.firewall_check.ryu_log_compare --rules /tmp/flows.json --default-action allow
```

ปิด:

```bash
docker compose down          # เก็บฐานข้อมูลไว้ (named volume `nids-data`)
docker compose down -v       # ล้างฐานข้อมูลด้วย
```

> อย่าใช้ `docker stop $(docker ps -q)` — จะไปหยุด container อื่นที่ไม่เกี่ยวข้องด้วย
> ระบุชื่อ service เสมอ (`docker compose stop app`)

---

## สิ่งที่ยังรันไม่ได้ในเครื่องนี้: Mininet + Ryu

`network_simulation/` มี 4 ส่วน รันได้แค่ส่วนเดียว:

| ไฟล์ | รันได้? | ต้องใช้ |
|---|---|---|
| `firewall_rules.py` | ✅ รันได้ | Python ล้วน |
| `topology.py` | ❌ | Mininet + Open vSwitch |
| `ryu_app.py` | ❌ | Ryu SDN Controller |
| `attack_scripts/` | ❌ | Mininet + `hping3` / `nmap` |

ตรวจแล้วในเครื่องนี้ **ไม่มี** `mn`, `ovs-vsctl`, `hping3`, `nmap`, แพ็กเกจ `mininet`, แพ็กเกจ `ryu`

สาเหตุที่ยังไม่ได้ติดตั้ง (ตรงกับที่เขียนไว้ใน `network_simulation/README.md`):

1. **Mininet** ต้องใช้สิทธิ์ root และแพ็กเกจระดับระบบปฏิบัติการในการติดตั้ง
2. **Ryu** ยังไม่รองรับ Python 3.12 ซึ่งเป็นรุ่นที่ใช้พัฒนาโครงงาน (ติดที่ `eventlet`)

ส่วนที่ **ทวนสอบแล้ว** คือรอยต่อระหว่างการจำลองกับโมดูล 6 — นโยบายไฟร์วอลล์
และการ export ออกมาเป็น JSON รูปแบบเดียวกับที่ `source/firewall_check` อ่านจริง
(`tests/test_network_simulation.py` ตรึงการ round-trip นี้ไว้ และตรวจว่าการ render
นโยบายเดียวกันเป็น Ryu กับ iptables ให้คำตัดสินตรงกัน)

### ถ้าจะรัน Mininet จริงในเทอมหน้า

ต้องใช้เครื่อง/VM แยก (Ubuntu 20.04 หรือ 22.04) ที่มี Python 3.9:

```bash
sudo apt install mininet openvswitch-switch hping3 nmap
python3.9 -m venv ryu-venv && ryu-venv/bin/pip install ryu

ryu-venv/bin/ryu-manager network_simulation/ryu_app.py &     # terminal 1
sudo python3 network_simulation/topology.py                   # terminal 2
```

**ข้อควรระวังตอนวัดผล:** ถ้าเราสร้างทั้งทราฟฟิกปกติและทราฟฟิกโจมตีเองทั้งคู่
recall ที่ได้จะเข้าใกล้ 100% ซึ่งไม่ได้พิสูจน์อะไรเลย — เพราะทราฟฟิกปกติที่เราสร้าง
มันง่ายเกินกว่าของจริงมาก **ควรวาง Mininet เป็น end-to-end integration test**
(พิสูจน์ว่าท่อทั้ง 6 โมดูลต่อกันติดจริง) ไม่ใช่การประเมินความแม่นยำ

คุณค่าสูงสุดของมันคือได้ pcap จริงมาปิดช่องว่างของโมดูล 1 — ตอนนี้ยังไม่เคยทวนสอบ
กับ nProbe บนทราฟฟิกจริงเลย (`verify_skew.py` แค่จำลอง skew ด้วยการสลับคอลัมน์)

---

## ตรวจว่าทุกอย่างทำงาน

```bash
curl -s 'http://localhost:8000/stats?window=1h'
curl -s 'http://localhost:8000/alerts?limit=1'
curl -s 'http://localhost:8000/firewall-gaps?limit=200&gaps_only=false'
curl -s 'http://localhost:8000/stats/trend?window=1h&buckets=60'
```

ควรได้ `200` ทั้งหมด และ `/stats` ควรมี `total_flows` มากกว่า 0
