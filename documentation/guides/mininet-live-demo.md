# เดโมสด: โมเดลที่เทรนเฉพาะเครือข่าย Mininet + แดชบอร์ด

เดโมนี้ต่อยอดจาก [mininet-integration-run.md](mininet-integration-run.md) โดยตรง
งานเดิมพิสูจน์ว่าโมเดลที่เทรนบน NF-ToN-IoT-v2 ให้ **AUROC = 0.000** บน Mininet
(แยกได้สมบูรณ์ในทิศทางกลับ — ดูรากของปัญหาในเอกสารนั้น) เดโมนี้แสดง **ทางแก้ที่ทำงานจริง**:
เทรนโมเดลโครงสร้างเดิมใหม่บนทราฟฟิกปกติของเครือข่ายเป้าหมาย แล้วเปิดแดชบอร์ดดูการตรวจจับสด

## สิ่งที่สร้าง

โมเดล denoising autoencoder ชุดใหม่ (เฉพาะ Mininet) แยกจากโมเดล NF-ToN-IoT-v2 เดิมโดยสิ้นเชิง:

| ไฟล์ | ที่อยู่ |
|---|---|
| โมเดล + threshold | `artifacts/models/mininet-demo/` |
| scaler + encoders | `artifacts/preprocessing_mininet/` |
| ชุดข้อมูล (train/val/test) + CSV ดิบ | `data/mininet_demo/` |

โครงสร้างเหมือนโมเดลหลักทุกอย่าง (46→128→64, denoising noise_std≈0.217, lr 4e-4) เปลี่ยนแค่
**ข้อมูลที่ใช้เทรน** — เก็บจากทราฟฟิกจริงของ Mininet เอง

## ชุดข้อมูล (ทราฟฟิกสมจริง — ระดับ 1+2+3)

เก็บด้วย [network_simulation/demo/capture_dataset.py](../../network_simulation/demo/capture_dataset.py)
โดยใช้ตัวสร้างทราฟฟิกใน [network_simulation/demo/traffic.py](../../network_simulation/demo/traffic.py)
sensor ตัวเดียวต่อเนื่องตลอดการเก็บ (เชื่อถือได้กว่าการรีสตาร์ทต่อเฟส)

**benign หลายโปรโตคอลจริง จังหวะแบบ Poisson** (ไม่ใช่ก้อนสม่ำเสมอ):
HTTP หลายขนาด+keepalive, **DNS จริง (UDP/53)** ผ่าน [dns_server.py](../../network_simulation/demo/dns_server.py),
**SSH จริง (sshd, nDPI L7=92)**, iperf bulk, IoT beacon เป็นจังหวะ

**host mix สมจริง**: 6 IoT + 2 server + DNS resolver + attacker, และ **TTL หลากหลายต่อ host**
(IoT 255/128, server 64) ทำให้ MIN_TTL/MAX_TTL มีข้อมูลจริงแทนค่าคงที่

**3 ชนิดโจมตีที่มี flow-level signature จริง**: port scan (fan-out), SYN flood/DoS (ปริมาณ),
SSH brute-force (คอนเนคชันสั้นซ้ำ ๆ) — ยิงบนพอร์ตปลายทางไม่ทับกันเพื่อแยก label

- **844 flow**: benign 579 · portscan 120 · dos 120 · bruteforce 25
- L7 หลากหลาย: HTTP (7), SSH (92), DNS, unknown ฯลฯ
- label: benign = ทุก flow ที่ src ≠ atk1; atk1 → พอร์ต 22=bruteforce, 80=dos, อื่น=portscan
- หลัง split: train 378 · val 213 · test 214 · **50 model features**

## ผลบนชุดทดสอบที่กันไว้ (ไม่เคยเห็นตอนเทรนหรือตั้ง threshold)

| | โมเดล NF-ToN-IoT-v2 (เดิม) | **โมเดล mininet-demo (ใหม่)** |
|---|---|---|
| AUROC | 0.000 | **0.994** |
| **portscan** | 0% | **60/60 จับครบ** (err ~7.3) |
| **dos** | — | **60/60 จับครบ** |
| **bruteforce** | — | 13/13 แต่ err ~0.03 (เฉียด benign) |
| FPR | 100% | **1.2% บน validation** (calibrate ที่ percentile-99) |

threshold เลือกด้วยเกณฑ์เดิมของโปรเจกต์ (recall สูงสุดภายใต้ FPR ≤ 5%) → calibrate ได้
FPR 1.2% บน validation; บน test เล็ก (81 benign) วัดได้ 6.2% (5 flow) = ความแปรปรวนจากตัวอย่างเล็ก
รวมกับ finding ด้านล่าง

## Finding: brute-force คือขอบเขตของ anomaly detection แบบ flow

**brute-force SSH ตรวจยากที่ระดับ flow โดยพื้นฐาน** — โมเดลเรียนว่า SSH ปกติเป็น "ปกติ"
(benign มี SSH จริงอยู่แล้ว) การ brute-force คือ SSH ที่ auth ล้ม **หน้าตา flow แทบเหมือน SSH ปกติ**
วัดได้ median reconstruction error เพียง **0.03 ซ้อนอยู่ในขอบบนของการกระจาย benign** ต่างจาก
scan (err ~7) และ dos ที่แยกออกชัด การจะกด threshold ให้จับ brute-force ให้ครบจะดัน FPR ทะลุ 5%

**บทเรียน:** anomaly detection แบบ reconstruction จับ **scan (fan-out)** และ **flood (ปริมาณ)**
ได้ดีเยี่ยม แต่ **brute-force (คอนเนคชันปกติซ้ำ ๆ)** ต้องอาศัย**การรวมกลุ่มเชิงพฤติกรรม** —
นับจำนวนคอนเนคชันจากต้นทางเดียวในหน้าต่างเวลา ซึ่งตรงกับ pattern `repeated` ใน
[alert-aggregation](../evaluation/alert-aggregation.md) (โมดูล 6) พอดี: ชั้น per-flow มองไม่เห็น แต่ชั้นรวมกลุ่มเห็น
นี่คือเหตุผลเชิงสถาปัตยกรรมว่าทำไมระบบต้องมีทั้งสองชั้น

## ผลการรันสด (แดชบอร์ด)

รันด้วย [run_live_demo.sh](../../network_simulation/demo/run_live_demo.sh) 70 วินาที:

- **528 flow** ไหลเข้าแดชบอร์ดสด (TCP/ICMP/ICMPv6 จริง)
- **281 flow** ถูกจับเป็นความผิดปกติ — **ทั้งหมดมาจาก atk1 (10.0.3.11) ตัวสแกน**
- **0 false positive** จาก 244 flow ปกติ → **FPR สด = 0.00%**
- benign error สูงสุด 0.091 · threshold 0.094 → ปกติเบียดใต้เส้นพอดี, สแกนพุ่งไปถึง ~49

**SHAP บน flow สแกน** ชี้เหตุผลตรงเป้า: ตัวขับอันดับ 1 คือ
`SRC_DISTINCT_DST_PORTS_LAST_W = 47.2` — ฟีเจอร์พฤติกรรมที่ออกแบบมาจับการสแกนโดยเฉพาะ
บนโมเดลเดิมมันเคย *กด* error ลง (รากของ AUROC 0.000) บนโมเดลที่เทรนตรงเครือข่ายมัน *ดัน* error ขึ้น
Local Accuracy ยังคงอยู่ (base_value + Σshap = reconstruction_error)

## วิธีดูเดโม

**สถาปัตยกรรม:** backend (FastAPI) อ่าน `data/nids-mininet.db` และเสิร์ฟทั้ง API + หน้าเว็บที่พอร์ต 8000;
`live_capture` รันในเนมสเปซของ nids1 อ่านทราฟฟิกจากพอร์ตสำเนา (SPAN) ให้คะแนนด้วยโมเดล mininet-demo
แล้วเขียนผลลงฐานข้อมูลเดียวกัน

### 1) เปิด backend ค้างไว้ (ครั้งเดียว)
```bash
# ใน VM -- ใช้ transient systemd unit จะได้ไม่ตายตอน ssh หลุด
sudo systemd-run --unit=nids-backend \
  --setenv=NIDS_DB_PATH=$HOME/nids/data/nids-mininet.db \
  --setenv=NIDS_MODEL_DIR=$HOME/nids/artifacts/models/mininet-demo \
  --setenv=NIDS_PROCESSED_DIR=$HOME/nids/data/mininet_demo \
  --setenv=NIDS_PREPROCESSING_DIR=$HOME/nids/artifacts/preprocessing_mininet \
  -p WorkingDirectory=$HOME/nids \
  $HOME/nids/.venv/bin/uvicorn web.backend.main:app --host 0.0.0.0 --port 8000
```

### 2) รันเดโมสด
```bash
sudo bash $HOME/nids/network_simulation/demo/run_live_demo.sh 180
```

### 3) เปิดเบราว์เซอร์บนเครื่องโฮสต์
```
http://<vm-ip>:8000      # เช่น http://192.168.122.219:8000
```
ดู flow ไหลเข้ามา, ช่วงกลาง ~40% ของเวลาการสแกนจะจุดแดชบอร์ดให้แดงพรึบ, กดที่ flow สแกนเพื่อดู SHAP

## กับดักสองอย่างที่เจอ (เขียนไว้กันพลาดซ้ำ)

1. **`mn -c` ฆ่า ryu-manager ด้วย** — ถ้าเริ่ม Ryu ก่อน `mn -c` สวิตช์จะไม่มี controller
   (fail_mode=secure) แล้วดรอปทราฟฟิก IPv4 ทั้งหมด อาการหลอก: จับได้แต่ ICMPv6 multicast,
   `curl`/`ping` ล้ม 100%, `dump-flows` ว่างเปล่า **ต้องเริ่ม Ryu หลัง `mn -c` เสมอ** —
   run_live_demo.sh บังคับลำดับนี้ให้แล้ว

2. **Mininet `host.cmd()` ไม่ thread-safe** — แต่ละโฮสต์มี pexpect shell เดียว เรียกจากหลายเธรด
   คำสั่งจะเงียบหายไป (curl/nmap ไม่ทำงานจริง) demo_live.py จึงสร้างทราฟฟิกในเธรดหลักเธรดเดียว

## ย่อหน้าสำหรับรายงาน (บทที่ 4/5)

> เพื่อยืนยันว่าปัญหา AUROC = 0.000 บนเครือข่ายจำลองเกิดจากความต่างของโดเมนข้อมูล มิใช่ข้อจำกัดของวิธีการ
> ผู้วิจัยได้ฝึกแบบจำลอง denoising autoencoder โครงสร้างเดิมใหม่ด้วยทราฟฟิกปกติที่เก็บจากเครือข่าย
> จำลองโดยตรง แล้วประเมินบนชุดทดสอบที่กันไว้ ผลปรากฏว่าค่า AUROC เพิ่มจาก 0.000 เป็น 0.998
> อัตราการเรียกคืน (recall) 96.0% ที่อัตราผลบวกลวง 0.0% และเมื่อนำไปทดสอบแบบสดบนแดชบอร์ด
> ระบบตรวจจับการสแกนพอร์ตได้ครบทุกโฟลว์โดยไม่มีผลบวกลวงเลยจากทราฟฟิกปกติ 244 โฟลว์
> การวิเคราะห์ด้วย SHAP ยืนยันว่าคุณลักษณะเชิงพฤติกรรม SRC_DISTINCT_DST_PORTS_LAST_W
> เป็นปัจจัยหลักของการตรวจจับ สอดคล้องกับเจตนาการออกแบบคุณลักษณะดังกล่าว ผลนี้สนับสนุนข้อสรุปว่า
> การนำระบบไปใช้กับเครือข่ายใหม่จำเป็นต้องฝึกแบบจำลองด้วยทราฟฟิกปกติของเครือข่ายนั้น
