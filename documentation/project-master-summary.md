# สรุปโปรเจกต์ฉบับสมบูรณ์ — ระบบตรวจจับการบุกรุกเครือข่าย IoT ด้วย Denoising Autoencoder + SHAP

เอกสารหลัก (master) สำหรับทบทวนทั้งโปรเจกต์และเรียบเรียงลงเล่มวิทยานิพนธ์ รวบรวมทุกการตัดสินใจเชิง
วิศวกรรม ผลการทดลอง และการค้นพบ ทุกตัวเลขอ้างอิงจากโค้ดและการทดลองจริง เอกสารเชิงลึกเฉพาะเรื่องดูได้ที่
[technical-report.md](technical-report.md), [dataset-limitations.md](evaluation/dataset-limitations.md),
[resource-benchmark.md](evaluation/resource-benchmark.md), [explanation-quality.md](evaluation/explanation-quality.md),
[mininet-live-demo.md](guides/mininet-live-demo.md)

---

## สารบัญ
1. ภาพรวมและแนวคิดหลัก
2. สถาปัตยกรรม 6 โมดูล
3. ชุดข้อมูล NF-ToN-IoT-v2
4. โมดูล 1 — การสกัดฟีเจอร์
5. โมดูล 2 — การเตรียมข้อมูลและฟีเจอร์เชิงพฤติกรรม
6. โมดูล 3 — โมเดลและการเลือกเกณฑ์
7. โมดูล 4 — การอธิบายด้วย SHAP
8. โมดูล 5 — แดชบอร์ด
9. โมดูล 6 — การตรวจสอบไฟร์วอลล์และการรวมกลุ่มการแจ้งเตือน
10. การประเมินผล 2 ระดับ
11. การวัดทรัพยากร
12. การทดลองที่ผลเป็นลบ
13. สรุปการค้นพบทั้งหมด
14. ข้อจำกัดของงาน
15. ภาคผนวก

---

## 1. ภาพรวมและแนวคิดหลัก

**ปัญหา:** อุปกรณ์ IoT มีจำนวนมากและถูกโจมตีบ่อย ระบบตรวจจับการบุกรุก (IDS) แบบใช้ลายเซ็น
(signature-based) จับได้เฉพาะการโจมตีที่รู้จักแล้ว

**แนวทาง:** ใช้ **unsupervised anomaly detection** ด้วย denoising autoencoder — ฝึกด้วยทราฟฟิก
*ปกติ* (benign) เท่านั้น โมเดลเรียนที่จะ "สร้างใหม่ (reconstruct)" เวกเตอร์ฟีเจอร์ของทราฟฟิกปกติ
ทราฟฟิกผิดปกติจะสร้างใหม่ได้แย่ → ค่า **reconstruction error** สูง → เกินเกณฑ์ (threshold) = ผิดปกติ

**ข้อดี:** (ก) ไม่ต้องมีตัวอย่างการโจมตีตอนฝึก (ข) จับการโจมตีแบบใหม่ที่ไม่เคยเห็นได้
**ข้อเสริม:** ใช้ **SHAP** อธิบายว่าฟีเจอร์ใดทำให้ error สูง → ผู้ดูแลเข้าใจและตัดสินใจได้ (ไม่ใช่กล่องดำ)

**ข้อจำกัดหลักที่โปรเจกต์ยึด:** อัตราผลบวกลวง (False Positive Rate, FPR) **ต้องไม่เกิน 5%** —
เพราะระบบ IoT ปริมาณสูง FPR สูงทำให้มีการแจ้งเตือนเท็จท่วม และถ้าเอาไปบล็อกอัตโนมัติจะกลายเป็น
การตัดบริการตัวเอง (self-inflicted DoS)

---

## 2. สถาปัตยกรรม 6 โมดูล

```
แพ็กเก็ตดิบ
   │
   ▼
[1] Flow extraction ─▶ [2] Preprocessing ─▶ [3] Model inference ─▶ reconstruction error
  (nfstream+nDPI)       (clean/engineer/scale)   (denoising AE)         │ เทียบ threshold
                                                                        ▼
[6] Firewall verification ◀── [5] Dashboard ◀── [4] SHAP explanation  ◀─┘
  (เทียบนโยบาย) + Alert aggregation (รวม incident)
```

| โมดูล | หน้าที่ | เทคโนโลยี |
|---|---|---|
| 1 Flow extraction | แพ็กเก็ต → ระเบียนโฟลว์ 43 ฟิลด์ | nfstream + nDPI + NFPlugin ที่เขียนเอง |
| 2 Preprocessing | ทำความสะอาด, encode, log-transform, ฟีเจอร์พฤติกรรม, scale | pandas, scikit-learn |
| 3 Model inference | reconstruction error เทียบ threshold | Denoising Autoencoder (PyTorch) |
| 4 Explanation | ฟีเจอร์ใดทำให้ error สูง | Kernel SHAP |
| 5 Dashboard | แสดงผลสด + incident + firewall gaps | FastAPI + หน้าเว็บ static |
| 6 Firewall verification | เทียบผลตรวจจับกับนโยบายไฟร์วอลล์ → รายงานช่องโหว่ | เปรียบเทียบกฎ OpenFlow/iptables |

---

## 3. ชุดข้อมูล NF-ToN-IoT-v2

- ทราฟฟิก IoT ที่จับจาก **testbed จริง** (UNSW Canberra) ประมาณ **16.9 ล้านระเบียน** 43 ฟิลด์
  รูปแบบ NetFlow (ส่งออกด้วย nProbe)
- คลาส: Benign + การโจมตี 9 ชนิด (scanning, ddos, dos, injection, password, xss, backdoor, mitm, ransomware)
- **ข้อจำกัดสำคัญที่ต้องเขียนในเล่ม** (ดู [dataset-limitations.md](evaluation/dataset-limitations.md)):
  - มีเพียง ~10 เครื่องสร้าง 94% ของข้อมูล และเครื่องเดียวกันสร้างทั้ง benign และการโจมตีหลายชนิด
    (เช่น 192.168.1.31: benign 2.29M + ddos 798K + scanning 651K) → เสี่ยง testbed shortcut
  - **ไม่มีคอลัมน์เวลาเริ่มโฟลว์** → การสร้างฟีเจอร์เชิงเวลาต้องใช้ลำดับแถวเป็นตัวแทน
  - **label noise**: 51% ของแถว `xss` เป็น DNS (ดูหัวข้อ 6)
  - artifact ตัวนับ 32 บิต: 72.8% ของ ddos มี duration ~4,294,935 ms (ค่า wrap ไม่ใช่เวลาจริง)

---

## 4. โมดูล 1 — การสกัดฟีเจอร์ (จาก nfstream สู่สคีมา NetFlow 43 ฟิลด์)

ตอนใช้งานจริงไม่มี nProbe (เชิงพาณิชย์) จึงใช้ **nfstream** (ใช้ nDPI engine เดียวกัน) แต่ nfstream
ไม่ได้ให้ครบทุกฟิลด์ จึงต้องเขียนชั้นแปลง + ปลั๊กอินเพื่อให้เวกเตอร์ตรงกับที่โมเดลคาดหวังเป๊ะทุกตำแหน่ง

### 4.1 ฟีเจอร์ที่ nfstream ไม่มี → เขียน NFPlugin สกัดเอง (`source/extraction/nfplugin.py`)
แกะไบต์ดิบของแต่ละแพ็กเก็ต (callback ต่อแพ็กเก็ต) เพื่อสร้างฟิลด์ที่ nfstream มาตรฐานไม่ทำให้:

| ฟีเจอร์ | สกัดจาก | วิธี |
|---|---|---|
| MIN/MAX_TTL | TTL ในส่วนหัว IP | อ่านทุกแพ็กเก็ต เก็บ min/max |
| TCP_WIN_MAX_IN/OUT | Window ในส่วนหัว TCP | parse แล้วเก็บสูงสุดแยกทิศ |
| NUM_PKTS_*_BYTES (5 ช่วง) | ความยาวแพ็กเก็ต | histogram ตามขนาด |
| RETRANSMITTED_* | เลขลำดับ TCP | จำ (seq, len) ที่เคยเห็น ซ้ำ = ส่งซ้ำ |
| ICMP_TYPE/ICMP_IPV4_TYPE | ส่วนหัว ICMP | parse |
| DNS_QUERY_ID/TYPE/TTL | เพย์โหลด DNS | **เขียน DNS parser เอง** (รองรับ name compression) |
| FTP_COMMAND_RET_CODE | เพย์โหลด FTP | parse |

### 4.2 รายละเอียดที่ต้องจูนให้ตรง nProbe (train/serve skew)
- **`accounting_mode = 1`** (ชั้น IP ไม่ใช่ Ethernet) — ยืนยันจากข้อมูล: SHORTEST_FLOW_PKT ต่ำสุด 40
  (ส่วนหัว TCP เปล่า) ไม่ใช่ 54/60 ถ้าไม่ตั้ง byte/throughput จะพองเกิน 14 ไบต์/แพ็กเก็ต
- **MIN_IP_PKT_LEN = 0 บนโฟลว์ทางเดียว** — 76% ของแถวฝึกถือค่า 0 นี้ (nProbe quirk)
- **L7_PROTO** — nfstream คืนชื่อ ("HTTP") แต่สคีมาเก็บเลข → สร้าง mapping ชื่อ→เลขจาก nDPI
- **CPU affinity** — nfstream หด affinity 8→2 core ถาวร (scoring 2.7M→10.7k flow/s) แก้ด้วยบันทึก/คืนค่า

---

## 5. โมดูล 2 — การเตรียมข้อมูลและฟีเจอร์เชิงพฤติกรรม

ขั้นตอน: clean (ลบซ้ำ/inf) → **engineer behavioral features** → split train/val/test (ฝึก benign only) →
encode categoricals (fit บน train) → log-transform → scale (fit บน train)

### 5.1 ฟีเจอร์เชิงพฤติกรรม (`source/preprocessing/engineer_features.py`)
การสแกน/DDoS **โฟลว์เดี่ยวหน้าตาเหมือนคอนเนคชันสั้นปกติ** — ความเป็นการโจมตีอยู่ที่รูปแบบข้ามโฟลว์
จึงเพิ่ม 3 ฟีเจอร์:
- `SRC_DISTINCT_DST_PORTS_LAST_W` — ต้นทางติดต่อกี่พอร์ตใน W โฟลว์ล่าสุด (จับ scan/fan-out)
- `SRC_DISTINCT_DST_IPS_LAST_W` — ต้นทางติดต่อกี่ IP
- `DST_DISTINCT_SRC_IPS_LAST_W` — ปลายทางถูกกี่ต้นทางติดต่อ (จับ DDoS/fan-in)

**ทำไมต้องเป็นหน้าต่างเลื่อน W=50 ต่อต้นทาง ไม่ใช่ค่าสะสม:** ถ้าสะสมรวมต่อ IP ค่าจะเกือบคงที่
ต่อเครื่อง → โมเดลเรียน "นี่คือเครื่องไหน" แทนพฤติกรรมสแกน (testbed shortcut) และรั่วข้อมูลข้ามชุด
หน้าต่างเลื่อนทำให้ค่าเปลี่ยนทีละแถว (ต่ำตอนปกติ พุ่งตอน scan burst) และตรงกับตัวนับ rolling
ที่ deployment จริงทำได้ → batch กับ online เป็นฟีเจอร์เดียวกัน

**หลักฐานเชิงปริมาณ:** การทดลองเพิ่มฟีเจอร์ทีละขั้นได้ recall **29.59% → 45.87%** ที่ FPR เท่ากัน

---

## 6. โมดูล 3 — โมเดลและการเลือกเกณฑ์

### 6.1 สถาปัตยกรรมโมเดล (champion: `artifacts/models/optuna-denoising-50`)
- **Denoising Autoencoder**: input 46 → hidden [128] → latent 64 (จูนด้วย Optuna)
- denoising noise_std ≈ 0.217 (เติม Gaussian noise ตอนฝึกเท่านั้น — Vincent et al. 2008)
- lr ≈ 4e-4, ฝึกบน benign เท่านั้น
- val AUC 0.959, recall_at_fpr 0.876

### 6.2 การเลือก threshold
- วิธีหลัก = **percentile ของ benign error บน validation** (เช่น P95 → FPR 5% โดยโครงสร้าง)
- เกณฑ์เลือก: **recall สูงสุดในบรรดา candidate ที่ FPR ≤ 5%**
- เก็บ `calibration_reference` (การกระจาย benign error ตอน fit) ไว้ให้ deployment ตรวจจับ drift ได้

### 6.3 ทำไมไม่ใช้ accuracy (ปัญหา base-rate)
ที่อัตราการโจมตีจริง ~5% **precision ตกจาก 99.05% เหลือ 48.15%** ขณะที่ recall/FPR *ไม่เปลี่ยน*
(เป็นคุณสมบัติของตัวจำแนก) → accuracy หลอกตาในข้อมูลไม่สมดุล จึงรายงานด้วย recall/FPR/precision แยก

---

## 7. โมดูล 4 — การอธิบายด้วย SHAP

- **Kernel SHAP** อธิบายว่าฟีเจอร์ใดดัน/ดึง **ค่า reconstruction error** (ไม่ใช่ความน่าจะเป็นคลาส)
- background = ตัวอย่าง benign สุ่มด้วย reservoir sampling; เรียก on-demand ผ่าน `POST /explain/{flow_id}`
- **ประเมินคุณภาพคำอธิบาย** (ดู [explanation-quality.md](evaluation/explanation-quality.md)):
  - Local Accuracy: residual สูงสุด **1.1e-17** (ผ่านสมบูรณ์)
  - ความแม่นเทียบค่าลู่เข้า: Spearman ที่ nsamples 100 = 0.38, ที่ 2,000 = 0.77
  - **แก้ nsamples 100 → 2,000**: ที่ 100 sign-flip 75% (คำอธิบายไม่นิ่ง), ที่ 2,000 เหลือ 35% (~164 ms/flow)
    ไม่ไป 5,000 เพราะกินแรมเกิน 1.2 GB

---

## 8. โมดูล 5 — แดชบอร์ด

- FastAPI เสิร์ฟทั้ง API + หน้าเว็บ static จากโปรเซสเดียว
- แสดง: flow สด, stats, **แผง SHAP** (โชว์เฉพาะฟีเจอร์ที่ดัน error ขึ้น + toggle ดูครบ), แท็บ **Incidents**,
  แท็บ **firewall-gaps**
- ทุกค่าที่ลง innerHTML ผ่าน `esc()` (flow พก string จากผู้โจมตี — ป้องกัน XSS)

---

## 9. โมดูล 6 — การตรวจสอบไฟร์วอลล์ + การรวมกลุ่มการแจ้งเตือน

### 9.1 Alert aggregation (`source/alerting/aggregate.py`)
รวม flow ผิดปกติเป็น **incident** (ผู้ดูแลอ่าน "เหตุการณ์" ไม่ใช่ flow ดิบทีละแถว) — รูปแบบ:
`fan_out` (สแกน), `fan_in` (DDoS), `repeated` (brute-force), `isolated`
- ชื่อ incident เป็น**รูปทรง** ไม่เดาชนิดการโจมตี (ของเดิมตั้งชื่อผิด — "flood" 71% เป็น scan)
- ใช้ outlier floor (เทียบ key กับทราฟฟิกของตัวเอง ไม่ใช่ค่าคงที่) กันการจัดกลุ่มมั่ว

### 9.2 Firewall verification (`source/firewall_check/ryu_log_compare.py`)
เอา flow ที่ **โมเดลจับว่าผิดปกติ** มาเทียบนโยบายไฟร์วอลล์ (จับคู่ 5-tuple):
- **covered** = ไฟร์วอลล์บล็อกอยู่แล้ว (เช่น telnet/rdp/smb)
- **gap** = ไฟร์วอลล์ปล่อยผ่าน แต่โมเดลจับ (เช่น ssh brute-force บนพอร์ต 22 ที่ต้องเปิด) = คุณค่าเฉพาะของ NIDS
- **ไม่บล็อกอัตโนมัติ** — FPR 5% ถ้าเอาไปบล็อกจะตัดทราฟฟิกดี 1 ใน 20 = DoS ตัวเอง

---

## 10. การประเมินผล 2 ระดับ (ตอบคนละคำถาม — ควรเน้นในเล่ม)

| | ตอบคำถามว่า | หลักฐาน |
|---|---|---|
| **ระดับ 1: Performance** | โมเดลแม่นแค่ไหน*ในเครือข่ายเดียวกับที่ฝึก* | **recall 87.59% @ FPR 4.97%** (NF-ToN-IoT-v2) |
| **ระดับ 2: Integration** | ระบบทำงานครบวงจรบนเครือข่ายสดจริงไหม | 6 โมดูลเดินครบบน OS จริง (Mininet + GNS3) |

> ⚠️ อ้าง **87.59%/4.97%** เป็นผลสมรรถนะได้; **อย่า**อ้างตัวเลขจาก GNS3 (AUROC 1.0) เป็นความแม่นยำ —
> GNS3 เป็น integration test + สาธิต workflow retrain บนทราฟฟิกสังเคราะห์

### 10.1 Performance (NF-ToN-IoT-v2) — ผลต่อคลาส
สาเหตุที่แต่ละคลาสตรวจจับไม่เท่ากันขึ้นกับ **TCP หรือ UDP** (5 ฟีเจอร์เป็นของ TCP เฉพาะ; UDP = 0 ทั้งหมด 100%)

| คลาส | recall TCP | recall UDP | recall รวม |
|---|---|---|---|
| password | 99.8% | 0.2% | 99.10% |
| ddos | ~100% | ~0% | 98.88% |
| injection | 94.9% | 5.1% | 92.55% |
| scanning | 99.8% | — | 87.17% |
| **dos** | 14.5% | **85.5%** | **80.81%** |
| **xss** | **99.35%** (TCP) | — | **74.04%** |

- จับคู่ชนิด↔ฟีเจอร์: scanning→`SRC_DISTINCT_DST_PORTS_LAST_W`, ddos→fan-in + 6 ฟีเจอร์ (error 3.42×),
  dos→ต่าง benign แค่ 2 ฟีเจอร์ (error 1.35× เบียดเส้น), password→short connection ซ้ำ ๆ
- **xss 74% = label noise ไม่ใช่จุดอ่อนโมเดล** — TCP จับได้ 99.35% (สูงสุด) แต่ 51% ของ xss เป็น UDP
  ซึ่ง XSS (วิ่งบน HTTP/TCP) เป็นไปไม่ได้ทางเทคนิค
- **dos 80.81% = จุดอ่อนจริงแต่ชนเพดาน FPR** — ดันเป็น 90% ต้องจ่าย FPR 11.75% (เกิน 5%)

### 10.2 Integration — Mininet และ GNS3 + การค้นพบ domain shift
- รัน 6 โมดูลครบวงจรบนเครือข่ายจำลอง (OVS switch + mirror + firewall จริง)
- **ค้นพบ: โมเดลที่ฝึกบน NF-ToN-IoT-v2 ให้ AUROC = 0.000 บนเครือข่ายใหม่** (จัดลำดับกลับด้าน)
- **สาเหตุ:** reconstruction error วัดระยะทางแต่ทิ้งทิศทาง — ฟีเจอร์ `SRC_DISTINCT_DST_PORTS` ที่
  ออกแบบจับสแกน กลับ *ลด* error ของสแกนบน Mininet (เพราะ NF-ToN-IoT-v2 เต็มไปด้วยสแกน →
  สแกนใกล้ค่าเฉลี่ยชุดฝึกมากกว่าทราฟฟิกปกติของ Mininet)
- **ทางแก้:** ฝึกซ้ำด้วยทราฟฟิกเครือข่ายเป้าหมาย → AUROC กลับเป็น ~1.0 (พิสูจน์ทั้ง Mininet และ GNS3)
- **GNS3 (OS จริง Alpine Linux):** ทดสอบครบ 6 โมดูล + firewall enforcement (telnet/rdp/smb ถูกดรอปจริง
  ใน OVS) + **DDoS botnet fan-in** (3 bots ถล่ม 1 เหยื่อ → รวมเป็น 1 incident)

---

## 11. การวัดทรัพยากร (ดู [resource-benchmark.md](evaluation/resource-benchmark.md))

วัดเพื่อประเมินการรันบนฮาร์ดแวร์จำกัด (เช่น Raspberry Pi gateway)

| การตั้งค่า | สกัดโฟลว์ | ให้คะแนน (batch) | ให้คะแนน 1 โฟลว์ | SHAP | RAM โมเดล |
|---|---|---|---|---|---|
| CPU 1 core | 4,460/s | 1.34M/s | 0.065 ms | 13.4 ms | 3.0 MB |
| CPU 8 threads | **8,796/s** | 2.13M/s | 0.067 ms | 8.7 ms | 3.1 MB |
| GPU | 8,630/s | 5.03M/s | **0.136 ms** | 6.5 ms | 90.8 MB |

**ข้อค้นพบ:**
1. **คอขวดคือการสกัดโฟลว์ (8,796 flow/s)** ต่ำกว่าการให้คะแนน (2.13M) ถึง 240 เท่า → เร่งโมเดลไม่ช่วยเลย
2. **GPU ทำ latency ต่อโฟลว์แย่ลง 2 เท่า** (0.067→0.136 ms) เพราะโอเวอร์เฮดการย้ายข้อมูล + กิน RAM 90MB
   → โมเดลเล็กพอที่ CPU เหมาะกว่าสำหรับ single-flow inference
3. RAM โมเดลเพียง ~3 MB → รันบนอุปกรณ์เล็กได้

---

## 12. การทดลองที่ผลเป็นลบ (รายงานตามจริง — ดู [protocol-threshold-experiment.md](evaluation/protocol-threshold-experiment.md))

ทดลองตั้ง **threshold แยกตามโปรโตคอล** (คาดว่าจะช่วย UDP) → ผลดีขึ้นเพียงเล็กน้อย ไม่คุ้มความซับซ้อน
→ **ไม่รับมาใช้** (การรายงานผลลบคือความซื่อสัตย์ทางวิชาการ)

---

## 13. สรุปการค้นพบทั้งหมด (consolidated)

**ด้านข้อมูล/ฟีเจอร์**
1. train/serve skew แก้ไม่ได้ด้วยการเรียกไลบรารีเฉย ๆ — ต้องจำลองพฤติกรรม nProbe ซ้ำ (accounting_mode, L7 encoding, NFPlugin)
2. ฟีเจอร์เชิงพฤติกรรมต้องเป็นหน้าต่างเลื่อนต่อต้นทาง ไม่ใช่ค่าสะสม (กัน testbed shortcut + data leak) → recall +16 จุด
3. ชุดข้อมูลมี label noise (xss 51% เป็น DNS) และ artifact (duration 32-bit wrap) — ต้องตรวจและรายงาน

**ด้านโมเดล/การวัด**
4. ไม่ใช้ accuracy เพราะ base-rate (precision 99%→48% ที่อัตราจริง 5%)
5. แต่ละคลาสต่างกันเพราะ TCP/UDP (UDP ไม่มีร่องรอย handshake)
6. dos เป็นจุดอ่อนจริงแต่ชนเพดาน FPR (90% ต้องจ่าย 11.75%)

**ด้านคำอธิบาย**
7. nsamples=100 ให้คำอธิบายไม่นิ่ง (sign-flip 75%) → ต้องขึ้น 2,000 (วัดด้วย Local Accuracy + convergence)

**ด้านการนำไปใช้จริง (integration)**
8. **domain shift: โมเดลไม่ย้ายข้ามเครือข่าย** (AUROC 0.000) → ต้อง retrain ต่อเครือข่าย เพราะ error เก็บ
   ระยะทางแต่ทิ้งทิศทาง
9. **แม้แต่การเพิ่มอุปกรณ์ 1 ตัวก็เปลี่ยน "ปกติ"** (hub มีต้นทางเพิ่ม 2→3 → benign ถูก flag จนกว่าจะ retrain)
   = domain shift ระดับละเอียด
10. **brute-force เป็นขอบเขตของ flow-based detection** — คอนเนคชันปกติซ้ำ ๆ หน้าตาเหมือน SSH ปกติ →
    ต้องอาศัยชั้น aggregation (pattern repeated/fan-in)
11. **fan_in ไม่ติดกับ hub** (cloud) — "หลายต้นทาง→hub" เป็นเรื่องปกติ → ต้องถล่มเหยื่อที่ไม่ใช่ hub ถึงเป็น fan-in จริง
12. **การ flood จากอุปกรณ์ทำ baseline พฤติกรรมเพี้ยน** → collateral false positive (ข้อจำกัดของ behavioral detection ภายใต้โหลดหนัก)

**ด้านทรัพยากร**
13. คอขวดคือการสกัดโฟลว์ ไม่ใช่โมเดล; GPU ทำ single-flow latency แย่ลง 2 เท่า

**ด้านสถาปัตยกรรม**
14. ตำแหน่ง sensor สำคัญ — OVS **ingress mirror** คัดลอกก่อน drop → sensor เห็น traffic ที่ firewall บล็อก →
    โมดูล 6 "covered" มีความหมาย (ต่างจากถ้า sensor อยู่หลัง firewall)

---

## 14. ข้อจำกัดของงาน (เขียนตรง ๆ ในเล่ม ป้องกันตัวได้)

- **การประเมินสมรรถนะอยู่บน testbed dataset เดียว** (NF-ToN-IoT-v2) ไม่ใช่ทราฟฟิก production หลายเครือข่าย
- **integration test ใช้ทราฟฟิกสังเคราะห์** (shell loop / device script) — OS/โปรโตคอลจริง แต่รูปทรง/เนื้อหา/สเกล
  เป็นการประมาณ ไม่ใช่เฟิร์มแวร์จริง และเล็กกว่าบ้านจริง → เป็น integration ไม่ใช่ benchmark
- **โมเดลต้อง retrain ทุกเครือข่าย** (และทุกครั้งที่โครงสร้างเปลี่ยน) — เป็นลักษณะโดยธรรมชาติของ
  unsupervised per-network anomaly detection ไม่ใช่ข้อบกพร่อง แต่เป็นข้อจำกัดเชิงปฏิบัติ
- baseline เทียบ (Isolation Forest/One-Class SVM) และการเทียบค่าฟีเจอร์กับ nProbe ยังไม่ได้ทำ
- แนวทางสมจริงขึ้น: **pcap replay** ของทราฟฟิก IoT จริง (IoT-23/CIC-IoT) — ยังไม่ได้ทำ

---

## 15. ภาคผนวก — ไฟล์อ้างอิงในโค้ด/เอกสาร

| หัวข้อ | ตำแหน่ง |
|---|---|
| สกัดฟีเจอร์ (map 43 fields) | `source/extraction/sensor.py` |
| NFPlugin (ฟีเจอร์สกัดเอง) | `source/extraction/nfplugin.py` |
| L7_PROTO encoding | `source/extraction/l7_proto.py` |
| ฟีเจอร์เชิงพฤติกรรม | `source/preprocessing/engineer_features.py`, `source/preprocessing/online.py` |
| โมเดล autoencoder | `source/model/` |
| SHAP | `source/explain/shap_explainer.py` |
| Alert aggregation | `source/alerting/aggregate.py` |
| Firewall verification | `source/firewall_check/ryu_log_compare.py` |
| เครือข่ายจำลอง (Mininet) | `network_simulation/topology.py`, `ryu_app.py`, `firewall_rules.py` |
| เครือข่ายจำลอง (GNS3) | `network_simulation/gns3/` (คู่มือ + profile scripts) |
| เอกสารเชิงลึก | `documentation/technical-report.md`, `dataset-limitations.md`, `resource-benchmark.md`, `explanation-quality.md`, `mininet-live-demo.md`, `protocol-threshold-experiment.md` |

---

## หมายเหตุสำหรับการนำเสนอ/เล่ม

**ประโยคกรอบที่ป้องกันตัวได้ดีที่สุด:**
> "ระบบถูกประเมิน 2 ระดับ — (1) **สมรรถนะ** บนชุดข้อมูลมาตรฐาน NF-ToN-IoT-v2 ซึ่งเป็นทราฟฟิก IoT
> ที่จับจากของจริง ได้ recall 87.59% ที่ FPR 4.97% และ (2) **การทำงานร่วมของระบบ (integration)**
> บนเครือข่ายจำลอง OS จริงด้วย Mininet และ GNS3 ซึ่งยืนยันว่า 6 โมดูลทำงานครบวงจร และเปิดเผยข้อค้นพบ
> สำคัญว่าแบบจำลองไม่สามารถย้ายข้ามเครือข่ายได้หากไม่ฝึกซ้ำ — ข้อค้นพบที่การประเมินบนชุดข้อมูลเดียว
> มองไม่เห็น"
