# NIDS with Autoencoder + Explainable AI (SHAP)

ระบบตรวจจับการบุกรุกเครือข่าย (Network Intrusion Detection System) แบบ unsupervised โดยใช้ autoencoder ตรวจจับความผิดปกติจากข้อมูลระดับโฟลว์ของเครือข่าย IoT ร่วมกับ Kernel SHAP อธิบายผลแบบ on-demand และมีโมดูลตรวจสอบความสอดคล้องของไฟร์วอลล์เป็นส่วนเสริม

โปรเจกต์นี้เป็นโครงงานปริญญาตรี (CS 2568, CP354771 โครงงานทางวิทยาการคอมพิวเตอร์ 1) สาขาวิทยาการคอมพิวเตอร์ วิทยาลัยการคอมพิวเตอร์ มหาวิทยาลัยขอนแก่น

## เป้าหมายหลัก

1. ตรวจจับความผิดปกติของโฟลว์เครือข่ายแบบ unsupervised (ไม่ต้องมีข้อมูล label ระหว่างใช้งานจริง) เพื่อรองรับการโจมตีรูปแบบใหม่ (zero-day)
2. อธิบายว่าทำไมโฟลว์หนึ่งถึงถูกตัดสินว่าผิดปกติ ด้วย SHAP เพื่อแก้ปัญหา black-box
3. ใช้เป็นกลไกตรวจสอบซ้ำ (secondary verification) ว่ากฎไฟร์วอลล์ที่ตั้งไว้ครอบคลุมจริงหรือไม่

## ข้อจำกัดที่ต้องยึดถือ (non-negotiable constraints)

- **ห้าม auto-block** — โมดูลตรวจสอบไฟร์วอลล์เป็น post-hoc verification เท่านั้น ไม่แก้ไขกฎไฟร์วอลล์อัตโนมัติ (ป้องกัน self-inflicted DoS จาก false positive)
- **SHAP ต้องเป็น on-demand เท่านั้น** ห้ามรันกับทุกโฟลว์แบบ real-time เพราะ Kernel SHAP มีต้นทุนการคำนวณสูง ให้รันเฉพาะเมื่อผู้ใช้ร้องขอผ่าน dashboard
- **ฟีเจอร์ที่สกัดด้วย NFStream ต้องตรงกับ schema 43 ฟีเจอร์ของ NF-ToN-IoT-v2** (ดูรายการด้านล่าง) เพื่อไม่ให้เกิด train-serve skew ระหว่างข้อมูลฝึกกับข้อมูลที่สกัดสดตอนใช้งานจริง
- **Autoencoder ฝึกด้วยข้อมูล benign เท่านั้น** ห้ามใช้ label ของ attack ในการฝึก (ใช้เฉพาะตอน validation/test)
- **อย่ารายงานผลด้วย accuracy อย่างเดียว** — ข้อมูลไม่สมดุล (benign 36% / attack 64%, และบางคลาส เช่น Ransomware มีสัดส่วน <0.1%) ต้องรายงาน precision, recall, F1, FPR ทั้งระดับภาพรวมและระดับรายคลาส

## Tech stack

| ส่วน | เทคโนโลยี | เหตุผล |
|---|---|---|
| ภาษาหลัก | Python | ระบบนิเวศเดียวกันทั้งหมด |
| Deep learning | PyTorch | ยืดหยุ่นสำหรับสร้าง autoencoder เอง |
| Flow extraction | NFStream + custom NFPlugin | ต้องเขียน plugin คำนวณฟีเจอร์ให้ตรง NetFlow v9 schema |
| Preprocessing | scikit-learn | feature scaling / standardization |
| Explainability | SHAP (KernelExplainer) | model-agnostic ใช้กับ autoencoder ได้โดยตรง |
| Network simulation | Mininet + Ryu (SDN controller) | เบากว่า GNS3, เขียนด้วย Python, รองรับ OpenFlow |
| Firewall reference | iptables / nftables | ใช้เป็นกฎอ้างอิงในสภาพแวดล้อมจำลอง |
| Backend | FastAPI | เรียกโมดูล ML ในโปรเซสเดียวกันได้ตรง, รองรับ REST |
| Database | SQLite | เบา ไม่ต้องตั้งเซิร์ฟเวอร์แยก |
| Frontend | HTML/JS + Chart.js | แดชบอร์ดเล็ก ไม่จำเป็นต้องใช้เฟรมเวิร์กหนัก |
| Attack simulation | hping3, Metasploit | ยิงทดสอบใน Mininet |
| OS ที่ใช้พัฒนา | Pop!_OS (Linux) | Mininet รองรับเต็มรูปแบบ ไม่ต้องผ่าน VM |

## Dataset: NF-ToN-IoT-v2

- ดาวน์โหลด: https://staff.itee.uq.edu.au/marius/NIDS_datasets/ (หัวข้อ "NetFlow V2 Datasets" → "NF-ToN-IoT-v2") หรือ mirror ที่ Kaggle: https://www.kaggle.com/datasets/dhoogla/nftoniotv2
- อ้างอิง: Sarhan, M., Layeghy, S., & Portmann, M. (2022). Towards a standard feature set for network intrusion detection system datasets. *Mobile Networks and Applications, 27*(1), 357–370. doi:10.1007/s11036-021-01843-0
- ชุดข้อมูลต้นทาง: Alsaedi, A., Moustafa, N., Tari, Z., Mahmood, A., & Anwar, A. (2020). TON_IoT telemetry dataset. *IEEE Access, 8*, 165130–165150.
- ขนาด: 16,940,496 โฟลว์ (attack 63.99% / benign 36.01%)
- 10 คลาส: Benign, Scanning, XSS, DDoS, Password, DoS, Injection, Backdoor, MITM, Ransomware
- คอลัมน์ label: `Label` (0/1) และ `Attack` (ชื่อคลาส หรือ "Benign")

### 43 ฟีเจอร์ NetFlow v2 (ต้องใช้ชื่อคอลัมน์เดียวกันทุกตัวอักษร)

```
IPV4_SRC_ADDR, IPV4_DST_ADDR, L4_SRC_PORT, L4_DST_PORT, PROTOCOL, L7_PROTO,
IN_BYTES, OUT_BYTES, IN_PKTS, OUT_PKTS, FLOW_DURATION_MILLISECONDS,
TCP_FLAGS, CLIENT_TCP_FLAGS, SERVER_TCP_FLAGS, DURATION_IN, DURATION_OUT,
MIN_TTL, MAX_TTL, LONGEST_FLOW_PKT, SHORTEST_FLOW_PKT, MIN_IP_PKT_LEN,
MAX_IP_PKT_LEN, SRC_TO_DST_SECOND_BYTES, DST_TO_SRC_SECOND_BYTES,
RETRANSMITTED_IN_BYTES, RETRANSMITTED_IN_PKTS, RETRANSMITTED_OUT_BYTES,
RETRANSMITTED_OUT_PKTS, SRC_TO_DST_AVG_THROUGHPUT, DST_TO_SRC_AVG_THROUGHPUT,
NUM_PKTS_UP_TO_128_BYTES, NUM_PKTS_128_TO_256_BYTES, NUM_PKTS_256_TO_512_BYTES,
NUM_PKTS_512_TO_1024_BYTES, NUM_PKTS_1024_TO_1514_BYTES, TCP_WIN_MAX_IN,
TCP_WIN_MAX_OUT, ICMP_TYPE, ICMP_IPV4_TYPE, DNS_QUERY_ID, DNS_QUERY_TYPE,
DNS_TTL_ANSWER, FTP_COMMAND_RET_CODE
```

หมายเหตุ: ตัดฟีเจอร์ระบุตัวตน (IPV4_SRC_ADDR, IPV4_DST_ADDR, L4_SRC_PORT, L4_DST_PORT) ออกก่อนป้อนเข้าโมเดล เพื่อไม่ให้โมเดลเรียนรู้ทางลัดเฉพาะสภาพแวดล้อมทดสอบ (testbed-specific shortcuts) — เก็บไว้เฉพาะตอนบันทึกลง DB สำหรับแสดงผลบน dashboard

## สถาปัตยกรรมระบบ (6 โมดูล)

```
เครือข่าย IoT
     │
     ▼
[1] NFStream ──► สกัดฟีเจอร์ NetFlow v9 (43 ฟีเจอร์)
     │
     ▼
[2] scikit-learn ──► standardization / feature scaling
     │
     ▼
[3] Autoencoder (PyTorch) ──► reconstruction error + percentile threshold
     │                              │
     ▼                              ▼ (ล็อกจาก Ryu SDN)
[5] Dashboard (แดชบอร์ด)      [6] Firewall Verification Module
     │  ▲                          │
     │  │ (on-demand)              │
     ▼  │                          ▼
   ผู้ดูแลระบบ            บันทึกช่องโหว่ลง DB เดียวกัน
        │
        └──► [4] Kernel SHAP (อธิบายเฉพาะโฟลว์ที่ถูกร้องขอ)
```

1. **Flow extraction** — NFStream + custom NFPlugin ที่คำนวณ 43 ฟีเจอร์ให้ตรง schema ข้างต้น
2. **Preprocessing** — standardization (fit บน training set เท่านั้น แล้ว save scaler ไว้ใช้ตอน inference)
3. **Detection** — autoencoder (unsupervised, ฝึกด้วย benign only), threshold แบบ percentile-based เป็นหลัก (เทียบกับ KDE-based เป็นการทดลองเสริม)
4. **Explanation** — Kernel SHAP อธิบาย reconstruction error, เรียกเฉพาะ on-demand ผ่าน backend API
5. **Dashboard** — FastAPI backend + SQLite + HTML/JS frontend (ดูรายละเอียดด้านล่าง)
6. **Firewall verification** — เทียบล็อกไฟร์วอลล์ (Ryu) กับผลตรวจจับ, บันทึกช่องโหว่, ไม่บล็อกอัตโนมัติ

## Database schema (SQLite)

```sql
CREATE TABLE flows (
    flow_id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    reconstruction_error REAL NOT NULL,
    threshold_used REAL NOT NULL,
    is_anomaly INTEGER NOT NULL CHECK (is_anomaly IN (0, 1)),
    features_json TEXT NOT NULL
);

CREATE TABLE firewall_checks (
    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL REFERENCES flows(flow_id),
    firewall_rule_matched INTEGER CHECK (firewall_rule_matched IN (0, 1)),
    firewall_action_logged TEXT,
    gap_detected INTEGER CHECK (gap_detected IN (0, 1))
);

CREATE TABLE explanations (
    explanation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL REFERENCES flows(flow_id),
    requested_at DATETIME NOT NULL,
    shap_values_json TEXT NOT NULL,
    base_value REAL NOT NULL,
    computation_time_ms REAL
);
```

`explanations` แยกจาก `flows` เพราะ SHAP ถูกเรียกเฉพาะบางโฟลว์ (on-demand) — อย่ารวมคอลัมน์ SHAP ไว้ใน `flows` โดยตรง

## API endpoints (FastAPI)

| Method | Path | หน้าที่ |
|---|---|---|
| GET | `/alerts?since=<timestamp>` | ดึงผลตรวจจับล่าสุด (สำหรับ dashboard polling) |
| GET | `/flow/{flow_id}` | รายละเอียดโฟลว์เดียว |
| POST | `/explain/{flow_id}` | เรียก Kernel SHAP คำนวณ on-demand แล้วบันทึก+ส่งกลับผลลัพธ์ |
| GET | `/firewall-gaps` | ดึงรายการช่องโหว่ที่โมดูล 6 ตรวจพบ |
| GET | `/stats?window=1h` | สรุปสถิติ (จำนวนแจ้งเตือนในช่วงเวลาที่ระบุ สำหรับการ์ดสรุปบน dashboard) |

## Workflow

**เส้นทางที่ 1 — ตรวจจับต่อเนื่อง (อัตโนมัติ)**
1. โฟลว์เข้ามาที่เกตเวย์ → NFStream สกัดฟีเจอร์ → ส่งให้โมดูลตรวจจับ
2. Standardize → คำนวณ reconstruction error → เทียบ threshold → บันทึกลง `flows`
3. โมดูล firewall verification เทียบล็อก Ryu กับผลตรวจจับ → บันทึกลง `firewall_checks`
4. Backend polling ดึงข้อมูลใหม่จาก DB → ส่งให้ frontend แสดงผล

**เส้นทางที่ 2 — อธิบายผลแบบ on-demand**
1. ผู้ใช้คลิก "อธิบายผล" บน dashboard สำหรับ flow_id ที่สนใจ
2. Frontend → `POST /explain/{flow_id}` → backend เรียก Kernel SHAP (ใช้ `features_json` ที่เก็บไว้แล้ว ไม่ต้องคำนวณฟีเจอร์ใหม่)
3. บันทึกผลลง `explanations` พร้อม `computation_time_ms` (เก็บไว้ทำ resource benchmarking)
4. ส่งกลับไปแสดงเป็นกราฟฟีเจอร์ที่มีอิทธิพลสูงสุด

## Model design notes

- **Latent size**: อ้างอิง Song et al. (2021) latent size เป็นปัจจัยวิกฤต — ต้อง tune ด้วยการทดลองหลายค่า ไม่ fix ตายตัว เริ่มทดลองที่ compression ratio ~4-8x ของ input dim (43 หรือ 39 หลังตัด identifier features)
- **Loss function**: MSE ระหว่าง input กับ reconstruction
- **Threshold**: percentile-based (เริ่มทดลองที่ P95/P97/P99 บน validation set) เป็นหลัก, เปรียบเทียบกับ Gaussian KDE-based (ตาม Kim et al., 2025) เป็นการทดลองเสริม
- **Train/val/test split**: train = benign only, validation = benign + attack บางส่วน (ใช้หา threshold), test = benign + attack ที่ไม่เคยเห็น (ใช้ประเมินผลสุดท้าย) — ห้ามหา threshold จาก test set (data leakage)
- **Evaluation metrics**: accuracy, precision, recall, F1, FPR — รายงานทั้ง macro/weighted average และ per-class (โดยเฉพาะคลาสหายาก เช่น Ransomware, MITM, Backdoor)

## แผนพัฒนา (16 สัปดาห์, ปรับตามปฏิทินจริง)

| ช่วง | งาน | หมายเหตุ |
|---|---|---|
| สัปดาห์ 1–3 | ทบทวนทฤษฎี + ติดตั้งเครื่องมือทั้งหมด | |
| สัปดาห์ 3–5 | เตรียม/ทำความสะอาดข้อมูล NF-ToN-IoT-v2 | |
| สัปดาห์ 5–8 | พัฒนาและฝึกโมเดล autoencoder | คู่ขนานกับแทร็กเครือข่าย |
| สัปดาห์ 5–8 | โครงพื้นฐานเว็บแดชบอร์ด (DB schema + API skeleton) | คู่ขนานกับงานโมเดล |
| สัปดาห์ 6–9 | ตั้งค่า Mininet + Ryu + กฎไฟร์วอลล์อ้างอิง | คู่ขนานกับงานโมเดล |
| สัปดาห์ 8–9 | กำหนดเกณฑ์ตัดสินใจ (threshold) + วิเคราะห์ ROC/PR | ต้องรอโมเดลฝึกเสร็จ |
| สัปดาห์ 9–11 | พัฒนาการอธิบายผล (Kernel SHAP) | |
| สัปดาห์ 9–11 | พัฒนาโมดูลตรวจสอบไฟร์วอลล์ | |
| สัปดาห์ 11–13 | เชื่อมต่อแดชบอร์ดกับทุกโมดูล + บูรณาการระบบทั้งหมด | |
| สัปดาห์ 13–15 | ทดสอบและประเมินผล (public dataset, simulated attack, explainability, resource usage) | |
| สัปดาห์ 15–16 | สรุปผลและจัดทำรายงาน | |

## Folder structure

```
project/
├── documentation/                # PROJECT.md (this file), MODEL_DEVELOPMENT.md
├── data/                      # NF-ToN-IoT-v2 raw + processed (gitignore)
├── artifacts/                  # trained model, scaler, threshold, metrics (gitignore)
├── configuration/                     # search_space.yaml etc.
├── source/                         # ML / network pipeline
│   ├── common/                 # shared schema constants + paths
│   ├── extraction/              # NFStream + custom NFPlugin (module 1)
│   ├── preprocessing/           # scaler fit/transform (module 2)
│   ├── model/                    # autoencoder architecture, training, threshold (module 3)
│   ├── explain/                  # Kernel SHAP wrapper (module 4)
│   └── firewall_check/           # Ryu log comparison (module 6)
├── web/                          # dashboard app + shared storage (module 5)
│   ├── backend/                  # FastAPI app
│   │   └── routers/                # /alerts, /explain, /firewall-gaps, /stats
│   ├── frontend/                  # HTML/JS + Chart.js dashboard
│   └── database/                    # SQLite schema + access layer
├── network_simulation/                    # Mininet topology + Ryu controller app
├── notebooks/                       # EDA, model experiments
├── tests/
└── README.md                        # developer quick-start (setup, commands)
```

## Reference papers (สำหรับ methodology grounding)

- Autoencoder + threshold (KDE): Kim, D., Im, H., & Lee, S. (2025). *Sensors, 25*(13), 4174.
- Latent size study: Song, Y., Hyun, S., & Cheong, Y.-G. (2021). *Sensors, 21*(13), 4294.
- SHAP + autoencoder (methodology ต้นแบบ): Antwarg, L., Miller, R. M., Shapira, B., & Rokach, L. (2021). *Expert Systems with Applications, 186*, 115736.
- SHAP + autoencoder บนข้อมูลเครือข่าย: Roshan, K., & Zafar, A. (2021). *IJCNC, 13*(6), 109–128.
- Feature set มาตรฐาน NetFlow v2: Sarhan, M., Layeghy, S., & Portmann, M. (2022). *Mobile Networks and Applications, 27*(1), 357–370.
