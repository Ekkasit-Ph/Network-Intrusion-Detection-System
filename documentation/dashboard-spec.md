# Dashboard — สเปกสำหรับออกแบบใหม่

เอกสารนี้เขียนเพื่อใช้เป็นวัตถุดิบในการออกแบบหน้าเว็บใหม่ ทุกตัวเลขและ
ทุก field ในนี้ตรวจจาก API ที่รันจริงแล้ว ไม่ได้เขียนจากความจำ

---

## 1. ระบบนี้คืออะไร

Network Intrusion Detection System ที่ใช้ **autoencoder แบบ unsupervised**
จับความผิดปกติของ network flow แล้วอธิบายผลด้วย **SHAP**

หลักการที่ต้องเข้าใจก่อนออกแบบ เพราะมันกำหนดว่าหน้าเว็บควรพูดอะไร:

- โมเดลเรียนรู้จาก traffic **ปกติ** เท่านั้น แล้ววัดว่า flow ใหม่
  "สร้างกลับคืนมาได้ยากแค่ไหน" (reconstruction error) ยิ่งสูง = ยิ่งแปลก
- เกิน **threshold** = flag ว่าผิดปกติ
- **"ผิดปกติ" ไม่เท่ากับ "การโจมตี"** — flow ปกติที่แปลกไปก็ถูก flag ได้
  นี่คือขีดจำกัดโดยธรรมชาติ ไม่ใช่บั๊ก และเป็นเหตุผลว่าทำไมต้องมี SHAP
  ให้คนตัดสินต่อ **หน้าเว็บไม่ควรใช้คำว่า "โจมตี" กับสิ่งที่โมเดล flag**

ผลลัพธ์จริงบน test set 6.3 ล้าน flow: recall 87.59%, FPR 4.97%,
precision 99.05%

---

## 2. ข้อมูลที่ดึงได้ (API ที่มีอยู่จริง)

Backend: FastAPI + SQLite frontend เสิร์ฟเป็น static file จาก `/`

### `GET /alerts?since=<ISO8601>&limit=<n≤1000>`
รายการ flow ใหม่สุดก่อน ใช้ polling ทุก 2 วินาที (`since` = cursor)

```
flows: [ {
  flow_id               str    "demo-e8a51f44201b"
  timestamp             str    "2026-08-21T08:16:02.240966+00:00"
  src_ip                str    "192.168.1.40"
  dst_ip                str    "10.0.0.28"
  src_port              int    2077
  dst_port              int    21
  protocol              str    "TCP" | "UDP" | "ICMP" | ...
  reconstruction_error  float  0.004123631864786148
  threshold_used        float  0.0019442916382104158
  is_anomaly            int    0 | 1
  features_json         str    JSON ของ 46 feature (ค่า standardized)
  true_label            int?   1 | 0 | null      ← null เสมอสำหรับ traffic จริง
  true_attack           str?   "xss" | null
} ]
count: int
```

### `GET /stats?window=1h`
```
since, window, total_flows, anomalies, anomaly_rate, avg_reconstruction_error
```

### `GET /stats/trend?window=<5m..24h>&buckets=<5..200>`
```
window: "1h"
buckets: [ { t: ISO8601, count: int, anomaly_rate: float|null } ]
```
`anomaly_rate: null` = ช่วงนั้นไม่มี traffic เลย **ต่างจาก 0.0 ที่แปลว่า
มี traffic แต่ปกติหมด** — อย่ารวมสองอันนี้เป็นเส้นเดียวกัน

### `POST /explain/{flow_id}`
คำนวณ SHAP ตามคำขอ ใช้เวลาจริง **~23 ms ถึงไม่กี่วินาที**
```
flow_id, requested_at, base_value, reconstruction_error, threshold_used,
is_anomaly, true_label, true_attack, computation_time_ms,
shap_values: { <46 ชื่อ feature>: float }
features:    { <46 ชื่อ feature>: float }
```
สมบัติสำคัญ: **base_value + ผลรวม shap_values = reconstruction_error พอดี**
(ตรวจแล้ว คลาดเคลื่อน 0.000000) — ออกแบบให้เห็นสมการนี้ได้จะอธิบายง่ายมาก

### `GET /firewall-gaps?limit=<n≤1000>`
```
gaps: [ {
  check_id, flow_id, timestamp, src_ip, dst_ip, reconstruction_error,
  firewall_rule_matched   int    1 | 0 | null
  firewall_action_logged  str    "allow tcp dst=10.0.2.0/24 dport=22 prio=150"
  gap_detected            int    1 | 0 | null
} ]
count: int
```
**gap** = flow ที่โมเดลจับได้ แต่ firewall จะปล่อยผ่าน คือสิ่งที่มีแต่ระบบนี้
เท่านั้นที่เห็น `null` = ข้อมูล flow ไม่พอจะตัดสิน (ไม่ใช่ "ปลอดภัย")

### `GET /flow/{flow_id}`
flow เดียว field เดียวกับใน `/alerts`

---

## 3. หน้าเว็บปัจจุบันทำอะไรได้บ้าง

Stack: **vanilla JS + Chart.js ไม่มี framework** รวม 1,739 บรรทัด
(app.js 806 / style.css 561 / index.html 214 / feature-labels.js 158)
ภาษาไทยทั้งหมด

**แถบสถิติ 6 ตัว** — total flows, anomalies, anomaly rate, avg error,
threshold, throughput (flow/วินาที), เวลาอัปเดตล่าสุด

**Spotlight** — เน้น flow ล่าสุดใบเดียวขนาดใหญ่ เพราะ flow ไหลเร็วมาก
จนตารางอ่านไม่ทัน

**ปุ่ม Pause** — หยุดรับ flow ใหม่ชั่วคราวเพื่อให้อ่านทัน (ปัญหาจริงที่เจอ
ตอนสาธิต)

**กราฟ anomaly rate** — เลือกช่วงได้ 8 ระดับ (5m / 10m / 30m / 1h / 4h /
8h / 12h / 24h) เส้นเปลี่ยนสีตามความรุนแรง: เขียว <30% / เหลือง 30–60% /
แดง >60% ช่วงที่ไม่มี traffic เว้นเป็นช่องว่าง ไม่ลากเส้นผ่าน

**ตาราง flow** — เลื่อนขึ้นแบบ real-time มีตัวกรอง "เฉพาะที่ผิดปกติ"

**Insight 4 คอลัมน์** — protocol mix, top source IPs, top destination ports,
และอัตราการมาของ flow

**Modal อธิบายผล (SHAP)** — เปิดจากการคลิก flow ประกอบด้วย
- คำตัดสิน + แถบสเกลบอกว่า error อยู่ตรงไหนเทียบ threshold
- feature ที่ผลักให้ผิดปกติมากสุด พร้อม**ชื่อภาษาไทยครบทั้ง 46 ตัว**
  และค่า z-score ที่อ่านออก
- สมการ base_value + Σshap = error

**Dev mode (ปิด/เปิดได้)** — แสดงเฉลยว่า flow นั้นจริงๆ คืออะไร และระบบ
ตัดสินถูกหรือผิด พร้อมคำอธิบายว่า**ควรคาดหวังอะไร**สำหรับการโจมตีแต่ละแบบ
รองรับ 9 คลาส: scanning, ddos, dos, password, backdoor, ransomware, mitm,
xss, injection

**แถบแจ้งเตือน** — บอกว่ากำลังดูข้อมูล replay ไม่ใช่ traffic จริง

---

## 4. สิ่งที่คนออกแบบต้องระวัง (แต่ละข้อมาจากปัญหาจริง)

1. **flow มาเร็วมาก** จนตารางที่เลื่อนตลอดเวลาอ่านไม่ทัน — Spotlight กับ
   ปุ่ม Pause เกิดจากปัญหานี้ ดีไซน์ใหม่ต้องตอบโจทย์นี้ให้ได้
2. **มีตัวเลข 2 ชนิดที่คนสับสนตลอด**: reconstruction error (เลขเล็กมาก
   เช่น 0.0041) กับ threshold (0.0019) — การเทียบสองค่านี้ให้เห็นภาพคือ
   หัวใจของหน้าเว็บ ตัวเลขดิบอย่างเดียวไม่สื่อ
3. **แยก "ไม่มี traffic" ออกจาก "traffic ปกติ"** ให้ชัดในทุกกราฟและทุก
   สถิติ การยุบรวมทำให้ช่วงเงียบดูเหมือนช่วงปลอดภัย
4. **traffic จริงไม่มีเฉลย** — `true_label` เป็น null เสมอ Dev mode ต้อง
   ซ่อนตัวเองอัตโนมัติ ห้ามแสดงช่องว่างที่ดูเหมือนข้อมูลหาย
5. **ห้ามเรียกสิ่งที่ flag ว่า "การโจมตี"** ใช้คำว่า "ผิดปกติ" และให้ SHAP
   เป็นตัวช่วยให้คนตัดสิน
6. **SHAP ช้าและเรียกตามคำขอเท่านั้น** ห้ามยิงอัตโนมัติทุก flow ต้องมี
   สถานะกำลังโหลด
7. **ค่าที่แสดงมาจาก DB โดยตรง** (IP, port, ชื่อ attack) ต้อง escape
   ทุกจุด — นี่คือ dashboard ความปลอดภัย ที่เคยมีช่อง XSS มาแล้ว
8. **หน้าจอสาธิตคือจอโปรเจกเตอร์** ตัวอักษรเล็กและ contrast ต่ำจะอ่านไม่ออก

---

## 5. ข้อมูลประกอบที่มีให้ใช้

- **46 feature พร้อมชื่อไทย** ใน `web/frontend/feature-labels.js`
- **คำอธิบายความคาดหวังต่อการโจมตี 9 คลาส** ในไฟล์เดียวกัน เช่น scanning =
  "ต้นทางเดียวไล่ติดต่อหลายปลายทาง/หลายพอร์ตในเวลาสั้น"
- xss กับ injection ตั้งใจให้ `expect: []` เพราะเป็นการโจมตีระดับ payload
  ที่ NetFlow มองไม่เห็น — เป็นข้อค้นพบของโปรเจกต์ ไม่ใช่ข้อมูลขาด

## 6. ข้อจำกัดทางเทคนิค

- เสิร์ฟเป็น static file จาก FastAPI — **ไม่มี build step**
- Chart.js โหลดแบบ local ไม่มี CDN (รันใน Docker แบบ offline ได้)
- polling ทุก 2 วินาที ไม่ใช่ WebSocket
- ต้องรันใน Docker บนเครื่องนำเสนอได้โดยไม่ต้องต่อเน็ต
