# เอกสารประกอบระบบ FlowSentry

ดัชนีเอกสารของระบบตรวจจับการบุกรุกเครือข่าย IoT
(Denoising Autoencoder + SHAP) จัดกลุ่มตามการใช้งาน

> อยากเริ่มรันระบบ? ดู [how-to-run.md](how-to-run.md)
> อยากเข้าใจสเปกและการออกแบบทั้งหมด? ดู [PROJECT.md](PROJECT.md)

---

## 📄 เอกสารหลัก

| ไฟล์ | เนื้อหา |
|---|---|
| [PROJECT.md](PROJECT.md) | สเปกฉบับเต็มและการตัดสินใจเชิงออกแบบ |
| [how-to-run.md](how-to-run.md) | วิธีรันระบบ ทั้งแบบ venv และ Docker |

---

## 📘 guides/ — คู่มือติดตั้งและใช้งาน

| ไฟล์ | เนื้อหา |
|---|---|
| [guides/deployment-runbook.md](guides/deployment-runbook.md) | คู่มือนำไปใช้จริง: เริ่มใช้ครั้งแรก + ขั้นตอนเทรนใหม่เมื่อเจอ domain shift |
| [guides/dashboard-spec.md](guides/dashboard-spec.md) | สเปกหน้าแดชบอร์ด |

---

## บน branch `development`

เครื่องมือและเอกสารที่ไม่เกี่ยวกับการติดตั้งใช้งาน เก็บไว้บน branch `development`
(`git checkout development`):

- **เครือข่ายจำลอง** — Mininet VM, GNS3 ที่ลง OS จริง, เดโมสด, สคริปต์ traffic/attack
- **การวัดผลและการทดลอง** (`documentation/evaluation/`) — บันทึกพัฒนาโมเดล,
  ข้อจำกัดชุดข้อมูล, resource benchmark, คุณภาพ SHAP, การรวมกลุ่ม alert,
  การทดลอง threshold แยกโปรโตคอล
- **รายงานผลดิบ** (`artifacts/benchmark*.json`, `metrics_report*.json`, ฯลฯ)
- **ชุดทดสอบ** `pytest` และสคริปต์ benchmark
