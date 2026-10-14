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
| [guides/mininet-vm-setup.md](guides/mininet-vm-setup.md) | ติดตั้ง VM สำหรับ Mininet บน Pop!_OS 24.04 |
| [guides/mininet-integration-run.md](guides/mininet-integration-run.md) | ผลการรันท่อทั้ง 6 โมดูลบน Mininet |
| [guides/mininet-live-demo.md](guides/mininet-live-demo.md) | เดโมสด: โมเดลเทรนเฉพาะเครือข่าย + ข้อค้นพบ domain shift / brute-force |
| [guides/demo-script.md](guides/demo-script.md) | สคริปต์พูดเดโมสดตอนนำเสนอ (~6–8 นาที) |

> คู่มือ GNS3 (เครือข่ายจำลองที่ลง OS จริง) อยู่ที่
> [`../network_simulation/gns3/gns3-setup.md`](../network_simulation/gns3/gns3-setup.md)

---

## 📊 evaluation/ — การวัดผลและการทดลอง

| ไฟล์ | เนื้อหา |
|---|---|
| [evaluation/MODEL_DEVELOPMENT.md](evaluation/MODEL_DEVELOPMENT.md) | บันทึกพัฒนาโมเดล: ทำความสะอาดข้อมูล → เทรน → จูน อะไรเวิร์ก/ไม่เวิร์ก |
| [evaluation/dataset-limitations.md](evaluation/dataset-limitations.md) | ข้อจำกัดของชุดข้อมูล NF-ToN-IoT-v2 ที่วัดได้จริง — caveat เบื้องหลังทุกตัวเลข |
| [evaluation/resource-benchmark.md](evaluation/resource-benchmark.md) | ผลวัดทรัพยากร (CPU/GPU/throughput/latency) — คอขวดอยู่ที่การสกัดฟีเจอร์ |
| [evaluation/explanation-quality.md](evaluation/explanation-quality.md) | คุณภาพคำอธิบาย SHAP (local accuracy) |
| [evaluation/alert-aggregation.md](evaluation/alert-aggregation.md) | การรวมกลุ่มการแจ้งเตือน (fan-out / fan-in / repeated) |
| [evaluation/protocol-threshold-experiment.md](evaluation/protocol-threshold-experiment.md) | การทดลอง threshold แยกตามโปรโตคอล — **ผลเป็นลบ ไม่นำไปใช้** |
