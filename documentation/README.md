# เอกสารประกอบโปรเจกต์ FlowSentry

ดัชนีเอกสารทั้งหมดของระบบตรวจจับการบุกรุกเครือข่าย IoT
(Denoising Autoencoder + SHAP) จัดกลุ่มตามการใช้งาน

> อยากเริ่มรันระบบก่อน? ดู [how-to-run.md](how-to-run.md)
> อยากเห็นภาพรวมทั้งโปรเจกต์ในที่เดียว? ดู [project-master-summary.md](project-master-summary.md)

---

## 📄 เอกสารหลัก (อ่านก่อน)

| ไฟล์ | เนื้อหา |
|---|---|
| [project-master-summary.md](project-master-summary.md) | **สรุปทั้งโปรเจกต์ในที่เดียว** — ทุกโมดูล ทุกผลลัพธ์ ทุกข้อค้นพบ พร้อมนำไปเขียนเล่ม |
| [technical-report.md](technical-report.md) | รายงานเชิงลึก — การสกัดฟีเจอร์, การตรวจจับแยกตามการโจมตี, 3 ฟีเจอร์เชิงพฤติกรรม |
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

---

## 📝 thesis-notes/ — บันทึกการเขียนเล่ม/นำเสนอ

เอกสารร่าง สำหรับเขียนเล่มรายงานและเตรียมนำเสนอ (ไม่ใช่สเปกระบบ)

| ไฟล์ | เนื้อหา |
|---|---|
| [thesis-notes/progress-2-summary.md](thesis-notes/progress-2-summary.md) | สรุปความก้าวหน้าครั้งที่ 2 (สำหรับอาจารย์) |
| [thesis-notes/professor-comments.md](thesis-notes/professor-comments.md) | คอมเมนต์อาจารย์จาก progress 1 |
| [thesis-notes/roadmap.md](thesis-notes/roadmap.md) | แผนงานถึงปลายภาค |
| [thesis-notes/qa-briefing.md](thesis-notes/qa-briefing.md) | ข้อมูลระบบจัดระเบียบไว้ตอบคำถามป้องกัน |
| [thesis-notes/progress-report-data.md](thesis-notes/progress-report-data.md) | ข้อมูลดิบสำหรับเขียนเล่ม |
| [thesis-notes/report-paste-ready.md](thesis-notes/report-paste-ready.md) | ข้อความพร้อมคัดลอกลงเล่ม |
| [thesis-notes/report-corrections.md](thesis-notes/report-corrections.md) | ข้อความแก้ไขสำหรับเล่ม |
| [thesis-notes/report-review.md](thesis-notes/report-review.md) | ผลตรวจเล่มรายงาน |
| [thesis-notes/report-review-v3.md](thesis-notes/report-review-v3.md) | ผลตรวจเล่มฉบับล่าสุด (เน้นหัวข้อ 4.4) |
| [thesis-notes/slide-script.md](thesis-notes/slide-script.md) | บทพูดนำเสนอ 19 สไลด์ (~15 นาที) |
| [thesis-notes/slide-prompt.md](thesis-notes/slide-prompt.md) | prompt ทำสไลด์ด้วย Claude Design |
| [thesis-notes/architecture-diagram-prompt.md](thesis-notes/architecture-diagram-prompt.md) | prompt วาดแผนภาพสถาปัตยกรรม |
| [thesis-notes/topology-diagram-prompt.md](thesis-notes/topology-diagram-prompt.md) | prompt วาดแผนภาพ topology |
