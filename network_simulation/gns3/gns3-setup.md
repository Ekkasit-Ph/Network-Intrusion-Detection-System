# คู่มือ GNS3: ทดสอบ NIDS บนบ้านอัจฉริยะ (OS จริง)

ต่อยอดจาก [mininet-live-demo.md](../../documentation/guides/mininet-live-demo.md) ตามคอมเมนต์อาจารย์ที่ว่า
"ทดสอบบน GNS3 + OS จริง จะสมจริงกว่า" — GNS3 รันแต่ละ node เป็น VM/คอนเทนเนอร์จริง
(kernel แยกกันจริง) ต่างจาก Mininet ที่ทุก host แชร์ kernel เดียว

## ⚠️ อ่านก่อน 3 ข้อ

1. **GNS3 = เครือข่ายใหม่อีกโดเมน** โมเดลเดิม (ทั้ง NF-ToN-IoT-v2 และ mininet-demo) **จะไม่ fit**
   ตาม finding ของเราเอง → ต้อง **เก็บ benign ของ GNS3 แล้วเทรนใหม่** (ขั้นที่ 10)
   นี่ไม่ใช่ปัญหา แต่เป็นการ**ตอกย้ำ finding** + โชว์ workflow การเทรนต่อเครือข่าย
2. **GNS3 เป็น GUI เป็นหลัก** ขั้นตอนลาก-วาง-คลิกขวาทำในหน้าต่างโปรแกรม คู่มือนี้บอกว่าคลิกอะไร
   แต่เมนูอาจต่างเล็กน้อยตามเวอร์ชัน
3. **ทรัพยากร**: ปิด VM Mininet แล้ว (คืน ~4.7GB) ตอนรันจริงปิด Steam/Discord/เกมด้วย
   งบ RAM ที่วางไว้ ~6GB จาก ~9-10GB ที่มี

---

## สถาปัตยกรรมที่จะสร้าง

```
┌──────────── บ้าน LAN 192.168.10.0/24 ─────────────┐
│ 9 IoT (cam1 cam2 spk tv plug bulb thermo vac phone)│
│ atk1 (อุปกรณ์โดนยึด) .20                             │
│         └──────────┬──────────────┐                │
│              [OVS sw1] ──mirror──▶ [sensor (Docker)]│──▶ แดชบอร์ด :8000
│              [gw] .1 / 203.0.113.1                  │
└──────────────────┼──────────────────────────────────┘
          [cloud] 203.0.113.10  (MQTT + HTTP + DNS)
```
- **IoT + atk1 + gw + cloud** = Alpine QEMU (OS จริง)
- **sw1** = Open vSwitch appliance (ทำ port mirror เหมือนที่เราทำใน Mininet)
- **sensor** = Docker จาก image ของโปรเจกต์ (มี nfstream+torch+โค้ดครบ → capture/retrain/detect ในตัว)

ไฟล์ประกอบ (อยู่ใน `network_simulation/gns3/profiles/`):
`device.sh` (พฤติกรรมอุปกรณ์), `cloud_services.sh` (บริการคลาวด์),
`attack.sh` (โจมตี), `dns_server.py` (DNS resolver)

---

## 1. ลง GNS3 บน Pop!_OS 24.04
```bash
sudo add-apt-repository ppa:gns3/ppa
sudo apt update
sudo apt install -y gns3-gui gns3-server
# ยอมให้ผู้ใช้รัน ubridge/kvm ได้ (ตอบ Yes ตอนถามเรื่อง non-root)
sudo usermod -aG ubridge,libvirt,kvm,docker,wireshark "$USER"
# รีบูตหรือ logout/login ให้ group มีผล
```
ตรวจ KVM เร่งความเร็ว (สำคัญมากกับ QEMU):
```bash
kvm-ok 2>/dev/null || egrep -c '(vmx|svm)' /proc/cpuinfo   # >0 = ใช้ KVM ได้
ls -l /dev/kvm                                             # ต้องมีไฟล์นี้
```

## 2. เปิด GNS3 ครั้งแรก
```bash
gns3
```
- Setup wizard → เลือก **"Run appliances on my local computer"** (local server)
  — จะได้ใช้ KVM เร่ง QEMU และ Docker บนเครื่องตรง ไม่ต้องมี GNS3 VM ซ้อน
- Edit → Preferences → Server → ดูว่า local server ขึ้น **Connected**

## 3. เตรียม image 3 ชนิด

### 3.1 Alpine Linux (OS จริง สำหรับทุกอุปกรณ์)
ดาวน์โหลด cloud image เล็ก:
```bash
mkdir -p ~/GNS3/images/QEMU && cd ~/GNS3/images/QEMU
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2 \
  -O alpine-3.20.qcow2
```
ใน GNS3: Edit → Preferences → **QEMU VMs** → New →
- ชื่อ `alpine-iot`, RAM **192 MB**, console type **telnet**
- เลือก disk image = `alpine-3.20.qcow2`
- เสร็จแล้ว Edit template นี้ → Network → **Adapters = 1**, type e1000 (หรือ virtio)
> ภายหลังจะ **clone** template นี้เป็นทุกอุปกรณ์ (เปลี่ยน RAM เฉพาะ atk1/cloud เป็น 384/512)

### 3.2 Open vSwitch (สวิตช์ + mirror)
Edit → Preferences → หา **"Open vSwitch"** ใน built-in / marketplace appliance → ติดตั้ง
(เป็น Docker appliance เบา รองรับ `ovs-vsctl` เต็ม) ถ้าหาไม่เจอให้ "Import appliance"
จาก gns3.com/marketplace (ค้น "Open vSwitch")

### 3.3 NIDS sensor (Docker จากโปรเจกต์)
บนเครื่อง host:
```bash
cd ~/Workspace/Project/Network-Intrusion-Detection-System
docker build -t nids-sensor:latest .
```
ใน GNS3: Edit → Preferences → **Docker** → New → เลือก image `nids-sensor:latest`
- ชื่อ `sensor`, Adapters **1**, start command เว้นว่าง (จะ exec เข้าไปสั่งเอง)
- Environment: ไม่ต้องใส่ (ตั้งตอนรันใน console)

## 4. วาง topology (ลากลงพื้นที่ทำงาน)
ลาก node ลงมา: `alpine-iot` ×10 (9 IoT + atk1), ×1 เป็น gw, ×1 เป็น cloud,
Open vSwitch ×1 (sw1), Docker sensor ×1
- เปลี่ยนชื่อ node (ดับเบิลคลิก) ให้ตรง: cam1 cam2 spk tv plug bulb thermo vac phone atk1 gw cloud sw1 sensor
- ลากสายเชื่อม: **ทุก IoT + atk1 + gw → sw1**, **gw → cloud**, **sw1 (พอร์ตว่าง 1 อัน) → sensor**
  > จำพอร์ตบน sw1 ที่ต่อ sensor ไว้ (เช่น eth9) — ใช้ตั้ง mirror ขั้นที่ 8

## 5. ตั้งค่าเครือข่ายแต่ละ Alpine (ทำครั้งเดียวต่อ node)
เปิด console (ดับเบิลคลิก node) ล็อกอิน root แล้ว:
```sh
# ตัวอย่างสำหรับ cam1 (.11) -- เปลี่ยน IP/role ต่อเครื่อง
cat >/etc/network/interfaces <<EOF
auto eth0
iface eth0 inet static
  address 192.168.10.11
  netmask 255.255.255.0
  gateway 192.168.10.1
EOF
echo "nameserver 203.0.113.10" >/etc/resolv.conf
rc-service networking restart
# ลงเครื่องมือ (ครั้งเดียว ต้องมีเน็ตผ่าน gw หรือใส่ผ่าน shared folder)
apk add --no-cache mosquitto-clients nmap openssh-client
echo "cam-stream" >/etc/device-role        # <- role ของเครื่องนี้
```
ตาราง IP/role:
| node | IP | role (ใน /etc/device-role) |
|---|---|---|
| cam1 | .11 | cam-stream |
| cam2 | .12 | cam-motion |
| spk | .13 | speaker |
| tv | .14 | tv |
| plug | .15 | plug |
| bulb | .16 | bulb |
| thermo | .17 | thermostat |
| vac | .18 | vacuum |
| phone | .19 | phone |
| atk1 | .20 | (ไม่ต้องตั้ง — ใช้ attack.sh) |

> **ทางลัด:** ตั้งค่า alpine template ให้ครบ (ลง tools + วาง device.sh) **ก่อน clone**
> จะได้ไม่ต้อง apk ทีละเครื่อง เหลือแค่แก้ IP + role

## 6. วาง profile script + ให้รันตอนบูต
คัดลอก `profiles/device.sh` เข้าแต่ละ IoT (ผ่าน console paste หรือ wget จาก cloud) ไว้ที่ `/root/device.sh` แล้ว:
```sh
chmod +x /root/device.sh
# ให้รันอัตโนมัติตอนบูต (Alpine ใช้ /etc/local.d/)
rc-update add local
cat >/etc/local.d/device.start <<EOF
#!/bin/sh
CLOUD_IP=203.0.113.10 /root/device.sh >/var/log/device.log 2>&1 &
EOF
chmod +x /etc/local.d/device.start
# เริ่มเลยไม่ต้องรอ reboot:
CLOUD_IP=203.0.113.10 /root/device.sh >/var/log/device.log 2>&1 &
```

## 7. ตั้งบริการคลาวด์ (node cloud, .10 ฝั่ง LAN และ 203.0.113.10)
```sh
apk add --no-cache mosquitto python3
# วาง cloud_services.sh + dns_server.py ไว้ที่ /root/
chmod +x /root/cloud_services.sh
/root/cloud_services.sh &
```
> gw ต้องเปิด IP forwarding: `sysctl -w net.ipv4.ip_forward=1` และมี route สองฝั่ง

## 8. ตั้ง port mirror บน OVS ไป sensor (หัวใจ)
เปิด console ของ **sw1** (OVS) — สมมติ sensor ต่อพอร์ต `eth9`:
```sh
# คัดลอกทุกแพ็กเก็ตบนบริดจ์ ไปออกพอร์ตที่ต่อ sensor (เหมือน mirror_to_sensor ใน Mininet)
ovs-vsctl -- --id=@p get Port eth9 \
  -- --id=@m create Mirror name=nids-span select-all=true output-port=@p \
  -- set Bridge br0 mirrors=@m
ovs-vsctl list Mirror        # ตรวจว่าสร้างแล้ว
```
(ชื่อบริดจ์อาจเป็น `br0` — ดูด้วย `ovs-vsctl show`)

## 9. ตรวจก่อนเก็บข้อมูล
- จาก cam1: `ping -c2 203.0.113.10` ควรได้, `nslookup x.iot.example.com 203.0.113.10` ควรตอบ
- จาก sensor console: `tcpdump -i eth0 -c 20` ควรเห็นทราฟฟิกของ **อุปกรณ์อื่น** (ยืนยัน mirror ทำงาน)
- ปล่อยบ้านทำงาน ~2-3 นาที ให้ทุก device loop เริ่มปล่อยทราฟฟิก

## 10. เก็บ benign → เทรนโมเดล GNS3 → ตั้ง threshold  (ทำใน sensor Docker)
exec เข้า sensor:
```bash
# บน host: หา container id ของ node sensor แล้ว exec (หรือใช้ console ใน GNS3)
docker exec -it <sensor-container> sh
```
ในคอนเทนเนอร์ (มีโค้ด+nfstream+torch ครบ):
```sh
# 10.1 เก็บ benign ล้วน ~3 นาที (อย่ายิงโจมตีช่วงนี้)
.venv/bin/python -m source.extraction.sensor --source eth0 \
  --output /app/data/gns3_benign.csv --idle-timeout 3 --active-timeout 8 &
sleep 180; pkill -f extraction.sensor

# 10.2 เก็บช่วงโจมตี (รัน attack.sh บน atk1 พร้อมกัน) -> label by src=atk1
.venv/bin/python -m source.extraction.sensor --source eth0 \
  --output /app/data/gns3_attack.csv --idle-timeout 3 --active-timeout 8 &
#   ... ไปรัน attack.sh scan / dos / brute / ddos บน atk1+bots ...
sleep 120; pkill -f extraction.sensor

# 10.3 รวม+label (benign=0, flow ที่ src=192.168.10.20 = attack) แล้ว pipeline/train/threshold
#   ใช้ขั้นตอนเดียวกับ data/mininet_demo (ดู mininet-live-demo.md ข้อ "ชุดข้อมูล")
#   เขียนออก artifacts/models/gns3-demo/ + artifacts/preprocessing_gns3/
```
> รายละเอียด pipeline→train→threshold เหมือนเป๊ะกับที่ทำใน Mininet (เอกสาร mininet-live-demo.md)
> เปลี่ยนแค่ path เป็น `gns3_*`

## 11. เปิดตรวจจับสด + ดูแดชบอร์ด
ในคอนเทนเนอร์ sensor:
```sh
# backend (แดชบอร์ด) ชี้โมเดล gns3-demo
NIDS_MODEL_DIR=/app/artifacts/models/gns3-demo \
NIDS_PROCESSED_DIR=/app/data/gns3_demo \
NIDS_DB_PATH=/app/data/nids.db \
.venv/bin/uvicorn web.backend.main:app --host 0.0.0.0 --port 8000 &

# live_capture ป้อน DB เดียวกัน
.venv/bin/python -m web.backend.live_capture --source eth0 \
  --processed-dir /app/data/gns3_demo \
  --artifacts-dir /app/artifacts/models/gns3-demo \
  --preprocessing-dir /app/artifacts/preprocessing_gns3 \
  --db-path /app/data/nids.db --idle-timeout 3 --active-timeout 8 &
```
เปิดแดชบอร์ดจาก host: map พอร์ต 8000 ของ node sensor (GNS3 Docker node → right-click →
"Show in Wireshark" ไม่ใช่; ใช้ right-click node → Console หรือเพิ่ม Cloud/NAT เพื่อ map :8000)
วิธีง่ายสุด: ต่อ sensor อีกขาไป **NAT node** ของ GNS3 แล้วเข้า http://<ip-ที่ NAT ให้>:8000

## 12. เดโมการโจมตี (บน atk1 + อุปกรณ์ที่สวมบท bot)
```sh
# atk1: สแกนหาอุปกรณ์ทั้งบ้าน (fan-out)
./attack.sh scan
# atk1: brute-force / DoS ใส่ cloud หรืออุปกรณ์เป้าหมาย
./attack.sh brute 203.0.113.10
./attack.sh dos   203.0.113.10
# DDoS (Mirai): รัน ddos-bot "พร้อมกัน" บน atk1 + cam1 + plug + bulb -> fan-in
./attack.sh ddos-bot 203.0.113.10      # ยิงพร้อมกันหลายเครื่อง
```
บนแดชบอร์ด: scan/dos ขึ้นแดง, DDoS จะถูกจับเป็น **incident แบบ fan-in** (แท็บ Incidents)

---

## Troubleshooting
| อาการ | สาเหตุ/แก้ |
|---|---|
| QEMU ช้ามาก/ค้าง | ไม่ได้ใช้ KVM — เช็ค `/dev/kvm`, group `kvm`, เปิด VT-x ใน BIOS |
| อุปกรณ์ ping cloud ไม่ได้ | gw ไม่ได้เปิด ip_forward หรือ route ไม่ครบสองฝั่ง |
| sensor tcpdump ไม่เห็นทราฟฟิกคนอื่น | mirror ไม่ติด (ข้อ 8) หรือต่อผิดพอร์ต; `ovs-vsctl list Mirror` |
| nfstream จับได้แต่ ICMPv6 | เครือข่ายไม่ forward IPv4 — เช็ค OVS/gw |
| RAM ไม่พอ boot ไม่ขึ้น | ลดจำนวน IoT, ปิดแอป host, ลด RAM/node เหลือ 128MB |
| apk add ใช้ไม่ได้ | อุปกรณ์ยังออกเน็ตไม่ได้ — ตั้ง gw/NAT ให้ออก internet ชั่วคราวตอนลง tools |

## หมายเหตุความสมจริง (บอกอาจารย์ตามจริง)
- ✅ แต่ละ node เป็น **OS จริง kernel แยก** (Alpine Linux) — ตอบโจทย์ที่อาจารย์แนะนำ
- ✅ โปรโตคอลจริง: HTTP, DNS, MQTT (IoT), SSH, TCP stream
- ⚠️ เป็น **subset** ของบ้านจริง (อุปกรณ์จริงมีมากกว่า + โปรโตคอลเฉพาะ เช่น CoAP/mDNS/Zigbee-gateway)
- ⚠️ ทราฟฟิกสร้างจาก profile script ไม่ใช่เฟิร์มแวร์จริง — รูปทรง flow สมจริงแต่ payload สังเคราะห์
