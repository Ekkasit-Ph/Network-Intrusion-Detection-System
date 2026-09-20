# ติดตั้ง VM สำหรับ Mininet บน Pop!_OS 24.04

> ขั้นตอนในไฟล์นี้รันบนเครื่องคุณ **ผมทดสอบให้ไม่ได้** เพราะต้องใช้สิทธิ์ผู้ดูแลระบบ
> ตรวจสเปกเครื่องแล้ว: VT-x เปิดอยู่ · `/dev/kvm` มีแล้ว · RAM 15 GB · ดิสก์ว่าง 250 GB

## ทำไมเลือก KVM ไม่ใช่ VirtualBox

| | KVM/QEMU | VirtualBox |
|---|---|---|
| โมดูลเคอร์เนล | **อยู่ในเคอร์เนลแล้ว** (`/dev/kvm` พร้อมใช้) | ต้องคอมไพล์เอง (DKMS) |
| อัปเดตเคอร์เนล Pop!_OS | ไม่พัง | **พังบ่อย** ต้องคอมไพล์ใหม่ |
| Secure Boot | ไม่เกี่ยว | ต้องเซ็นโมดูลเอง |
| ความเร็ว | เร็วกว่า | ช้ากว่าเล็กน้อย |

Pop!_OS อัปเดตเคอร์เนลถี่ **VirtualBox จะพังกลางเทอมแน่นอน** — ใช้ KVM

## ทำไมต้อง Ubuntu 20.04 ไม่ใช่รุ่นใหม่กว่า

**Ryu ต้องใช้ Python ≤ 3.9** (ติดที่ `eventlet`)

| Ubuntu | Python | Ryu |
|---|---|---|
| **20.04 LTS** | **3.8** | ✅ |
| 22.04 LTS | 3.10 | ❌ |
| 24.04 LTS | 3.12 | ❌ (เหมือนเครื่องหลัก) |

---

## ขั้นที่ 1 — ลง KVM บนเครื่องหลัก

```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients \
                    bridge-utils virt-manager virtinst ovmf

# เพิ่มตัวเองเข้ากลุ่ม แล้ว**ออกจากระบบแล้วเข้าใหม่** (หรือรีบูต)
sudo usermod -aG libvirt,kvm $USER
```

⚠️ **ต้องออกจากระบบแล้วล็อกอินใหม่** กลุ่มจะยังไม่มีผลจนกว่าจะทำ ตรวจด้วย:

```bash
groups | grep -o 'libvirt\|kvm'      # ต้องเห็นทั้งสองคำ
systemctl status libvirtd --no-pager  # ต้อง active (running)
virsh list --all                      # ต้องไม่ error
```

## ขั้นที่ 2 — โหลด ISO

```bash
mkdir -p ~/VMs && cd ~/VMs
wget https://releases.ubuntu.com/20.04/ubuntu-20.04.6-live-server-amd64.iso
```

ใช้ **live-server** ไม่ใช่ desktop — เบากว่ามาก และงานนี้ใช้แต่บรรทัดคำสั่ง (~1.4 GB)

## ขั้นที่ 3 — สร้าง VM

```bash
virt-install \
  --name mininet-nids \
  --memory 6144 \
  --vcpus 4 \
  --disk path=$HOME/VMs/mininet-nids.qcow2,size=40,format=qcow2 \
  --cdrom $HOME/VMs/ubuntu-20.04.6-live-server-amd64.iso \
  --os-variant ubuntu20.04 \
  --network network=default \
  --graphics spice \
  --noautoconsole

virt-manager      # เปิดหน้าต่างแล้วดับเบิลคลิก mininet-nids เพื่อติดตั้งต่อ
```

**ทรัพยากรที่ให้:** RAM 6 GB · 4 vCPU · ดิสก์ 40 GB
เครื่องหลักมี 15 GB — เหลือ 9 GB ให้ระบบหลัก พอสบาย แต่**ปิดเบราว์เซอร์ตอนรัน VM**

ตอนติดตั้ง Ubuntu: เลือกค่าเริ่มต้นทั้งหมด **ติ๊ก "Install OpenSSH server"** จะได้ `ssh` เข้าได้

## ขั้นที่ 4 — เข้า VM แล้วลง Mininet

```bash
virsh domifaddr mininet-nids          # หาเลข IP ของ VM
ssh <user>@<ip-ของ-vm>
```

ใน VM:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch openvswitch-testcontroller \
                    python3-pip python3-venv git tcpdump hping3 nmap

# ปิดตัวควบคุมสำรองที่ Ubuntu เปิดให้อัตโนมัติ -- มันจะชนกับ Ryu ที่พอร์ต 6653
sudo systemctl disable --now openvswitch-testcontroller 2>/dev/null || true

# ทดสอบว่า Mininet ใช้ได้
sudo mn --test pingall
```

ต้องเห็น `*** Results: 0% dropped` ถ้าเห็นแล้วแปลว่า Mininet กับ Open vSwitch พร้อม

## ขั้นที่ 5 — ลง Ryu (แยก venv เพราะต้องกดเวอร์ชัน)

```bash
python3 -m venv ~/ryu-venv
~/ryu-venv/bin/pip install --upgrade pip

# eventlet รุ่นใหม่ตัด ALREADY_HANDLED ออก ทำให้ Ryu พัง -- ต้องกดเวอร์ชัน
~/ryu-venv/bin/pip install 'eventlet==0.30.2' ryu

~/ryu-venv/bin/ryu-manager --version    # ต้องขึ้นเลขเวอร์ชัน ไม่ใช่ traceback
```

⚠️ ถ้าขั้นนี้ error เรื่อง `ALREADY_HANDLED` แปลว่า eventlet ไม่ได้ถูกกดเวอร์ชัน ให้ลงใหม่

## ขั้นที่ 6 — เอาโปรเจกต์เข้า VM

```bash
# ใน VM
git clone https://github.com/Ekkasit-Ph/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

**ไฟล์ที่ไม่ได้อยู่ใน git และต้องคัดลอกเข้าไปเอง** — `train.parquet` (74 MB) ซึ่ง `ShapExplainer` ต้องใช้:

```bash
# รันบนเครื่องหลัก
scp data/processed_w50/train.parquet <user>@<ip-ของ-vm>:~/Network-Intrusion-Detection-System/data/processed_w50/
```

> ถ้ายังไม่คัดลอก ระบบจะยังทำงานได้ทุกอย่างยกเว้น `/explain` ซึ่งจะตอบ 503
> สำหรับการทดสอบเชื่อมต่อรอบแรกไม่จำเป็น

ตรวจว่าใช้ได้:

```bash
cd ~/Network-Intrusion-Detection-System
.venv/bin/python -m pytest -q          # ควรผ่านทั้งหมด
```

## ขั้นที่ 7 — ทดสอบว่าทุกชิ้นทำงานร่วมกัน

```bash
# เทอร์มินัล 1 -- ตัวควบคุม Ryu
~/ryu-venv/bin/ryu-manager --observe-links ryu.app.ofctl_rest \
  ~/Network-Intrusion-Detection-System/network_simulation/ryu_app.py

# เทอร์มินัล 2 -- โทโพโลยี
cd ~/Network-Intrusion-Detection-System
sudo .venv/bin/python network_simulation/topology.py

# เทอร์มินัล 3 -- ดึงกฎไฟร์วอลล์จากตัวควบคุมจริง
curl -s http://localhost:8080/stats/flow/1 | head -c 400
```

ถ้าคำสั่งสุดท้ายคืน JSON ที่มีกฎอยู่ **แปลว่าโมดูล 6 ต่อกับตัวควบคุมจริงได้แล้ว**
ซึ่งเป็นรอยต่อที่เดิมทวนสอบได้แค่ด้วยไฟล์ที่ export ไว้

---

## สิ่งที่ยังต้องทำหลังจากนี้ (ยังไม่มีในโค้ด)

`topology.py` ปัจจุบัน **ยังไม่ได้สร้างโฮสต์สำหรับ NIDS และยังไม่มี mirror port**
ตัวสกัดโฟลว์จึงยังไม่มีที่ยืน ต้องเพิ่ม:

1. โฮสต์ `nids1` ต่อเข้าสวิตช์
2. ตั้ง OVS ให้ mirror ทราฟฟิกทั้งหมดไปที่พอร์ตนั้น
3. รัน `web.backend.live_capture` บนโฮสต์นั้น

**บอกผมเมื่อ VM พร้อม เดี๋ยวผมเขียนส่วนนี้ให้** — หรือจะให้เขียนรอไว้ก่อนก็ได้

## ตรวจสอบแล้ว

ก่อนเขียนคู่มือนี้ ตรวจแล้วว่า:

- ISO `ubuntu-20.04.6-live-server-amd64.iso` ดาวน์โหลดได้จริง (HTTP 200)
- แพ็กเกจฝั่งเครื่องหลัก (Pop!_OS 24.04) มีครบ: `qemu-kvm` `libvirt-daemon-system`
  `virt-manager` `virtinst` `ovmf`
- แพ็กเกจฝั่ง VM (Ubuntu 20.04) มีครบ: `mininet` `openvswitch-switch`
  `openvswitch-testcontroller` `python3-venv` `hping3` `nmap`
- เครื่องคุณ: VT-x เปิด · `/dev/kvm` มีแล้ว · RAM 15 GB · ดิสก์ว่าง 250 GB

**สิ่งที่ยังไม่ได้ตรวจ** — ขั้นตอนที่ต้องใช้ `sudo` และการติดตั้งจริงทั้งหมด
รวมถึงการกดเวอร์ชัน `eventlet==0.30.2` ให้ Ryu ทำงาน ซึ่งเป็นวิธีแก้ที่รู้กันทั่วไป
แต่ผมยืนยันด้วยการรันไม่ได้จากที่นี่ **ถ้าติดตรงไหนบอกได้ เดี๋ยวช่วยไล่**

## ปัญหาที่เจอบ่อย

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| `virsh` ขึ้น permission denied | ยังไม่ได้ออกจากระบบหลัง `usermod` |
| `mn --test pingall` ค้าง | มีตัวควบคุมเก่าค้างอยู่ → `sudo mn -c` |
| Ryu ขึ้น `ALREADY_HANDLED` | eventlet ใหม่เกิน → กด `eventlet==0.30.2` |
| พอร์ต 6653 ถูกใช้แล้ว | `sudo systemctl stop openvswitch-testcontroller` |
| VM ช้ามาก | ไม่ได้ใช้ KVM → ตรวจ `virsh dumpxml mininet-nids \| grep kvm` |
| เน็ตใน VM ไม่ทำงาน | `sudo virsh net-start default` บนเครื่องหลัก |
