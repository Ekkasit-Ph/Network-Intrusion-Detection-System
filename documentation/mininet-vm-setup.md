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

## ทำไมต้อง Ubuntu 22.04 — และทำไมไม่ใช่ 20.04

ใน VM ต้องมี Python **สองรุ่น** เพราะสองฝั่งต้องการคนละอย่าง

| ต้องการ | เงื่อนไข | เหตุผล |
|---|---|---|
| **Ryu** | Python ≤ 3.9 | `eventlet` พังบน 3.10+ |
| **`requirements.txt` ของโปรเจกต์** | Python ≥ 3.9 | numpy 1.26, pandas 2.2, scikit-learn 1.4, scipy 1.12 ทุกตัวกำหนด `>=3.9` |

| Ubuntu | Python ของระบบ | ใช้กับโปรเจกต์ | หา Python สำหรับ Ryu ได้ไหม |
|---|---|---|---|
| 20.04 | 3.8 | ❌ **ต่ำเกินไป** | ❌ deadsnakes **เลิกรองรับ focal แล้ว** |
| **22.04** | **3.10** | ✅ | ✅ **`python3.9` จาก deadsnakes** |
| 24.04 | 3.12 | ✅ | ❌ deadsnakes/noble ไม่มี 3.9 แล้ว |

> **22.04 เป็นรุ่นเดียวที่ทั้งสองฝั่งลงตัว** — ระบบให้ 3.10 สำหรับโปรเจกต์
> และ deadsnakes ให้ 3.9 สำหรับ Ryu

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

## ขั้นที่ 1.5 — เก็บ VM ไว้บนดิสก์ลูกที่สอง

> 🔴 **ต้องทำขั้นที่ 1 ให้เสร็จก่อน** — `/var/lib/libvirt/images` ซึ่งเป็นปลายทางของ bind mount
> ถูกสร้างโดยแพ็กเกจ `libvirt-daemon-system` ถ้ายังไม่ได้ลง คำสั่ง `mount --bind` จะขึ้น
> *"mount point does not exist"* ส่วนคำสั่ง `mkdir`/`chown`/`chmod` ข้างล่างทำก่อนได้ไม่มีปัญหา

เครื่องนี้มี NVMe ลูกที่สอง (Samsung PM9A1) **ว่าง 419 GB จาก 469 GB** อยู่ที่ `/media/ekkasit/Games`
เหมาะกว่าดิสก์หลักเพราะ **I/O ของ VM จะไม่ไปชนกับระบบปฏิบัติการ**

### ปัญหาที่ต้องแก้ก่อน: libvirt เข้าไม่ถึงเส้นทางนั้น

```
/media/ekkasit         user:ekkasit:r-x  other::---     <- ACL ให้เฉพาะ ekkasit
/media/ekkasit/Games   user::rwx  group::---  other::---
```

libvirt รัน qemu ด้วยผู้ใช้ **`libvirt-qemu`** ซึ่ง**เดินผ่านสองชั้นนี้ไม่ได้**
วางไฟล์ VM ไว้ตรงนั้นตรง ๆ แล้วจะขึ้น permission denied

### วิธีแก้: bind mount ไปทับที่เก็บมาตรฐานของ libvirt

```bash
# สร้างที่เก็บบนดิสก์ลูกที่สอง ให้สิทธิ์แบบเดียวกับของเดิมของ libvirt
sudo mkdir -p /media/ekkasit/Games/VMs
sudo chown root:root /media/ekkasit/Games/VMs
sudo chmod 0711 /media/ekkasit/Games/VMs

# ผูกเข้ากับที่เก็บมาตรฐาน
sudo mount --bind /media/ekkasit/Games/VMs /var/lib/libvirt/images
```

ให้ถาวรโดยเพิ่มบรรทัดนี้ใน `/etc/fstab` **ต่อจากบรรทัดที่ mount ดิสก์ Games**:

```
/media/ekkasit/Games/VMs  /var/lib/libvirt/images  none  bind,nofail,x-systemd.requires-mounts-for=/media/ekkasit/Games  0  0
```

**ทำไมวิธีนี้ถึงได้ผล** — หลัง bind mount เคอร์เนลจะไล่เส้นทางผ่าน `/var/lib/libvirt/images`
ซึ่งเข้าถึงได้ปกติ **ACL บน `/media/ekkasit` ไม่ถูกตรวจอีกต่อไป**

**และได้ประโยชน์อีกข้อ** — AppArmor ของ Ubuntu จำกัดสิทธิ์ qemu ตามเส้นทางในไฟล์ XML ของ VM
การใช้เส้นทางมาตรฐาน `/var/lib/libvirt/images` ทำให้ไม่ต้องไปแก้โปรไฟล์ AppArmor เลย

ตรวจว่าใช้ได้:

```bash
findmnt /var/lib/libvirt/images   # source ต้องเป็น /dev/nvme1n1p1
df -h /var/lib/libvirt/images     # ต้องเห็นว่าง ~419G ไม่ใช่ 250G
sudo touch /var/lib/libvirt/images/.probe && sudo rm /var/lib/libvirt/images/.probe \
  && echo "เขียนได้"
```

> **อย่าตรวจด้วย `sudo -u libvirt-qemu test -w`** — จะได้ผลว่าเขียนไม่ได้ ซึ่ง**ถูกต้องแล้ว**
> ที่เก็บนี้เป็น `0711 root:root` โดยออกแบบ: `libvirtd` (รันเป็น root) เป็นคนสร้างไฟล์อิมเมจ
> แล้วค่อยเปลี่ยนเจ้าของให้ `libvirt-qemu` ซึ่งต้องการแค่สิทธิ์**เดินผ่าน** ไม่ใช่สิทธิ์สร้างไฟล์

> **ทางเลือกที่ง่ายกว่าแต่สะอาดน้อยกว่า** — แก้ `/etc/libvirt/qemu.conf` ให้ `user = "ekkasit"`
> แล้ว qemu จะเดินผ่าน ACL ได้ แต่เปลี่ยนรูปแบบความปลอดภัยของ VM **ทุกตัว** และอาจยังติด AppArmor
> แนะนำให้ใช้ bind mount

> ⚠️ ดิสก์นี้ mount ด้วย `nosuid,nodev` ซึ่ง**ไม่มีผลกับไฟล์อิมเมจ qcow2** ใช้ได้ปกติ
> และในบรรทัด fstab เดิมมี `nofail` อยู่แล้ว ถ้าดิสก์ไม่มีตอนบูตเครื่องก็ยังบูตขึ้น

## ขั้นที่ 2 — โหลด ISO

```bash
# เก็บ ISO บนดิสก์ลูกที่สอง แต่**อ้างผ่านเส้นทาง bind mount เสมอ**
sudo mkdir -p /var/lib/libvirt/images/iso
sudo chmod 0755 /var/lib/libvirt/images/iso
cd /var/lib/libvirt/images/iso
sudo wget https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso
sudo chmod 0644 ubuntu-22.04.5-live-server-amd64.iso
```

> 🔴 **อย่าโหลดไว้ใน `~/` หรืออ้างผ่าน `/media/ekkasit/Games/...`**
> `/home/ekkasit` เป็น `drwxr-x--- ekkasit ekkasit` และ `/media/ekkasit` มี ACL ให้เฉพาะ `ekkasit`
> ส่วน qemu รันเป็นผู้ใช้ `libvirt-qemu` (uid 64055 กลุ่ม kvm) ซึ่ง**เดินผ่านทั้งสองที่ไม่ได้**
> จะขึ้น permission denied ตอนเปิด ISO — และ AppArmor ก็อนุญาตเฉพาะเส้นทางมาตรฐาน

ตรวจก่อนไปต่อ:

```bash
sudo -u libvirt-qemu test -r /var/lib/libvirt/images/iso/ubuntu-22.04.5-live-server-amd64.iso \
  && echo "libvirt-qemu อ่านได้"
```

ใช้ **live-server** ไม่ใช่ desktop — เบากว่ามาก และงานนี้ใช้แต่บรรทัดคำสั่ง (~1.4 GB)

## ขั้นที่ 3 — สร้าง VM

```bash
virt-install \
  --name mininet-nids \
  --memory 6144 \
  --vcpus 4 \
  --disk path=/var/lib/libvirt/images/mininet-nids.qcow2,size=60,format=qcow2 \
  --cdrom /var/lib/libvirt/images/iso/ubuntu-22.04.5-live-server-amd64.iso \
  --os-variant ubuntu22.04 \
  --network network=default \
  --graphics spice \
  --noautoconsole

virt-manager      # เปิดหน้าต่างแล้วดับเบิลคลิก mininet-nids เพื่อติดตั้งต่อ
```

> ถ้า `--os-variant ubuntu22.04` ขึ้นว่าไม่รู้จัก ให้ดูรายชื่อที่มีด้วย
> `osinfo-query os | grep ubuntu` แล้วเลือกตัวที่ใกล้เคียง หรือใช้ `--os-variant generic`
> (มีผลแค่ค่าปรับแต่งเริ่มต้น ไม่กระทบว่า VM จะทำงานได้หรือไม่)

**ทรัพยากรที่ให้:** RAM 6 GB · 4 vCPU · **ดิสก์ 60 GB** (ให้เผื่อได้เพราะมีที่ว่าง 419 GB)
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

## ขั้นที่ 5 — ลง Ryu บน Python 3.9 แยกต่างหาก

Python ของระบบคือ 3.10 ซึ่ง **Ryu ใช้ไม่ได้** ต้องเอา 3.9 มาจาก deadsnakes

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.9 python3.9-venv python3.9-dev

python3.9 -m venv ~/ryu-venv
~/ryu-venv/bin/pip install --upgrade pip

# eventlet รุ่นใหม่ตัด ALREADY_HANDLED ออก ทำให้ Ryu พัง -- ต้องกดเวอร์ชัน
~/ryu-venv/bin/pip install 'eventlet==0.30.2' ryu

~/ryu-venv/bin/python --version         # ต้องขึ้น Python 3.9.x
~/ryu-venv/bin/ryu-manager --version    # ต้องขึ้นเลขเวอร์ชัน ไม่ใช่ traceback
```

⚠️ ถ้า error เรื่อง `ALREADY_HANDLED` แปลว่า eventlet ไม่ได้ถูกกดเวอร์ชัน ให้ลงใหม่
⚠️ **ห้ามใช้ `python3 -m venv` เฉย ๆ** — จะได้ 3.10 แล้ว Ryu จะพัง

## ขั้นที่ 6 — เอาโปรเจกต์เข้า VM

**รีโปเป็น private** — `git clone` ใน VM จะติดการยืนยันตัวตน ใช้ `rsync` จากเครื่องหลักง่ายกว่า
และได้ไฟล์ที่ไม่ได้อยู่ใน git มาพร้อมกันเลย

```bash
# รันบนเครื่องหลัก -- ส่งทั้งโค้ดและข้อมูลที่จำเป็นในคำสั่งเดียว
rsync -av --info=progress2 \
  --exclude '.venv' --exclude '.git' --exclude '__pycache__' \
  --exclude 'data/raw' --exclude 'data/processed' \
  --exclude 'data/processed_experiments' \
  --exclude 'data/processed_w50/val.parquet' \
  --exclude 'data/processed_w50/test.parquet' \
  --exclude '*.db' \
  ~/Workspace/Project/Network-Intrusion-Detection-System/ \
  <user>@<ip-ของ-vm>:~/nids/
```

ส่งไปประมาณ **80 MB** — โค้ด + `artifacts/` + `train.parquet` (74 MB ซึ่ง `ShapExplainer` ต้องใช้)
`val.parquet` กับ `test.parquet` ถูกตัดออกเพราะใน VM เราจับทราฟฟิกสดจาก Mininet ไม่ได้ใช้ replay

ใน VM:

```bash
cd ~/nids
python3 -m venv .venv                  # Python 3.10 ของระบบ -- ผ่านเงื่อนไข >=3.9
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q          # ควรผ่านทั้งหมด
```

## ขั้นที่ 7 — ทดสอบว่าทุกชิ้นทำงานร่วมกัน

```bash
# เทอร์มินัล 1 -- ตัวควบคุม Ryu
~/ryu-venv/bin/ryu-manager --observe-links ryu.app.ofctl_rest \
  ~/nids/network_simulation/ryu_app.py

# เทอร์มินัล 2 -- โทโพโลยี
cd ~/nids
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

- ISO `ubuntu-22.04.5-live-server-amd64.iso` ดาวน์โหลดได้จริง (HTTP 200)
  — รุ่น 22.04.4 ถูกแทนที่ไปแล้ว (404)
- แพ็กเกจฝั่งเครื่องหลัก (Pop!_OS 24.04) มีครบ: `qemu-kvm` `libvirt-daemon-system`
  `virt-manager` `virtinst` `ovmf`
- แพ็กเกจฝั่ง VM (Ubuntu 22.04) มีครบ: `mininet` `openvswitch-switch`
  `openvswitch-testcontroller` `python3-venv` `hping3` `nmap`
- deadsnakes มี `python3.9` สำหรับ jammy จริง (เวอร์ชัน `3.9.25-1+jammy1`)
- **deadsnakes เลิกรองรับ focal แล้ว** — ดัชนีแพ็กเกจของ 20.04 ว่างเปล่า (0 ไบต์)
  ซึ่งเป็นเหตุผลที่คู่มือนี้เปลี่ยนจาก 20.04 มาเป็น 22.04
- `requirements.txt` ต้องการ Python ≥ 3.9 (ตรวจจาก metadata ของ numpy 1.26,
  pandas 2.2, scikit-learn 1.4, scipy 1.12 บน PyPI) — Python 3.8 ของ 20.04 จึงใช้ไม่ได้
- เครื่องคุณ: VT-x เปิด · `/dev/kvm` มีแล้ว · RAM 15 GB
- ดิสก์ลูกที่สอง `/dev/nvme1n1p1` ว่าง 419 GB · อยู่ใน `/etc/fstab` แล้ว (มี `nofail`)
- ACL บน `/media/ekkasit` ให้สิทธิ์เฉพาะผู้ใช้ `ekkasit` — เป็นเหตุผลที่ต้อง bind mount

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
| สร้าง VM แล้วขึ้น permission denied | bind mount ยังไม่ทำงาน → `findmnt /var/lib/libvirt/images` |
| `mount --bind` ขึ้น mount point does not exist | ยังไม่ได้ลง KVM (ขั้นที่ 1) → `/var/lib/libvirt/images` ยังไม่ถูกสร้าง |
| `virsh` / `virt-install` ไม่พบคำสั่ง | ขั้นที่ 1 ยังไม่ได้รัน → ตรวจด้วย `dpkg -s libvirt-daemon-system` |
| เปิด ISO ไม่ได้ / permission denied | ISO อยู่ใน `~/` หรืออ้างผ่าน `/media/...` → ย้ายไป `/var/lib/libvirt/images/iso/` |
| `qemu-kvm` ลงไม่ได้ | บน 24.04 เป็นแพ็กเกจเปล่า ตัวจริงคือ `qemu-system-x86` — ไม่ใช่ปัญหา |
| ดิสก์สลับเลข nvme0/nvme1 หลังบูต | ปกติ — fstab ใช้ UUID จึงไม่กระทบ |
| บูตมาแล้ว VM หาย | ดิสก์ Games ไม่ได้ mount → `sudo mount -a` แล้วดู `journalctl -u libvirtd` |
