"""ตัวสร้างทราฟฟิกสมจริงสำหรับ capture/demo บน Mininet.

ออกแบบตามข้อจำกัดที่เจอมา:
 * ทุกฟังก์ชันเรียกจาก **เธรดหลักเธรดเดียว** -- Mininet host.cmd() ใช้ pexpect
   shell ต่อโฮสต์ ไม่ thread-safe เรียกข้ามเธรดคำสั่งจะเงียบหาย
 * จังหวะเป็นแบบ **Poisson** (สุ่ม inter-arrival แบบ exponential) ไม่ใช่ fix
   ทำให้ flow duration / rate กระจายเหมือนทราฟฟิกจริง ไม่ใช่ก้อนสม่ำเสมอ

benign ครอบคลุมหลายโปรโตคอล (HTTP หลายขนาด+keepalive, DNS จริง UDP/53, SSH จริง,
IoT beacon เป็นจังหวะ, bulk transfer) -- ยิ่งหลากหลาย "ปกติ" ที่โมเดลเรียนยิ่งใกล้จริง
และ scaler generalize ดีขึ้น -> FPR ต่ำ

attack ครอบคลุมสิ่งที่มี flow-level signature จริง: port scan (fan-out),
SYN flood/DoS, SSH brute-force (short repeated), และความพยายามต่อพอร์ตที่ firewall
บล็อก (โชว์ defense-in-depth: NIDS เห็นความพยายามแม้ firewall ดรอป)
"""
from __future__ import annotations

import os
import time

DNS_HOST = "dns1"
DNS_IP = "10.0.2.13"
SERVERS = ["10.0.2.11", "10.0.2.12"]
IOT_HOSTS = ["iot1", "iot2", "iot3", "iot4", "iot5", "iot6"]
CLIENTS = IOT_HOSTS + ["srv2"]
SSH_KEY = "/tmp/demo_ssh_host_ed25519_key"
FAKE_DOMAINS = ["update.example.com", "api.service.io", "telemetry.device.net",
                "ntp.pool.org", "cdn.assets.com", "mqtt.broker.local"]


# ---------- services ----------------------------------------------------

def setup_services(net) -> None:
    """เปิดบริการบนเซิร์ฟเวอร์ให้ benign มีของจริงให้คุย: HTTP (ไฟล์หลายขนาด),
    DNS (UDP/53), SSH (sshd จริง), iperf (bulk). เรียกครั้งเดียวหลัง start."""
    from network_simulation.topology import set_realistic_ttls
    set_realistic_ttls(net)

    # host key สำหรับ sshd (สร้างครั้งเดียว ใช้ร่วมทุก namespace ผ่าน fs เดียวกัน)
    if not os.path.exists(SSH_KEY):
        os.system(f"ssh-keygen -t ed25519 -f {SSH_KEY} -N '' -q </dev/null 2>/dev/null")

    nids_root = os.environ.get("NIDS_ROOT",
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

    # ⚠️ Mininet host namespaces แชร์ PID namespace กับ VM -- pkill โดนทั้งเครื่อง
    # จึงต้องเคลียร์ของเก่า **ครั้งเดียวก่อน loop** ถ้า pkill ในแต่ละรอบ รอบของ srv2
    # จะไปฆ่า http.server/sshd ของ srv1 ที่เพิ่งสตาร์ท (เจอมาแล้ว srv1 ไม่เหลือบริการ)
    # และห้าม pkill 'sshd' กว้าง ๆ -- จะฆ่า sshd ของ VM เอง; match เฉพาะ key ของเดโม
    net.get("srv1").cmd(f"pkill -f 'http.server'; pkill -f '{SSH_KEY}'; "
                        f"pkill -f 'iperf -s'; sleep 0.2")

    for s in ("srv1", "srv2"):
        h = net.get(s)
        h.cmd("mkdir -p /tmp/www && cd /tmp/www && "
              "head -c 1500 /dev/urandom > s.bin && "
              "head -c 30000 /dev/urandom > m.bin && "
              "head -c 250000 /dev/urandom > l.bin && "
              "head -c 1500000 /dev/urandom > xl.bin")
        h.cmd("cd /tmp/www && python3 -m http.server 80 &>/dev/null &")
        h.cmd("cd /tmp/www && python3 -m http.server 8080 &>/dev/null &")
        # sshd จริง: banner + key exchange ทำให้ nDPI แยกเป็น SSH ได้
        h.cmd(f"/usr/sbin/sshd -D -p 22 -h {SSH_KEY} "
              f"-o UsePAM=no -o PidFile=none -o PermitRootLogin=no "
              f"-o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no "
              f"&>/dev/null &")
        # iperf server สำหรับ bulk transfer
        h.cmd("iperf -s &>/dev/null &")

    # DNS resolver จริงบน dns1
    dns = net.get(DNS_HOST)
    dns.cmd(f"python3 {nids_root}/network_simulation/demo/dns_server.py --port 53 &>/dev/null &")
    time.sleep(1.5)


def teardown_services(net) -> None:
    for s in ("srv1", "srv2"):
        net.get(s).cmd(f"pkill -f 'http.server'; pkill -f '{SSH_KEY}'; pkill -f 'iperf -s'")
    net.get(DNS_HOST).cmd("pkill -f dns_server.py")


# ---------- benign activities (แต่ละตัว = ทราฟฟิกจริงหนึ่งชุด) ------------

def http_fetch(net, rng) -> None:
    """HTTP ขนาดต่าง ๆ + keepalive (หลาย URL ในคอนเนคชันเดียว)."""
    c = net.get(rng.choice(CLIENTS))
    srv = rng.choice(SERVERS)
    port = rng.choice(["80", "8080"])
    files = rng.sample(["s.bin", "m.bin", "l.bin", "xl.bin", ""], k=rng.randint(1, 3))
    urls = " ".join(f"http://{srv}:{port}/{f}" for f in files)
    c.cmd(f"curl -s -m5 -o /dev/null {urls}")


def dns_query(net, rng) -> None:
    """DNS จริง UDP/53 ไป dns1 -- โปรโตคอลที่โมเดลเคยอ่อน."""
    c = net.get(rng.choice(CLIENTS))
    name = rng.choice(FAKE_DOMAINS)
    c.cmd(f"dig +time=2 +tries=1 @{DNS_IP} {name} A >/dev/null 2>&1")


def ssh_session(net, rng) -> None:
    """SSH จริง: banner+kex แล้ว auth ล้ม (ไม่ต้องมี credential จริง) -- ได้ flow SSH."""
    c = net.get(rng.choice(IOT_HOSTS))
    srv = rng.choice(SERVERS)
    c.cmd(f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          f"-o ConnectTimeout=2 -o BatchMode=yes "
          f"-o PreferredAuthentications=publickey -o PubkeyAuthentication=no "
          f"svc@{srv} true >/dev/null 2>&1")


def iot_beacon(net, rng) -> None:
    """อุปกรณ์ IoT ส่ง 'สัญญาณเป็นจังหวะ' -- คอนเนคชันสั้น ๆ ไปเซิร์ฟเวอร์เดิมซ้ำ ๆ
    (mimic โทรกลับบ้าน) ยิงพร้อมกันหลายตัวจาก IoT หลายเครื่อง."""
    for name in rng.sample(IOT_HOSTS, k=rng.randint(2, 4)):
        h = net.get(name)
        h.cmd(f"curl -s -m2 -o /dev/null http://{SERVERS[0]}/s.bin")


def ping_check(net, rng) -> None:
    c = net.get(rng.choice(CLIENTS))
    c.cmd(f"ping -c{rng.randint(2,4)} -i0.2 -W1 {rng.choice(SERVERS)} >/dev/null 2>&1")


def bulk_transfer(net, rng) -> None:
    """iperf bulk ~2s -> flow ยาว byte เยอะ (ปลายสเปกตรัมของ 'ปกติ')."""
    c = net.get(rng.choice(IOT_HOSTS))
    c.cmd(f"iperf -c {SERVERS[1]} -t 2 -y c >/dev/null 2>&1")


BENIGN_ACTIVITIES = [
    (http_fetch, 5),    # (ฟังก์ชัน, น้ำหนักความถี่)
    (dns_query, 4),
    (iot_beacon, 3),
    (ping_check, 2),
    (ssh_session, 2),
    (bulk_transfer, 1),
]


def benign_step(net, rng) -> None:
    """ทำกิจกรรม benign หนึ่งอย่าง เลือกตามน้ำหนัก."""
    acts, weights = zip(*BENIGN_ACTIVITIES)
    fn = rng.choices(acts, weights=weights, k=1)[0]
    fn(net, rng)


def poisson_gap(rng, rate_per_sec: float) -> float:
    """ช่วงเวลารอแบบ exponential (กระบวนการ Poisson) มี cap กันค้างนาน."""
    return min(rng.expovariate(rate_per_sec), 3.0)


# ---------- attacks (มี flow-level signature จริง) -----------------------

def attack_port_scan(net) -> None:
    """fan-out: หนึ่งต้นทาง หลายพอร์ต/หลายปลายทาง -- flow สั้นทางเดียวจำนวนมาก.

    ใช้ช่วงพอร์ต 200-340 (เลี่ยง 22/80) เพื่อให้แยก label ได้จากพอร์ตปลายทาง
    เมื่อใช้ sensor ตัวเดียวต่อเนื่อง: atk1->22=bruteforce, ->80=dos, ->อื่น=scan.
    signature ของ scan คือ 'ติดต่อพอร์ตปลายทางหลากหลาย' ไม่ได้ผูกกับพอร์ตใดพอร์ตหนึ่ง."""
    atk = net.get("atk1")
    atk.cmd(f"nmap -sT -p 200-340 -T4 --max-retries 1 {SERVERS[0]} >/dev/null 2>&1")
    atk.cmd(f"nmap -sT -p 200-340 -T4 --max-retries 1 {SERVERS[1]} >/dev/null 2>&1")


def attack_syn_flood(net, seconds: int = 3) -> None:
    """DoS: SYN flood ไปพอร์ต 80 -- packet เยอะทางเดียว.

    ⚠️ `--flood` ส่งเร็วสุดโดยไม่จำกัด -- วัดได้ ~7,600 flow/วินาที (แต่ละ SYN
    สุ่ม source port = คนละ flow) ท่วมทั้ง sensor จนเฟสถัดไปเก็บอะไรไม่ได้เลย
    และ net.stop() ค้าง. จำกัดอัตราไว้ ~700 pps ก็ยังเป็น DoS ชัดเจน (fan-out
    ทางพอร์ตต้นทาง) แต่ไม่ทำให้ทั้งระบบล่ม; ตอน label ยัง cap จำนวนต่อคลาสอีกชั้น."""
    atk = net.get("atk1")
    atk.cmd(f"timeout {seconds} hping3 -S -p 80 -i u1500 {SERVERS[0]} >/dev/null 2>&1")


def attack_ssh_bruteforce(net, tries: int = 25) -> None:
    """brute-force: คอนเนคชัน SSH สั้น ๆ ซ้ำ ๆ จากต้นทางเดียว byte ใกล้กันหมด."""
    atk = net.get("atk1")
    atk.cmd(f"for i in $(seq 1 {tries}); do "
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=2 -o BatchMode=yes "
            f"-o PreferredAuthentications=password -o PubkeyAuthentication=no "
            f"admin@{SERVERS[0]} true >/dev/null 2>&1; done")


def attack_blocked_ports(net, rounds: int = 8) -> None:
    """พยายามต่อพอร์ตที่ firewall บล็อก (telnet 23, rdp 3389) -- packet ถูกดรอป
    ในสวิตช์ แต่ยัง mirror ถึงเซนเซอร์ -> NIDS เห็นความพยายาม (defense in depth)."""
    atk = net.get("atk1")
    for _ in range(rounds):
        atk.cmd(f"timeout 1 bash -c '</dev/tcp/{SERVERS[0]}/23' 2>/dev/null")
        atk.cmd(f"timeout 1 bash -c '</dev/tcp/{SERVERS[1]}/3389' 2>/dev/null")


ATTACKS = {
    "portscan":   attack_port_scan,
    "dos":        attack_syn_flood,
    "bruteforce": attack_ssh_bruteforce,
    "blocked":    attack_blocked_ports,
}
