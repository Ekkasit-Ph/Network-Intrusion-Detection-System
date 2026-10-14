#!/usr/bin/env python3
"""เดโมสด (สมจริง ระดับ 1+2+3): Mininet + nids1 ตรวจจับด้วยโมเดล mininet-demo
เขียนผลลง data/nids-mininet.db ที่แดชบอร์ดอ่าน.

ทุกอย่างรันในเธรดหลักเธรดเดียว (Mininet host.cmd() ไม่ thread-safe).
benign หลายโปรโตคอลจังหวะ Poisson เป็นพื้นหลัง แล้วช่วงท้ายยิงโจมตีหลายแบบต่อเนื่อง
(scan -> dos -> bruteforce -> blocked-ports) ให้เป็น flow ใหม่สุด -> โผล่บนสุดของหน้าแรก

รัน: sudo NIDS_ROOT=$HOME/nids bash network_simulation/demo/run_live_demo.sh [duration]
"""
import argparse
import os
import random
import subprocess
import sys
import time

NIDS = os.environ.get("NIDS_ROOT",
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, NIDS)

# Mininet host.popen(shell=True) reads os.environ['SHELL']; systemd/cron don't
# set it, so give it a default or popen() raises KeyError: 'SHELL'.
os.environ.setdefault("SHELL", "/bin/bash")

from mininet.log import setLogLevel  # noqa: E402
from network_simulation.topology import (  # noqa: E402
    build, _configure_routes, mirror_to_sensor, clear_mirror, SENSOR,
)
from network_simulation.demo import traffic  # noqa: E402

ATTACK_SEQUENCE = ["portscan", "bruteforce", "dos"]
ATTACK_LABEL = {
    "portscan":   "PORT SCAN (fan-out)",
    "dos":        "SYN FLOOD / DoS",
    "bruteforce": "SSH BRUTE-FORCE",
    "blocked":    "พยายามต่อพอร์ตที่ firewall บล็อก (telnet/rdp)",
}


def start_capture(nids_host):
    iface = nids_host.defaultIntf()
    cmd = (f"cd {NIDS} && NIDS_DB_PATH={NIDS}/data/nids-mininet.db "
           f".venv/bin/python -m web.backend.live_capture "
           f"--source {iface} "
           f"--processed-dir data/mininet_demo "
           f"--artifacts-dir artifacts/models/mininet-demo "
           f"--preprocessing-dir artifacts/preprocessing_mininet "
           f"--db-path data/nids-mininet.db "
           f"--idle-timeout 3 --active-timeout 8")
    return nids_host.popen(cmd, shell=True,
                           stdout=subprocess.DEVNULL, stderr=open("/tmp/capture.log", "w"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    setLogLevel("warning")
    net = build()
    net.start()
    _configure_routes(net)
    traffic.setup_services(net)
    mirror_to_sensor(net)
    nids = net.get(SENSOR[0])

    cap = start_capture(nids)
    print(">> live_capture เริ่มแล้ว รอ warm up...", flush=True)
    time.sleep(6)
    print(f">> ปล่อย benign หลายโปรโตคอล -- เปิด http://192.168.122.219:8000", flush=True)

    # benign พื้นหลังจนถึง 65% ของเวลา แล้วค่อยยิงโจมตีต่อเนื่องช่วงท้าย
    benign_until = args.duration * 0.65
    start = time.time()
    while time.time() - start < benign_until:
        traffic.benign_step(net, rng)
        time.sleep(traffic.poisson_gap(rng, rate_per_sec=3.0))

    print(">> === เริ่มลำดับการโจมตี ===", flush=True)
    for name in ATTACK_SEQUENCE:
        print(f">> !!! {ATTACK_LABEL[name]} จาก atk1 !!!", flush=True)
        traffic.ATTACKS[name](net)
        # แทรก benign นิดหน่อยระหว่างการโจมตีให้ภาพจริง (แต่ไม่มากพอจะบังของท้าย)
        for _ in range(2):
            traffic.benign_step(net, rng)
            time.sleep(0.4)

    print(">> การโจมตีจบ ให้ flow สุดท้าย flush...", flush=True)
    time.sleep(8)
    cap.kill()
    traffic.teardown_services(net)
    clear_mirror(net)
    net.stop()
    print(">> เดโมจบ ทราฟฟิกยังอยู่ในแดชบอร์ด", flush=True)


if __name__ == "__main__":
    main()
