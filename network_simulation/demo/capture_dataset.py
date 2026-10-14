#!/usr/bin/env python3
"""เก็บชุดข้อมูล Mininet สมจริง (ระดับ 1+2+3) สำหรับเทรนโมเดลเฉพาะเครือข่ายนี้.

เฟส benign หลายโปรโตคอล (HTTP/DNS/SSH/IoT-beacon/bulk) จังหวะแบบ Poisson แล้วตาม
ด้วยการโจมตีทีละชนิด (portscan, dos, bruteforce, blocked) แต่ละชนิดเก็บด้วย sensor
ของตัวเองเพื่อติด label สะอาด (flow ที่ src=atk1 = โจมตีชนิดนั้น).

ผลลัพธ์: /tmp/mininet_raw.csv  (NETFLOW_FEATURES + Label + Attack)
รัน: sudo NIDS_ROOT=$HOME/nids PYTHONPATH=$HOME/nids python3 capture_dataset.py
"""
import argparse
import csv
import os
import random
import subprocess
import sys
import time
from pathlib import Path

NIDS = os.environ.get("NIDS_ROOT",
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, NIDS)

# Mininet host.popen(shell=True) reads os.environ['SHELL']; systemd/cron don't
# set it, so give it a default or every popen() raises KeyError: 'SHELL'.
os.environ.setdefault("SHELL", "/bin/bash")

from mininet.log import setLogLevel  # noqa: E402
from network_simulation.topology import (  # noqa: E402
    build, _configure_routes, mirror_to_sensor, clear_mirror, SENSOR,
)
from network_simulation.demo import traffic  # noqa: E402

ATK_IP = "10.0.3.11"
OUT_CSV = os.path.join(NIDS, "data", "mininet_demo", "mininet_raw.csv")
BENIGN_SECONDS = 120
ATTACK_ORDER = ["portscan", "bruteforce", "dos"]


def start_sensor(nids_host, out_path):
    iface = nids_host.defaultIntf()
    cmd = (f"cd {NIDS} && .venv/bin/python -m source.extraction.sensor "
           f"--source {iface} --output {out_path} "
           f"--idle-timeout 3 --active-timeout 8")
    return nids_host.popen(cmd, shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def relabel(src_csv, writer, label_fn, cap_attack=None, rng=None):
    """เขียน benign ในเฟสทั้งหมด แต่ cap จำนวน flow ที่เป็น 'โจมตี' ต่อคลาส
    (SYN flood สร้างได้เป็นพัน flow ถ้าไม่ cap คลาสเดียวจะกลืนทั้ง dataset)."""
    if not Path(src_csv).exists():
        return 0
    benign_rows, attack_rows = [], []
    with open(src_csv) as fh:
        for row in csv.DictReader(fh):
            lbl, atk = label_fn(row)
            row["Label"], row["Attack"] = lbl, atk
            (attack_rows if lbl == "1" else benign_rows).append(row)
    if cap_attack is not None and len(attack_rows) > cap_attack:
        attack_rows = (rng or __import__("random")).sample(attack_rows, cap_attack)
    for row in benign_rows + attack_rows:
        writer.writerow(row)
    return len(benign_rows) + len(attack_rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-seconds", type=int, default=BENIGN_SECONDS)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    setLogLevel("warning")
    net = build()
    net.start()
    _configure_routes(net)
    traffic.setup_services(net)
    mirror_to_sensor(net)
    nids = net.get(SENSOR[0])

    # sensor ตัวเดียวต่อเนื่องตลอดการเก็บ -- เชื่อถือได้กว่าการ kill/restart ต่อเฟส
    # (การรีสตาร์ท nfstream ต่อเฟสมี race ทำให้บางเฟสจับได้ 0 flow แบบสุ่ม)
    raw_csv = "/tmp/mn_capture.csv"
    try:
        s = start_sensor(nids, raw_csv)
        time.sleep(6)  # warm up

        # ---- benign (หลายโปรโตคอล, Poisson) ----
        print(f">> benign {args.benign_seconds}s", flush=True)
        t0 = time.time()
        while time.time() - t0 < args.benign_seconds:
            traffic.benign_step(net, rng)
            time.sleep(traffic.poisson_gap(rng, rate_per_sec=3.0))

        # ---- การโจมตีต่อเนื่อง (พอร์ตปลายทางไม่ทับกัน -> แยก label ได้ตอนหลัง) ----
        for name in ATTACK_ORDER:
            print(f">> attack: {name}", flush=True)
            traffic.ATTACKS[name](net)
            time.sleep(4)  # เว้นให้ flow ของชนิดนี้ทยอยจบก่อนชนิดถัดไป

        time.sleep(10)  # ให้ flow สุดท้าย flush (idle-timeout 3, active 8)
        s.kill(); time.sleep(1)
    finally:
        traffic.teardown_services(net)
        clear_mirror(net)
        net.stop()

    # ---- label: benign = src != atk1; atk1 flow แยกชนิดจากพอร์ตปลายทาง ----
    # bruteforce->22, dos->80, ที่เหลือ (พอร์ต scan 200-340) -> portscan
    def classify(row):
        if row["IPV4_SRC_ADDR"] != ATK_IP:
            return ("0", "Benign")
        try:
            dport = int(row["L4_DST_PORT"])
        except (ValueError, KeyError):
            dport = -1
        if dport == 22:
            return ("1", "bruteforce")
        if dport == 80:
            return ("1", "dos")
        return ("1", "portscan")

    from source.common.constants import NETFLOW_FEATURES
    fields = NETFLOW_FEATURES + ["Label", "Attack"]
    counts = {"benign": 0, "portscan": 0, "dos": 0, "bruteforce": 0}
    by_class = {"portscan": [], "dos": [], "bruteforce": []}
    benign_rows = []
    if Path(raw_csv).exists():
        with open(raw_csv) as fh:
            for row in csv.DictReader(fh):
                lbl, atk = classify(row)
                row["Label"], row["Attack"] = lbl, atk
                (benign_rows if lbl == "0" else by_class[atk]).append(row)

    with open(OUT_CSV, "w", newline="") as out:
        w = csv.DictWriter(out, fieldnames=fields)
        w.writeheader()
        for row in benign_rows:
            w.writerow(row)
        counts["benign"] = len(benign_rows)
        for name, rows in by_class.items():
            if len(rows) > 120:              # cap ให้สมดุล (dos flood ได้เยอะ)
                rows = rng.sample(rows, 120)
            for row in rows:
                w.writerow(row)
            counts[name] = len(rows)

    print(">> flows per class:", counts, flush=True)
    print(f">> wrote {OUT_CSV}", flush=True)


if __name__ == "__main__":
    main()
