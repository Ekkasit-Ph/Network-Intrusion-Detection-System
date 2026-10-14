#!/usr/bin/env bash
# เดโมสด Mininet + แดชบอร์ด NIDS ด้วยโมเดลที่เทรนเฉพาะเครือข่ายนี้ (mininet-demo).
#
# ลำดับสำคัญมาก: `mn -c` ฆ่า ryu-manager ด้วย -- ต้องเริ่ม Ryu *หลัง* mn -c เสมอ
# ไม่งั้นสวิตช์ (fail_mode=secure) จะไม่มี controller และดรอปทราฟฟิก IPv4 ทั้งหมด
# (อาการ: จับได้แต่ ICMPv6 multicast, curl/ping ล้มเหลว 100%).
#
# ใช้: sudo NIDS_ROOT=$HOME/nids bash run_live_demo.sh [duration_seconds]
set -uo pipefail
# ผู้เรียกจริง: SUDO_USER (ตอน sudo), USER (ทั่วไป), หรือเจ้าของโฟลเดอร์โปรเจกต์
# (ใต้ systemd ไม่มีทั้ง SUDO_USER และ USER -- set -u จะ error ถ้าไม่ default)
_SELF="$(stat -c %U "$(dirname "$(readlink -f "$0")")" 2>/dev/null || echo ekkasit)"
OWNER="${SUDO_USER:-${USER:-$_SELF}}"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"   # $HOME คือ /root ใต้ sudo -- ใช้ home ของผู้เรียกจริง
NIDS_ROOT="${NIDS_ROOT:-$OWNER_HOME/nids}"
DURATION="${1:-180}"
DB="$NIDS_ROOT/data/nids-mininet.db"
VENV="$NIDS_ROOT/.venv/bin"
RYU="${RYU_MANAGER:-$OWNER_HOME/ryu-venv/bin/ryu-manager}"
RYU_PID=""

cleanup() { [ -n "$RYU_PID" ] && kill "$RYU_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo ">> [1/4] ล้าง Mininet เดิม (ฆ่า ryu ไปด้วย -- จะเริ่มใหม่หลังจากนี้)"
mn -c >/dev/null 2>&1 || true
pkill -f ryu-manager 2>/dev/null || true
sleep 1

echo ">> [2/4] เริ่ม Ryu controller ใหม่ (เป็นลูกของสคริปต์นี้ อยู่จนเดโมจบ)"
PYTHONPATH="$NIDS_ROOT" "$RYU" --observe-links ryu.app.ofctl_rest \
  "$NIDS_ROOT/network_simulation/ryu_app.py" >/tmp/ryu-demo.log 2>&1 &
RYU_PID=$!
sleep 6
if ! kill -0 "$RYU_PID" 2>/dev/null; then
  echo "   Ryu ไม่ขึ้น -- ดู /tmp/ryu-demo.log"; tail -5 /tmp/ryu-demo.log; exit 1
fi
echo "   ryu: pid $RYU_PID (port 6653)"

echo ">> [3/4] ล้างตารางในฐานข้อมูลเดโมให้เริ่มสด"
chown "$OWNER:$OWNER" "$DB" 2>/dev/null || true
if [ -f "$DB" ]; then
  sudo -u "$OWNER" "$VENV/python" -c "import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
try: c.execute('DELETE FROM flows'); c.commit(); print('   cleared')
except sqlite3.OperationalError: print('   (ยังไม่มีตาราง -- live_capture จะสร้างเอง)')" "$DB" || true
fi

echo ">> [4/4] รันเดโม ${DURATION}s -- เปิดแดชบอร์ดที่ http://<vm-ip>:8000"
PYTHONPATH="$NIDS_ROOT" python3 "$NIDS_ROOT/network_simulation/demo/demo_live.py" --duration "$DURATION"
echo ">> เดโมจบ (Ryu จะถูกปิดอัตโนมัติ)"
