#!/bin/sh
# บริการฝั่งคลาวด์สำหรับเดโม smart-home (รันบน node "cloud", Alpine)
# คือปลายทางที่อุปกรณ์ IoT โทรกลับบ้าน: MQTT broker + HTTP + DNS (+ NTP ถ้าต้องการ)
#
# เตรียม: apk add mosquitto python3 ; (NTP ถ้าจะเปิด: apk add openntpd)
# คัดลอก dns_server.py มาไว้ที่ /root/dns_server.py (มาจาก network_simulation/demo/)

set -e
echo "[cloud] starting services..."

# 1) MQTT broker (พอร์ต 1883) -- ปลายทาง publish ของปลั๊ก/หลอดไฟ/ลำโพง
mosquitto -d -p 1883 2>/dev/null || mosquitto -d
# มี subscriber ค้างไว้ให้ broker มี session จริง
(mosquitto_sub -h 127.0.0.1 -t 'home/#' >/dev/null 2>&1 &)

# 2) ไฟล์หลายขนาดให้ HTTP เสิร์ฟ (ทำให้ byte/flow ของอุปกรณ์กระจายจริง)
mkdir -p /srv/www && cd /srv/www
dd if=/dev/urandom of=obj_1k.bin   bs=1024 count=1    2>/dev/null
dd if=/dev/urandom of=obj_50k.bin  bs=1024 count=50   2>/dev/null
dd if=/dev/urandom of=obj_500k.bin bs=1024 count=500  2>/dev/null
# busybox httpd: path ที่ไม่มีไฟล์จะได้ 404 (ยังเป็น flow) -- แต่ชื่อ obj_*.bin มีจริง
python3 -m http.server 80 >/dev/null 2>&1 &

# 3) DNS resolver จริง (UDP/53) -- อุปกรณ์ query ตลอด = ทราฟฟิก UDP หลากหลาย
#    ใช้ dns_server.py ตัวเดียวกับเดโม Mininet
python3 /root/dns_server.py --port 53 >/dev/null 2>&1 &

# 4) (ออปชัน) NTP server -- ให้ ntpd ของอุปกรณ์ sync ได้จริง (UDP/123)
#    เปิดโดย: apk add openntpd ; echo "listen on *" >/etc/ntpd.conf ; ntpd -d &
#    ข้ามได้ -- UDP diversity ได้จาก DNS อยู่แล้ว

echo "[cloud] mqtt:1883 http:80 dns:53 พร้อม"
echo "[cloud] (ค้าง process ไว้; ปิดด้วย pkill mosquitto; pkill -f http.server; pkill -f dns_server)"
# ค้าง foreground ให้ node ไม่จบ
tail -f /dev/null
