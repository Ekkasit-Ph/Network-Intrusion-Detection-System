#!/bin/sh
# โปรไฟล์ทราฟฟิกของอุปกรณ์ IoT สำหรับเดโม smart-home บน GNS3 (Alpine / busybox, POSIX sh)
#
# วางไฟล์นี้ในทุก VM อุปกรณ์ แล้วตั้ง role ไว้ที่ /etc/device-role (คำเดียว) หรือ env DEVICE_ROLE
# เมื่อบูต มันจะวนลูปปล่อยทราฟฟิกตามบุคลิกของอุปกรณ์นั้น "ตลอดเวลา" โดยไม่ต้องสั่งทีละคำสั่ง
# -> บ้านทั้งหลังคุยกันเองเหมือนทำงานจริง
#
# ต้องมี: apk add mosquitto-clients nmap   (busybox มี wget/nslookup/nc/ntpd อยู่แล้ว)
# cloud node ต้องรัน cloud_services.sh (MQTT broker + HTTP + DNS)

CLOUD="${CLOUD_IP:-203.0.113.10}"
ROLE="${DEVICE_ROLE:-$(cat /etc/device-role 2>/dev/null || echo phone)}"
MQTT=1883
HTTP=80
STREAM=8554

# สุ่มจำนวนเต็ม [min,max)
rand() { awk -v a="$1" -v b="$2" 'BEGIN{srand();print int(a+rand()*(b-a))}'; }
# หน่วงแบบ exponential (กระบวนการ Poisson) รอบค่าเฉลี่ย m วินาที, cap ที่ 3m
esleep() { sleep "$(awk -v m="$1" 'BEGIN{srand();s=-m*log(1-rand());if(s>m*3)s=m*3;if(s<0.1)s=0.1;printf"%.1f",s}')"; }

dns()  { nslookup "svc$(rand 1 99).iot.example.com" "$CLOUD" >/dev/null 2>&1; }
ntp()  { ntpd -nq -p "$CLOUD" >/dev/null 2>&1; }           # NTP จริง (UDP/123) ถ้า cloud เปิด ntp
mqtt() { mosquitto_pub -h "$CLOUD" -p $MQTT -t "$1" -m "$2" >/dev/null 2>&1; }
get()  { wget -q -O /dev/null "http://$CLOUD:$HTTP/$1" 2>/dev/null; }   # $1 = ชื่ออ็อบเจกต์ (มีขนาดต่างกัน)

echo "[device] role=$ROLE cloud=$CLOUD"
case "$ROLE" in
  cam-stream)  # กล้อง: สตรีมต่อเนื่อง (TCP ยาว byte เยอะ)
    while :; do (nc "$CLOUD" $STREAM </dev/zero >/dev/null 2>&1) & p=$!; sleep 20; kill $p 2>/dev/null; dns; esleep 5; done ;;
  cam-motion)  # กล้อง: อัปคลิปเป็นช่วง (flow กลาง)
    while :; do get obj_500k.bin; dns; esleep 12; done ;;
  speaker)     # ลำโพง: เงียบแล้ว burst ตอนถูกเรียก
    while :; do esleep 25; mqtt home/speaker/cmd wake; get obj_50k.bin; dns; done ;;
  tv)          # ทีวี: สตรีมใหญ่ + DNS เยอะ
    while :; do dns; dns; get obj_500k.bin; esleep 6; done ;;
  plug)        # ปลั๊ก: heartbeat MQTT จิ๋วทุก 30s สม่ำเสมอ
    while :; do mqtt home/plug/state "on,$(rand 100 240)W"; sleep 30; done ;;
  bulb)        # หลอดไฟ: สถานะทุก 60s
    while :; do mqtt home/bulb/state "$(rand 1 100)%"; sleep 60; done ;;
  thermostat)  # เทอร์โมสตัท: รายงาน HTTPS เล็กทุก 5 นาที
    while :; do get "report?temp=$(rand 18 30)"; ntp; sleep 300; done ;;
  vacuum)      # ดูดฝุ่น: ปกติเงียบ อัปแมพใหญ่เป็นครั้งคราว
    while :; do mqtt home/vac/state idle; esleep 40; [ "$(rand 0 4)" = "0" ] && get obj_500k.bin; done ;;
  phone)       # มือถือ: เล่นเน็ตเป็นช่วง ๆ ไม่สม่ำเสมอ
    while :; do n=$(rand 1 5); i=0; while [ $i -lt $n ]; do dns; get obj_50k.bin; i=$((i+1)); esleep 1; done; esleep 15; done ;;
  *) echo "unknown role: $ROLE (ดูรายชื่อ role ในหัวไฟล์)"; exit 1 ;;
esac
