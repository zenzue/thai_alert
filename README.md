# 1. Verify the pipeline end-to-end (generates a test alert, validates, prints XML)
python thai_alert.py selftest

# 2. Build a real flood alert for Bangkok (+ a district polygon), save for review
python thai_alert.py send --type flood --target bangkok --polygon-file bangkok_flood.wkt \
  --text-th "ประกาศ: น้ำท่วมสูงในพื้นที่กรุงเทพฯ ฝั่งตะวันออก ประชาชนอพยพไปยังจุดปลอดภัย" \
  --text-en "FLOOD WARNING: High water in east Bangkok. Evacuate to the nearest safe zone." \
  --instruction-th "อพยพไปยังจุดพักพิงใกล้บ้าน และติดตามประกาศจาก ปภ." \
  --instruction-en "Move to the nearest shelter and monitor NDPM updates." \
  --expires 24 --transport file

# 3. Once you have gateway credentials from the national system / operator:
python thai_alert.py send ... --transport http \
  --gateway https://<your-cbs-gateway>/api/alert --token <TOKEN> --secret <HMAC_SECRET>
