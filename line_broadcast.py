import json, urllib.request
TOKEN = "YOUR_LINE_OA_CHANNEL_ACCESS_TOKEN"   # LINE Developers console

def broadcast(text: str):
    req = urllib.request.Request(
        "https://api.line.me/v2/bot/message/broadcast",
        data=json.dumps({"messages": [{"type": "text", "text": text}]}).encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req) as r:
        print("LINE broadcast:", r.status, r.read().decode()[:300])
