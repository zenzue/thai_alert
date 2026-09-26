#!/usr/bin/env python3
"""
thai_alert.py — Thailand city-wide emergency alert originator (cell broadcast style)
Builds CAP 1.2 (th-TH + en-US), geotargets by Thai province or polygon,
optionally signs, and delivers via a pluggable transport (stdout / file / http).
Stdlib only.
"""
from __future__ import annotations

import argparse, hashlib, hmac, json, re, sys, uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import urllib.request
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------- constants
TZ_BKK = timezone(timedelta(hours=7))          # ICT (UTC+7)
CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"
DEFAULT_SENDER = "th:ndpm:your-unit-id"        # your registered originator ID
DEFAULT_MAX_CHARS = 300                        # Thai = 2 bytes/char on CBS; keep short

# Subset of provinces: key -> (ISO 3166-2:TH code, Thai name).
# Extend from the official ISO 3166-2:TH table (77 provinces) as needed.
PROVINCES = {
    "bangkok":           ("TH-10", "กรุงเทพมหานคร"),
    "nonthaburi":        ("TH-12", "นนทบุรี"),
    "lop-buri":          ("TH-16", "ลพบุรี"),
    "nakhon-nayok":      ("TH-19", "นครนายก"),
    "nakhon-ratchasima": ("TH-31", "นครราชสีมา"),
    "chiang-mai":        ("TH-50", "เชียงใหม่"),
    "chiang-rai":        ("TH-58", "เชียงราย"),
    "chonburi":          ("TH-71", "ชลบุรี"),
    "chumphon":          ("TH-77", "ชุมพร"),
    "krabi":             ("TH-81", "กระบี่"),
    "phuket":            ("TH-83", "ภูเก็ต"),
    "songkhla":          ("TH-94", "สงขลา"),
}

# --type -> (SAME-style event code, default event name th, en)
TYPES = {
    "flood":      ("FLOOD",   "ประกาศภัยน้ำท่วม",          "Flood Warning"),
    "earthquake": ("EQ",      "ประกาศเตือนภัยแผ่นดินไหว",    "Earthquake Warning"),
    "tsunami":    ("TSUNAMI", "ประกาศเตือนภัยสึนามิ",       "Tsunami Warning"),
    "heatwave":   ("HEAT",    "ประกาศเตือนภัยอากาศร้อนจัด",  "Heat Wave Warning"),
    "haze":       ("SMOKE",   "ประกาศเตือนภัยฝุ่น PM2.5",    "Haze / Air Quality Alert"),
    "amber":      ("CB",      "ประกาศเตือนเด็กถูกพาตัว",      "Child Abduction (AMBER)"),
    "safety":     ("Other",   "ประกาศเตือนภัย",             "Public Safety Alert"),
}
SEVERITY = {"haze": "Moderate", "heatwave": "Severe", "safety": "Severe"}  # else Extreme

ET.register_namespace("", CAP_NS)

# ------------------------------------------------------------------- models
@dataclass
class Area:
    kind: str                       # "province" | "polygon"
    code: str | None = None
    name: str | None = None
    points: str | None = None       # "lat,lon;lat,lon;..." WGS84

@dataclass
class Alert:
    alert_type: str
    status: str = "Actual"                      # Actual | Test
    msg_type: str = "Alert"                     # Alert | Cancel
    cancel_identifier: str | None = None
    text_th: str = ""
    text_en: str = ""
    instruction_th: str = ""
    instruction_en: str = ""
    areas: list[Area] = field(default_factory=list)
    sender: str = DEFAULT_SENDER
    expires_h: float = 12.0
    max_chars: int = DEFAULT_MAX_CHARS
    secret: str | None = None                   # HMAC secret (gateway signing hook)

# ------------------------------------------------------------------ CAP xml
def _iso(dt: datetime) -> str:
    return dt.astimezone(TZ_BKK).strftime("%Y-%m-%dT%H:%M:%S+07:00")

def _el(parent, tag, text=None):
    e = ET.SubElement(parent, f"{{{CAP_NS}}}{tag}")
    if text is not None:
        e.text = text
    return e

def _add_area(info, ar: Area):
    ae = _el(info, "area")
    _el(ae, "areaDesc", ar.name or ar.code or "Thailand")
    if ar.kind == "polygon":
        _el(ae, "polygon", ar.points)
    else:
        gc = _el(ae, "geocode")
        _el(gc, "valueName", "tha:province")     # hook: match your gateway's spec
        _el(gc, "value", ar.code)

def _add_info(root, lang, event, desc, instr, now, exp, areas, sig=None):
    i = _el(root, "info")
    _el(i, "language", lang)
    _el(i, "category", "Alert")
    _el(i, "event", event)
    ec = _el(i, "eventCode"); _el(ec, "valueName", "SAME"); _el(ec, "value", desc and "X" or "")
    return i   # placeholder — replaced in build_cap for clarity

def sign_payload(a: Alert, ident: str) -> str | None:
    """HMAC over the core fields. Hook: replace with the exact scheme your
    gateway specifies (e.g. RSA/XML-DSig like US EAS)."""
    if not a.secret:
        return None
    core = {
        "identifier": ident, "sender": a.sender, "status": a.status,
        "alert": a.alert_type, "text_th": a.text_th, "text_en": a.text_en,
        "areas": [[ar.kind, ar.code, ar.name, ar.points] for ar in a.areas],
    }
    blob = json.dumps(core, ensure_ascii=False, sort_keys=True).encode()
    return hmac.new(a.secret.encode(), blob, hashlib.sha256).hexdigest()

def build_cap(a: Alert) -> str:
    now = datetime.now(TZ_BKK)
    exp = now + timedelta(hours=a.expires_h)
    event_code, event_th, event_en = TYPES[a.alert_type]
    ident = f"TH-{uuid.uuid4().hex}"
    sev = SEVERITY.get(a.alert_type, "Extreme")
    sig = sign_payload(a, ident)

    root = ET.Element(f"{{{CAP_NS}}}alert")
    _el(root, "identifier", ident)
    _el(root, "sender", a.sender)
    _el(root, "sent", _iso(now))
    _el(root, "status", a.status)
    _el(root, "msgType", a.msg_type)
    _el(root, "scope", "Public")
    if a.cancel_identifier:
        _el(root, "references", a.cancel_identifier)

    def info_block(lang, event, desc, instr, with_areas):
        i = _el(root, "info")
        _el(i, "language", lang)
        _el(i, "category", "Alert")
        _el(i, "event", event)
        ec = _el(i, "eventCode"); _el(ec, "valueName", "SAME"); _el(ec, "value", event_code)
        _el(i, "sent", _iso(now)); _el(i, "effective", _iso(now)); _el(i, "expires", _iso(exp))
        _el(i, "headline", event)
        _el(i, "description", desc)
        if instr: _el(i, "instruction", instr)
        _el(i, "responseType", "Execute, Where Possible")
        _el(i, "urgency", "Immediate")
        _el(i, "confidence", "Certain")
        _el(i, "certainty", "Observed")
        _el(i, "severity", sev)
        if with_areas:  # areas live in the first <info> (WEA convention)
            for ar in a.areas:
                _add_area(i, ar)
        if with_areas and sig:
            p1 = _el(i, "parameter"); p1.set("name", "signer");    p1.text = a.sender
            p2 = _el(i, "parameter"); p2.set("name", "signature"); p2.text = sig

    info_block("th-TH", event_th, a.text_th, a.instruction_th, True)
    info_block("en-US", event_en, a.text_en, a.instruction_en, False)

    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body

# ------------------------------------------------------------------ helpers
def validate(xml: str, a: Alert) -> list[str]:
    try:
        r = ET.fromstring(xml)
        assert r.tag == f"{{{CAP_NS}}}alert" and r.findall(f"{{{CAP_NS}}}info")
    except Exception as e:
        return [f"XML error: {e}"]
    probs = []
    for t, label in ((a.text_th, "th"), (a.text_en, "en")):
        if len(t) > a.max_chars:
            probs.append(f"{label} text = {len(t)} chars (limit {a.max_chars}); CBS may truncate")
    return probs

def parse_points_file(path: Path) -> str:
    nums = re.findall(r"-?\d+(?:\.\d+)?", path.read_text(encoding="utf-8"))
    if len(nums) < 6 or len(nums) % 2:
        raise ValueError("polygon file: need at least 3 'lat lon' pairs")
    return ";".join(f"{nums[i]},{nums[i+1]}" for i in range(0, len(nums), 2))

# --------------------------------------------------------------- transports
def send_stdout(xml): print(xml)

def send_file(xml, out_dir) -> Path:
    d = Path(out_dir); d.mkdir(parents=True, exist_ok=True)
    p = d / f"alert_{datetime.now(TZ_BKK):%Y%m%d_%H%M%S}.xml"
    p.write_text(xml, encoding="utf-8")
    return p

def send_http(xml, gateway, token=None, timeout=15):
    """Point this at your authorized CBS / national-system gateway once you
    have credentials. Content type: match the portal spec (xml or json)."""
    headers = {"Content-Type": "application/xml; charset=utf-8"}
    if token: headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(gateway, data=xml.encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        print(f"[ok] gateway responded: {r.status}")
        print(r.read().decode()[:500])

# -------------------------------------------------------------------- CLI
def build_areas(args) -> list[Area]:
    areas = []
    for t in args.target or []:
        if ":" in t:
            code, name = t.split(":", 1)
            areas.append(Area("province", code.strip(), name.strip()))
        elif t.lower() in PROVINCES:
            c, n = PROVINCES[t.lower()]
            areas.append(Area("province", c, n))
        else:
            sys.exit(f"unknown target '{t}' (use a PROVINCES key or 'CODE:Name')")
    if args.polygon_file:
        areas.append(Area("polygon", None, Path(args.polygon_file).name,
                          parse_points_file(Path(args.polygon_file))))
    if not areas:
        sys.exit("no target: pass --target (repeatable) and/or --polygon-file")
    return areas

def cmd_send(args):
    a = Alert(alert_type=args.type, status=args.status,
              msg_type="Cancel" if args.cancel_identifier else "Alert",
              cancel_identifier=args.cancel_identifier,
              text_th=args.text_th, text_en=args.text_en,
              instruction_th=args.instruction_th or "",
              instruction_en=args.instruction_en or "",
              areas=build_areas(args), sender=args.sender,
              expires_h=args.expires, max_chars=args.max_chars, secret=args.secret)
    xml = build_cap(a)
    for p in validate(xml, a):
        print(f"[warn] {p}", file=sys.stderr)
    if args.transport == "stdout": send_stdout(xml)
    elif args.transport == "file": print(f"[ok] wrote {send_file(xml, args.out_dir)}")
    elif args.transport == "http":
        if not args.gateway: sys.exit("--gateway required for http transport")
        send_http(xml, args.gateway, args.token)

def cmd_selftest(args):
    a = Alert(alert_type="flood", status="Test",
        text_th="ทดสอบระบบ: ประกาศเตือนภัยน้ำท่วมพื้นที่เป้าหมาย ประชาชนเตรียมอพยพไปยังจุดปลอดภัย (ข้อความทดสอบ ไม่ใช่เหตุการณ์จริง)",
        text_en="TEST of the emergency alert system: flood in target area. Move to a safe location. This is a test, no action required.",
        instruction_th="ติดตามประกาศจากทางการและเตรียมความพร้อม",
        instruction_en="Monitor official channels and prepare.",
        areas=[Area("province", *PROVINCES["bangkok"]),
               Area("polygon", points="13.720,100.518;13.760,100.518;13.760,100.560;13.720,100.560;13.720,100.518")])
    xml = build_cap(a)
    for p in validate(xml, a): print(f"[warn] {p}")
    print(f"[ok] selftest alert written to {send_file(xml, args.out_dir)}")
    print(xml)

def main():
    ap = argparse.ArgumentParser(description="Thailand emergency alert originator (CAP 1.2 -> cell broadcast gateway)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("send", help="build + deliver an alert")
    s.add_argument("--type", required=True, choices=sorted(TYPES))
    s.add_argument("--status", choices=["Actual", "Test"], default="Actual")
    s.add_argument("--cancel-identifier", help="identifier to cancel (msgType=Cancel)")
    s.add_argument("--target", action="append", help="province key or 'CODE:Name'; repeatable")
    s.add_argument("--polygon-file", help="file of 'lat lon' pairs (any delimiter) for a polygon area")
    s.add_argument("--text-th", required=True)
    s.add_argument("--text-en", required=True)
    s.add_argument("--instruction-th"); s.add_argument("--instruction-en")
    s.add_argument("--expires", type=float, default=12.0, help="hours (default 12)")
    s.add_argument("--sender", default=DEFAULT_SENDER)
    s.add_argument("--secret", help="optional HMAC secret for the signature parameter")
    s.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    s.add_argument("--transport", choices=["stdout", "file", "http"], default="stdout")
    s.add_argument("--out-dir", default="alerts")
    s.add_argument("--gateway", help="http: CBS / national-system gateway URL")
    s.add_argument("--token", help="http: Bearer token from the gateway")
    s.set_defaults(func=cmd_send)

    t = sub.add_parser("selftest", help="generate + verify a test alert")
    t.add_argument("--out-dir", default="alerts")
    t.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
