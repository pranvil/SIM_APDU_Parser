
import re
from typing import Optional, Tuple
from core.models import Apdu

HEX_RE = re.compile(r"[0-9A-Fa-f]{2}")

def normalize_hex(s: str) -> str:
    return "".join(HEX_RE.findall(s)).upper()

def split_bytes(hexstr: str):
    return [hexstr[i:i+2] for i in range(0, len(hexstr), 2)]

def parse_apdu_header(hexstr: str) -> Apdu:
    b = split_bytes(hexstr)
    apdu = Apdu()
    if len(b) < 4:
        return apdu
    try:
        apdu.cla = int(b[0], 16)
        apdu.ins = int(b[1], 16)
        apdu.p1 = int(b[2], 16)
        apdu.p2 = int(b[3], 16)
    except Exception:
        return apdu
    # naive Lc (short)
    if len(b) >= 5:
        try:
            apdu.lc = int(b[4], 16)
        except Exception:
            apdu.lc = None
    # data / Le not decoded fully; leave to higher layers
    return apdu

def first_tlv_tag_after_store_header(hexstr: str) -> Optional[str]:
    """Strip 5-byte APDU header (CLA INS P1 P2 Lc) then return first BER tag (1 or 2 bytes)."""
    s = hexstr.upper()
    if len(s) < 10:
        return None
    body = s[10:]
    if len(body) < 2:
        return None
    t1 = body[:2]
    if t1 in ("9F","5F","7F","BF") and len(body) >= 4:
        return t1 + body[2:4]
    return t1


def parse_iccid(hexv: str) -> str:
    """Decode ICCID from BCD with possible 'F' padding."""
    s = normalize_hex(hexv)
    # ICCID stored as swapped BCD (semi-octets)
    # Swap nibbles in each byte: e.g., "98 10" -> "89 01"
    out_digits = []
    for i in range(0, len(s), 2):
        b = s[i:i+2]
        if len(b) < 2: break
        hi = b[0]; lo = b[1]
        out_digits.append(lo)
        out_digits.append(hi)
    digits = ''.join(out_digits)
    digits = digits.rstrip('F')  # strip padding
    return digits

def hex_to_utf8(hexv: str) -> str:
    try:
        return bytes.fromhex(normalize_hex(hexv)).decode('utf-8')
    except Exception:
        try:
            return bytes.fromhex(normalize_hex(hexv)).decode('ascii', errors='ignore')
        except Exception:
            return ""
