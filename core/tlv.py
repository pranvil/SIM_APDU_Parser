
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class Tlv:
    tag: str
    length: int
    value_hex: str

def _read_len(bs: bytes, i: int):
    if i >= len(bs): return 0, i
    first = bs[i]; i += 1
    if first < 0x80: return first, i
    n = first & 0x7F
    v = 0
    for _ in range(n):
        if i >= len(bs): break
        v = (v<<8) | bs[i]; i += 1
    return v, i

def _read_tag(bs: bytes, i: int):
    if i >= len(bs): return "", i
    t1 = bs[i]; i += 1
    if t1 in (0x9F,0x5F,0x7F,0xBF) and i < len(bs):
        t2 = bs[i]; i += 1
        return f"{t1:02X}{t2:02X}", i
    return f"{t1:02X}", i

def parse_ber_tlvs(hexstr: str) -> List[Tlv]:
    bs = bytes.fromhex(hexstr)
    i = 0; out: List[Tlv] = []
    while i < len(bs):
        tag, i = _read_tag(bs, i)
        length, i = _read_len(bs, i)
        val = bs[i:i+length].hex().upper()
        i += length
        out.append(Tlv(tag=tag, length=length, value_hex=val))
    return out
