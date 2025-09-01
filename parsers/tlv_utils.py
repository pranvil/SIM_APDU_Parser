
def _is_printable(b):
    try:
        ch = chr(b)
    except:
        return False
    return 32 <= b <= 126

def _indent(n):
    return "  " * n

def parse_ber_tlv(data_hex: str):
    data = bytes.fromhex(''.join(ch for ch in data_hex if ch in '0123456789abcdefABCDEF'))
    items = []
    i = 0
    n = len(data)
    while i < n:
        tag_bytes = [data[i]]; i += 1
        if (tag_bytes[0] & 0x1F) == 0x1F:
            while i < n and (data[i] & 0x80):
                tag_bytes.append(data[i]); i += 1
            if i < n:
                tag_bytes.append(data[i]); i += 1
        tag_hex = ''.join(f"{b:02X}" for b in tag_bytes)
        if i >= n:
            items.append({"tag": tag_hex, "len": 0, "value_hex": "", "children": None})
            break
        L = data[i]; i += 1
        if L & 0x80:
            ln = L & 0x7F
            if ln == 0 or i+ln>n:
                length = 0
            else:
                length = int.from_bytes(data[i:i+ln], 'big')
                i += ln
        else:
            length = L
        val = data[i:i+length] if i+length<=n else data[i:]; i += length
        constructed = (tag_bytes[0] & 0x20) != 0
        children = None
        if constructed and len(val) > 0:
            try:
                sub, _ = parse_ber_tlv(val.hex())
                children = sub
            except Exception:
                children = None
        items.append({"tag": tag_hex, "len": len(val), "value_hex": val.hex().upper(), "children": children})
    return items, i

def dump_ber_tlv(items, level=0):
    lines = []
    for it in items:
        tag = it["tag"]; ln = it["len"]
        lines.append(f"{_indent(level)}Tag {tag}  Len {ln}")
        if it["children"]:
            lines.extend(dump_ber_tlv(it["children"], level+1))
        else:
            vh = it["value_hex"]
            lines.append(f"{_indent(level+1)}HEX: " + ' '.join(vh[i:i+2] for i in range(0,len(vh),2)))
            try:
                bs = bytes.fromhex(vh)
                ascii_preview = ''.join(chr(b) if _is_printable(b) else '.' for b in bs)
                if ascii_preview.strip():
                    lines.append(f"{_indent(level+1)}ASCII: {ascii_preview}")
            except Exception:
                pass
    return lines
