
import re
from typing import List
from core.models import Message
from core.utils import normalize_hex

APDU_RX0 = re.compile(r'^\s*APDU_rx\s+0:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_TX0 = re.compile(r'^\s*APDU_tx\s+0:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_RXN = re.compile(r'^\s*APDU_rx\s+(\d+):\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_TXN = re.compile(r'^\s*APDU_tx\s+(\d+):\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')

def _collect_one(lines: List[str], i: int, head_re0, cont_re):
    m = head_re0.match(lines[i])
    if not m: return None, i
    parts = [m.group(1)]; i += 1
    while i < len(lines):
        n = cont_re.match(lines[i])
        if n:
            parts.append(n.group(2)); i += 1
        else:
            break
    return ' '.join(parts), i

class MTKExtractor:
    def extract_from_text(self, text: str) -> List[Message]:
        """Preserve chronological order of APDU_tx/APDU_rx groups."""
        lines = text.splitlines()
        msgs: List[Message] = []
        i = 0
        while i < len(lines):
            r = _collect_one(lines, i, APDU_TX0, APDU_TXN)
            direction = None
            if r[0] is not None:
                raw, i = r; direction = "tx"
            else:
                r = _collect_one(lines, i, APDU_RX0, APDU_RXN)
                if r[0] is not None:
                    raw, i = r; direction = "rx"
                else:
                    i += 1; continue
            s = normalize_hex(raw)
            if not s: continue
            msgs.append(Message(raw=s, direction=direction, meta={"source":"mtk"}))
        return msgs
