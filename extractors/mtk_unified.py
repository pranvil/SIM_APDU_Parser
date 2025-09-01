import re
from typing import List, Dict, Iterable
from utils_common import normalize_hex_line, esim_semantic_for

APDU_RX = re.compile(r'^\s*APDU_rx\s+0:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_TX = re.compile(r'^\s*APDU_tx\s+0:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_RX_CONT = re.compile(r'^\s*APDU_rx\s+(\d+):\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_TX_CONT = re.compile(r'^\s*APDU_tx\s+(\d+):\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
HEX_LINE = re.compile(r'^\s*(?:[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')





def extract_events_from_mtk_log(path: str) -> List[Dict]:
    """Extract Proactive and eSIM (ESIM=>LPA, LPA=>ESIM per CLA/E2 rules) from MTK raw logs."""
    events: List[Dict] = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    def is_hex_line(s: str) -> bool:
        return HEX_LINE.match(s) is not None

    i = 0
    while i < len(lines):
        line = lines[i]
        m_rx = APDU_RX.match(line)
        m_tx = APDU_TX.match(line)
        if m_rx or m_tx:
            header_bytes = (m_rx or m_tx).group(1).strip()
            header_tokens = header_bytes.split()
            direction = 'rx' if m_rx else 'tx'

            payload_tokens = header_tokens[:]
            j = i + 1
            while j < len(lines):
                nxt = lines[j].rstrip('\\n')
                if APDU_RX.match(nxt) or APDU_TX.match(nxt):
                    break
                m_cont = APDU_RX_CONT.match(nxt) if direction == 'rx' else APDU_TX_CONT.match(nxt)
                if m_cont:
                    payload_tokens.extend(m_cont.group(2).strip().split())
                    j += 1
                    continue
                if is_hex_line(nxt):
                    payload_tokens.extend(nxt.strip().split())
                    j += 1
                    continue
                break

            raw = ''.join(tok.upper() for tok in payload_tokens)

            first_tok = header_tokens[0].upper() if header_tokens else ''
            second_tok = header_tokens[1].upper() if len(header_tokens) > 1 else ''

            def make_bf_tag(b1: str, b2: str = None):
                b1u = (b1 or '').upper()
                if b1u == 'BF' and b2:
                    b2u = b2.upper()
                    return 'BF' + b2u if re.fullmatch(r'[0-9A-F]{2}', b2u) else None
                if b1u.startswith('BF') and len(b1u) >= 4 and re.fullmatch(r'BF[0-9A-F]{2}', b1u[:4]):
                    return b1u[:4]
                return None

            bf_tag = None
            es_dir = None
            if first_tok == 'BF' and re.fullmatch(r'[0-9A-F]{2}', second_tok):
                bf_tag = 'BF' + second_tok
                es_dir = 'esim_to_lpa' if direction == 'rx' else 'lpa_to_esim'
            elif first_tok.startswith('BF') and re.fullmatch(r'BF[0-9A-F]{2}', first_tok[:4]):
                bf_tag = first_tok[:4]
                es_dir = 'esim_to_lpa' if direction == 'rx' else 'lpa_to_esim'
            else:
                if direction == 'tx' and len(header_tokens) >= 2:
                    cla = first_tok
                    ins = second_tok
                    def in_range(tok):
                        try:
                            v = int(tok, 16)
                        except Exception:
                            return False
                        return (0x80 <= v <= 0x83) or (0xC0 <= v <= 0xCF)
                    if in_range(cla) and ins == 'E2':
                        es_dir = 'lpa_to_esim'
                        if len(payload_tokens) >= 7:
                            bf_tag = make_bf_tag(payload_tokens[5], payload_tokens[6] if len(payload_tokens) > 6 else None)

            if bf_tag is not None and es_dir is not None:
                title = f"{'ESIM=>LPA' if es_dir=='esim_to_lpa' else 'LPA=>ESIM'}: {esim_semantic_for(bf_tag, es_dir)}"
                events.append({
                    'kind': 'esim',
                    'direction': 'ESIM=>LPA' if es_dir == 'esim_to_lpa' else 'LPA=>ESIM',
                    'tag': bf_tag,
                    'title': title,
                    'raw': raw,
                    'parser_hint': (bf_tag.lower() if (es_dir=='esim_to_lpa' and bf_tag in ('BF22','BF2D','BF37','BF39','BF3A','BF3B','BF3C')) else None),
                })
            elif first_tok.startswith('80') or first_tok.startswith('D0'):
                dir_str = 'TERMINAL=>UICC' if direction == 'tx' else 'UICC=>TERMINAL'
                events.append({
                    'kind': 'proactive',
                    'direction': dir_str,
                    'tag': first_tok if first_tok.startswith('D0') else first_tok[:4],
                    'title': f"{dir_str}: {first_tok if first_tok.startswith('D0') else first_tok[:4]}",
                    'raw': raw,
                    'parser_hint': 'proactive',
                })
            else:
                if direction == 'tx' and len(header_tokens) >= 2:
                    cla = first_tok; ins = second_tok
                    def in_range(tok):
                        try:
                            v = int(tok, 16)
                        except Exception:
                            return False
                        return (0x80 <= v <= 0x83) or (0xC0 <= v <= 0xCF)
                    if in_range(cla) and ins == 'E2':
                        events.append({
                            'kind': 'esim',
                            'direction': 'LPA=>ESIM',
                            'tag': 'STORE',
                            'title': 'LPA=>ESIM: STORE DATA',
                            'raw': raw,
                            'parser_hint': None,
                        })

            i = j
            continue
        i += 1

    return events
def build_events_from_apdu_lines(lines: Iterable[str]) -> List[Dict]:
    events: List[Dict] = []
    # seen_esim_raw removed
    for ln in lines:
        s = normalize_hex_line(ln)
        if not s:
            continue
        if s.startswith('BF') and len(s) >= 4:
            tag2 = s[:4]
            title = f"ESIM: {esim_semantic_for(tag2, 'unknown')}"
            events.append({
                'kind': 'esim',
                'direction': 'UNKNOWN',
                'tag': tag2,
                'title': title,
                'raw': s,
                'parser_hint': tag2.lower() if tag2 in ('BF22','BF2D','BF37') else None,
            })
        elif s.startswith('80') or s.startswith('D0'):
            dir_str = 'UNKNOWN'
            title = f"Proactive: {s[:4] if s.startswith('80') else 'D0'}"
            events.append({
                'kind': 'proactive',
                'direction': dir_str,
                'tag': s[:4] if s.startswith('80') else 'D0',
                'title': title,
                'raw': s,
                'parser_hint': 'proactive',
            })
    return events