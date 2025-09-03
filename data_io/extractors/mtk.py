
import re
from typing import List, Tuple
from core.models import Message
from core.utils import normalize_hex

def reassemble_e2_segments(segments: List[str], tag_hex: str) -> str:
    """把多段 LPA=>eSIM APDU（首段含 BFxx 和原长度）重组为 TLV（tag + 新长度 + value）。"""
    if not segments:
        return ""
    norm_segments = [normalize_hex(s) for s in segments if s]
    first = norm_segments[0]
    if len(first) <= 10:
        return ""
    first_data = first[10:]
    if len(first_data) >= 2 and first_data[-2:] == "00":
        first_data = first_data[:-2]

    # 确认tag/len位置
    # 允许 1/2字节 tag；len 可为短/长格式
    tag_in_first, _, len_len = _extract_esim_tag_and_length(first)
    tag_hex2 = tag_in_first or tag_hex
    tag_len = len(tag_hex2) // 2
    value_start = tag_len*2 + len_len*2
    if len(first_data) < value_start:
        return ""
    value_hex = first_data[value_start:]

    for seg in norm_segments[1:]:
        if len(seg) <= 10:
            continue
        data = seg[10:]
        if len(data) >= 2 and data[-2:] == "00":
            data = data[:-2]
        value_hex += data

    vlen = len(value_hex) // 2
    if vlen < 0x80:
        len_enc = f"{vlen:02X}"
    else:
        blen = (vlen.bit_length() + 7) // 8
        len_enc = f"{0x80 | blen:02X}" + vlen.to_bytes(blen, "big").hex().upper()
    # 前置首段的 APDU 5字节头部
    header = first[:10]
    return header + (tag_hex2 or tag_hex) + len_enc + value_hex



APDU_RX0 = re.compile(r'^\s*APDU_rx\s+0:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_TX0 = re.compile(r'^\s*APDU_tx\s+0:\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_RXN = re.compile(r'^\s*APDU_rx\s+(\d+):\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')
APDU_TXN = re.compile(r'^\s*APDU_tx\s+(\d+):\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$')

def _is_lpa_to_esim(apdu_hex: str) -> bool:
    """检查是否为LPA=>eSIM消息"""
    if len(apdu_hex) < 8:  # 至少需要4字节头部
        return False
    cla = int(apdu_hex[0:2], 16)
    ins = int(apdu_hex[2:4], 16)
    return ((0x80 <= cla <= 0x83) or (0xC0 <= cla <= 0xCF)) and ins == 0xE2

def _parse_apdu_header(apdu_hex: str) -> Tuple[int, int, int, int]:
    """解析APDU头部：CLA, INS, P1, P2"""
    if len(apdu_hex) < 8:
        return 0, 0, 0, 0
    cla = int(apdu_hex[0:2], 16)
    ins = int(apdu_hex[2:4], 16)
    p1 = int(apdu_hex[4:6], 16)
    p2 = int(apdu_hex[6:8], 16)
    return cla, ins, p1, p2

def _extract_esim_tag_and_length(apdu_hex: str) -> Tuple[str, int, int]:
    """从APDU数据中提取eSIM TAG、长度值、以及长度字段占用的字节数（支持短/长格式）。
    返回: (tag_hex, value_length, len_len_bytes)
    """
    s = normalize_hex(apdu_hex)
    if len(s) < 10:
        return "", 0, 0
    data_start = 10  # 跳过5字节头部
    if len(s) < data_start + 2:
        return "", 0, 0

    # 处理1字节或2字节的Tag
    tag = s[data_start:data_start+2]
    if tag in ("9F", "5F", "7F", "BF") and len(s) >= data_start + 4:
        tag = s[data_start:data_start+4]
        length_start = data_start + 4
    else:
        length_start = data_start + 2

    if len(s) < length_start + 2:
        return tag, 0, 0

    first_len_octet = int(s[length_start:length_start+2], 16)
    if first_len_octet < 0x80:
        value_len = first_len_octet
        len_len = 1
    else:
        n = first_len_octet & 0x7F  # 后续长度字节数
        if len(s) < length_start + 2 + 2*n:
            return tag, 0, 0
        value_len = int(s[length_start+2:length_start+2+2*n], 16)
        len_len = 1 + n
    return tag, value_len, len_len
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
        """Preserve chronological order of APDU_tx/APDU_rx groups with LPA=>eSIM reassembly."""
        lines = text.splitlines()
        msgs: List[Message] = []
        i = 0
        processed_indices = set()  # 记录已处理的行索引
        
        while i < len(lines):
            # 跳过已处理的行
            if i in processed_indices:
                i += 1
                continue
            
            line = lines[i].strip()
            
            # 处理TX消息
            if line.startswith("APDU_tx"):
                # 先收集当前TX段的所有行
                r = _collect_one(lines, i, APDU_TX0, APDU_TXN)
                if r[0] is not None:
                    raw, next_i = r
                    s = normalize_hex(raw)
                    if s and _is_lpa_to_esim(s):
                        # 尝试重组多段LPA=>eSIM消息
                        reassembled, processed_lines = self._try_reassemble_lpa_esim(lines, i, s)
                        if reassembled and len(processed_lines) > 1:
                            msgs.append(Message(raw=reassembled, direction="tx", meta={"source":"mtk", "reassembled":True}))
                            # 标记所有已处理的行
                            for line_idx in processed_lines:
                                processed_indices.add(line_idx)
                            # 跳到下一个未处理的行
                            i = max(processed_lines) + 1
                            continue
                        else:
                            # 单段消息
                            msgs.append(Message(raw=s, direction="tx", meta={"source":"mtk"}))
                            i = next_i
                            continue
                    else:
                        # 非LPA=>eSIM消息
                        msgs.append(Message(raw=s, direction="tx", meta={"source":"mtk"}))
                        i = next_i
                        continue
            
            # 处理RX消息
            elif line.startswith("APDU_rx"):
                r = _collect_one(lines, i, APDU_RX0, APDU_RXN)
                if r[0] is not None:
                    raw, i = r
                    s = normalize_hex(raw)
                    if s:
                        msgs.append(Message(raw=s, direction="rx", meta={"source":"mtk"}))
                    continue
            
            i += 1
        
        return msgs
    
    def _try_reassemble_lpa_esim(self, lines: List[str], start_idx: int, first_apdu: str) -> Tuple[str, List[int]]:
        """尝试重组LPA=>eSIM的多段消息（支持跨 APDU_rx 分隔的多组 APDU_tx 0..N）。
        规则：P1=0x11表示后续仍有数据；P1=0x91表示最后一块；P2为block号应递增。
        返回：(重组后的APDU(hex), 本次被消费的行索引列表)；若无法重组则返回首段原样。
        """
        first_apdu = normalize_hex(first_apdu)
        cla0, ins0, p10, p20 = _parse_apdu_header(first_apdu)
        if not _is_lpa_to_esim(first_apdu):
            return first_apdu, [start_idx]

        # 提取首段的 TAG/长度信息（用于校验/构造）
        tag_hex, _, _ = _extract_esim_tag_and_length(first_apdu)
        if not tag_hex:
            return first_apdu, [start_idx]

        segments = [first_apdu]
        consumed = [start_idx]
        expected_p2 = p20
        found_last = (p10 == 0x91)

        i = start_idx + 1
        while i < len(lines) and not found_last:
            line = lines[i].rstrip("\n")

            # 寻找下一组 "APDU_tx 0:" 开头的块
            m0 = APDU_TX0.match(line)
            if not m0:
                i += 1
                continue

            # 收集该组的所有 "APDU_tx N:" 行
            seg_start = i
            parts = [m0.group(1)]
            i += 1
            while i < len(lines):
                mn = APDU_TXN.match(lines[i])
                if mn:
                    parts.append(mn.group(2))
                    i += 1
                else:
                    break
            apdu_hex = normalize_hex(' '.join(parts))

            cla, ins, p1, p2 = _parse_apdu_header(apdu_hex)
            # 必须同一 CLA/INS 且 P1 in {0x11,0x91} 且块号递增（允许 00->01 起步）
            if not (((cla == cla0 and ins == ins0) and (p1 in (0x11, 0x91)) and ((p2 == expected_p2 + 1) or (expected_p2 == 0 and p2 == 1)))):
                # 不是连续块，停止
                i = seg_start  # 回退到该行，下次主循环会处理它
                break

            segments.append(apdu_hex)
            consumed.extend(range(seg_start, i))

            expected_p2 = p2
            found_last = (p1 == 0x91)

        # 若收集到多个段，则重组
        if len(segments) > 1:
            reassembled = reassemble_e2_segments(segments, tag_hex)
            return reassembled, consumed

        return first_apdu, [start_idx]