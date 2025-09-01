
from typing import List, Dict
from apdu_parser import parse_apdu_lines_in_memory

def parse_events_from_lines(lines: List[str]) -> List[Dict]:
    """Use existing proactive parser to build Event dicts with prepared details."""
    results = parse_apdu_lines_in_memory(lines)
    events = []
    for item in results:
        events.append({
            "kind": "proactive",
            "direction": _direction_from_title(item.get("title","")),
            "tag": _tag_from_raw(item.get("raw","")),
            "title": item.get("title","Proactive Item"),
            "raw": item.get("raw",""),
            "parser_hint": "proactive",
            "prepared_details": item.get("details",""),
        })
    return events

def _direction_from_title(title: str) -> str:
    t = title.upper()
    if "UICC=>TERMINAL" in t:
        return "UICC=>TERMINAL"
    if "TERMINAL=>UICC" in t:
        return "TERMINAL=>UICC"
    return "UNKNOWN"

def _tag_from_raw(raw: str) -> str:
    s = ''.join(ch for ch in raw if ch in "0123456789ABCDEFabcdef").upper()
    if s.startswith("80") and len(s)>=4:
        return s[:4]
    if s.startswith("D0"):
        return "D0"
    return ""
