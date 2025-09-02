
from typing import Iterable, List
from core.models import Message
from core.utils import normalize_hex

class GenericExtractor:
    def extract(self, lines: Iterable[str]) -> List[Message]:
        msgs: List[Message] = []
        for ln in lines:
            s = normalize_hex(ln)
            if not s: continue
            msgs.append(Message(raw=s, direction="tx", meta={"source":"generic"}))
        return msgs
