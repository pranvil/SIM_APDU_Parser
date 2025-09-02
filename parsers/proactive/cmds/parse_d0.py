# parsers/proactive/cmds/parse_d0.py
from core.models import MsgType, ParseNode
from core.registry import register
from parsers.proactive.common import parse_comp_tlvs_to_nodes

@register(MsgType.PROACTIVE, "D0")
class ProactiveD0Parser:
    """UICC => TERMINAL Proactive UICC (D0)."""
    def build(self, payload_hex: str, direction: str) -> ParseNode:
        comp_root, first = parse_comp_tlvs_to_nodes(payload_hex)
        title = ("Proactive UICC (D0)" + (f": {first}" if first else ""))
        root = ParseNode(name=title)
        root.children.extend(comp_root.children)
        return root
