
from core.models import ParseResult, ParseNode

def to_tree_dict(result: ParseResult):
    def walk(n: ParseNode):
        return {
            "name": n.name,
            "value": n.value,
            "hint": n.hint,
            "children": [walk(c) for c in n.children],
        }
    return walk(result.root) if result.root else {}

def to_tree_for_gui(result: ParseResult):
    """
    Convert to a shape friendly to a TreeWidget-like UI:
    Each node -> {"text": name or "name: value", "hint": hint, "children":[...]}
    """
    def walk(n: ParseNode):
        text = n.name if n.value is None else f"{n.name}: {n.value}"
        return {"text": text, "hint": n.hint, "children": [walk(c) for c in n.children]}
    return walk(result.root) if result.root else {"text":"(empty)","children":[]}
