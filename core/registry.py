
from typing import Dict, Type
from core.models import MsgType

_REGISTRY: Dict[tuple, Type] = {}

def register(msg_type: MsgType, key: str):
    def deco(cls):
        _REGISTRY[(msg_type, key.upper())] = cls
        return cls
    return deco

def resolve(msg_type: MsgType, key: str):
    return _REGISTRY.get((msg_type, key.upper()))

def all_keys():
    return [k for k in _REGISTRY.keys()]
