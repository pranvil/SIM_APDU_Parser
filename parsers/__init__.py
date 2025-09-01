import importlib

def get_parser(tag):
    try:
        # 将标签转换为小写，以便匹配文件和函数名称
        tag_lower = tag.lower()
        module = importlib.import_module(f"parsers.parse_{tag_lower}")
        parser_func = getattr(module, f"parse_{tag_lower}")
        return parser_func
    except (ModuleNotFoundError, AttributeError):
        print(f"No parser found for tag: {tag}")
        return None
