"""scanner adapters —— 每个上游工具一个转换器。

约定（见 scanner/README.md）:
    adapters/<tool>.py 暴露三个同构接口:
        find_tool(tools_dir)      定位工具，找不到抛 ToolError
        run(target, ...)          跑一次扫描，返回解析后的 JSON dict
        to_groups(data, target)   JSON -> ToolGroup 列表（内部分组单位）
    ToolGroup 字段契约见 merge.py 模块 docstring。
"""
