# IB Tool Box 解析器

本目录为参考工具箱提供原始格式适配：`db_csv.py`、`net_dump.py`、`net_dump_ext.py`、
`smdb.py` 和 `partitions_conf.py`。每个模块只负责一种外部格式，返回工具箱 inventory/topology
层使用的结构；`__init__.py` 仅声明包。

使用场景是 `../../scripts/` 的单项诊断。项目自动批处理使用
`../../../../ibdiagnet-analyze-tool/lib/parsers/`，两者的格式修复需要分别验证。
