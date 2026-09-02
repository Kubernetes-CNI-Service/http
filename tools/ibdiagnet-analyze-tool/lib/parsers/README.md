# ibdiagnet 原始格式解析器

本目录把外部工具的文本/CSV 格式转换为稳定 Python 结构，供 inventory 和 topology 层使用。

- `db_csv.py`：读取 ibdiagnet 数据库 CSV，统一列名、GUID、端口和缺失值。
- `iblinkinfo.py`：解析 iblinkinfo 链路文本，支持时间戳前缀文件名和端点配对。
- `net_dump.py`：解析 OpenSM/ibdiagnet net dump 的节点、端口和连接。
- `net_dump_ext.py`：解析扩展 dump 属性并补充基础拓扑。
- `smdb.py`：解析 subnet manager database。
- `partitions_conf.py`：解析 partition/P_Key 配置。
- `__init__.py`：包边界，不是命令入口。

解析器应保持无文件发现副作用：读取指定文件、返回结构化数据、对格式错误给出包含文件和行的
异常。新增格式时应先使用最小脱敏样例在隔离环境验证，再合入正式解析流程。
