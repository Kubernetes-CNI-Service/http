# ibdiagnet 分析库

本目录是 `../analyze.py` 和 `../scripts/` 的共享领域层。入口脚本负责发现输入和编排；本目录负责
解析后的数据模型、inventory、差异与报告，避免把批处理路径逻辑混入分析算法。

| 模块 | 责任 |
|---|---|
| `__init__.py` | 包标记，使其他入口能以稳定模块路径导入共享库。 |
| `snapshot.py` | 识别 snapshot 目录/归档，安全准备分析输入并定位必需文件。 |
| `topology.py` | 规范化实际/期望端点，计算 matching、miswired、missing、undefined。 |
| `inventory.py` | 生成 switch/router/PSU/temp/HCA/cable inventory 并比较 DataFrame。 |
| `link_errors.py` | 聚合端口错误、BER、降速和计数器异常。 |
| `connection.py` | Endpoint/Connection 公共规范化、排序和配对。 |
| `excel.py` | 读取 CVT/P2P，创建带样式、筛选和摘要的 XLSX。 |
| `reporting.py` | 命令行分节、计数、告警和表格格式。 |
| `parsers/` | 隔离每种 ibdiagnet/OpenSM 原始格式的解析。 |

库模块不应自行扫描工作区或创建 latest 链接；这些副作用属于 `analyze.py`。调用者应把明确的
snapshot/CVT 路径传入，并把解析异常提升为可诊断错误。
