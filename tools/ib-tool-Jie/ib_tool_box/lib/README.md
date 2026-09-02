# IB Tool Box 共享库

这是 `../scripts/` 使用的参考/独立 IB 分析库。它与项目增强版
`ibdiagnet-analyze-tool/lib/` 分开，避免现场工具更新影响主分析流程。

- `connection.py`：连接端点模型和规范化。
- `__init__.py`：Python 包标记，保持参考工具的导入路径稳定。
- `excel.py`：Excel/CVT 输入输出。
- `inventory.py`：设备、HCA、cable 和传感器 inventory。
- `link_errors.py`：链路错误统计。
- `reporting.py`：终端报告。
- `parsers/`：db_csv、net dump、SMDB 和 partition 解析。

修改此参考库时应明确是否也需要同步增强版；不要假设两个目录自动共享代码。
