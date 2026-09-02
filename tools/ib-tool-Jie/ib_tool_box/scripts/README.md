# IB Tool Box 命令

本目录提供原始工具箱的独立命令：`show_ib_inventory.py` 展示 inventory，
`trace_ib_path.py` 跟踪路径，`check_ib_link_errors.py` 检查 link error，
`check_hca_ooo_sl_mask.py` 检查 HCA mask，`parse_ib_partition_config.py`、
`parse_ib_smdb.py`、`parse_m_keys.py` 解析控制面数据，`validate_ib_topology.py` 验证拓扑。
脚本直接调用 `../lib/`，适合工程师针对一个
snapshot 做局部诊断；项目自动发现最新输入和批量生成报告时使用
`../../../ibdiagnet-analyze-tool/analyze.py`。

运行前先查看脚本 `-h`，明确传入 snapshot/CVT 路径；不要依赖当前目录中碰巧存在的历史文件。
