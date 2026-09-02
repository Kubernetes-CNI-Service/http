# 独立 InfiniBand 诊断命令

这些脚本复用 `../lib/`，用于只运行某一类诊断，而不执行完整 `analyze.py` 批处理。

| 脚本 | 用途 |
|---|---|
| `show_ib_inventory.py` | 输出交换机、HCA、cable、PSU 和传感器 inventory。 |
| `trace_ib_path.py` | 在解析后的 fabric 图中跟踪两个端点路径。 |
| `check_ib_link_errors.py` | 汇总链路错误、BER 和异常计数。 |
| `check_hca_ooo_sl_mask.py` | 检查 HCA out-of-order service-level mask。 |
| `parse_ib_partition_config.py` | 把 partition 配置转为可审计表。 |
| `parse_ib_smdb.py` | 展示/转换 SMDB。 |
| `parse_m_keys.py` | 提取并核对 M_Key。 |
| `validate_ib_topology.py` | 将实际 fabric 与 CVT/P2P 期望连接比较。 |

从 `ibdiagnet-analyze-tool/` 运行并先查看各命令 `-h`。完整项目流程优先使用 `../analyze.py`，
因为它负责输入发现、命名和批量输出。
