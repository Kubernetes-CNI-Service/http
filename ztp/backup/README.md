# 交换机配置备份

`yaml-collect.py` 读取 setup 建立的设备 CSV，连接交换机并备份 startup YAML，同时回收
管理地址、MAC 和序列号，用于部署后的配置核对。

## 在整体架构中的位置

备份属于部署后验证面，不参与配置生成或 ZTP 发布。它使用与持续监控相同的 AIR/Production
身份和同网段 SVI fallback 规则，把结果写回当前项目，供 feedback、download/import 和人工
审计使用。整体流程见根目录 `USER_MANUAL.md`“场景七、十”。

## 输入与输出

- `02-devices_config.csv`：当前项目设备清单软链接。
- AIR-only 动态设备：从当前项目 `*-air.json` 取得 hostname/MAC，并按 MAC 从
  `/var/lib/dhcp/dhcpd.leases` 解析当前地址；可用 `DHCP_LEASES_FILE` 覆盖测试路径。
- 已转正 AIR 设备仍持有旧 lease：以静态 hostname/MAC 为权威，把旧地址放在标准 IP 之前作为
  临时传输候选；仅该候选允许 hostname 尚未更新，实际 eth0 MAC 必须完全一致。
- `yaml-backup/`：当前项目 `99-output-backup/` 的软链接。
- Production 输出：`yaml-backup/<时间戳>-prod-backup/`。
- AIR 输出：`yaml-backup/<时间戳>-air-backup/`。
- 网络子目录：`eth/`、`spx/`、`ib/`、`nvl/`；`eth`、`eth_spx` 与 `air` 写入
  `eth/`，只有独立 SPX 网络的 `type=spx` 写入 `spx/`。
- 报告：`backup.log`、`devices_config.csv`、`diff.log`。
- 来源元数据：`collection.json`，记录环境、清单、采集器和带时区时间。

## 使用

```bash
python3 yaml-collect.py
python3 yaml-collect.py -y
python3 yaml-collect.py --type prod
python3 yaml-collect.py --prod
python3 yaml-collect.py --air
python3 yaml-collect.py --air -y
```

脚本优先使用 SSH 公钥；失败时按设备类型提示共享密码。密码只用于当前进程，不应记录
到 CSV、命令行或日志。默认模式要求至少一个重叠 IP 可通过 SSH 公钥读取实际 hostname
和 eth0 MAC；无法自动识别时必须明确使用 `--type prod` 或 `--type air`。
`--prod`/`--air` 分别是这两种 `--type` 写法的短参数；冲突组合会直接拒绝执行。

## 内部阶段

默认比较统一清单中 Production/AIR 的同 IP 设备，SSH 读取实际 hostname/eth0 MAC 并只选择当前可达
环境；IP 仅用于连接，不能作为环境身份。`--type prod/air` 可显式限定，但逐台采集仍要求
设备实际 hostname 与所选清单完全一致，否则跳过，防止串写。脚本按
eth/eth_spx/spx/air、ib、nvl 选择连接地址和用户；连接顺序为 eth0 IP、与 eth0 同网段的
SVI、eth1 IP、hostname。AIR 精简行没有 SVI 字段时，会按共享 eth0 IP 继承 Production
设备行的同网段 SVI 候选。环境自动识别也使用相同 fallback，但最终仍以目标实际
hostname/eth0 MAC 判定 AIR 或 Production。
AIR-only 设备没有静态清单行：active lease 已解析时按同样流程采集，并用拓扑 eth0 MAC 作为
最终身份门禁（允许默认配置尚未设置 hostname）；未解析时逐台打印明确警告并跳过，不会被
泛化成普通“所有地址不可达”。
优先 key，失败后为对应类型只询问一次共享密码并用临时 askpass；随后执行设备类型对应的
startup/config 命令，写入网络子目录，并生成回收后的设备 CSV。最后 `compare_csv_files()`
只比较本次所选环境的设备与回收字段，把缺失、变化和连接失败写入 `diff.log`。

适用于配置发布后的审计、变更前快照和故障现场留档，不是配置恢复器。输出目录必须保留原始
时间戳；不要手工把不完整批次改名为 latest。
