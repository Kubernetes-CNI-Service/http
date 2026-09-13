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

脚本优先使用 SSH 公钥；失败时按设备类型提示共享密码。AIR 与 Production 可以使用同一用户名和密码，
但凭据相同不会合并 host-key pin 身份。密码只用于当前进程，不应记录到 CSV、命令行、环境、状态或日志。
默认模式要求至少一个重叠 IP 可通过 SSH 公钥读取实际 hostname
和 eth0 MAC；无法自动识别时必须明确使用 `--type prod` 或 `--type air`。
`--prod`/`--air` 分别是这两种 `--type` 写法的短参数；冲突组合会直接拒绝执行。

Switch Status 的“配置备份”按钮会弹出共享密码输入框；“信息收集”不需要密码。收集与备份
可以同时运行，并拥有独立状态、周期和冷却。“持续收集”与“持续备份”各自可设置
10–1440 分钟、最小 10 分钟，也可以同时运行。

“信息收集”和“配置备份”两个手工按钮的使用逻辑相同：旁边显示“单次执行；开始后不可中断”，
点击后一直显示运行中并禁用，直到任务收口。两个持续按钮旁显示“周期执行；停止只取消后续
轮次”，停止时不会中断已经开始的当前轮。

同类型共用 10 分钟冷却：信息收集与持续收集共享收集冷却，配置备份与持续备份共享备份冷却；
跨类型不会互相阻塞。持续收集启用时只禁用信息收集，持续备份启用时只禁用配置备份，停止对应
持续模式后手工按钮才重新启用。停止持续收集不会停止配置备份或持续备份，停止持续备份也不会
停止信息收集或持续收集。停止只取消后续调度；当前轮已开始时不被中断，页面显示“停止中，等待
当前任务完成”，同类型手工按钮保持禁用，直到当前轮成功或失败收口。停止操作保留同类型最后
一次成功留下的冷却；只有 worker/Supervisor 整体关闭才会有界终止正在运行的子任务。
页面按用户授权以 HTTP POST 传送密码；CGI 通过本机 Unix socket 转交，yaml collector
只从匿名 FD 读取。持续备份凭据仅保存在 root worker 内存，不进入 argv、状态文件或日志；
单轮密码认证把秘密写入 inode 绑定的 `0600` FIFO，由 `0700` 的一次性 `SSH_ASKPASS` helper
读取，子进程环境只携带 FIFO 的路径和 inode 身份，不携带明文密码。worker 重启后不会自动恢复持续模式。

密码分支为每个项目的“项目 + scope + target”建立持久 pin：首次连接 TOFU 先在无秘密阶段以
有界 `ssh-keyscan` 取得并校验原始公钥，再通过持有的 `.ssh-known-hosts` 目录 FD 以 `openat`、
`O_EXCL` 和 file/directory `fsync` 写入精确记录。同一 IP 在 AIR、Production 或另一个项目中
使用不同 pin；用户名和密码不参与 pin 身份。随后 SSH 使用 `StrictHostKeyChecking=yes`、
空的 user/global known-hosts、`KnownHostsCommand` 注入这一条记录、精确的
`HostKeyAlgorithms`、`CheckHostIP=no` 与 `UpdateHostKeys=no`，不会再沿项目可写路径读取 pin。
该能力要求 OpenSSH 8.5 或更高版本；实际调用与探测绑定同一个规范 ssh 可执行文件，固定
`/usr/bin/printf` helper 及其祖先必须 root-owned 且组/其他不可写。

首次连接 TOFU 本身不认证远端主机，残余风险必须由受信管理网和带外公钥指纹核对承担。
host key 改变时，会在调用 askpass/sudo 之前停止，分别从受校验的原始记录计算 pinned/offered
SHA256 指纹，并只给出一个针对该精确 pin 的 `rm -- <pin>` 唯一修复命令。操作员必须先带外核对
新旧指纹和变更授权，才可执行该命令后重试；不得删除整个 `.ssh-known-hosts` 目录。

单台设备不可达、认证失败或 YAML/信息采集失败时不再让整批提前退出；其余设备继续执行并发布
成功结果，最终状态为“完成但有警告”，同时汇总失败设备、失败阶段和原因。部分成功仍记入冷却
并允许持续模式调度下一轮；全部所选设备失败或全局事务失败才返回整体失败。

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
优先 key，失败后为对应类型只询问一次共享密码并用上述 FIFO askpass；随后执行设备类型对应的
startup/config 命令，写入网络子目录，并生成回收后的设备 CSV。最后 `compare_csv_files()`
只比较本次所选环境的设备与回收字段，把缺失、变化和连接失败写入 `diff.log`。

适用于配置发布后的审计、变更前快照和故障现场留档，不是配置恢复器。输出目录必须保留原始
时间戳；不要手工把不完整批次改名为 latest。
