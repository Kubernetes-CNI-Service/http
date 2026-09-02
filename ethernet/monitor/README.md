# 交换机监控采集

本目录是 Ethernet、InfiniBand 和 NVLink 监控共用的采集实现。其他网络目录中的
`cron.sh`、`sw-info.sh` 和 `sw-link.sh` 通常是指向这里的固定软链接。

## 在整体架构中的位置

本目录属于状态采集面：读取 setup 激活的统一设备清单，通过 SSH 在设备侧生成原始信息，再
将带环境和时区元数据的归档交给链路验证器及 `monitor/generate-monitor-html.py`。它不生成 ZTP 配置，也
不决定当前项目；项目、scope 和输出链接由 setup/load 管理。用户操作入口见
根目录 `USER_MANUAL.md`“场景七”。

## 工作流

1. `cron.sh` 根据所在目录选择 `eth.csv`、`ib.csv` 或 `nvsw.csv`。Ethernet 默认先用
   同 IP 设备的实际 hostname 与 eth0 MAC 自动判断当前可达的是 Production 还是 AIR，
   再只读取该环境清单；IP 本身不代表环境。Ethernet 清单中
   `eth` 只采集 info；`eth_spx`（inband/OOB）和 `spx`（独立 SPX 网络）同时采集
   info 与 SPX link。AIR 批次还调用 `ztp/dynamic_air_inventory.py`，从当前 AIR JSON 与
   `/var/lib/dhcp/dhcpd.leases` 追加已取得 active lease 的 AIR-only Cumulus 节点；没有租约的
   节点逐台告警、跳过 SSH，但不令整轮静态设备采集失败。Production 批次还调用
   `ztp/dhcp_runtime_inventory.py`（`--prod`、`--type ethernet` 或自动识别为 Production
   的整环境采集），只把 DHCP 事件已识别为 `platform=cumulus`、具有
   `active/observed` lease 和有效 IP、且 MAC 尚未绑定到项目清单的设备加入 ETH info 采集。
   临时稳定名为 `DISCOVERED-CUMULUS-<完整12位MAC大写>`；它们不会加入 SPX。平台为 `nvos`
   或 `unknown` 的租约不会误入 Cumulus collector。尚未完成 bootstrap 的设备 hostname 可能
   仍为 `cumulus`；采集器必须先严格匹配 DHCP chaddr/远端 eth0 MAC，匹配后才允许 hostname
   处于过渡状态，普通静态设备仍要求 hostname 完全一致。
2. 验证 SSH 公钥登录，必要时在交互模式下使用密码安装共享公钥。
3. 把采集脚本复制到交换机并异步执行。设备端脚本先在同目录临时文件生成完整内容，再原子
   替换 `.info`/`.link`；未知平台、非法 hostname 或 NVLink 没有可解析端口时不会发布空快照。
4. 拉取 `.info` 或 `.link`，写入带时区的 `collection.json`，归档为含 `-prod` 或
   `-air` 环境后缀的时间戳文件。
5. Ethernet info 归档成功后，`post-collect.py` 把本轮归档作为明确的 `--archive` 输入，
   AIR 明确使用当前 P2P 的 `*-air.dot`，Production 使用 `*-lldpq.dot`，调用 LLDP analyzer
   生成同名 `*-ethernet-topology-validation.xlsx`，再按本轮
   AIR/Production scope 刷新 `monitor.html`。它不会按目录中的“最新文件”猜测输入。
6. IB/NVLink 的 info 归档以及 SPX/IB/NVLink link CSV 是统一页面的直接输入；成功采集后
   `cron.sh` 直接刷新 HTML，不再调用格式不匹配的拓扑分析器。
7. 清理超出保留期的数据。

## 文件

- `cron.sh`：调度、并发 SSH/SCP、归档和保留期清理。
- `post-collect.py`：Ethernet 采集闭环；只分析 `cron.sh` 本轮刚发布的归档，确认 XLSX
  已实际更新后才刷新 HTML。分析器返回 `1` 表示报告中存在链路不匹配，仍会刷新页面；
  分析器/依赖异常、报告未发布或 HTML 生成失败才使 cron 返回非零。
- `sw-info.sh`：采集平台、温度、接口和协议状态，输出 `<hostname>.info`。
- `sw-link.sh`：采集 SPX/IB/NVLink 链路，输出 `<hostname>.link`。SPX 的
  `Oper-Status` 取自 `nv show interface` 的 `Oper Status` 列，而不是
  `Admin Status`；因此管理状态为 `up`、物理链路为 `down` 时会正确记录为
  `down`。
- `eth.csv`：由 `DAY0-Prepare/01-a-setup.py` 建立的 Production 设备清单链接。
- `eth.csv` 同时包含 Production 与 AIR；`--type` 根据统一清单的 type 过滤环境。
- `DHCP_LEASES_FILE`：测试或非标准 ISC 路径时可覆盖 ISC lease 文件；AIR 动态设备和
  Production 未绑定设备发现都会读取它。
- `DHCP_RUNTIME_LOG_FILE`：测试或非标准日志路径时，指定包含 `ZTP_DHCP_EVENT_V1` 的单个
  DHCP 日志；未设置时 Production runtime resolver 读取标准 syslog/daemon.log 并补读
  `isc-dhcp-server` journal。
- `eth-info/`、`spx-link/`、`cronjob.log`：项目专属输出链接。

## 运行

```bash
bash cron.sh
```

建议由 cron 显式调用 Bash：

```cron
0 * * * * bash /var/www/html/ethernet/monitor/cron.sh >> /var/www/html/ethernet/monitor/cronjob.log 2>&1
```

首次在管理服务器启用 Ethernet 验证前，安装报表生成器依赖（infra 通常已完成）：

```bash
sudo apt-get install python3-xlsxwriter
```

闭环成功后，本轮归档、validation XLSX 和 `monitor.html` 会在同一次 cron 日志中依次出现；
任一步失败均以 `[ETH-CLOSED-LOOP] ERROR` 记录并返回非零，不会静默保留旧页面作为本轮结果。

## 安全边界

- 脚本会连接并修改交换机的 `authorized_keys` 和远端监控目录。
- 设备 CSV 应视为受信任配置，hostname 和管理 IP 必须先做严格格式校验。
- 首次部署先手工执行，确认 SSH 用户、公钥、目录和等待时间后再加入 cron。

## 内部架构与数据契约

`cron.sh` 是控制面，三个采集脚本/模式是数据面，`post-collect.py` 是 Ethernet 派生数据发布面。
控制面先把统一 CSV 拆成临时 host 文件，
对 hostname/IP 做字符校验，再通过有限并发的 SSH/SCP job 执行。SSH 准备会区分认证拒绝与
网络不可达：只有 `Permission denied` 类错误才提示共享密码；无路由、超时或拒绝连接的设备
从本轮临时清单移除，其余可达设备继续采集。每个阶段仍要求可达临时清单与实际文件数一致才
发布归档，完整项目清单不会被修改，页面会把本轮未采集设备显示为 Missing。Ethernet AIR 批次使用
`YYYYMMDD-HHMM-air.tar.gz`，Production 使用 `YYYYMMDD-HHMM-prod.tar.gz`；SPX/IB/NVL 链路
CSV 使用 UTC 文件名，页面显示时转换为本地时区。

AIR-only 动态节点不写回 `eth.csv`：AIR JSON 的 hostname/eth0 MAC 是身份权威，active lease
只是本轮传输地址。load 会为它生成“effective default + AIR hostname”的 baseline YAML 和
完整 12 位 MAC 链接；已解析节点进入与普通 AIR Ethernet 相同的 key/SSH/采集闭环，未解析
节点仍由 HTML 生成器以 Missing 占位显示在 AIR“其他”类，避免因为暂时没有 IP 而从页面消失。
bootstrap 成功后 hostname 应为 AIR JSON hostname；在 bootstrap 尚未完成的过渡窗口才可暂时
看到 `cumulus`。SSH 准备阶段读取 `/sys/class/net/eth0/address`，只有它与 AIR JSON 的权威
MAC 完全一致才放宽 hostname 门禁。MAC 不一致时立即拒绝目标，不能通过可达 IP 或临时
hostname 猜测设备身份。
节点后来进入完整静态 AIR 清单时，resolver 按 hostname/MAC 消除旧动态别名。若它仍持有与
计划地址不同的 active lease，本轮采集临时使用该 lease，但输出仍写在静态 canonical hostname
下；实际设备 MAC 必须匹配。lease 消失后自动恢复清单 eth0_ip，不修改 `eth.csv`。

SSH 准备 worker 使用 `ssh -n` 与 host-list 标准输入隔离。该选项不能删除：worker 从
`while read` 循环启动时，未隔离的 OpenSSH 可能吞掉下一条设备记录，表现为清单数量正确，
但某台设备既没有成功日志也没有失败日志，并从归档中消失。

Ethernet 连接目标按 `eth0_ip → 同网段 SVI` 排序。生成临时 host-list 时，脚本从每个
Production 行的重复 EVPN 字段组中寻找与 eth0 使用相同 IP 子网的 `svi_ip`；统一清单末尾的
AIR 行继承共享 eth0 IP 的 Production 备选地址。只有 eth0 失败才尝试 SVI，连接成功后仍严格
核对实际 hostname；备选地址返回其他设备身份时立即拒绝，不会采集错误设备。

`sw-info.sh` 根据 `nv show platform` 的 system-type 选择 ETH、IB 或 NVLink 专属命令。
`VX` 作为虚拟 Ethernet 交换机，按 ETH 规则采集和解析接口、BGP、CPU、内存及磁盘信息。
其 `nv show system health` 结果保持原值，即虚拟硬件服务使其返回 `Not OK` 时页面仍如实显示；
VX 不支持 SPX 链路命令，因此仍会从 `sw-link.sh` 采集目标中跳过。
ETH 专属采集还包含 `clagctl` 和 `nv show evpn multihoming esi`，供 Switch Status 在 BGP 后
分别汇总 MLAG 与 EVPN multihoming bond。EVPN-only 设备出现
`Unable to communicate with clagd`、或未配置 ESI 时出现 `No Data`，都表示该机制未使用，页面
显示 `—` 而不是采集失败；旧归档没有这两个 section 时也保持兼容。
命令输出都有 `# Execute Command:` 分节，`generate-monitor-html.py` 按该稳定边界解析。采集头
包含 hostname、switch type 和本机时间；`timedatectl` 提供时区解释依据。
CPU 使用 `top -bn2 -d 1` 的第二个样本；页面的 Disk Use 过滤
`/dev/loop*`、tmpfs、devtmpfs、`/mnt/cl-etc` 和 `/mnt/cl-system-2` 等虚拟或
系统内部挂载。

`sw-link.sh` 使用 `/tmp` 锁防止同设备重入，在临时目录生成完整 CSV 后 `mv` 发布。SPX、IB、
NVLink 分别有固定表头；修改字段时必须同步 monitor 的行规范化、watch fields 和测试。六类批次
归档名都以 UTC 生成，CSV 中 AIR 行即使排在共用地址的 Production 行之前，也会在完整扫描后
继承同网段 SVI，不再依赖人工行顺序。

当前 `cron.sh` 为兼容频繁 rebuild 的 AIR 仿真，SSH/SCP 仍使用
`StrictHostKeyChecking=no` 与临时 known-hosts。后续 hostname/MAC 校验只能防止普通地址串线；
因为值来自同一个未认证 SSH 会话，它不是密码学主机认证，不能抵御主动中间人。Production 应
优先在隔离管理网运行，并规划 root-owned 持久 `known_hosts`/SSH CA；AIR rebuild 应通过明确的
重建操作刷新单台 key，而不是永久关闭校验。这是当前采集链路的已知高优先级信任边界。

### 自动分析边界

- Ethernet `*.info` 包含 `nv show interface` 和 LLDP 邻居，且已有 `*-lldpq.dot` 设计输入，
  因此自动运行 `lldp-analyze-tool`。
- Switch Status 的 Ethernet/IB/NVLink `*.info` 由 HTML 生成器直接解析，不需要再生成中间报告。
- SPX、IB 和 NVLink 的 `*.link` 已是监控页差异引擎的标准 CSV；页面直接比较多轮快照，
  不调用 LLDP 或 ibdiagnet 分析器。
- `ibdiagnet-analyze-tool` 需要完整 `ibdiagnet2` 快照或原始 `iblinkinfo` 日志以及 CVT；日常
  `sw-link.sh` 的 CSV 不包含这些数据，不能互换。用户把这类诊断文件放入项目后仍应显式
  运行该工具，生成的 IB validation XLSX 会在下一次 HTML 刷新时自动展示。

## 场景与排障

```bash
bash cron.sh --air            # 只采集 AIR Ethernet 状态（推荐）
bash cron.sh --prod           # 只采集 Production（等价于 --type prod）
bash cron.sh --type air       # 明确限定 AIR
bash cron.sh --type prod      # 明确限定 Production
bash cron.sh --type ethernet  # eth + eth_spx + spx
bash cron.sh --type eth       # 只采集普通 Ethernet info
bash cron.sh --type eth_spx   # inband/OOB SPX：info + link
bash cron.sh --type spx       # 独立 SPX 网络：info + link
bash cron.sh                  # 自动判断当前可达环境，再采集该环境 Ethernet
```

显式限定环境时，普通静态设备的 SSH 准备阶段仍要求实际 hostname 与清单完全一致；不再接受
`AIR-X` 清单连接到 hostname 为 `X` 的设备。唯一例外是 AIR-only 动态设备和刚从动态状态转成
静态清单的过渡设备：它们可保留默认 hostname，但必须通过权威 eth0 MAC 校验。任何 MAC
不一致的目标都不会进入本轮归档。

Production 未绑定 Cumulus 也使用同一条 MAC 身份门禁，但与 AIR 计划节点的语义不同：它没有
被自动绑定到任何客户 hostname，采集文件始终保存为稳定的
`DISCOVERED-CUMULUS-<完整12位MAC大写>.info`。完整 MAC 是物理身份键，可避免不同 OUI 的
设备发生别名碰撞。管理页面可以用这个名称/MAC 关联对应的“动态待绑定 DHCP 设备”行。租约 IP
仅用于 SSH 传输，远端 `/sys/class/net/eth0/address` 必须与 DHCP runtime
记录完全一致；默认 hostname `cumulus` 只有在 MAC 校验成功后才接受。公钥认证失败时，cron
等非交互执行将其标记 unavailable，不猜默认密码、不触发初始改密，也不会因此采集到同 IP 的
错误设备。操作员完成物理/链路识别并把 MAC 写入 `02-devices_config.csv`、重新 load 后，runtime
helper 会按 MAC 去重，该临时行消失，后续归档使用正式 hostname。

`dhcp_runtime_inventory.py` 同时识别 Cumulus、NVOS 和真正 unknown，但本 Ethernet collector
只接收 Cumulus；NVOS 的运行时设备由 ZTP/NVOS 流程处理。NVOS 可能从 eth0 或 eth1 发出 DHCP，
转正时必须用观察到的完整 MAC 唯一匹配清单的 `eth0_mac`/`eth1_mac`，不能把所有 lease 都当成
eth0。服务端 release/free 一条 ISC lease 也不会主动通知客户端停止使用地址；采集端始终只读
日志和 lease，不把服务端记录变化当作设备重新 DHCP 的证据。

先检查 `cronjob.log` 的 CSV、KEY、deploy、trigger、retrieve 和 count 阶段。设备缺文件时到远端
`monitor/` 查看脚本及 `.info/.link`；页面状态错误时先比较原始 `nv show` 与 CSV 列，避免在
HTML 层掩盖采集错误。
