# Real-environment acceptance cases

这里保存不能在本机隔离测试中安全、真实地完成的验收案例。它们不是自动化回归的替代品；
对应解析、事务和失败分支仍应在 `test_*.py` 中使用 fixture 自动覆盖。

四类 bundle 的边界和 `2026-12-vb-gb300` 场景选择见
[《四类交付制品与 2026-12 部署流程》](../docs/deployment/BUNDLE_WORKFLOWS.md)；下面只登记必须在
Ubuntu、Docker、adapter、网络隔离或真实设备上取得的证据。

## TC-REAL-DHCP-001 — AppArmor 与 DHCP 事务安装

- Ubuntu 管理服务器启用 AppArmor enforcement。
- 确认首次 `dhcpd -t` 使用 `/etc/dhcp/.load-dhcp-transaction-*/staged/`。
- staged 与 final 两次语法检查均通过；无 AppArmor DENIED。
- 四个最终文件 hash 与 DHCP manifest 一致，临时事务目录已清理。
- 任一步失败时 parent release 未提交，旧 DHCP 与 YAML latest 已恢复。

## TC-REAL-DHCP-002 — Cumulus/NVOS/未知平台 DORA

- 抓包验证 option 60 Cumulus 获得 option 239。
- 验证 option 61 `NVOS##` 与 option 77 `NVOS-ZTP` 获得 option 67。
- 真正未知平台只能获得 lease，不得收到 ZTP URL/bootfile。
- DHCP release、expiry、地址重分配后旧身份不得继续有效。

## TC-REAL-OOB-001 — OOB 双路径与 transit 身份

- OOB Leaf 用前面板 swp 从 ZTP server transit 网段取得 bootstrap。
- bootstrap 使用 eth0 MAC 下载唯一专属 YAML。
- apply 后 transit 路径消失，监控只用最终 eth0 地址 SSH，并再次核对管理 MAC。
- 同 IP 重分配、跨 AIR/Production 或伪造 HTTP GET 均不得冒认 canonical 身份。

## TC-REAL-ZTP-001 — Cumulus 完整 ZTP

- 验证版本、网络、专属/default 配置、`nv config apply/save`、SSH key、持久日志和 receipt。
- 日志从第一行写入 `/var/lib/nvidia-ztp/logs/`，latest pointer 指向本轮文件。
- `/run/nvidia-ztp.*` 私有工作区在退出后清理。
- apply/save/key 任一步失败时页面阶段、证据和回退状态准确。

## TC-REAL-NVOS-001 — NVOS 完整 ZTP

- 分别验证 IB/NVLink、eth0/eth1 身份、option 61/77、apply/save 和重启。
- 未绑定 NVOS 不得进入正式 IB/NVLink 完成状态或触发错误 SSH。
- factory reset、强制 ZTP 和 image/version 分支均形成新的轮次证据。

## TC-REAL-MONITOR-001 — 轮次、重启与跨时区

- 手工 ZTP/reset 前后改变 timezone，验证 network/version 不会永久等待。
- boot ID、boot time、latest-log pointer 与 log mtime 必须共同证明本轮。
- 重启窗口的瞬态 SSH failure 不得提前把操作终止为失败。
- 旧日志、未来 mtime、同 boot DHCP renew 均不得晋级新轮次。

## TC-REAL-MONITOR-MULTI-IP-001 — eth0 与同网段 VLAN 双地址状态

- 前置条件：选择一台清单中同时包含静态 eth0 地址和同网段静态 VLAN/SVI 地址的隔离测试交换机；
  两个地址均可 SSH 到同一设备，hostname 与清单管理 MAC 一致。不得为本用例修改交换机、NIC、
  Netplan、DHCP 或宿主服务。
- 执行一次受支持的 ZTP 状态采集并保存本轮 JSON、管理服务器采集日志 delta、页面截图和两个
  地址的 SSH/身份结果。完整远端日志脚本必须只通过首个成功地址执行一次；另一个地址只能执行
  固定的轻量 hostname/MAC 身份探测。
- 页面必须把实际用于完整采集的 eth0 地址显示为绿色，把独立可达且身份匹配的 VLAN 地址显示为
  明显的淡绿色；不得新增单独的 `connected_ip` 展示字段。刷新页面后颜色和接口标签保持一致。
- 负例：在隔离 fixture 中让备用地址返回其他 hostname 或其他预期管理 MAC，必须显示红色且不得
  覆盖主地址的成功采集；未探测的旧报告仍为灰色，动态 DHCP/ZTP transit 地址仍按黄色规则显示。

## TC-REAL-MONITOR-SORT-001 — 统一 Monitor 全列排序

- 前置条件：在隔离浏览器中打开包含 AIR/Production、多设备、多端口及缺失采集值的统一
  `monitor.html`；同时准备 ZTP、SPX、InfiniBand 和 NVLink Link Monitor 数据。只读验证页面，
  不触发手工 ZTP、重置、时间同步或采集操作。
- ZTP：逐一点击 16 个可排序表头验证升序/降序。IP 必须按首个显示 IPv4 的数值排序，不能把
  `eth0:` 前缀当地址；多地址设备仍以第一个显示地址为主键。状态顺序覆盖失败、警告、进行中、
  等待、未知、跳过、不适用、成功；缺失值在两个方向都保持末尾，同值以设备名自然顺序稳定
  排列。环境及 OOBofOOB/OOB/TAN/IB/NVL/其他分组边界保持不变。
- Link Monitor：SPX、IB、NVLink 分别验证设备列会移动当前环境内的完整设备组，其他列只排序
  该设备的端口行；`leaf2 < leaf10`、`swp2 < swp10`，小数与科学计数法（例如
  `9E-9 < 1E-8`、`0.001 < 0.01`）按数值排序，温度使用未格式化数值，缺失值始终在末尾。
  历史差异分组表头不得显示可点击排序光标。
- 状态与可访问性：每个表仅显示一个 `aria-sort` 当前方向；折叠、筛选后行顺序不丢失；刷新及
  Auto-Refresh 后四张表各自恢复上次列和方向，损坏或跨列类型不匹配的 localStorage 状态被忽略。
  保存点击前后截图、DOM 中 `data-sort-*`/`aria-sort`、localStorage 项及刷新后顺序。

## TC-REAL-MANUAL-001 — 当前运行配置比较

- 在设备运行态增加一个 latest 中不存在的配置。
- preview 必须以 selector-normalized `nv config show` 对比 current latest 并显示变化路径。
- receipt 只作为审计/TOCTOU 证据，不能掩盖运行态漂移。
- preview 后修改运行配置或发布 release，confirm 必须拒绝旧指纹。

## TC-REAL-TIME-001 — 时间检测与同步按钮

- 验证同步前页面显示 offset/uncertainty，按钮只影响时间状态，不重置 ZTP round/index。
- `abs(offset) + uncertainty > 5s` 必须为 warning/failed，不能报告成功。
- 高 RTT、设备时间向前/向后跳变和 NTP 后续校时均需覆盖。

## TC-REAL-HANDOFF-001 — 不同采集类型错峰完成

- 在同一项目中让 AIR Ethernet、Production Ethernet、IB 和 NVLink 分别在不同时间完成 ZTP。
- 某组全部正式设备达到 100% 后应立即生成该组采集归档，不等待其他类型。
- 同组仍有设备等待、身份待定或动态转正时，该组不得提前交接，但不得阻塞兄弟组。
- 让一个采集器失败，确认只有该组退避/重试，其他就绪组仍能成功并持久化签名。
- 重启 ZTP monitor 后已成功组不重复采集；后完成组仍能独立交接。
- TAN、OOB、OOBofOOB 和角色等 AIR/Production 展示子类不作为独立门禁，按所属采集组验收。

## TC-REAL-MONITOR-INVENTORY-LINK-001 — Fresh load 重建采集清单入口

- 前置条件：使用受控 upload overlay 得到不携带 setup-managed runtime links 的 fresh 管理服务器
  HTTP root；项目包含非空、有效且与管理服务器私钥匹配的 `mgmt-server.pub`。不得手工创建链接、
  复制公钥或设置 `MGMT_PUBKEY_FILE` 绕过身份推导。
- 执行正式 Linux load 后，用 `lstat`/`readlink` 留证三条 single-link symlink 的原始目标分别严格为
  `../eth.csv`、`../ib.csv`、`../nvsw.csv`；用 `readlink -e` 证明三条链最终都落到当前项目的
  `02-devices_config.csv`，并确认它们已写入本轮 setup manifest。
- 用 `ssh-keygen -lf` 只记录项目管理公钥和一台已授权交换机上对应 key 的指纹，二者必须一致；
  不在证据中保存私钥或完整公钥。随后分别触发适用的 AIR/Production Switch Status 采集，必须不再
  出现 `active project mgmt-server.pub is missing or empty`，且归档写入当前项目的
  `99-output-monitor/<type>`。
- 在 InfiniBand/NVLink monitor 目录额外放置可解析、指向另一项目且带有效不同公钥的
  `eth.csv`/`ib.csv` 异类别名，并为进程设置指向该外部公钥的 `MGMT_PUBKEY_FILE`。Ethernet、
  InfiniBand、NVLink 三个真实入口仍必须分别选择 `eth.csv`、`ib.csv`、`nvsw.csv`，并从各自最终
  inventory 的项目目录读取公钥；不得按第一个存在文件扫描，也不得接受环境覆盖。
- 删除任一 monitor CSV 别名并重新执行同一受支持 load，别名必须自动恢复；若上层网络 CSV 缺失或
  monitor 路径是普通文件，load 必须 fail closed 且不得覆盖该对象。上层链接指向其他项目时，缺少
  独立项目切换授权必须阻断；只有正式 load 明确确认目标后才能在同一事务内切换全部链接。清理只
  使用项目的 unload/setup 事务，不手工删除其他项目数据。
- 风险：链接串到旧项目会使采集器读取错误 inventory 或信任错误管理 key，因此任何目标、类型、
  manifest 或公钥指纹不匹配都阻断 Switch Status。

## TC-REAL-DEPLOY-001 — 上传、锁与常驻进程更新

- 中断 rsync 后从 `.partial` 续传并重新验证 SHA-256。
- 先只上传并记录本地/远端归档路径、size 和 SHA-256，再执行脚本输出的
  `--deploy-uploaded <ARCHIVE>`；确认命中远端同名同 SHA 归档，不会重新打包、不会重新传输，
  且只执行一次归档内绑定 guard 的持锁 overlay。禁止在管理服务器手工运行 `tar`。
- sync、tar deploy 与 load 竞争时只能有一个持有 `.deployment.lock`。
- marker 清除前 load 必须拒绝；失败 marker 保留供人工诊断。
- 成功后重新 load，确认 worker、monitor 页面、Apache policy 和 bootstrap 都加载新版本。

## TC-REAL-RELAY-UPLOAD-001 — 可信中转归档的服务器本地安全应用

- 前置条件：使用隔离的 Ubuntu 22.04/24.04 管理服务器；保存 live root、deployment lock、
  source owner/receipt、宿主服务及受管容器状态。由项目电脑生成已通过完整门禁的 upload archive，
  可信中转只传输该 archive 与归档中同字节的 `tools/deploy-upload-archive.py`。
- 以 root 私有 `0700` 目录、installer `0500`、archive `0600` 安装，记录两文件的 owner、mode、
  nlink、size 与外部批准 SHA-256。先执行 `--verify-only`，确认 installer/source manifest/embedded
  guard 绑定通过，且没有 lock、quiesce、marker、receipt 或 live 写入。
- 分别验证 `--runtime native` 与 `--runtime docker`。正式执行必须只由归档内绑定的 guard 通过
  私有 staging 和共享 deployment lock 应用 overlay；Native 只提示项目 `11-load.py`，Docker 或
  guard 的 rebuild marker 只提示 `deploy.sh deploy`，安装器本身不得执行二者。
- 负向注入：分别替换 installer、archive、manifest/guard record，制造 symlink/hardlink、错误
  owner/mode、重复/逃逸/特殊 tar member、多个项目、读时变化和锁竞争；全部必须在 live 写入前
  fail closed。正向确认归档内 P2P 的 `lldp-analyze-tool` 相对软链接只解析到同一归档已验证的
  `tools/lldp-analyze-tool/` 目录；模板 0 字节占位按 manifest 摘要验证但不得被当作非空权威脚本。
  禁止手工 `tar -xzf ... -C /var/www/html`。
- 风险与清理：内部摘要防止损坏和单边替换，但可信中转不等于制品来源认证；installer 与 upload
  archive 一起被恶意替换时必须由外部签名/批准摘要发现。保存 stdout/stderr、退出码、前后树
  manifest、marker/receipt 和锁时间线；按现有 unload/恢复流程回到测试前状态。

## TC-REAL-STP-001 — 终端二层端口 Edge 与 BPDU Guard

- 使用 schema v2，准备一个连接终端、带 bridge 配置的独立二层 `swp` 和一个带两个 member 的逻辑二层 bond；
  CSV 不增加 STP 策略字段。另准备 routed BGP、peerlink 和 bond member 作为负向样本。
- 分别使用 Cumulus 5.14 与 5.15+ 的隔离设备验证版本边界：5.14 应为
  `admin-edge=on`、`bpdu-guard=on`，5.15+ 应为 `admin-edge=enabled`、
  `bpdu-guard=enabled`；当前 2026-12 的 5.18.1 设备必须使用后一组枚举。应用生成配置后，
  确认独立 swp 与逻辑 bond 自动获得对应版本的精确字符串值；
  routed BGP、peerlink 和 bond member 本身没有这两个 bridge STP 配置。
- 以 `oobofoob-leaf` 的 `bond49b51` 及 `oobofoob-spine` 的 `bond1` 到 `bond11` 验证固定
  交换机互联例外：这些接口继续运行普通 STP，不得出现 Edge/Guard；同设备的其他合格独立
  二层接口仍应自动获得防护。
- 正常终端接入后端口立即 forwarding；使用隔离测试交换机向端口发送 BPDU，确认对应逻辑
  bridge port 进入 `protodown`，reason 为 `bpduguard`，且没有形成广播环路。
- 移除错误接线后运行 NVUE `bpduguardviolation` clear action，确认端口恢复；记录
  `nv show interface ... bridge domain ... stp`、`ip -p -j link show` 和 syslog 作为证据。
- 该案例会中断被测端口，具有破坏性，只能在无生产流量且已确认 console/OOB 管理可用时执行。

## TC-REAL-QOS-EVPN-001 — Border/TAN QoS 与 EVPN-MH uplink

- 风险：会在真实交换机上 apply QoS/PFC 与 EVPN-MH uplink tracking，需在维护窗口执行，
  并准备已验证的上一版 NVUE 配置用于回退。
- 前置：至少一台 Border（普通父物理口）、一台非 1G TAN（breakout BGP 子接口），其中
  一台启用 EVPN-MH；另准备一台 MLAG 或非 MH 设备作为负向对照。
- 步骤：用 v2 项目生成、发布并执行 ZTP；检查全局 RoCE lossless、目标物理端口
  PFC watchdog、所有接口型 BGP neighbor 的 MH uplink，以及 `peerlink.4094`/bond/非目标端口。
- 预期：Border 只在普通父口、TAN 只在 breakout 子口启用 watchdog；MH 的所有 BGP
  物理口均启用 uplink；非 MH 与 `peerlink.4094` 不出现 uplink。BGP/EVPN 邻接保持稳定，
  PFC watchdog 没有异常触发。
- 清理与证据：保存生成 YAML、`nv config show`、BGP/EVPN/PFC 状态和 ZTP applied receipt；
  如有异常立即 apply/save 上一版配置并保存回退日志。

## TC-REAL-CUMULUS-518-001 — 5.18 SVI MAC 与 AIR 拓扑策略

- 前置：隔离的 Cumulus 5.18 交换机、同版本 AIR image，以及一份经审批的 AIR-only
  link policy；保留未修改的原始 P2P 和旧配置用于回退。
- 生成并发布一个相同 SVI IP、没有 `vrr_ip`、但有派生 `vrr_mac` 的 schema-v2 配置；确认
  5.18 使用 `interface.vlan*.link.mac-address`，不生成旧的 ifupdown2 snippet，设备 apply/save
  后运行值与 latest 一致。再用一个 5.16 对照确认仍使用旧 snippet。
- AIR 转换应使用 global 中的 Cumulus 版本；获准的唯一错误链路只在 AIR DOT/JSON 中被
  替换，原 P2P 和 LLDPQ 输出逐字节不变。节点 allowlist 之外的防火墙、PDU 和计算节点
  不得进入 AIR；零命中、多命中、自连接或端口复用必须中止。
- 证据：保存源文件 SHA-256、AIR DOT/JSON、设备 `nv config show`、apply receipt、P2P/LLDPQ
  前后 hash。异常时恢复旧配置并销毁 AIR 仿真实例；该案例不得在生产端口直接执行。

## TC-REAL-AIR-MINI-H19-001 — 异构 AIR 容量与项目抽样策略

- 前置：隔离 AIR 环境，使用真实异构命名/角色容量和经审批的项目
  `03-air-topology-policy.json`；保留原始 P2P、客户 mini 清单、旧 canonical 与旧 release 供回退。
- 步骤：先以 `unknown_role_action=error` 执行 `11-load.py --mini`，再分别在副本中验证
  `keep`/`exclude`；让 `04-air-mini-devices.txt` 显式补入一台本应被抽样省略的已知角色设备，
  并覆盖 management-eth0 anchor。记录各角色真实可用容量、生成审计报告、AIR DOT/JSON、DHCP、
  parent release 和 `current-release.json`。
- 预期：选择数符合项目 `mini_sampling.roles`/anchor，显式 04 设备优先且原因确定；未知角色按
  显式动作处理。parent release 同时记录 policy 和最终 canonical 04 的 SHA-256。生成期间替换
  policy、客户源或 canonical 必须在提交前失败，旧 release 与旧发布保持完整。
- 清理与证据：保存命令、输入/输出 SHA-256、逐设备 selected/omitted 原因和容量对照；删除本轮
  AIR 实例并恢复旧输入/release。不得在 Production 端口执行容量或漂移注入。

## TC-REAL-CRASH-001 — 断电与磁盘故障

- 仅在隔离实验服务器执行磁盘满、SIGKILL 和断电注入。
- 覆盖 child latest、DHCP 四文件、parent release 和服务启动各提交边界。
- 重启后不得出现“新 parent + 旧/混合 DHCP”或对外暴露半代配置。

## TC-REAL-DOCKER-ZTP-001 — Ubuntu host-network 动态 DHCP 运行容器

- 前置条件：隔离 Ubuntu 22.04 和 24.04 管理服务器或 VM，rootful Docker 可用且 Compose
  插件可选；至少准备管理口、
  两个独立 ZTP 二层广播域接口及一个无关 Docker bridge。保存 Netplan、路由、防火墙、现有
  Apache/DHCP 状态和 `/var/www/html` 快照；测试口不得承载生产流量。
- 宿主/容器版本矩阵：在 22.04 与 24.04 宿主分别执行 `doctor → deploy → health → status`，
  保存宿主 `/etc/os-release`、架构、Docker daemon/context/socket 与最终 image/container inspect。
  两种宿主都必须运行同一个 Ubuntu 24.04 image contract；容器内 `/etc/os-release`、base-os label
  和 source receipt 不能随宿主变为 22.04。另用隔离 fixture/VM 验证非 Ubuntu、Ubuntu 20.04、
  23.10、25.04、26.04 均在 build/create/stop/remove 前 fail closed。Compose 缺失时必须由 plain
  Docker 路径得到相同的 labels、binds、caps、health 和服务结果。
- 输入与启动：使用经全量测试批准的 upload 包和 2026-12 项目；在宿主机给两个 ZTP 逻辑接口
  分别配置 `10.43.41.200/23`、`10.43.55.200/23`，通过 host network 启动容器。容器必须显式
  设置 `HTTP_ZTP_RUNTIME_BACKEND=supervisor`，不得使用 privileged、host PID、Docker socket
  或 host root/cgroup mount。
- 发布选择：分别验证 Production 全平台与 AIR mini 两个独立新容器。Production 使用
  `HTTP_ZTP_SCOPE=prod`、`HTTP_ZTP_SWITCH_SCOPE=all`、`HTTP_ZTP_MINI=disabled`；AIR simulation
  使用 `air`、`eth`、`enabled`。保存容器 inspect 环境、hostctl 的真实 11-load argv、parent
  release、runtime plan、activation marker 与 health 输出，证明五处选择完全一致。AIR mini
  不得生成或发布 Production、IB、NVL 配置；显式 AIR+IB/NVL、Production+mini、旧容器环境或旧
  release 必须在服务启动前 fail closed。不得用修改容器环境或手工调用宿主 load 绕过重建。
- 动态接口证据：保存容器启动前后的 `ip -j link show`、`ip -j -4 address show`、运行计划及
  DHCPD `/proc/<pid>/cmdline`。argv 后缀必须恰好是按项目行序解析出的两个 ZTP 接口；管理口、
  NAT 口和 `docker0` 均不能出现。`10.43.42.0/23` 通过 relay 使用现有入口，不能生成第三个
  监听接口。
- 正向 DHCP/HTTP：分别从两个直连广播域完成 DORA，并从 relayed `10.43.42.0/23` 完成 DORA；
  抓包证明 Offer/Ack 只从选定接口发出。验证两个 service IP 的 bootstrap、专属 YAML、镜像和
  Apache publication boundary；Supervisor 状态和容器日志能够替代 systemd/journald 证据。
- 失败注入：把第二个 shared-network 地址作为 secondary IP 临时加到第一个监听 ifindex，重新
  load/activate 必须在 `dhcpd -t`、服务 restart 和 desired-state 提交前因
  `multiple shared networks` 失败；旧服务/发布仍保持一致。再分别验证 required NIC 缺失、
  stale allowlist、重复 service IP、接口 DOWN/tentative、relay-only 无显式 ingress 和空 argv。
- Guardian 隔离：在已激活状态分别改动一个受管 runtime 源文件、改变选中 VLAN 的 ID/parent/MAC、
  让 health 命令超过硬超时。确认普通探测期间另一事务仍可取得 lock；第三次同 generation 失败后
  `activation.json` 消失、`quarantine.json` 留存，三个 worker、DHCP、Apache 均精确 `STOPPED`，
  `runtime-guardian` 自身仍为 `RUNNING`，Docker health 为 unhealthy。恢复文件/NIC 后不得自动拉起，
  必须显式 `deploy`（源码漂移）或 `load`（NIC/项目漂移）才能清 quarantine 并恢复。
- 锁与构建竞争：持有真实 `.deployment.lock` 时同时执行 sync、`deploy.sh build` 与 recreate，确认
  build/旧容器 stop 均先等待安全 regular-file lock，symlink/hardlink lock 会 fail closed；释放后生成
  的 image source manifest 必须覆盖固定运行闭包且无混合 hash。记录 lock inode、时间线和 image
  digest。该注入不得在生产管理服务器执行。
- 重启与扩展：移除故障地址后重建容器，确认 ifindex 改变时重新发现而非复用缓存；再使用一张
  trunk NIC 的两个 VLAN 子接口验证同一物理 parent 下两个 ifindex 独立监听，并增加第三个直连
  DHCP 网段确认无需代码改动即可得到三个 argv 接口。
- Service IP 换接口：在没有 source write 的已激活容器上，先保存容器/image ID、parent release、
  activation generation、runtime plan、dhcpd PID/argv、lease 文件元数据与宿主网络快照。由隔离
  simulation 的宿主网络工具把同一个 Service IP 从接口 A 移到接口 B（项目本身不得操作 NIC/
  Netplan），确认旧接口不再持有该地址、新接口唯一持有且网络/路由稳定；随后只执行
  `deploy.sh reload-network → health → status`。必须证明容器与 image/source identity 不变，listener name、
  ifindex、fingerprint 和 dhcpd PID/argv 精确切换到接口 B，endpoint/subnet 集合保持一致，lease
  文件未被截断，项目/YAML/DHCP/release 字节与 generation authority 保持可信且五个业务服务健康；
  保存 hostctl 输出，证明没有调用 `11-load.py`、没有 build/recreate、没有重置 worker control，
  并从新二层广播域完成 DORA/HTTP，证明旧
  广播域不再收到 Offer/Ack。不得运行宿主 `systemctl restart isc-dhcp-server` 或直接
  `supervisorctl restart dhcpd`。再分别注入双接口同时持有 Service IP、B 不在 allowlist、B 为
  DOWN/tentative、路由在双快照间变化、rebuild/quarantine/guardian fault、stale source/release，
  确认均在新 activation 与服务启动前 fail closed。注入 prepare/start/health 失败时必须确认
  activation/precommit 均撤销且五个业务服务停止，不得猜测恢复旧接口。
- 清理与恢复：停止并删除测试容器和专用 volume，恢复宿主机地址/路由/防火墙/Netplan及原服务，
  恢复 `/var/www/html` 快照。保存 Compose config、image digest、runtime plan、Supervisor 日志、
  DHCPD argv、pcap、HTTP/DHCP 请求结果、load 输出和清理后状态；该案例会占用 UDP 67/TCP 80
  并修改隔离接口地址，具有破坏性，禁止在未审批的生产管理服务器执行。

## TC-REAL-LOAD-SCOPE-001 — Native Production/AIR 端到端生成范围

- 前置条件：隔离的项目电脑副本与 Ubuntu 管理服务器，项目同时含 Production ETH/IB/NVL 和
  可导入的 AIR 拓扑；保存输入、现有 child/parent release、DHCP/YAML latest 和服务状态。
- 默认范围：本机不带 `--air`/`--prod` 正式 load，证明 Production 与 AIR 的 DHCP host、
  Cumulus YAML、NVOS YAML 及 child/parent release 全部生成，且全量测试证明与最终字节一致。
- 单一范围：在隔离管理服务器分别运行 `--prod` 与 `--air`；前者不得发布 AIR 设备，后者不得
  发布 Production/IB/NVL 设备。`--air --mini` 还必须只保留 mini 清单和安全最低集合中的 AIR
  设备；AIR full profile 可在 staging 临时渲染对应 Production 来源，但最终 release 不得包含它。
- monitor：单一范围使用 `--ztp-monitor-scope auto`，保存 worker argv/状态证明继承同一范围；
  显式冲突必须在部署锁、setup、配置生成和服务变更前失败。默认双环境非交互启动 monitor 时
  未明确 `--ztp-monitor-scope air|prod` 也必须失败关闭。
- release/恢复：保存 DHCP/Cumulus/NVOS/parent manifest 的 `deployment_scope`、设备集合、文件 hash
  和 latest target。把任一 child 换成另一 scope 必须拒绝 parent commit；失败后旧 release 和服务
  保持一致。完成后恢复原项目、latest 和服务状态。

## TC-REAL-LOAD-SWITCH-001 — Native 单平台选择性 release

- 前置条件：隔离项目电脑副本和 Ubuntu 管理服务器；项目同时包含有效 ETH、IB、NVL 输入与镜像。
  保存三个平台的生成目录、DHCP 四文件、child/parent manifest、`latest` 链接和服务状态。
- 分别执行 `--switch eth`、`--switch ib`、`--switch nvl`。每轮只允许读取所选平台的业务字段、
  校验对应镜像、运行对应配置生成器，并在 DHCP、child 与 parent manifest 中记录相同
  `switch_scope`；未选平台的人为字段错误不得阻断，所选平台同类错误必须阻断。
- `--switch eth` 的 release 只能包含 ETH/ETH-SPX/SPX/AIR，`--switch ib` 只能包含 IB，
  `--switch nvl` 只能包含 NVL。成功后未选平台旧 `latest` 必须退役，HTTP 不得继续暴露跨平台
  旧发布；在 parent 校验或 DHCP 安装阶段注入失败时，所有旧链接和服务状态必须恢复。
- AIR 不指定 `--switch` 时保存证据证明默认选择 `eth`；显式 `--air --switch ib` 或 `nvl` 必须在
  部署锁、setup、文件写入和服务变化之前失败。完成后执行不带 `--switch` 的正式 load 恢复全平台
  release，并记录三个平台及 DHCP/parent 再次属于同一代。

## TC-REAL-NETWORK-SNAPSHOT-001 — Ubuntu 动态计时字段与拓扑稳定性

- 前置条件：隔离 Ubuntu 24.04 arm64、local rootful Docker、host-network managed candidate，
  至少有两个由当前项目 subnet 配置唯一选中的真实接口及一个无关 Linux bridge。执行前保存
  NIC/地址/路由与全部 Netplan 文件 hash；不得修改接口、Netplan 或宿主服务。
- 复现与预期：在同一 activation 观察窗口连续保存 `ip -d -j link show`、
  `ip -j -4 address show` 和 `ip -j -4 route show table all`。只出现 bridge 精确路径
  `linkinfo.info_data.gc_timer` 数值变化，或 DHCP `valid_life_time`/`preferred_life_time` 在 Linux
  uint32 有限范围 `1..4294967294` 内保持或递减时，稳定性检查必须通过，且 planner 使用第一次
  原始完整 link/address 快照得到与复测相同的 listener names、ifindexes 和 fingerprints。
  `0`、字符串 `forever`、数值 sentinel `4294967295`、增长、超界值、非规范值以及
  tentative/deprecated/dadfailed 边界不得被动态归一化；全表 IPv4 route 必须逐字段保持不变。
- 负向注入：只在 synthetic fixture 或专用隔离 VM 中逐项改变 ifindex/name、MAC、flags、
  operstate、link type/kind/parent、VLAN ID、IPv4 local/prefix/scope 或任一 IPv4 route 字段；
  必须在 runtime plan、Apache listener、activation/precommit 发布和服务启动前 fail closed，且
  不得产生部分发布。禁止在生产 NIC 或 route table 上注入这些变化。
- 本轮真实诊断证据：
  `/var/lib/http-ztp-container/logs/validation/http-ztp-evidence-20260906T133303Z-aed5fda7b1b7.tar.gz`
  （SHA-256 `36d442005cb4db1b662d271f153cfbc55c3db138c10f334d5183fbdd8cfeb0cd`）及同目录
  `http-ztp-evidence-20260906T133303Z-aed5fda7b1b7-diagnostic.tar.gz`
  （SHA-256 `0d872fc9ad6297937a36099a3db9883a11908cd4ce80f99035910cc1a75dfc32`）。证据只用于
  证明动态字段误报，不把 VM 地址、租约正文或凭据复制进公开 fixture。
- 清理与证据：保存前后 snapshot、activation 退出码/有界 stderr、发布路径不存在或 hash 未变、
  listener fingerprints，以及 NIC/Netplan/宿主 Apache/DHCP 前后对比。不得为了通过检查删除原始
  snapshot 的动态字段；失败容器只可在完整身份复核后按 immutable CID 通过受支持锁路径收口。

## TC-REAL-SWITCH-CONTINUOUS-BACKUP-001 — Web 独立持续收集与持续备份

- 前置条件：隔离的 Native 管理服务器，当前项目已完成 load，Switch collection worker
  正常运行，且至少一台测试交换机可用 SSH key 或受批准的共享密码登录。
  先保存 worker PID、收集/备份及两个持续模式状态 JSON、两类冷却文件和当前 YAML backup 目录清单；
  不得使用生产密码录屏或把密码写入证据。
- 正向步骤：首次打开 Switch Status，证明 Auto-Refresh 默认关闭。分别执行“信息收集”和
  “配置备份”，并在其中一项仍运行时启动另一项，证明收集与备份可以同时运行。核对两类成功后
  各自进入 10 分钟冷却，且一个冷却不会阻断另一类型。分别给“持续收集”和“持续备份”设置不同
  的 10–1440 分钟周期并启用；两者必须独立等待自己的同类型冷却，然后可以并行产生新的 Switch
  归档和 YAML backup，随后各自进入下一轮 scheduled。确认四个按钮的解释与按钮相邻：手工项
  为“单次执行；开始后不可中断”，持续项为“周期执行；停止只取消后续轮次”。两个手工按钮在
  点击后均显示运行中且不可用，直到各自任务收口；不得出现手工停止动作。
- 互斥与安全证据：持续模式只禁用同类型手工按钮。直接构造同类型的同源 POST 必须返回 409，
  跨类型 POST 必须仍可下发。记录 collector argv、`/proc/<pid>/environ`、worker 状态/日志和 Unix socket
  元数据，确认密码不在 worker/collector argv、任何子进程 environment、状态文件、日志
  或 HTTP 响应中；单轮 SSH 密码只进入 inode 绑定的 `0600` FIFO，askpass 环境只含 FIFO
  路径和 inode 身份。证据不保存 POST body、FIFO payload 或任何子进程 environment 原文。
  时间间隔 9、0、1441、非数字、重复字段、超长/换行密码都必须 fail closed。
- 部分失败证据：在收集和备份各自的测试轮中保留至少一台可访问设备，并让另一台测试设备不可达
  或拒绝认证。确认可访问设备仍完成采集/备份并发布，页面显示“完成但有警告”，列出失败设备、
  阶段和原因，且部分成功进入冷却并允许持续模式下一轮继续。再在隔离清单中让全部目标不可达，
  以及注入一次清单/发布全局错误，二者都必须显示整体失败且不得冒充部分成功。
- 恢复与清理：分别在持续收集和持续备份的一轮任务仍在运行时按停止。确认页面显示“停止中，
  等待当前任务完成”，没有向当前 collector 发送 TERM/KILL，同类型手工按钮保持禁用，且另一类型
  的手工/持续任务不受影响；当前轮自然成功或失败收口后才显示 stopped，不再调度下一轮。两个
  手工按钮继续显示各自同类型剩余冷却，冷却结束后才恢复可下发。重新启用两个持续模式后重启
  worker，整体关闭路径必须有界终止当前子任务；重启后两个持续模式都显示 stopped 且不自动
  恢复；持续备份密码仅保存在内存。删除测试生成的归档前先保存文件清单、size/SHA-256 和终端日志；
  不修改生产设备配置、NIC/Netplan、Apache 或 DHCP。

## TC-REAL-BACKUP-KHC-SSHD-001 — Stock OpenSSH KnownHostsCommand 与严格 pre-pin

- 前置条件：隔离主机存在 stock `ssh`、`sshd`、`ssh-keygen` 和 root-trusted `/usr/bin/printf`；
  测试以普通用户在 loopback ephemeral port 启动临时 sshd，不要求 root，也不读取真实项目凭据。
  2026-09-12 本机 macOS 已实测 `OpenSSH_10.2p1, LibreSSL 3.3.6`，并执行完整正负向 loopback。
- CI 边界：GitHub Ubuntu 24.04 runner 只有 openssh-client、没有 sshd 时，本案例以明确命名的
  `C1 stock OpenSSH loopback/REAL_ENV` 原因报告 **CI NOT-COVERED**；不在测试中临时 apt 安装
  未钉定的 openssh-server。无论是否存在 sshd，离线 direct/workflow 仍必须验证同一规范 ssh
  二进制的 `-V` 与无网络 `-G` capability probe、OpenSSH 8.5 下限、GNU/BSD `/usr/bin/printf`
  的 `%%` 展开，以及精确 `KnownHostsCommand` argv。
- 步骤与证据：生成临时 server key A，先无秘密 keyscan 并通过 held project directory 原子
  pre-pin，再以 `StrictHostKeyChecking=yes`、user/global known-hosts `/dev/null`、
  `KnownHostsCommand` ORDER/HOSTNAME、精确 `HostKeyAlgorithms`、`CheckHostIP=no` 和
  `UpdateHostKeys=no` 连接。保存脱敏 argv、ssh/printf inode 与版本、pin basename/hash、退出码和
  helper 调用计数；不得保存私钥、密码、Authorization 或 FIFO 内容。
- 负向与清理：matching key 必须通过 host-key verification 并到达 authentication（若本案例配置了
  可用 user key 才要求完整登录成功）；把 A 换成同算法 B、不同算法 B，以及 helper missing、
  empty 或 nonzero 都必须拒绝，且不进入 askpass/sudo、不写 auth cache。确认没有继承 FD 伪证明，
  临时 sshd/子孙进程均有界终止，删除临时 host/user keys、配置、pin 和目录，并记录清理后 PID/FD。

## TC-REAL-BACKUP-SCOPE-PIN-002 — AIR/Production 同凭据、same-IP pin 隔离与轮换

- 前置条件：隔离管理网中准备可重用同一管理 IP 的测试交换机或三个经批准的等价 target；
  project-A/prod、project-A/air、project-B/prod 均使用相同用户名和密码。先保存三个项目/scope
  的 `.ssh-known-hosts` 目录元数据、现有 pin basename/SHA256 和 worker 状态；证据不记录凭据。
- 正向步骤：依次从真实 worker → `yaml-collect.py` 流程执行三次密码回退，核对三条 authority
  路径整体不同：同项目 prod/air 文件名不同、不同项目目录不同，每次 SSH 只使用本 scope 的
  精确 pin。AIR 与 Production 可以使用同一用户名和密码，但不会合并 host-key pin 身份或
  password auth cache；记录脱敏 task ID、项目、scope、target hash、pin basename/hash 与退出码。
- 改 key 证据：只把 project-A/air 的测试 target 换成已授权的新 key。该轮必须在 askpass/sudo 之前
  fail closed；日志显示由原始 key 计算的 pinned/offered SHA256 指纹和该精确 pin 的唯一
  `rm -- <pin>` 修复命令，且 project-A/prod、project-B/prod pin、输出和 cache 不变。先通过带外
  渠道核对新指纹与变更授权，再执行唯一修复命令并重试；首次连接 TOFU 不得被密码相同替代。
- 清理：恢复测试 key/设备状态，停止测试持续任务；仅在保存前后 basename、owner/mode、size 与
  SHA256 后删除本案例创建的精确 pin/backup，不删除整个 `.ssh-known-hosts`，不修改生产设备、
  NIC/Netplan、Apache 或 DHCP。

## TC-REAL-BUNDLE-GENERIC-001 — 项目无关 generic image 构建与离线导入

- 前置条件：准备同架构的联网 Ubuntu 22.04/24.04 rootful Docker 构建机和已阻断 Internet/registry
  的隔离目标机；源码已通过全量测试和 `--check`，`deployment-source-manifest.json` 与源码一致。
- 步骤与证据：在不存在项目目录和 `infra-runtime.conf` 的构建副本执行
  `sudo ./infra/docker/deploy.sh image-export /root/http-ztp-generic-<arch>`；保存命令输出、源码
  manifest SHA、image inspect 和输出目录清单。目录必须严格只有 OCI tar、`image-metadata.json`、
  `SHA256SUMS`。复制整个目录后在目标校验摘要，只执行一次 `docker load`，并保存完整 immutable ID。
- 拒绝与恢复：相对/源码树内/已存在输出、架构不符、篡改 metadata/tar、tag-only 和缺项均须在服务
  变化前拒绝。证明构建动作没有读取项目/runtime、生成 upload、启动或停止容器；目标导入期间无
  DNS/registry/APT 流量。清理测试 image、私有 bundle 和网络阻断，保留摘要与终端证据。

## TC-REAL-BUNDLE-UPLOAD-001 — 独立 upload release 与 matching installer

- 前置条件：项目电脑上的 `2026-12-vb-gb300` 已完成正式 load、全量测试与批准状态复核；准备隔离
  Native 和 Docker live root、可信中转介质及初始 source/owner/lock/容器证据。
- 步骤与证据：分别执行
  `tar-for-upload.py 2026-12-vb-gb300 --runtime native|docker --relay-bundle DIRECTORY`。输出必须严格
  只有项目 archive、matching `deploy-upload-archive.py`、`upload-metadata.json` 和 `SHA256SUMS`，
  且没有 image/apps/firmware。经中转复制后先校验摘要，再分别运行 installer `--verify-only` 和正式
  apply；保存 source manifest、archive/installer hash、共享锁、owner/rebuild-required 与下一步提示。
- 拒绝与恢复：将 installer 与另一 bundle 对调、篡改 archive/metadata、手工加入额外文件、混用
  runtime 或并发 writer，必须 fail closed；verify-only 不得写 live、锁服务或停止容器。清理隔离
  root/marker，恢复原 release；禁止在生产 live root 做故障注入。

## TC-REAL-BUNDLE-SHARED-001 — 项目派生 shared artifacts 的选择与安装

- 前置条件：准备 `2026-12-vb-gb300` 项目输入、各平台合法 switch image、完整离线 APT fixture 和
  显式 firmware fixture；源码先完成全量测试与 `--check`。准备隔离目标 root 及已有同名/异内容
  artifact 对照。
- 步骤与证据：分别构建默认 scope/platform、`--no-upgrade`、显式 `--apps-platform` 和重复
  `--firmware` 组合。证明 switch image family/version 自动来自项目输入；apps 仅在 offline 平台被
  显式选择，firmware 仅运输指定文件，`--no-upgrade` 不含 switch image，零 payload 不创建空 bundle。
  目标端校验摘要，执行 shared installer verify/apply，保存 metadata、receipt、文件 SHA/mode 和锁。
- 拒绝与恢复：缺失/冲突 switch image、APT closure 不完整、路径逃逸、symlink/hardlink、项目输入
  漂移、同目标异内容及篡改 receipt 均须在发布前拒绝。证明 installer 只写
  `image/`、`apps/`、`firmware/`，不运行 load、离线 infra setup 或 firmware 刷写。清理 fixture 并
  恢复共享目录。

## TC-REAL-BUNDLE-PROJECT-001 — bootstrap-only project image

- 前置条件：同架构 Ubuntu rootful Docker 主机已加载并验证 generic immutable ID；准备由
  `--runtime docker --relay-bundle` 生成的精确 `2026-12-vb-gb300` upload bundle，以及可选的同项目、
  同 scope/input hash shared bundle。源码先完成全量测试与 `--check`，目标 `/var/www/html` 为 fresh
  root，保存初始 metadata。
- 步骤与证据：在阻断 build network 的条件下执行 `package-project-image.py build`，分别覆盖无 shared
  与有 shared；证明 build 使用 `--network none --pull=false`，输出只有项目 OCI tar、
  `project-image-metadata.json` 和 `SHA256SUMS`。目标校验、一次 `docker load`，逐字执行 packager 打印
  的受限 bootstrap `docker run`，再 `init → doctor → deploy-project-preloaded <IMAGE_ID> → status`。
  有 shared 时还要分别保存 shared upgrade policy 的 enabled/disabled 两条部署路径证据：enabled
  只能使用无 `--no-upgrade` 的命令，disabled 只能使用带 `--no-upgrade` 的命令，反向组合必须拒绝。
- 拒绝与恢复：generic base/tag/架构错误、非 Docker upload、upload/source manifest 不同、shared
  项目或输入 hash 不同、非 fresh live root、篡改 embedded payload 均须在 live 写入或容器替换前
  拒绝。bootstrap 成功后再次执行 installer必须拒绝；日常更新走 tar/sync，不借 bootstrap 覆盖。
  清理 project image/container 和隔离 root，恢复网络与原服务。

## TC-REAL-DOCKER-PRELOADED-001 — 无 Internet 的 immutable generic image 部署

- 前置条件：两台 CPU 架构相同、宿主为 Ubuntu 22.04 或 24.04 的隔离主机或 VM；构建端可以访问
  Ubuntu APT，目标端
  已安装 local rootful Docker 但必须临时阻断外网/Docker registry。两端使用同一份已通过全量门禁
  的 upload 包；保存目标端 `/var/www/html`、既有受管容器、activation/owner marker、端口与服务状态。
- 输入与步骤：在构建端从可信 source manifest 执行
  `sudo ./infra/docker/deploy.sh image-export /root/http-ztp-generic-<arch>`（`build-export` 为兼容别名）；
  确认该动作没有读取项目/runtime 或创建、启动、停止、load、激活服务容器，并保存 generic bundle
  中的 image tar、`image-metadata.json`、两项 `SHA256SUMS` 与完整 `sha256:<64 hex>` image ID。项目
  电脑另行生成 Docker upload bundle，并按需生成 shared bundle。经批准通道分别传输完整目录，在
  目标端逐目录执行 `sha256sum --check SHA256SUMS`；先由 upload installer verify/apply archive，
  按需安装 shared artifacts，随后严格按 generic metadata 只执行一次
  `docker load --input http-ztp-ubuntu-24.04.tar`，确认完整 ID 存在；执行
  `sudo ./infra/docker/deploy.sh deploy-preloaded "$image_id"`。全过程抓取 registry/DNS 流量，必须证明
  wrapper 没有 build、pull 或 APT 请求，并保存 preloaded verifier 和 load/health 输出。
- 归档部署证据：核对独立 upload bundle 中的 current project upload archive，以及同目录、root-owned mode
  `0500` 的 matching `deploy-upload-archive.py`。先执行 installer 的 `--verify-only`，再由它以
  `--runtime docker` 安全应用归档；证明 installer 与归档内自身副本、source manifest 和 embedded
  guard 哈希绑定，且全过程没有手工解压 live `/var/www/html`。
- 正向证据：保存构建端与目标端 image ID/architecture/OS/config/labels、tar SHA-256、live 与 image
  source manifest、runtime contract、image-coupled record diff、最终容器 immutable ID、`docker inspect`、runtime plan、
  Supervisor/health 状态及 HTTP/DHCP 验证。目标必须由传入 image ID 启动，即使同名 tag 随后被改写
  也不能改变该次选择；记录 Ubuntu 24.04 的 `/etc/os-release -> ../usr/lib/os-release` 原始 link target
  及 `/usr/lib/os-release` regular-file 元数据。容器的全新 `/run` tmpfs 必须重建 mode `01777` 的
  `/run/lock`，并证明发行版原生 `/var/lock -> /run/lock` 能解析到运行中的 Apache 锁目录；有 Compose
  插件和没有 Compose 插件时都必须走相同 plain Docker 路径。另从不含 `ztp/status` 发布链接的全新
  HTTP root 启动一次，确认 Supervisor 能先在持久日志卷创建 `ztp-monitor-background.log`，再由 load
  发布项目 status，启动日志中不得出现日志父目录缺失错误。分别在三个控制文件完全不存在，以及
  预置 `paused`、`collect` 和旧手工 ZTP 请求队列的状态下执行 load；必须证明 hostctl 在 no-start
  `11-load.py` 成功之后、worker 获得启动权限之前，将 `ztp-monitor.control`、
  `switch-collection.request`、`manual-ztp.request.json` 初始化为 `running`、`idle`、空请求队列，且
  三者均为 root:www-data、mode `0664`、single-link regular file。把任一目标替换为 symlink、hardlink
  或 FIFO，或让 `ztp/status` 指向其他项目、让 `monitor/status` 逃逸 HTTP root，必须在任何队列被清空
  和任何 worker 启动前 fail closed。另在 activation marker 尚不存在的 fresh Supervisor 上，逐项保存
  五个 managed service 的 `supervisorctl pid` 原始 stdout 与退出码；Supervisor 4.2.5 的 STOPPED 合同
  必须为单行 `0` 和 LSB `NOT_RUNNING=7`，runtime-resume 与 guardian 应保持健康 inactive、不得误停或
  写 quarantine。注入 `rc=0/pid=0`、`rc=7/正 PID`、`rc=3`、空值、非数字、负数、多行及超大 PID 时
  必须全部 fail closed；RUNNING 服务仍须返回 `rc=0` 的规范正 PID。
- 失败注入：逐项使用缺失/短写/大写 image ID、错误 architecture/OS/contract label、Entrypoint、Cmd、
  User、WorkingDir、healthcheck、环境，及与 live tree 不同的 Dockerfile/脚本/source manifest。每项必须
  在移除旧受管容器或清 activation 前 fail closed。另放置同名但 label 或 `/var/www/html` bind 错误的
  foreign container，确认 wrapper 拒绝删除/复用它；把 `/etc/os-release` 分别替换为绝对 link、逃逸或
  非规范相对 link，并把 canonical target 替换为 symlink、hardlink、FIFO，必须全部拒绝。probe 必须是
  `network=none`、read-only、无 capability。
- 受限内存证据：分别记录 generic `image-export`、upload bundle installer 和 shared installer 的最大
  RSS、archive/member size 与退出码；验证大文件使用有界分块 SHA-256，不能按全局成员上限一次申请
  内存。资源不足必须返回结构化错误、清理私有 staging，且不得发布半成品 bundle。
- 并发与恢复：在 verifier 持锁时并发 sync/upload，确认 writer 等待；验证完成后、正式 start 前再改变
  live source，确认 entrypoint 二次验证阻止 Supervisor 启动。注入 probe/start/load 失败时保存 activation、
  rebuild-required、owner 与旧容器状态，确认失败不会回退到 tag 或自动 online build。
- 清理与风险：删除测试导入 image/tar 和新受管容器，恢复 `/var/www/html`、marker、端口、网络阻断和
  原服务；核对没有残留 probe container。该场景会加载/删除 Docker image、替换受管容器并占用 TCP 80
  与 UDP 67，只能在已审批隔离环境执行。image ID/源码 receipt 不等于制品签名，来源认证证据必须另存。

## TC-REAL-DEPLOYMENT-MATRIX-001 — 位置、后端与传输方式组合

- 前置条件：准备一台不连接交换机的 Mac canonical 工作区、一台由 Mac 直通 USB/UTP adapter 的
  Ubuntu 22.04/24.04 VM、一台可直连隔离管理服务器和一条可信中转链路。冻结项目输入、源码、
  full-suite attestation、upload archive、installer、目标 OS/架构与初始服务/网络状态。
- 步骤：Mac 只执行配置准备和全量测试；Ubuntu VM 分别验证 Native 与 Docker；可直连服务器分别
  验证 Native、Docker 在线 build、Docker 预构建；中转链路用同一 upload archive 和外部 installer
  重复上述三种后端。每轮只能选择一个生命周期，Docker 成功 deploy 后不得重复 load。
- 预期与证据：保存每轮 source manifest、archive/installer/image 摘要、完整 image/container ID、
  release/activation、服务、HTTP/DHCP 与命令时间线。Mac 不得启动 Apache/DHCP；VM 的 NAT 管理口
  不得成为 listener；中转不得手工解压或把 sync-code 当作离线增量包。另保存一次 macOS sender
  到 Ubuntu rsync 3.2.x receiver 的 Docker sync argv 与最终 owner：sender 不得协商 `-o/-g`，
  receiver 命令不得含 `--chown`、`--usermap` 或 `--groupmap`；同一 deployment lock 的 commit
  阶段必须仅把 source manifest 精确登记的对象及 manifest 本身收敛为 `root:root`，远端额外文件
  owner 不变。Native 对照轮次必须保持原 owner/group 传输合同。
- 清理与风险：所有服务、容器、地址和 adapter 直通仅在隔离环境操作；按对应 unload/down 和宿主
  网络恢复流程回到初始状态。任何组合缺少证据不得借用另一组合的 PASS。

## TC-REAL-SERVICE-IP-LIFECYCLE-001 — Service IP 接口漂移与地址值改变

- 前置条件：隔离 Ubuntu VM/服务器具有接口 A、B，项目当前 generation 已健康，保存项目输入、
  listener、route、DHCP argv、release、activation、lease 与宿主服务状态。allowlist 留空或首次已
  同时允许 A/B；地址移动由宿主现有网络工具完成，项目不得修改 NIC/Netplan。
- 同一地址换接口：先从 A 唯一移除并在 B 唯一配置相同地址，等待 link/address/route 稳定。Native
  重新执行完整 load；Docker 只执行 `reload-network → health → status`。证明 endpoint/subnet 不变，
  listener name/ifindex/fingerprint 和 DHCP argv 切到 B，旧广播域不再响应。
- 地址值改变：修改项目 DHCP subnet 输入后，必须回到项目电脑正式 load/full-suite，再受控
  upload/sync；Native 完整 load，Docker deploy 或匹配新 source manifest 的 deploy-preloaded。
  `reload-network` 必须拒绝用旧 release 接受新地址。
- 失败与清理：双接口同时持有地址、B 不在 allowlist、DOWN/tentative、route 不稳定、source/release
  漂移均在启动服务前阻断。恢复原地址、接口、路由和服务，保存前后网络与发布摘要。

## TC-REAL-RESTART-RECOVERY-001 — 重启与事务 checkpoint 恢复

- 前置条件：隔离 Native 与 Docker 管理服务器各一台，完成健康发布并保存服务 PID、release、
  activation、runtime plan、日志 inode/size、upload/image/container identity 和部署锁状态。
- 重启：分别执行宿主重启和 Docker 容器重启。Native 必须由 systemd 恢复同一发布；Docker 先
  `health → status`，只能按无 source write 的 load、网络专用 reload-network 或 source write 后的
  deploy 恢复，不得手工拉起单个业务进程。
- checkpoint：分别在 upload 完成、overlay 完成、docker load 完成、probe 完成、容器创建和 load
  提交后注入中断。重试必须复用已验证不可变项，不重复覆盖 upload 或导入 image，不回退 tag，
  foreign container 不得删除。
- 清理与证据：记录退出码、stderr、lock/marker、Supervisor/systemd、日志 append delta 和最终
  generation；恢复初始容器、服务和持久状态。该案例包含重启和故障注入，禁止在生产执行。

## TC-REAL-ARCHITECTURE-MATRIX-001 — amd64/arm64 在线与预构建镜像

- 前置条件：amd64 与 arm64 各有同版本 Ubuntu 22.04/24.04 隔离宿主、local rootful Docker 和同一
  已批准源码；各自准备联网构建端及阻断外网的同架构目标端。
- 步骤：每个架构独立执行 `image-export`（兼容别名 `build-export`），并分别生成/传输独立 upload
  release 与 matching external installer；按需另传 shared bundle。逐目录核对
  `SHA256SUMS`/metadata/source manifest，只执行一次 docker load，再用完整 immutable image ID
  deploy-preloaded。另执行在线 deploy 作为同架构对照；再发布一个只更新普通代码/项目数据且
  contract 仍兼容的 archive，证明旧 image 可复用；修改任一 image-coupled 文件并重签 live manifest，
  必须在替换容器前拒绝并要求新 image。
- 预期：目标 image/container 架构与宿主一致，容器始终为 Ubuntu 24.04；amd64 bundle 在 arm64
  目标及反向组合必须在容器替换前拒绝。Native 离线目标仍需独立 apps 仓库，不能把 image bundle
  当作宿主依赖。
- 清理与风险：保存两架构 tar/image ID、inspect、source receipt、activation 和网络阻断证据；删除
  测试 image/container 并恢复外网策略。制品摘要不替代组织批准的来源签名。

## TC-REAL-VM-ZTP-001 — Ubuntu 24.04 管理 VM 发布后只读验收

- 前置条件：在隔离 Ubuntu 24.04 VM 中完成 upload、load 和所需服务启动；两个直连 DHCP
  shared-network 的 service IP 必须分别位于两个独立 vNIC。验收期间不得再次运行 load、
  sync、更新密码、重启服务或编辑项目输入。
- `test_cases/` 不进入 upload/sync 包，因此从 Mac 单独复制验收器：

  ```bash
  scp test_cases/run_vm_validation.py root@192.168.56.2:/tmp/
  ssh root@192.168.56.2 \
    'python3 /tmp/run_vm_validation.py 2026-12-vb-gb300 \
      --root /var/www/html --full-systemd --worker-scope prod \
      --control-auth-user nvis \
      --output /tmp/2026-12-systemd-full-validation.json'
  ```

- 验收器只读检查 Ubuntu/依赖、项目和同步门禁、parent/child release 与全部输入/配置 hash、
  身份 MAC、DHCP 输出、service IP/vNIC shared-network 唯一性、Apache/DHCP 服务、worker PID
  与 scope。`--full-systemd` 还检查全部部署源码语法、systemd enable/MainPID、DHCP 接口策略
  （`INTERFACESv4` 空值允许 systemd/dhcpd 自动发现；非空值必须与实际 argv 一致）、
  Apache 发布边界/CGI、worker 状态与报告，以及公共/私有 HTTP 边界；不会运行 load、修改密码、
  重启服务或改项目，但会留下普通 Apache GET/HEAD access-log 记录。JSON 证据默认写到
  `/tmp/http-vm-validation-*.json`。AIR 管理服务器改用 `--worker-scope air`；只有项目真实存在且
  parent release 绑定 `04-air-mini-devices.txt` 时才增加 `--expect-mini`。
- 通过条件：退出码为 0 且汇总 `FAIL=0`。`WARN` 必须逐项人工审核；临时假 MAC
  可产生预期 warning，不能把 warning 当成真实硬件身份验收。需要把 warning
  也作为失败时增加 `--strict-warnings`。
- 保存终端全文、退出码、报告绝对路径和报告 SHA-256。把报告复制回 Mac 后再做独立复核；
  报告不包含密码明文或私钥。清理时只删除 `/tmp/run_vm_validation.py` 与该次 `/tmp` 报告，
  不删除任何 release、DHCP lease 或运行日志。

## TC-REAL-MONITOR-ORIGIN-001 — exact service-IP Origin authority

- Status: OPEN / NOT RUN。本地自动化只使用隔离目录和进程替身；自动化 fixture 不得冒充真实 Apache/端口证据。
- 风险与前置：仅在无生产流量、可恢复快照的 Ubuntu 22.04/24.04 隔离 VM 执行；分别准备
  Native/systemd 和 Docker/Supervisor 后端。保存 Apache、systemd/Supervisor、容器、
  `/etc/apache2/ports.conf`、`000-default`、`http-ztp-listeners.conf` 及 Monitor 控制状态的初始
  inode/hash/mode；确认项目 `service_ips` 只含一个本机已配置、非 wildcard 的 canonical IPv4。
  用人工交互式 Basic 认证（例如 `curl --user nvis`由 curl 提示密码）；命令、HAR、shell
  history 和报告不得包含密码、Authorization 或 cookie。
- 只读步骤（两个后端分别执行并保存脱敏 stdout/stderr 与退出码）：
  `sudo apache2ctl -S`；`sudo ss -ltnp 'sport = :80 or sport = :443'`；
  `sudo sed -n '1,200p' /etc/apache2/conf-enabled/http-ztp-listeners.conf`。预期只有
  `<SERVICE_IP>:80`，不得有 `0.0.0.0`、`[::]`、任何 wildcard 或 `:443`；`apache2ctl -S`
  的 VirtualHost/ServerName 必须精确映射同一 `<SERVICE_IP>`。Docker 还要保存 host-network
  容器的 immutable image/container ID 与 Supervisor/Apache 健康状态。
- 真实 CGI 正向：通过 Apache 分别请求
  `/cgi-bin/manual-ztp-control`、`/cgi-bin/switch-collection-control`、
  `/cgi-bin/ztp-monitor-control`。记录 Apache 实际交付的 `SERVER_ADDR=<SERVICE_IP>`、
  `SERVER_PORT=80`、`REQUEST_SCHEME=http`、HTTPS absent/off、`HTTP_HOST=<SERVICE_IP>` 或
  `<SERVICE_IP>:80`、`HTTP_ORIGIN=http://<SERVICE_IP>` 或显式 `:80`。使用 exact
  XRW token：manual=`ManualZTPControl`、switch=`SwitchCollectionControl`、
  ztp=`ZTPMonitorControl`；`Sec-Fetch-Site: same-origin` 与不携带该 header 各验证一次。
  带伪造 `Forwarded`/`X-Forwarded-Proto` 的合法请求仍只依据上述 Apache-owned
  `SERVER_*` authority，不能被 proxy header 改写。
- 破坏性/负向步骤（每行从快照恢复，并在请求前保存三个 CGI 状态）：逐项制造
  missing/empty/malformed `SERVER_ADDR`、`SERVER_PORT`、`REQUEST_SCHEME`，https/443，DNS hostname、
  其他 IPv4、IPv6、leading-zero/非 canonical 地址；分开只改 `HTTP_HOST` 或只改
  `HTTP_ORIGIN` 为 `:81`/`:080`，并覆盖 userinfo、path、query、fragment、padding。另逐项
  验证 XRW missing/empty/generic `XMLHttpRequest`/wrong-case/duplicate-like；它们均必须返回 403
  且无 mutation。每个请求必须先通过 Basic 认证，再由
  authority/origin/XRW gate 拒绝；stdin/body parse、action、subprocess 和任何状态写入都不得到达。
- listener 事务故障注入：Native 在 candidate configtest 失败、publish 后目录 fsync 失败、
  recovery cleanup fsync 失败各执行一次；验证旧 listener 同 inode 回滚，或明确报告
  `新配置已提交`/`cleanup durability unknown`。空状态、单个/多个/混合
  `.rollback`/`.recovery`、symlink、directory 和 FIFO 必须在 configtest/活跃配置修改前
  fail closed；仅根据诊断停止 Apache 后人工处理，不手工编辑或删除未取证对象。
- 证据与成功标准：保存内核/平台身份、exact project/release hash、`apache2ctl -S`、
  `ss -ltnp`、listener config hash/stat、三 CGI 的脱敏 HTTP status/时间线、configtest 和失败前后
  state hash。Native/systemd 与 Docker/Supervisor 均须正向通过，全部负向在首次状态副作用前
  fail closed，才可将 Status 改为已执行；本条当前仍为 OPEN / NOT RUN。
- 清理/回滚：每个负例后先保存证据，再从 VM 快照恢复；用同一受支持
  setup/load/deploy 流程重建 listener，执行 `sudo apache2ctl configtest`并重复只读步骤。
  确认 Apache/systemd/Supervisor 健康、无候选/rollback/recovery 残留、三 CGI 状态与初始
  snapshot 一致；删除仅含脱敏数据的临时证据。

## TC-REAL-MONITOR-AUTH-001 — Monitor 首次登录与持久凭据

- 前置条件：隔离且有 ACL 的可信管理网；Ubuntu 22.04/24.04 Native 和 Docker contract-3 各一套；
  已健康发布真实 `monitor.html`，备份 auth 文件的 hash、inode、mode、owner/group 及 Docker
  container/image ID。准备 Chrome、Safari、Firefox 的全新私密会话。不得在共享网络执行，因为
  本案例的 plain HTTP Basic 不提供传输保密。
- 步骤：每个浏览器访问 `/monitor/monitor.html`，确认匿名请求收到 401 和 exact realm；登录后依次
  执行页面刷新、ZTP monitor 状态读取和不会造成设备写入的 invalid control action。三条
  `/monitor/control/*` canonical URL 必须自动复用凭据。另以 curl 验证无/错凭据的新旧六个控制
  URL 均为 401，正确凭据 GET 为 200；PATH_INFO、大小写、编码斜杠和前后缀变体拒绝。
  两组用户名各执行一次完整案例，但不在证据中记录 Authorization 或密码。
- 持久性：分别轮换 `nvis` 和 `cumulus`；Native 再次 load/unload，Docker 依次 recreate、
  deploy-preloaded、reload-network，确认 auth bytes/inode 仅在显式轮换时变化且常驻容器挂载为只读。
  unsafe symlink/hardlink/mode/owner 或 contract-2 image 必须在 Apache/worker/容器激活前 fail closed。
- 预期：每个新浏览器会话首次只有一次登录提示，后续操作不再出现第二次登录提示；服务端日志仍
  显示每个控制请求具备允许用户，公开 bootstrap/`ztp.json`/YAML/公钥无需凭据。页面与 auth 响应
  带 `Cache-Control: no-store`。`factory_records_active=false` 只记录 byte inequality，不冒充两用户
  已轮换证明。
- 证据与清理：保存去除 Authorization/cookie 的 HAR、401/200 状态、realm、Apache configtest、
  helper status JSON、权限、RO mount、recreate 前后 hashes 和浏览器录屏。恢复轮换前状态只能通过
  经批准的显式轮换，不复制旧文件覆盖；删除临时 HAR/curl 文件并确认服务仍健康。该案例不测试
  Internet 暴露，TLS/mTLS 仍为独立 blocker。

## TC-REAL-MONITOR-AUTHORITY-001 — 固定 Monitor cache authority 与生命周期保留

- 前置条件：隔离 Ubuntu 22.04/24.04 Native 与 local-rootful Docker contract-3 管理服务器各一套；
  `www-data` 的 uid/gid 均须为 33，已保存 Apache/systemd/Supervisor、container/image ID、相关
  mount、`/var/lib/http-ztp` 和目标 authority 的初始 `stat`/inode/hash。只能由获批 root 操作员
  执行；禁止在生产或共享服务器做 symlink/FIFO/rebind 故障注入。
- 正向步骤：Native 正常 setup/load 和 `--skip-infra` load，Docker deploy、down/recreate、
  deploy-preloaded、load、reload-network、health 与 guardian 各执行一次。逐次证明 Native
  `/var/lib/http-ztp-monitor-auth` 以及 Docker 宿主
  `/var/lib/http-ztp-container/monitor-auth`→容器 `/var/lib/http-ztp-monitor-auth` 的 RW bind 保持同一
  状态；root 必须是 `root:root 0755`，固定 `status.lock` 是 `root:www-data 0660`/nlink=1，
  `monitor-auth` 是 `www-data:www-data 0700`，私有叶子是 `0600`。确认原有
  `/var/lib/http-ztp` 仍为 `0700`，未被放宽。
- 语义与只读性：分别建立合法 empty、N=1、N=2、N=3 cache 记录，逐条保存 bytes、inode、
  uid/gid、mode、mtime、ctime；所有日常 provision、attest、setup/load、health、guardian 与 CGI
  路径都只能验收，不能改写任何既存对象。再对 cache/breaker 各执行 malformed JSON、额外字段、
  错 schema、越界计数/记录数和 helper digest 漂移等十个 metadata-perfect 坏 payload，确认 real CGI、
  health 与 Native/Docker lifecycle 在启动服务前一致拒绝。
- 故障注入：在快照可回滚的隔离副本依次替换 missing、owner、group、mode、symlink、hardlink、
  FIFO、可写祖先和 D1→D2/L1→L2 rebind 形态。Native `--skip-infra` 只能 attest、不得创建；Docker
  host provision 必须在 container create 之前，image entrypoint 必须在 Supervisor/Apache 之前
  再 attest。任一失败均须保持 Apache 停止或阻止启动，且 CGI 请求不能创建/repair authority。
- 显式恢复：只有 Apache 已确认 inactive 后才运行
  `sudo ./infra/infra-setup.sh --recover-monitor-authority`；Docker 必须运行
  `sudo ./infra/docker/deploy.sh recover-monitor-authority`，并确认现有 writer 已按 stop→inspect→remove
  顺序消失。Docker 恢复成功后仍保持 stopped，只接受输出给出的正常恢复命令
  `sudo ./infra/docker/deploy.sh deploy`。恢复的任何非零、中断、结构化输出缺失/额外字节或
  `restart_allowed=false` 都不得重启服务。分别在 in-progress marker 与
  committed-cleanup-pending marker 的 write/fsync/unlink/parent-fsync 边界断电复活，保存 distinct
  machine classification；只通过上述同一显式恢复入口重试，禁止手工删 marker。
- 自动化边界：独立 `.github/workflows/monitor-authority-root.yml` 只接受 `workflow_dispatch`，并且只在
  GitHub-hosted Ubuntu 24.04 disposable VM 上运行；它绑定一个 exact committed tree 的
  immutable `HEAD^{tree}`。该作业先运行 Linux 全量门禁 `--all --no-approve -v`，再运行
  ordinary `--check` (without `--require-full`)；它不得写批准 ledger，随后重新证明工作树 clean 才可
  进入 source guard 与 root 场景。三角色边界是 launcher、namespace PID-1 warden、
  exactly one close-all supervisor child。
  launcher 以 root 打开宿主 mount-namespace FD 9 并进入 mount/PID/net namespace；只有 warden 保留
  FD 9/source/sentinel，递归 private 后建立 minimal pivot root。supervisor 不继承这些引用，只从
  root-owned finite PATH 真实执行上述 Native/Docker recovery 与
  `./infra/infra-teardown.sh --non-interactive --yes`，并验证十个坏 payload、正常 lifecycle→real CGI、
  warning/argv 矩阵及 teardown preservation。这只是 disposable VM 上项目已评审代码的
  `correctness and accidental-damage containment`，`NOT an adversarial-PR sandbox`。
- Warden 最终提交顺序固定为 `reap/zero → freeze raw evidence → nonparsing postflight`，随后
  `close host authority → positive FD inventory → private parse`，最后才允许
  `no-replace/fsync/reread PASS` 及可选的外部 append-only receipt copy；任何 survivor、额外 FD、mount、
  artifact 或 identity 漂移都不得封印 PASS。普通 macOS 全量测试只记录精确机器字段
  `root-entrypoint-workflow: NOT COVERED (requires Linux EUID 0 private namespace)`；这不等同于远端 Linux
  runtime 已在本机执行，也不把 CI 结果写入本机 full-suite 证明。本地 candidate freeze 必须明确
  `Ubuntu root workflow remains pending`，直到同一 exact committed tree 的手工 dispatch 取得完整证据。
- 保留、封装与证据：跨 Native load/unload 及 Docker down/recreate 后比较 lock/cache inode 和内容；
  检查 upload tar、project/shared image bundle、Docker build context 与脱敏 diagnostics 均不含该
  host-level 状态。保存脱敏后的命令顺序、exit code、`stat`、mount inspect、服务状态和前后 hash；
  不保存 cache 内容或 Authorization。
- 清理与风险：只回滚故障注入副本并删除脱敏临时证据，不删除或覆盖健康的持久 authority，不放宽
  `/var/lib/http-ztp`。若真实 authority 已损坏，保持 Apache/容器停止，通过同版本 lifecycle
  显式 recovery 修复后重新验收；不要由 CGI、日常 provision、手工 `chmod -R`、手工删除 marker
  或 package restore 修复。Linux namespace runner 的 fixture/tmpfs、stub、临时 source copy 和证据必须
  在 namespace 销毁前清理；任一 unmount 失败以 97 阻断，不得报告 PASS。
- N3 人工判读与步骤：已受损或有缺陷的 `www-data` 可反复放入同一碰撞 contaminant inode；驱动
  `same-identity breaker N=1→2→3`，逐次证明 block/no refresher/no start。它造成 fail-closed 可用性
  拒绝，但 `N=3 is not proof of an attacker`，不得启动自动修复；`automatic repair loops are forbidden`。
  取证只保存安全时间戳、classification、stopped state 和 inode/type/mode/owner/hash metadata，绝不
  保存 payload、credential 或 Authorization bytes。确认 Native Apache 已停止后仅运行一次
  `sudo ./infra/infra-setup.sh --recover-monitor-authority` 并验收 exactly one fixed warning；Docker 仅运行
  `sudo ./infra/docker/deploy.sh recover-monitor-authority`，保持 stopped 后只按其打印的
  `sudo ./infra/docker/deploy.sh deploy` 恢复。随后再驱动同一 N=1/2/3，证明 re-wedging 仍然可能。
  此处机器可检索的固定结论是 `exactly one fixed warning` 与 `re-wedging remains possible`；
  不能把一次恢复误报成永久修复。
  操作员必须 `never manually unlink/chmod/rewrite` authority、breaker 或 recovery marker；再次 wedging
  时保持服务停止并调查 `www-data`/CGI，不得盲目重复 recovery。

## TC-REAL-DOCKER-MANAGEMENT-SSH-KEY-001 — 固定 Docker 管理 SSH 身份

- 前置条件：只在一次性 Ubuntu 22.04/24.04 root 管理主机或 disposable VM 上执行；固定
  `/usr/bin/ssh-keygen` 可用，Docker daemon/容器均可安全停止。先记录 kernel、filesystem、EUID/EGID、
  capabilities，并用一次匿名 `O_TMPFILE` + `linkat(AT_EMPTY_PATH)` 真调用确认支持；`EPERM`、`ENOSYS`
  或 `EINVAL` 都是 NOT COVERED/失败，不得改走 pathname fallback。保存目标目录与既存 pair 的脱敏
  stat/inode/mode/owner/nlink/hash；禁止在共享或生产服务器做 rebind/FIFO/故障注入。
- 状态矩阵：分别在隔离副本驱动 host `/root/.ssh/id_ed25519{,.pub}` 与 service
  `/var/lib/http-ztp-container/ssh/id_ed25519{,.pub}` 的 ABSENT/VALID/INVALID 完整 3×3。只允许
  ABSENT/ABSENT 生成 host 后复制、VALID/ABSENT 的 host→service、ABSENT/VALID 的 service→host，
  以及两端同 identity 的逐字节保留；另外五格必须在任何 project/container/activation 写入前拒绝。
  逐格复核 root:root、目录0700、私钥0600、公钥0644、single-link、Ed25519、空口令、公私一致与
  OpenSSH SHA256 fingerprint；注释差异只能影响 bytes，不能改变 identity。
- 真实入口：在同一受控树上依次执行 `sudo ./infra/docker/deploy.sh load`、`deploy`、
  `deploy-preloaded sha256:<64hex>` 与 `deploy-project-preloaded sha256:<64hex>`，证明每次都由
  hostlock 持有固定 deployment lock，并在首次 Docker lifecycle 操作前完成 helper reconcile。
  随后运行 `sudo ./infra/docker/deploy.sh doctor`，证明它只执行 helper `check`，完整 authority/project
  tree 的 bytes、inode、uid/gid、mode、mtime、ctime 全部不变。容器 Supervisor 内的 11-load 只能
  attest `/root/.ssh` bind，不生成/修复；Native systemd 入口才可显式授权 generation。
- 故障与不泄漏：在一次性 mount namespace 中逐项注入 missing/half/RSA/encrypted/mismatch、owner/group/
  mode、symlink/hardlink/FIFO/socket、oversize、ancestor/leaf rebind、hostile umask、keygen timeout/oversize、
  fsync 与 no-replace 冲突。确认失败保持目标未覆盖、子进程与 FD 全部回收。向 project `.ssh` 植入唯一
  sentinel，实际执行 upload/package、project image、sync exclude、public audit 与 diagnostics；所有
  archive/member/output/evidence 都不得出现 sentinel、固定私钥路径或私有内容。
- R1-D 边界：正式 fault matrix 必须证明 root:root、`0700`、随机命名的 generation stage 只由
  `hostlock` 串行化的官方 writer 使用；在 pre-publication、两次 leaf publication 之间和
  pre-cleanup 分别替换 private/public stage leaf，并注入 stage directory rebind、unexpected child、
  cleanup unlink/rmdir/fsync/revalidation 故障。每个边界都要证明尚未开始的 publication 不发生、
  replacement inode 不被删除、FD/子进程有界回收且成功路径无 staging residue。
  Linux has no conditional unlink-by-inode API；non-cooperating concurrent root is outside this trust boundary。
  这种 root already has strictly stronger capabilities：可绕过 hostlock、ptrace/改写 canonical authority、
  mount 或删除任意文件，因此最后一次 stat→unlink nanorace adds no capability；
  private mount namespace is not used。不得把该残余边界记录成受保护的 hostile-root race。
- 证据与清理：只保存 action、退出码、exact argv 顺序、stat/hash、两个公钥 fingerprint、Docker immutable
  ID 与脱敏日志；绝不保存密钥内容。恢复只删除一次性 namespace/VM 与脱敏证据；真实健康 pair 不删除、
  不覆盖、不 chmod。若匿名 held-inode publish 不受支持，保持部署停止并记录 errno，不得手工复制绕过。

## TC-REAL-DOCKER-AUTH-ROTATE-TTY-001 — Docker 人工终端凭据轮换

- 前置条件：Ubuntu 22.04/24.04 管理服务器上的 Docker contract-3 容器已健康启动，宿主 auth
  状态与 image/container ID 已取证；测试必须由人类操作员在本机真实交互终端执行，不可自动化，
  不得通过 CI、配置管理、cron、管道、重定向、远端无 TTY SSH 或计划任务运行。初始验收账号为
  `nvis` / `nvidia` 与 `cumulus` / `cumulus`；这是公开 bootstrap 默认值，首次登录后必须立即
  轮换两组账号，且不得把输入或 Authorization 保存到证据。
- 步骤：记录 `tty`、`test -t 0`、`test -t 1`、`test -t 2` 和 `/dev/tty` 的类型/owner/mode，分别
  运行 `sudo ./infra/docker/deploy.sh rotate-auth nvis` 与 `... rotate-auth cumulus`。逐次观察两个密码提示均不回显字符，
  容器提示/诊断只出现在当前终端，命令替换得到的 hostlock JSON 保持独立
  且只含 `valid` 与 `factory_records_active`。另从无 TTY SSH 和 pipe 各尝试一次，必须在任何
  `docker container inspect`、`docker image inspect`、`docker run` 或 auth byte 修改前拒绝。
- 预期：one-shot 使用 exact `docker run --rm --interactive --tty`、`--log-driver none`，同一个已验证
  `/dev/tty` descriptor 连接 stdin/stdout/stderr；secret 不进入 argv、environment、host JSON、
  container log 或 shell history。Docker 的 zero/nonzero/transport 三类结果都只执行一次 host
  post-validate/status，绝不自动重试，也不声称新旧哪个密码有效。成功时 hostlock JSON 为唯一机器
  记录；容器内文本只是 terminal-only 诊断。
- 证据、清理与风险：保存脱敏后的终端类型、两次退出码、exact hostlock JSON、轮换前后 auth
  hash/inode/mode/owner、`docker inspect` 只读挂载与 `docker logs` 无 secret 证明；不保存按键录制、
  密码、Authorization 或 helper 输出。失败后先运行只读 validate/status 并人工判断，不盲目重试或
  覆盖 auth 文件。清理只删除脱敏临时证据；恢复凭据只能再次通过获批的人类 TTY 轮换，不能复制
  旧文件。无人值守凭据轮换不受支持，这是本方案的明确运维成本。

## TC-REAL-MONITOR-WRITER-QUIESCE-001 — Native writer 写前停止 Monitor

- 状态：**NOT RUN / REAL_ENV REQUIRED**。自动化只使用隔离目录与进程替身，未以 root 运行、未向
  真实 PID 发信号，也未启动或停止 systemd、Apache、DHCP 或真实 Monitor；不得把当前单元与 workflow
  结果当作真机证据。
- 前置条件：一次性 Ubuntu 22.04/24.04 Native 管理 VM；当前项目已正式 load；detached
  `12-ztp-monitor.py --watch` 正在运行；记录 deployment lock、Monitor PID/starttime/cmdline、
  `current-release.json`、项目 `01-global.yaml`、`02-devices_config.csv` 与 active `p2p-air.json` 的
  inode/hash。不得在生产服务器或仍服务真实交换机的环境执行。
- 步骤：分别从干净快照执行 setup、unsetup、load、unload、独立 DHCP generator、独立 P2P
  generator、password update、feedback global writeback，以及通过 deployment prewrite guard 的
  source/archive 更新。逐项证明同一 deployment lock 覆盖 identity 校验、停止确认和首次 authority
  mutation；load 的 generator/password 子流程只复用一次继承的 lock/quiesce。另注入 stale、复用、
  malformed、跨项目和不可读 PID，以及 TERM timeout/KILL failure，确认任何 authority byte 都未改变。
- 预期：仅严格匹配 Python/受支持 option grammar、精确 Monitor script、project 与 positive `--watch`
  的进程可被发信号；所有候选 identity 必须先全部验证，随后 TERM/KILL 有界完成并确认退出，才允许
  writer 首次写入。Docker 路径继续由 hostlock/owner 合同处理，不套用 Native PID 停止逻辑；
  import-from-download 对既有四项 authority 必须逐字节保留，只能增加不存在的项目条目。
- 证据、清理与风险：保存脱敏后的 exact argv、PID/starttime、lock 时间线、信号/退出时间线和四项
  authority 的前后 hash，不保存密码或项目秘密。每个场景恢复 VM 快照并确认无残留 Monitor、lock
  holder、临时文件或被停止服务；信号目标错误可能终止无关进程，因此只能在一次性 VM 执行。

## TC-REAL-ZTP-MONITOR-WATCH-RESILIENCE-001 — Native/Docker 持续 Monitor 恢复与 PID 串行

- 状态：**NOT RUN / REAL_ENV REQUIRED**。本机 direct/workflow 使用隔离目录、真实脚本链与进程
  替身，未在 Ubuntu systemd 或 Docker/Supervisor 下持续运行真实 Monitor，也未制造真实磁盘、
  网络或 Supervisor transport 故障；不得把自动化结果当作服务级恢复证据。
- 前置条件：一次性 Ubuntu 22.04/24.04 Native VM 和 Ubuntu 24.04 Docker/Supervisor VM；同一
  测试项目、scope 和成功 load/activation 已取证；保存 `12-ztp-monitor.py` PID/starttime/argv、
  `.ztp-monitor.pid.lock` inode/owner/mode/nlink，以及 setup manifest、active inventory、current
  release 与四项 authority 的 inode/hash。不得在服务真实交换机的管理服务器执行。
- 步骤：分别在两个后端注入一次可恢复 runtime transport 故障和一次报告发布故障，证明每次先
  刷新 unhealthy sidecar，再从 last-good 报告刷新告警页面，且 `latest`/报告不变；恢复后同一
  进程成功并清零预算。再连续注入五次、注入边界外异常，并逐项原子替换 project/scope 关联的
  setup manifest、active inventory、current release、`01-global.yaml`、`02-devices_config.csv` 与
  active `p2p-air.json`，确认下一轮工作前永久退出。用重复/变更 fingerprint 的故障核对首次日志、
  `max(300, 10 * max(watch, 5))` 摘要、恢复日志和无凭据泄漏。并发触发 Native load 与 Docker
  activation/Monitor cleanup，验证官方 writer/remover 都取得同一持久 sibling lock 后才发布或
  删除 PID，失败时没有孤儿子进程或残留自身 PID。
- 预期：A1-B 只重试命名边界且第五次不再 sleep；A2-B 每次失败都保持 last-good 数据并显示真实
  sidecar 的 unhealthy 横幅；A3-A 的 project/scope/输入身份固定只在当前进程有效，进程重启必须
  从完整受管输入重新建立基线，不声明跨进程 pin；C6 的日志限流/计数也仅在当前进程内，重启会
  重新发出首条告警。SIGTERM/SIGINT 分别返回 143/130、清理自己的 PID 且不消耗失败预算。
- 证据、清理与风险：保存脱敏 sidecar/HTML 摘要、`latest`/报告前后 hash、每轮时间线、退出码、
  锁/PID inode 与子进程回收证据；不得保存密码、Authorization、URI userinfo 或设备秘密。持久
  `.ztp-monitor.pid.lock` 只串行遵守协议的受支持 writer/remover；可绕过 advisory lock 的并发
  root 在保证边界外。每个场景恢复 VM 快照并确认无 Monitor、Supervisor child、临时 PID 或锁
  holder；锁文件本身按合同保留，不手工删除。

## TC-REAL-P-DEPENDENCY-CAPSULE-001 — macOS 正式证明的同 UID 并发边界

- 状态：**NOT RUN / REAL_ENV REQUIRED**。自动化会验证 anonymous read-only archive、逐个依赖 child 的 snapshot 与 `sandbox-exec` 写保护；只使用标准库的 orchestration harness 不套外层 sandbox。仅 `-B test_cases/run_related_tests.py --all -v`、`-B test_cases/run_related_tests.py --suite repository-governance -v` 与 `-B test_cases/run_related_tests.py --all --no-approve -v` 三组精确审定的 runner argv 会在进入 child sandbox 前，由父进程预启动受管 loopback OpenSSH fixture。sshd 本身不在该 child profile 内启动，但只监听 `127.0.0.1` ephemeral port，使用临时 host key、禁用交互认证且不读取真实项目凭据。父进程只传 routing marker，不传 fixture 路径或 FD；child 先认证既有 exact-nine environment protocol 与 exact-seven dependency descriptor，再从 authenticated `snapshot.parent` 派生固定 sibling 并自行验证 fixture。自动化不会创建一个独立恶意同 UID 进程去抢占 archive 建立窗口；不得把单元/workflow 结果解释为抵御该外部进程。
- 前置条件：绑定的 macOS/arm64/CPython 3.9 主机与专用本地会话；没有不受信任的同 UID watch、IDE agent、cron、测试或调试进程。正式 runner 必须在允许 `/usr/bin/sandbox-exec` 应用子 profile 的非嵌套 sandbox 环境运行。只记录脱敏 UID、OS/Python/sandbox identity 与 allowlisted 进程摘要，不保存完整 argv、环境、项目内容或凭据。
- 步骤与预期：先核对同 UID 进程摘要，再在允许 `/usr/bin/sandbox-exec` 建立顶层 profile 的非嵌套环境中执行正式 full/check/list/list-suites/repository/no-approve 链。保存 archive 的 dev/ino/mode/nlink/size/SHA-256、每个 fresh snapshot 与 `PYTHONHOME` 的 identity、精确三类父进程 loopback scope 的 `/usr/sbin/sshd` identity、临时 key/config/manifest/log 的持久 held identity、经 held root dirfd 对 PID file 执行的短持有 `NOFOLLOW` 双 `pread`/`fstat` 证据、父进程真实 KEX、child exact-seven FD 集合、fixture subtree 写入与重命名拒绝、完整 KnownHostsCommand 正负矩阵、daemon process-group 回收、退出码、ledger 与最终 clean tree；任何意外同 UID 进程、sandbox 不可用、依赖/ABI 漂移、ownership 漂移、daemon 未回收或临时对象残留都使本次证据无效，不能回退或手工批准。
- 清理与风险：确认所有 archive/snapshot/`PYTHONHOME`/loopback fixture FD 已关闭、受管 sshd process group 已回收且随机 state root 已删除；异常时终止本次证明、以有界 TERM→KILL 流程回收受管 daemon、清理受控临时目录，并在新的专用会话重跑。sshd 不在 child sandbox 内，但该自动化场景只使用 `127.0.0.1` loopback、ephemeral port、临时 key 与禁用交互认证的固定配置，属于非破坏性本机证明；它不发送外部网络流量、不读取真实凭据，也不修改系统 sshd 配置、服务或状态。独立恶意同 UID 进程仍可能在 transient named archive window 内预先取得 writable FD，这是用户明确接受且自动化不覆盖的剩余风险；root/ptrace 或内核级攻击同样不在该证明边界内。
