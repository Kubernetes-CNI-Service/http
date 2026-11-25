# XDR IB 交换机初始配置

## 在整体架构中的位置

`initial-setup.py` 让新装的 NVOS IB 交换机第一次可以被管理。它按项目 CSV 和 P2P 逐台归类：
连到已登记跳板的 IB 沿原跳板路径；没有管理口连线、对端不是跳板或被 `--direct-access` 明确选中的设备，
由管理服务器直连。配置完毕仍从管理服务器核对，之后的 NVOS ZTP、备份和监控都以此为前提。
它不替代 `DAY0-Prepare/11-load.py` 的配置生成和服务启动。整体场景见仓库根目录的 `user-manual.html`。

本脚本以现场使用的 v15 为底，并入了仓库版的项目口令核对、管理网核验等功能。`--version` 打印仓库版本串
（例如 `http-v3.1.3`），不读输入、不加锁、不写报告，以 0 退出。

与固件升级脚本的关系：本脚本和 `infiniband/bringup/xdr-upgrade/upgrade.py`、`upgrade2.py` 共用同一个运行锁
`/tmp/http-ib-bringup.runtime.lock`。同一台机器上同一时间只能有其中一个在跑；锁被占时本脚本不做任何事、以 75 退出。
锁文件是常驻的空文件，不要删除它来「解锁」。

在哪里运行：

- 管理服务器：随整棵代码树部署（sync 或上传包），从 `/var/www/html/infiniband/bringup/xdr-initial-setup/`
  运行。脚本要 import 仓库 `tools/` 下的模块，**不能只拷这一个文件**。
- Ethernet OOB Leaf 本地运行（`--execution-mode ethernet`）：按下面「在 OOB Leaf 上本地运行」的同目录布局拷文件。
- 默认 `--execution-mode auto`：本机的主机名（短名或 FQDN）对上 CSV 里某台 Ethernet 时，这台的命令在本机直接执行，
  其余 Ethernet 仍经 SSH；对不上时按管理服务器处理。

## 工作流程

1. 读输入：`ib.csv` 里 `type=ib` 的是候选 IB，仅类型以 `jump` 结尾的 Ethernet 行才作跳板。
   P2P 仍记录已知管理口连线（`eth0`、`mgmt`、`management`、`bmc` 都算管理口）；无该设备连线不等于清单漏项。
   版本 6 目标缓存同时保留原始连线和归类输入，不把本次显式直连覆盖写成原始连线。
2. OOB 登录方式：只为走跳板的目标建立 OOB 会话；每台要用到的 Ethernet 先用公钥建立本次复用连接（`BatchMode`）；公钥被拒的才要口令，先问
   「是否全部使用同一个口令 [Y/n]」，回车或 y 只输一次，n 则逐台输入。经管道给口令见「`--credentials-fd`」一节。
3. 先采集所用 OOB 的快照，再处理 IB：直连目标不进入跳板快照队列，不占跳板并发；每台实际用到的跳板只采集一次，取实际主机名（必须与 CSV 里这个登录地址对应的主机名
   一致，短名和同名 FQDN 算一致）、`nv show interface`、`ip -d link show`、`bridge fdb show`、`bridge vlan show`，
   原样存成快照文件；某台 Ethernet 连不上或认证失败，只影响接在它下面的 IB。
4. 跳板路径逐台判断 IB 能不能登录（只用快照，不再登录 Ethernet）；跳板失败不自动换成直连。
   管理服务器的直连路径按本机接口判断：同网段先用 IPv6 link-local，只有符合重试条件的网络失败才改试 CSV IPv4；
   不同网段或无法确认同网段时用 CSV IPv4。Leaf 本地不能执行直连目标，对这类设备记录跳过。
   - P2P 对应的 `swpX` 在 `nv show interface` 里的第 3 列 Oper Status 必须是 `up`；不是就跳过这台，不查 FDB、不登录；
   - 端口是 bond 成员时改查 bond master；在 FDB 里取这个口学到的动态 MAC（`permanent` 的本机 MAC 不算）；
   - 由 CSV 的 `eth0_mac` 按 EUI-64 算出 IPv6 link-local，不从邻居表选地址；按预期端口的 VLAN 选 SVI 和 VRF。没有邻居条目不预先阻断，仍须核对线路和设备身份。
   - 线路核对以动态 FDB 为准；未学到的设备先按跳板成组探测，再读一次该跳板的 FDB。默认线路检查未通过则跳过；
     `--ignore-cable-check` 允许经预期端口的 VLAN 继续，不改用实际发现位置，也不跳过登录后的身份核对。
5. 选跳板：目标 VLAN 在 Leaf 上有自己的 SVI 且 SVI 有 IPv4 时，从 Leaf 登录 IB；只有 Leaf 上没有这个 SVI 或 SVI 没有
   IPv4 时，才改由 Leaf 上联的 Spine 登录：
   - Spine 必须在 CSV 里登记为 `type=eth_jump`，并且出现在这台 Leaf 的 `nv show interface` 里状态为 UP 的 LLDP 邻居中；
     默认只认短名以 `oob-spine` 开头的 `eth_jump`，别的命名用 `--oob-spines <名字>[,<名字>...]` 指定（它不绕过 LLDP、
     SVI 和 MAC 的检查）；
   - Spine 走这条路时 IB 必须在 CSV 里填真实的 `eth0_mac`，并与 Leaf 的 FDB 一致；
   - Spine 要有这个 VLAN 自己的 SVI、IPv4、IPv6 link-local，并能确定 VRF；每台 Leaf 每次运行在合格的 Spine 里随机
     选一台，同一台 Leaf 下要上移的 IB 都走这台；选择结果写进快照目录的 `spine-jump-routes.json`。
   - 脚本不建 SVI、不改 trunk 或 VRF，也不在任何跳板上装公钥。
6. 调度：快照和跳板选完后，可以登录的 IB 放进一个全局队列，worker 数是 `min(--max-workers, ceil(可登录的 IB 数 / 16))`，
   最多 16；只有一台 worker 时在主进程里依次执行。每台 IB 从头到尾由一个 worker 做完，期限是 `--task-timeout`
   （默认 1800 秒，不含等操作员输入的时间）。只有主进程提问、确认、打印和写报告。
7. 每台 IB 依次走下面几个阶段，后一阶段只在前一阶段通过后才做：
   1. **登录与读回**：先用 NVOS 初始密码登录；不通时依次试项目的 IB 目标密码，再请操作员输入一次这台的实际当前密码。
      读回 `nv config show -o commands`。
   2. **Initial**：`nv set system config auto-save state enabled`、`nv set system ztp config-save enabled`，`apply -y`、
      `save`，然后核对 ZTP 已关闭（`nv show system ztp`）。两项都已开、ZTP 已关时跳过。
   3. **Network**：按 CSV 配 `eth0`、`eth1` 的地址和网关、主机名，`eth0`、`eth1` 链路 up、类型 eth；两个网关相同时写成一条
      `interface eth0-1 ipv4 gateway`。设备上已有 CSV 要求的全部值（多出的设置保留）时跳过；只缺一部分、或与 CSV 冲突时
      在任何写入之前拒绝这台；`--force` 只补缺的字段，从不覆盖冲突的值。只写缺的那几条，然后 `apply -y`、`save`、读回核对。
   4. **IPv4 就绪**（只在 `--apply` 时）：从同一台跳板、同一 VRF 用 IB 的 eth0 IPv4 登录核对，最多9次；Network本次有改动先等15秒，否则首探测立即开始，之后失败再等10秒。
   5. **Infra Services**：DNS、NTP、时区取项目的 `01-global.yaml`，global 里没写的取中性默认值 `infra-neutral.conf`；
      已有就跳过；没有 global 时这一阶段记 SKIP。
   6. **Public Keys**：把项目的非空 `*.pub` 合并进 IB 的 `authorized_keys`，已有的授权保留；管理服务器上有
      `~/.ssh/id_ed25519`（不是链接）时，用它单独核对 `mgmt-server.pub` 能免口令登录；`laptop.pub` 只核对写进去了。
   7. **管理服务器直连**：从管理服务器直接 SSH 到 IB 的 eth0 IPv4（不经跳板），只在 eth0 失败且 CSV 有 eth1 时再试 eth1。
      在 OOB Leaf 上本地运行时不做这一步。
8. 汇总：主进程打印英文 Summary（01 OVERVIEW 到 07 EVIDENCE & NEXT ACTIONS 七个模块），整次结果是 SUCCESS、
   INCOMPLETE 或 FAILED（见「退出码」），并写出本次的 `summary.json`。

一台 IB 失败只停这一台，其余 IB 照常做完（日志 `other IB tasks remain eligible`）；失败的设备不自动重放不确定的写入。
只有脚本或公共流程出错（例如运行中项目输入被改、worker 异常、操作员取消）才算 FAILED。

### OOB 跳板连接复用（I-013）

管理服务器到每台跳板，本次运行只保留一条外层 SSH master；公钥探测成功的连接本身就是 master。
需要口令时，同地址公钥被拒后再用已取得的口令建立 master，不逐条命令重新登录；`--credentials-fd`
仍从本次口令表取值、不再提问。建立后先核对跳板主机名，再采集快照和执行后续外层命令。

控制目录是操作员进程创建的 `/tmp/isj-*`，权限 0700，正常结束或异常退出时关闭 master 并删除目录。
root 等待父进程不创建它；在 OOB Leaf 本机执行的命令不创建 master。跳板到 IB 的内层 SSH 不复用，
不在跳板上创建控制目录。使用前先检查 socket；丢失时由协调进程沿已选地址串行重建，不主动改走独立连接。

真实 OpenSSH 的后台化、`ControlPersist`、会话上限及检查到使用之间的回退窗口，仍需现场卡
`TC-REAL-I013-JUMP-MULTIPLEX-001` 验证；本机假 SSH 测试不能代替现场连接数证明。

### NVUE 逗号合并的接口和 fnm 接口（I-005）

`nv config show -o commands` 会把设置相同的接口合成一行、用逗号连接，例如
`nv set interface eth0-1,fnm1 link state up`。脚本读回配置时先把这类行拆成每个接口一行
（`eth0-1 …`、`fnm1 …`），之后的检查、补缺、核验和待提交检查都只看拆开后的行；不带逗号的行
原样保留，包括单独的 `eth0-1` 行。

- `eth0`、`eth1`、`eth0-1` 照常记录 link、type、地址和网关；写在逗号行里也按同样的规则检查，
  link 不是 up、type 不是 eth 时照旧拒绝。
- 算作与管理口无关的接口：`eth2` 以上、`ethA-B`（A≥2）、`swp`/`ibp`/`bond`/`vlan` 加数字的各写法、`lo`，
  以及 `fnm<数字>`。**接口普查之前只认 fnm**：别的陌生接口名（例如 `ib0`）和越过 eth1 的范围（例如
  `eth0-2`）仍然让这台设备的读回不合格，这台设备失败，在任何网络写入之前拒绝：已配置的设备不做任何改动；
  未配置的设备（主机名为空或 `NVOS`、没有地址和网关）和带 `--force` 补缺的部分配置设备，在 `--apply` 时已经跑过 Initial，
  Initial 的两项设置（auto-save、ZTP config-save）已写入并保存，网络和之后的阶段不做。只读检查不写设备。
- 报错文字不变；报告和设备日志里另有一行
  `LOCATION: readback line <行号>, interface <接口名>, setting <设置项>`，只写行号、接口名和设置项，
  不写地址等值。行号按设备返回的原始读回计算。
- 不修改设备上的 fnm 配置。

### 写阶段前的待提交改动（U3，R-025）

Initial、Network、Infra Services 三个写阶段在本阶段第一条写之前读 `nv config diff -o commands`
（原来 T15 读的位置）：

- 空：照常做。
- 每一行都是本台自有的值：本台 CSV 决定的 Initial、Network 设置，以及本次 services profile 里的全部 DNS、NTP 和时区
  （不只缺的那几项；没有 `01-global.yaml` 时不认服务类的行），按 token 逐字比对。先把原行写进设备日志和逐台结果的
  `pending_detached`（`[{"stage": "initial" | "day0" | "services", "lines": [原行…], "detached": true | false}]`），
  再经本阶段原有的确认（Infra Services 在它自己的确认之后）、写前配置备份和写许可执行 `nv config detach`，复读必须为空，
  然后照常做本阶段。detach 是一次配置写，计入 `metrics.nvue_write_commands`，所以这台的结果类别是
  `CHECKED_AND_CONFIGURED`，不会是 `CHECKED_EXISTING_KEYS_*`。备份失败、detach 非零、复读不空或读不到，这台失败，
  不发后续写，`detached` 记 `false`。
- 有任何一行不认识（profile 以外的值、`nv unset`、带别的属性的 ntp 行、其他行）：照旧拒绝，不 detach、不写；
  原因里写出不认识的行数，并提示「用 `nv config diff -o commands` 核对，确认后在设备上手工 detach 或 apply，再重跑」。
- 只读检查：在 `--apply` 第一次要写的位置读一次 diff，不 detach。全是自有的行时设备日志写
  「有 N 行自有待提交，`--apply` 时会 detach 后重做」，`planned_changes` 加 `{"item": "pending", "value": "<N> owned lines"}`，
  `needs_change` 为 `true`；有不认识的行时这台按上面的原因失败。只用公钥做的只读检查不读待提交。
- 不变的：Keys 和改密阶段前不加这道检查；`--config-mode replace` 替换本体前后的空 pending 门照旧非空即拒；
  不提交、不接着用设备上原有的待提交。

## 输入文件

### ib.csv

支持项目标准 `devices_config.csv` 格式，至少需要以下相关列：

```text
hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw
```

- `eth0_ip`、第一组 `netmask` 和 `eth0_gw` 是每台 IB 必填。有效的 `eth0_mac` 也必填；支持冒号、短横线、Cisco 点分格式或连续 12 位十六进制。缺失或错误的必填值使该台跳过并在结果中记录。
- eth1 可选；第二个 netmask 为空时沿用第一个 netmask。有效地址但未填写网关时只配置地址。无效的 eth1 项只记非阻断提示，且不配置对应项。
- `eth0_gw` 必须属于 eth0 网段，`eth1_gw` 必须属于 eth1 网段。
- Ethernet 只有类型以 jump 结尾才是跳板候选；没有有效登录候选时只停用该跳板。其它 Ethernet 行不按跳板校验登录地址。
- CSV 中重复出现的两个 `netmask` 列按位置分别对应 eth0 和 eth1。
- IB hostname 不是唯一或合法的全局主机名时拒绝整次。接口地址不能使用网段地址或广播地址；可共享网关不得与接口地址重复。相同子网的网关冲突按受影响范围处理：eth0 冲突跳过受影响设备，eth1 冲突只提示并不配置冲突项，其他设备照常。

### P2P

支持以下格式：

- 原始 `.xlsx` 工作簿；脚本自动查找含两组 `name + port/HCA/port` 列的工作表；
- 项目生成的 `*-lldpq.dot`；
- 含 `A-Node/A-Port/Z-Node/Z-Port` 或 `SrcDevice/SrcPort/DstDevice/DstPort` 列的 CSV；
- 空白分隔的 P2P log：前两个字段为源设备、源端口，最后两个字段为目的设备、目的端口。

LLDPq 中的纯数字 Ethernet 端口（例如 `15`）自动转换为 Cumulus 接口名 `swp15`。同一物理链路正向/反向重复、端点连接
自身，或同一设备端口连接多个不同对端都会使输入校验失败。P2P 描述的是 IB 到实际 Leaf 的接线，不写到 Spine 的链路。

默认从执行命令的当前目录自动查找：CSV 优先使用 `ib.csv`，XLSX 优先使用 `p2p.xlsx`；标准文件名不存在时，分别接受唯一的
`.csv` 和唯一的 `.xlsx`。查找不递归，并忽略隐藏文件、Excel `~$` 临时文件以及名称包含 `TBD` 的文件。同类型有多个候选时，
脚本列出文件并要求用 `--ib-csv` 或 `--p2p` 明确指定，不会自行猜测。显式 `--p2p` 支持 XLSX、DOT、CSV 和空白分隔 log。

### 各项输入从哪里读：`--project-dir`

| 项 | 不给 `--project-dir`（默认） | 给了 `--project-dir <项目>` |
|---|---|---|
| CSV | 当前目录里找（显式 `--ib-csv` 照用） | `<项目>/ib.csv`（不读 `02-devices_config.csv`） |
| P2P | 当前目录里找（显式 `--p2p` 照用） | `<项目>/p2p.xlsx`；没有时取项目根唯一的 `.xlsx` |
| global | 脚本所在目录的 `01-global.yaml`（链接，指向当前激活的项目） | `<项目>/01-global.yaml` |
| 公钥 | 脚本所在目录 `publickey/` 下的非空 `*.pub`（当前激活项目的公钥） | `<项目>` 根上的非空 `*.pub`（例如 `laptop.pub`、`mgmt-server.pub`），空文件跳过 |
| 中性默认值 | 脚本所在目录的 `infra-neutral.conf` | `<项目>/infiniband/bringup/xdr-initial-setup/infra-neutral.conf`（setup 写出） |
| 报告、以太网快照、目标缓存 | 当前目录下的 `xdr-initial-setup-logs/`（显式参数照用） | 同左，仍按当前目录 |

- 给了 `--project-dir` 时只按项目自己的固定文件名读，不经脚本旁边的 `01-global.yaml`、`publickey`
  链接（它们只指向当前激活的项目），所以也能检查没有激活的项目。项目根上一个非空 `*.pub` 都没有时，
  报告里打一行 WARNING，不装公钥，也不因此拒绝运行。
- 报告开头的 `Input sources:` 一行写明 CSV、P2P 来自哪个目录，global、公钥、中性默认值来自哪个目录；
  两者不同时这一行会注明，但只是提示，不拒绝运行。
- 现场从脚本目录运行时，当前目录就是脚本所在目录，所有输入、输出都落在当前激活的项目里。
- 仅 patch 模式在没有 global 时也能 `--apply`：Infra Services 阶段记 SKIP，其余照做；IB 要求强制改密时因为没有可核对的目标密码而拒绝这台。

### 设备名怎样对应

CSV 和 P2P 里的设备名按下面的规则对应（v15 的规则）：

- 先按全名比较：去掉首尾空白和结尾的 `.`，不分大小写；
- 全名对不上时，接受一边以 `-<另一边>` 结尾、并且恰好只有一台这样的设备（后缀匹配，例如 P2P 的名字带
  站点前缀）；有多台或没有都算对不上；
- IB 端对不上时跳过这条链路并打 WARNING；Ethernet 端对不上时整次失败。

**已知限制**：本版 initial-setup 仍有后缀匹配。名字比较普查里只靠后缀对上的端点不为 0，所以没有换成
`tools/device_identity.py` 按短名比较、不做后缀匹配的规则；什么时候换，等 G14-1 的别名表（本版和下一版都不改项目的 P2P）。

## 口令

| 口令 | 怎么取 | 用在哪里 |
|---|---|---|
| OOB（Leaf、Spine 跳板） | 先试公钥；公钥被拒的才问，先问是否共用一个口令 | 登录 Ethernet；不用作 IB 的口令 |
| NVOS 初始密码 | 先读环境变量（`--ib-initial-password-env` 指定的名字，默认 `NVOS_INITIAL_PASSWORD`；加 `--factory-default-admin` 时读 `NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD`）；没有时要求终端，隐藏输入，5 秒内没有输完一整行或直接回车就用 `admin`；没有终端又没有变量时报错 | 首次登录 IB |
| IB 目标密码 | 隐藏输入两次，必须与项目 `01-global.yaml` 里 IB 账户的口令哈希一致（不是 OOB 口令） | 强制改密时设成它；有 global 时 `--apply` 要求设备的当前密码与它一致，否则这台报错、不配置 |
| IB 实际当前密码 | 初始密码和目标密码都登录不了时问一次 | 只用于这台 |

- 只读检查（不带 `--apply`）遇到要求强制改密的 IB 会取消登录、记 `PASSWORD_CHANGE_REQUIRED`，不改密。
- `--apply` 时强制改密要经过下面的首次改动确认；改完用新连接重新登录读回，结果不确定时停下这台，不重复改密。
- 脚本不把口令写进源码、argv、日志、报告和 JSON（root 切换身份时的例外见「以 root 或 sudo 运行」的已知限制）；目标密码
  按哈希核对，用的是系统的 libcrypt/libxcrypt。
- 隐藏参数 `--ethernet-password` 仍然存在，一给就以 2 退出并提示不要把口令放进 argv。

## 使用方法

建议按以下三步执行。

### 第一步：生成并检查目标 JSON

```bash
python3 initial-setup.py --generate-json
```

这一步强制重新解析 CSV 和 P2P，做 hostname、IPv4、gateway 以及 P2P 重复性和合法性检查，然后生成：

```text
xdr-initial-setup-logs/initial-setup-targets.json
xdr-initial-setup-logs/initial-setup-targets.json.sha256
```

不访问 Ethernet 或 IB，不写运行报告。完成后确认输出的 IB 数量和 P2P management link 数量一致，并人工检查 JSON 中每台 IB
的目标地址、gateway、Ethernet 对端和 `swpX`。可以验证文件完整性：

```bash
cd xdr-initial-setup-logs
sha256sum -c initial-setup-targets.json.sha256    # macOS：shasum -a 256 -c initial-setup-targets.json.sha256
```

存在任何输入错误时先修正 CSV/XLSX，再重新执行本步骤。

### 第二步：只读在线检查

```bash
python3 initial-setup.py
```

引用通过完整性保护的目标 JSON，采集每台 Ethernet 的快照，再逐台只读登录 IB，按上面的阶段判断还缺什么，缺的命令以
`WOULD APPLY:` 打在设备日志里。不执行首次改密、`nv set`、`nv config apply` 或 `nv config save`。

执行后看 Summary 的 06 ATTENTION REQUIRED 和 07 EVIDENCE & NEXT ACTIONS。拓扑、接口状态、MAC/IPv6 映射和当前配置都符合
预期，才进入第三步。

只读检查的结果怎么看：

- 有设备还要配置（Initial、Network 或 Infra Services 缺东西）时，这台记 `CHECK_ONLY`，整次 INCOMPLETE、以 2 退出。
- 一台设备只差 Initial（auto-save、ZTP config-save 没都开，或 ZTP 没关）也算要配置，同样是 `CHECK_ONLY`、整次 2；
  但 `summary.json` 里这台的 `stage_status` 中 `initial` 仍记 `CHECKED`，06 ATTENTION REQUIRED 里这台的 stage 记
  `unknown`，要看这台设备日志里 `Stage 1: initial configuration` 下的 `WOULD APPLY:` 行才知道缺的是 Initial。
- 在 OOB Leaf 上本地运行（`--execution-mode ethernet`）时不做管理服务器直连核对（这一项记 `DIRECT_SSH_NOT_TESTED`），
  整次 INCOMPLETE、以 2 结束；要到管理服务器上再跑一次只读检查，才算确认管理服务器能直连。

### 第三步：确认并执行配置

```bash
python3 initial-setup.py --apply
```

`--apply` 不在启动时确认。脚本先完成 Ethernet 快照和只读发现，到第一台真正要改设备的 IB 时，才显示这台 IB、Ethernet、
端口和要做的事，并提示：

```text
Authorize this change and subsequent eligible IB devices? [y/N]:
```

首次确认可能发生在强制改密之前，或第一台需要 Initial、Network、Infra Services 或公钥写入的设备之前。确认一次后，后续合格
设备不再确认。拒绝时整次停下、不改设备，结果是 FAILED、以 1 退出。`--yes` 表示预先确认，只用于已经演练过的场景；
`--yes` 不绕过冲突、身份、口令或待提交检查。

每台 IB 配置后都要通过读回核对、IPv4 就绪核对和管理服务器直连，才算完成。一台配置后核对失败只停这一台，并在 Summary
里标出要人工核对的阶段；其余 IB 继续。

`--plan`（可选）：生成或引用目标 JSON，列出每台可能执行的 Initial、Network、Infra Services 和公钥命令并写进报告，
不访问任何设备，因此也不能确认实际选到哪台 Spine。`--generate-json`（旧名 `--generate-json-only` 仍可用）不能与
`--plan` 或 `--apply` 同时使用。

### 整份替换模式（D7）

默认 `--config-mode patch` 不变。显式 `--config-mode replace` 用于管理服务器的独立入口，不支持 OOB Leaf 本地运行、
内部 managed 入口或 `--generate-json`。写入仍须当前项目的受管输入和目标口令核验；没有有效 global 不进入替换写路径。

不给 `--project-dir` 时通过 `<脚本目录>/latest_yaml` 找发布件；给了则从该项目自己的 `99-output-ib_nvl/latest` 取，
其 `current-release.json` 位于项目的 `99-output-ztp/`。运行前检查 `.published-complete`、`release-manifest.json`、
当前项目输入和发布目录/摘要是否一致；整体验证失败时整批退出码 2、零设备写入，先按提示重跑 load。
整体验证通过后，某台缺少或未通过资格检查的 YAML 记 `YAML_MISSING_OR_INVALID`，不回退到 patch；其余合格设备可以继续。

`--plan` 只预览，不访问设备；计划和在线只读检查都逐台显示“整份替换（会清掉 yaml 以外的配置）”。
replace 实际只读检查不写设备配置；有合格替换目标时为 `WOULD_REPLACE` / `CHECK_ONLY`，整次 `INCOMPLETE`、退出码 2。
只读仍可生成本地报告、快照等证据；入口验证失败与正常未执行替换要按报告区分。

应用时，首次实际改动的原确认只问一次并显示同一警示；`--yes` 只跳过交互，不绕过任何校验或许可。
每台的顺序是：核对身份 → 备份 → 关闭并核对 ZTP → 整份替换 → 应用并保存（经 IPv4 时用新会话核对完成回执）
→ 补回缺项 → 再核对 ZTP → 公钥 → IPv4 就绪。最后的 IPv4 检查先等 15 秒；中途回执成功不等于最后的核验已完成。

仅确证本次 replace 或 apply 失败时才按原许可尝试 detach，保留设备侧替换文件：`FAILED_DETACHED` 和
`FAILED_DETACH_FAILED` 分开报告。文件准备失败、save 失败或结果不明不据此清理；已写后补回失败或再核 ZTP 失败不自动重放。
逐台 JSON（含 `summary.json` 中的记录）用 `replace` 内的 `verdict`、`file`、`sha256`、`reason` 说明选择与结论；
用 `writes_attempted` 和 `verified_complete` 区分已经尝试写入与最终核验完成，不把设备配置内容公开在结果字段里。

### 常用参数

| 参数 | 说明 |
|---|---|
| `--version` | 打印版本串后以 0 退出，不读输入、不加锁、不写报告 |
| `--project-dir <项目>` | 按项目自己的文件名读输入（见上表） |
| `--devices <名单>` | 按 CSV 选择本次 IB；未匹配项在设备登录前拒绝，不默认为全部 |
| `--ib-csv`、`--p2p` | 显式指定 CSV、P2P |
| `--eth-user`、`--ib-user` | Ethernet 用户（默认 `cumulus`）、NVOS 用户（默认 `admin`） |
| `--oob-spines <名字>[,<名字>...]` | 指定可以当跳板的 Spine（CSV 里的 `eth_jump` 名字）；默认短名以 `oob-spine` 开头的 `eth_jump` |
| `--connect-timeout <秒>` | SSH 连接超时，1～600，默认 10 |
| `--max-workers <n>` | worker 上限，1～16，默认 16；只能调低 |
| `--task-timeout <秒>` | 每台 IB 的期限，1～86400，默认 1800，不含等操作员输入的时间 |
| `--verbose` | 终端也打印完整的设备日志块和阶段事件；不加时终端只打进度和 Summary，报告始终完整 |
| `--force` | 与默认相同：只补缺的 Network 字段，不覆盖冲突 |
| `--report`、`--snapshot-dir`、`--target-cache` | 报告、快照目录、目标缓存的位置（默认见「输出」） |
| `--execution-mode auto\|management\|ethernet` | 执行位置；`--local-ethernet-hostname <CSV 主机名>` 在本机主机名对不上时指定本机是 CSV 里哪台 |
| `--credentials-fd <n>` | 从继承的管道读口令（见下一节） |

执行位置示例（主机名是占位）：

```bash
python3 initial-setup.py --execution-mode management
python3 initial-setup.py --execution-mode ethernet --local-ethernet-hostname <本机在 CSV 里的主机名>
```

### 经管道传口令：`--credentials-fd`

一站式 bringup 等调用方用 `--credentials-fd N` 把口令交给 initial-setup：从继承的管道 fd `N` 读一个 JSON 对象（UTF-8，
不超过 64 KiB），读完立即关闭。读入由 `tools/credentials_fd.py` 完成，在入口只读一次，在碰任何设备（包括 OOB 公钥探测）
之前。

| 键 | 值 | 缺省时 |
|---|---|---|
| `jump_passwords` | 对象：跳板交换机主机名 → 口令（`eth_jump`、`eth` 类 OOB Leaf，Spine 跳板也用这张表；主机名按短名、不分大小写比较，同一短名出现两次以 2 退出） | 见下面第 3 条 |
| `nvos_initial_password` | 字符串：NVOS 初始密码 | 用 `admin` |
| `ib_target_password` | 字符串：IB 目标密码，仍按项目 `01-global.yaml` 的哈希核对 | 给了 `--apply` 时以 2 退出；只读检查不需要 |

- 只取上表的键，多余的键忽略；值必须是非空字符串（`jump_passwords` 是这样的对象）。
- fd 模式下不提问：不调隐藏输入，也不读 `NVOS_INITIAL_PASSWORD` 等环境变量。下面 4 条是入口和跳板的行为：
  1. 给了 `--apply` 就必须同时给 `--yes`，否则在入口以 2 退出：fd 模式不问首次改动确认。
  2. `ib_target_password` 在入口按目标密码的形状检查（8～128 个可打印 ASCII 字符），有没有 global 都查；不合格以 2 退出，
     提示里不带口令的值。
  3. 表里没有某台需要口令的跳板时，这台照常先试一次公钥（跳板的认证日志里会有一次公钥尝试），公钥不通就不拿任何口令登录它，
     按 OOB 不可用处理：接在它下面的 IB 记 SKIPPED，其余照做，整次 INCOMPLETE、以 2 退出。公钥通了就不用表里的口令。
  4. 在 OOB Leaf 上本地运行时，目录里缺用到的 `tools/` 模块（例如 `tools/credentials_fd.py`）就以 2 退出，提示里写出缺的
     文件路径。
- 口令被拒的跳板或 IB 只影响对应的设备，不再提问；整次 INCOMPLETE、以 2 退出，按 `summary.json` 的逐台结果看是哪几台。
- 口令不经 argv、环境变量或文件，报告、`summary.json` 和设备日志里都没有。
- 退出码：入口缺键、JSON 不合法、fd 不可读都以 2 退出；执行中有设备没做完（INCOMPLETE）也是 2，按 `summary.json` 区分。

### 在 OOB Leaf 上本地运行

Leaf 上不需要整棵代码树，也不需要 PyYAML；目标缓存要先在管理服务器上生成（版本 6），用 `--execution-mode ethernet`
时缺缓存、缓存校验不过或带 `--direct-access` 都会拒绝。脚本按下面的同目录布局拷，`tools/` 下不放 `__init__.py`，也不放 `project_contract.py`、`operator_identity.py`：

```text
<目录>/initial-setup.py
<目录>/tools/login_path.py         每次运行都需要
<目录>/tools/hostname_ranges.py    每次运行都需要
<目录>/tools/device_identity.py    每次运行都需要（hostname_ranges 的依赖）
<目录>/tools/credentials_fd.py      Leaf 上用 --credentials-fd 时
```

每次只读检查、`--plan`、`--generate-json` 和 `--apply` 都在碰设备前加载 `tools.login_path`；Leaf 每次带上上述三个必需模块，缺文件以 2 退出并写明缺名。
`<目录>/tools/` 存在时脚本按这个布局 import；同时又在仓库
布局里（`<仓库>/tools/device_identity.py` 存在）、或两种布局都不成立时，以 2 退出并写出两种
布局各要的文件，不猜。Leaf 上本地运行不认项目，也不判身份。

管理服务器生成缓存时已比对本次子清单与总清单，Leaf 只接受带合格比对记录且绑定同份输入的缓存。
`--inventory-checked` 是上层流程已完成同一清单比对时传递的内部标记，不是操作员绕过清单检查的选项。

本机主机密钥刷新库只编辑调用方指定的操作员 `~/.ssh/known_hosts`，拒绝其他文件和该文件的链接。
管理服务器的两种直连核验可在 `--apply` 下接入已认证设备的指纹回调：核实一致后只删目标地址的全部旧记录，重试一次并再核对新指纹；只读不删。
`ssh-keygen -R` 会按自身行为保留或覆盖 `known_hosts.old`；记录如实保存 `.old`、inode、权限前后变化，不主动改这些属性。
当前真实 link-local 公钥读者、跳板串行删除及 `--refresh-host-key` 名单已接入下文 v3.1.4 工作流；没有可信读者时仍拒绝自动删除。

### 以 root 或 sudo 运行（I-006）

只在仓库布局下（管理服务器上随代码树部署的那份）判身份；OOB Leaf 的同目录布局和单独拷出的文件不判身份，原样运行。
`--help`、`--version` 也不判身份。

进运行锁之前先认项目：给了 `--project-dir` 就用它，否则取 `DAY0-Prepare/activate-project` 指向的项目；没有指针时原样
运行；指针无效时报错、以 2 退出。认出项目后按 `tools/operator_identity.py`（与 load 相同的规则，操作员就是项目目录的属主）
判身份，并在 stderr 打印一行身份说明，例如
`操作员：U（项目目录属主）；当前：root 经 sudo（发起人 U）→ 项目侧以 U 执行`：

| 谁在运行 | 项目属于普通用户 U | 项目属于 root |
|---|---|---|
| 普通用户不加 sudo 直接运行 | 是 U 本人时原样运行；别的用户拒绝 | 拒绝（提示用 sudo 或以 root 运行） |
| root 直接登录 | 切到 U 执行 | 以 root 运行 |
| U 经 sudo | 切到 U 执行 | 以 root 运行 |
| 别的普通用户 V 经 sudo | 拒绝 | 以 root 运行 |

- 拒绝都在运行锁之前、以 2 退出，提示写明项目属于谁、当前是谁和可行的办法；sudo 的 `SUDO_USER`、`SUDO_UID` 无效（包括在 root
  的 shell 里再用 sudo 运行：这时 `SUDO_USER` 是 root），或项目属主在 passwd 里查不到，也拒绝。
- 切到 U 执行：root 父进程用 `runuser -u U -- env -i …` 以同一个 Python 解释器重新执行本脚本、参数不变，并等它结束，
  按子进程的退出码退出（子进程被信号结束时是 128+信号号）；Ctrl-C 和 SIGTERM 转发给子进程。父进程不拿运行锁。
- 子进程的环境只有这些：父进程环境里有的 `PATH`、`LANG`、`LC_ALL`、`TERM`；`--ib-initial-password-env` 指定的变量
  （默认 `NVOS_INITIAL_PASSWORD`），加 `--factory-default-admin` 时另有 `NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD`（父进程环境
  里有才带）；`HOME`（U 在 passwd 里的家目录）、`USER`、`LOGNAME`（都是 U）；标记变量 `HTTP_ZTP_ROOT_PARENT=1`
  （兜底标记：子进程以 U 运行，本来就不会再切换；它也传给子进程起的全部后代）。`--credentials-fd` 的 fd 原样交给子进程读。
- **M6b：独立环境管道**：显式请求且实际存在的 keep 变量保留原字符串，包括空值、非 ASCII 和 surrogateescape；
  值或其编码载荷不放进 runuser/重新执行链的 argv。共享机制通过本轮封存的非阻塞管道和固定标准库 bootstrap 恢复环境，
  不创建载荷文件。原 `credentials_fd` 仍由业务入口唯一读取并关闭，环境 bootstrap 不预读、不关闭它。
  passwd 的 HOME/USER/LOGNAME、框架 `HTTP_ZTP_ROOT_PARENT` 优先级不变，无关环境仍排除；普通 bootstrap 错误固定无值消息/2，
  wait 退出码、INT/TERM 转发及 128+信号号不变。空 keep 的 setup/upgrade2/cron 不额外创建载荷管道。
  Linux runuser/PAM、真实 UID 与终端行为仍为现场 OPEN/NOT RUN；macOS 合成替身通过不等于现场验证或设备操作授权。
- 切到 U 以后没有 root 的 ssh-agent（`SSH_AUTH_SOCK` 不在子进程环境里）。

### 旧 `--auto` 定时任务的移除步骤

`--auto` 和 `--credentials-file` 已随 v3.1.3 退役（owner 2026-11-02，统一改用一站式 bringup）：
再给这两个参数，脚本按未知参数以 2 退出，不建运行锁、不写报告。本脚本不再安装 cron，
也不再写 `auto.env`。

只有用过 DEV 版 `--auto` 的服务器才会有残留（现场的 v15 一进来就拒绝 `--auto`）。残留的
cron 行部署后每 10 分钟以参数错误退出、往 `auto-cron.log` 追加报错，明文 `auto.env` 一直
留着，所以要清理一次，**先删 cron 行，再删文件**（反过来，`02-unsetup.py` 会因为三个状态
文件都不在而不碰 cron 行）。状态目录是 `xdr-initial-setup-logs`，经链接落在
`<项目>/99-output-ib_nvl/bringup/xdr-initial-setup-logs`。

1. 只读普查，只看行数和元数据，不用 `cat`、`less`、`head`、`cp` 碰 `auto.env`：

   ```bash
   crontab -l 2>/dev/null | grep -c -F '# http-v3-req10c-auto'
   crontab -l 2>/dev/null | grep -c -E 'initial-setup\.py --auto --apply --yes --credentials-file'
   find <状态目录> -maxdepth 1 \( -name auto.env -o -name 'auto-*' -o -name auto.lock \) -printf '%p %u %m %s\n'
   ```

   以 root 查操作员的，`crontab` 加 `-u <操作员>`。
2. 确认没有轮次在跑：`<状态目录>/auto.lock` 存在时用 `fuser -v` 或 `lsof` 只读查看；不要用
   `flock` 探测（锁文件不存在时它会新建一个）。
3. 在没有其他同 UID crontab 写者的窗口里删 cron 行，**先落盘、核对、再装**，不要用管道
   `crontab -l | … | crontab -` 一步装表（`crontab -l` 出错时会装进空表，删掉这个用户全部
   cron 行）：
   1. `crontab -l > <备份>`，退出码不是 0 就停下（「no crontab」也算没有残留）；
   2. 数总行数 N：`wc -l < <备份>`；数要删的行数 K：
      `grep -c -E '# http-v3-req10c-auto|initial-setup\.py --auto --apply --yes --credentials-file' <备份>`；
   3. `grep -v -E '<同上>' <备份> > <新表>`：退出码 1 只表示没有剩下的行，退出码 2 才是出错，停下；
   4. 核对 `wc -l < <新表>` 等于 N − K，不等就停下；
   5. `crontab <新表>`，再确认上面两种行的计数为 0、总行数为 N − K；
   6. `<备份>` 按 0600 保留在操作员自己的目录里，出问题时 `crontab <备份>` 恢复。

   root 下清操作员的，每条 `crontab` 都加 `-u <操作员>`；当年用 sudo 跑过 `--auto` 的，root
   自己的 crontab 也照做一遍（`02-unsetup.py` 以 root 代表操作员时只处理操作员的 crontab）。
4. 删文件：`auto.env` 用 `shred -u`；`auto-watch.state`、`auto-terminal.json`、`auto-crontab.lock`、
   `auto.lock` 用 `rm -f`；`auto-cron.log` 按现场习惯保留或归档。
5. 留证据：前后的计数、`find -printf` 的元数据、`<备份>` 的路径；不保存 `auto.env` 的内容。

`02-unsetup.py` 仍保留旧 watch 的清理（保留到 K6r）：在指针还指着当年那个项目时运行，它删掉
当前用户（root 代表操作员时为操作员）crontab 里本项目的 auto 行和 `auto.env`、`auto-watch.state`、
`auto-terminal.json`。它只看当前链接的项目、不删 `auto-crontab.lock`、`auto.lock`、`auto-cron.log`，
也不碰 root 自己的 crontab；其余情况按上面的手工步骤处理。现场执行与留证按
`test_cases/REAL_ENVIRONMENT.md` 的 `TC-REAL-D1-AUTO-RESIDUE-001`。

## 退出码

| 退出码 | 意思 |
|---|---|
| 0 | SUCCESS：本次选中的全部 IB 完成要求的设置并通过管理服务器直连核对；`--version`、`--help`、`--plan`、`--generate-json` 正常结束也是 0 |
| 1 | FAILED：脚本或公共流程出错（运行中项目输入被改、worker 异常、批次停止、操作员拒绝首次改动确认等） |
| 2 | 入口错误（参数、输入校验、`--credentials-fd` 缺键或不合法、身份拒绝、运行锁以外的守卫错误），或 INCOMPLETE：本次选中的目标未齐、某台失败或跳过、只读发现需配置、或未通过所需直连核对。没有 P2P 管理连线本身不算失败；核对实际逐台结果。 |
| 75 | 运行锁被占（另一个 initial-setup 或升级在跑），什么都没做 |
| 128+n | root 运行、切到项目属主执行时，子进程被信号 n 结束 |

2 有两种意思（入口错误、执行中有设备没做完），按报告和 `summary.json` 的逐台结果区分。Ctrl-C 按的时机不同，结果也不同：
执行阶段按下，整次停下、FAILED、以 1 退出；在 NVOS 初始密码或 IB 目标密码的提示处按下，以 2 退出；在 OOB 快照阶段按下，进程被 SIGINT 结束
（root 运行时父进程以 130 退出）。

## 输出

默认都写在当前目录的 `xdr-initial-setup-logs/` 下。从脚本目录运行时，这个目录由 DAY0 setup 链接到当前项目的
`99-output-ib_nvl/bringup/xdr-initial-setup-logs/`，切换项目时跟着切换。文件都不含口令；日志含内部拓扑和配置，按私有资料
归档。

- `initial-setup-report-<YYYYmmdd-HHMMSS>.log`：本次运行的报告，**每次运行一个新文件**，不覆盖以前的报告；同一秒里文件名
  已存在时在时间戳后加 `-<进程号>`。报告第一行是 `Report: <完整路径>`，终端开头也打印这一行。内容有输入来源、设备映射、
  MAC/IPv6、VLAN/SVI、VRF、当前配置、计划或执行的命令、核对结果、错误和 Summary。用 `--report <路径>` 时照这个路径写
  （已存在的文件会被覆盖）。报告文件越积越多，脚本不自动清理，按现场习惯归档或删除旧报告。
- `devices-<YYYYmmdd-HHMMSS>-<随机后缀>/`：本次运行的证据目录，与报告在同一个目录，时间戳与报告文件名里的相同（用
  `--report` 时取本次运行开始的时间）。里面有每台 IB 的设备日志 `<IB 主机名>.log` 和结构化记录 `<IB 主机名>.json`，以及
  整次的 `summary.json`（权限 0600：项目、版本、模式、结果、逐台记录、管理服务器直连结果、OOB 快照失败、Spine 跳板选择）。
  选中设备只在 `records` 或 `selection.unmapped` 中出现一次。没有 P2P 管理连线本身不算失败，也不直接归为 unmapped；看本次归类和逐台结果。
- `initial-setup-targets.json` 和 `initial-setup-targets.json.sha256`：CSV/P2P 解析后的目标缓存（版本 6）。CSV、P2P、管理端
  `01-global.yaml` 和公钥的内容、生成器源码和 Python 运行时身份都没变、校验文件也对得上时直接复用，否则重新生成；回拨
  mtime 掩盖不了字节变化。管理服务器上缺当前 global 时缓存失效；OOB Leaf 上可以用管理服务器预先烘进缓存、仍通过来源校验的
  配置，Leaf 上不需要 YAML 文件或 PyYAML。旧缓存（版本不对或没有校验文件）由管理服务器重新生成，Leaf 不重建。用 `--target-cache <路径>` 指定
  别的文件时，校验文件是同名加 `.sha256`。
- `initial-setup-ethernet-snapshots/`：每台 Ethernet 的 `<主机名>.snapshot.txt`（采集时间、CSV 主机名、实际主机名、登录 IP、
  执行位置，以及 `nv show interface`、`ip -d link show`、`bridge fdb show`、`bridge vlan show` 的原始输出），走 Spine 判断时的
  `<主机名>.addresses.json`，以及 `spine-jump-routes.json`。每台采集成功后原子覆盖旧文件，失败时不留半成品。用
  `--snapshot-dir <目录>` 指定别的位置。`--plan` 和 `--generate-json` 不访问设备，不生成快照。

link、FDB、VLAN 和接口 VRF 是设备的实时状态，每次运行都重新核对。只读检查不写设备配置，但会更新上面这些本地文件，
SSH 的 `known_hosts` 也可能新增主机密钥（`StrictHostKeyChecking=accept-new`）。

## 安全规则

- 未指定 `--apply` 时不执行首次改密、任何 `nv set` 或 `nv config apply/save`；只生成本地 JSON、报告、快照，并执行只读
  设备命令。
- `--apply` 在第一台实际变更前确认；拒绝时整次停下、不改设备（以 1 退出）。`--apply --yes` 明确跳过交互确认。
- patch 默认只补缺；`--force` 与默认相同。真实冲突在写入前拒绝该台，不覆盖原值。设备上有不认识的待提交改动时不写；全是本台自有的值时记录后 detach 再做（见「写阶段前的待提交改动」）。
- 有公钥时只读核对一次，无公钥不读取；不回传 `authorized_keys`，也不写设备配置。
- 一台 IB 匹配多条管理链路、必填 CSV 输入无效或不能核对设备身份时，明确记录且不配置该台。线路检查根据本节前述 FDB 与已选入口判定。
- 改密或写入结果不确定时停下这台、标为要人工核对，不自动重放。
- 初始密码、目标密码、当前密码和 OOB 口令都不打印、不写进报告和 JSON。

## v3.1.4 跳板不可达、冷却与逐台记录（D4 WP-2）

各跳板最多有 8 台 IB 任务在途；全局 worker 数仍是 `min(--max-workers, ceil(ready/16))`，
硬上限 16，不把 worker 固定分配给某台跳板。连续两次针对实际跳板登录地址的网络失败，或一次
master 的所有候选地址都失败后，该跳板暂停派发 240 秒。换候选后成功不算一次失败。最多冷却
两轮；冷却到期且这台跳板没有在途任务后，检查/必要时重建 master，再验证 `hostname` 和既有
身份约束，成功才恢复。其他跳板继续派发，不为探测主动关闭仍有在途任务的 master。

冷却由协调进程管理，不计入某台任务的 `--task-timeout`。因跳板网络失败且尚未尝试写入的任务
保留本次 `.attempt-N.log`/`.attempt-N.json` 证据后重新入队，从头执行；最终结果才记为完成。
已经拿到写入许可的任务不自动重放，仍归跳板不可达，但明确标为“写入已尝试、结果未核实”。
两轮冷却后仍失败，这台跳板下剩余任务直接给出失败结果，不继续连接。快照先尝试所有跳板，
再统一冷却、只重试网络失败者，不让前一台的 240 秒等待挡住后续健康跳板的首轮采集。

`[DONE]` 与汇总先查询同一张 `failure_kind` 分类表，再回退旧分类：

| `failure_kind` | `category` | 含义 |
|---|---|---|
| `OOB_JUMP_UNREACHABLE` | `FAILED_OOB_JUMP_UNREACHABLE` | 实际外层跳板地址网络不可达；查跳板网络/SSH/master，不按失败所处阶段推断密码错误 |
| `OOB_JUMP_AUTHENTICATION` | `FAILED_OOB_JUMP_AUTHENTICATION` | 跳板认证被拒绝，既不算网络不可达，也不自动进入网络冷却 |
| `DIRECT_SSH_NETWORK` | `FAILED_DIRECT_SSH_NETWORK` | 原有管理服务器直连网络失败 |
| `TARGET_HOST_KEY_CHANGED` | `FAILED_TARGET_HOST_KEY_CHANGED` | 主机密钥冲突；不按网络故障重试，具体处理沿现有授权流程 |

逐台 JSON 保留 `category`、`failure_kind`、`writes_attempted`；`jump` 保留 `hostname`、
`login_ip`、`interface`、`vrf`、`access_vlan`、`selection_reason`，只新增 `type`。`login_ip`
是实际选中的登录候选地址；本地 Leaf 的 `selection_reason` 仍是 `LEAF_LOCAL_PATH`。
没有跳板的后续直接登录任务使用 `jump: null`，不占用跳板在途名额、不累计跳板失败。
`writes_attempted: true` 表示已经请求过受控写入，不是写入已成功；须核对设备状态后再决定是否
授权另一轮运行。网络判断使用地址/跳数事实，内层 IB 的 IPv4/link-local 失败不冒充跳板不可达。

## v3.1.4 IPv4 就绪等待（D4 WP-3）

每次 `--apply` 在 Network 核对后仍执行 IPv4 SSH 就绪检查。本次实际完成了 Network
配置写入时，先等 15 秒再探测；本次无需改 Network 时立即探测。普通端点未就绪（连接拒绝、
超时、无路由）失败后再等 10 秒，最多探测 9 次。只读检查不启动这段就绪探测。
每次等待之后仍先检查跳板 master，必要时协调重建并复查，再发本轮探测；外层跳板故障保留
既有分类和协调流程，不冒充 IB 收敛、在这里等待九轮。认证、主机密钥变化、要求改密、命令
不存在或不完整结果帧仍立即停止；中断、批次停止和项目输入变化也不重试。

仅在跑满九次时，有改动95秒、无改动80秒；提前就绪则等待更少。如果每次探测耗10秒，总耗时分别约185/170秒，都不是最坏上界。原单次
PTY 会话预算 `max(connect_timeout * 3, 45)`、master 核验/重建开销和任务截止约束仍保持，
不增加预算。九次仍未就绪时会提示“设备可能还在收敛”，由操作员核对现场再决定下一步，
不自动重放 Network 写入。

本工作包只解析完整的 OpenSSH 主机密钥变化事实，供后续受控处理读取；严格管理分支仍只
输出既有固定安全错误文字，不带原始告警。缺少地址、指纹或 Offending 行时仍停止，不伪造
事实。本包不接受变化后的密钥、不编辑 `known_hosts`，也未完成后续自动核实/删除/刷新流程。

## v3.1.4 受控主机密钥刷新（D3 WP-5）

此节补齐上节 WP-3 只解析事实的后续处理，不改变默认 SSH 身份校验、原凭据顺序或等待预算。
factory reset 后，跳板至 IB 的 IPv4 主机密钥变化会先经已经认证的 link-local 会话读取这台
IB 的固定主机公钥，用同一指纹算法核对。指纹一致且本次为 `--apply`，才进入原首次变更
确认；`--yes` 沿用原预授权。核实不一致、无法核实或未授权时不删记录，也不重放配置写入。

跳板上唯一新增写操作是固定命令
`ssh-keygen -f /home/cumulus/.ssh/known_hosts -R <告警点名的地址>`。目标必须为本次 IB、
账户必须为 cumulus，地址只能是该 CSV 的 eth0 IPv4 或该任务实际的带接口 link-local。
只删这个地址的全部密钥类型，不删主机名或其他设备记录。远端删除由父协调进程串行执行，
每次删除前重新 lookup；过期 Offending 行号不再属于当前 lookup 时保守拒绝，不额外登录或
暗中采用新行号。其他不受本协调器控制的 accept-new 写者不在隔离保证内。

默认 OpenSSH `-R` 可能留下或覆盖 `known_hosts.old`；报告只在返回输出实际说明留下该文件时
记为 true，不额外远程 stat。远端 inode、权限四项未采集时为 null，不伪造数值。本机编辑器
仍如实记录实际 `.old`、inode 和权限。AIR 的真实行为及并发追加边界仍须现场卡核实。

核实不了但操作员已通过可信方式确认 reset 的设备，可指定一次 IB 名单，例如：

```text
--apply --refresh-host-key 'example-ib[01-02]'
```

名单复用 `*`、等宽数字范围、字母范围及逗号写法，只和本次 CSV 全部 type=ib 名称匹配；
未匹配项、跳板名或不合法语法在设备访问前以 2 拒绝。`all` 不是全选关键字。名单仅跳过
指纹核实，不跳过地址/文件/账户/授权/Offending 子集或重试后新指纹核对。它不扩大权限。
尚未认证的 link-local 冲突没有安全 reader，只能在这份名单中才能删除并由调用方重试一次；
阶段内部仍每次只有一个凭据会话。实际现有传输用 `-B <接口>` 加未带 zone 的邻居地址，
解析器仍只接受 IPv4 或完整 scoped link-local 告警；真实现场告警结构未知时固定拒绝，
不能用合成 scoped 用例冒称现场已通过。

本地 Leaf 使用当前实际 passwd 用户自己的 `~/.ssh/known_hosts`，该用户必须等于
`--eth-user`，不强行要求名为 cumulus；管理端也只编辑操作员自己的文件。告警指向其他文件
则不删。IPv4 刷新后只再探测一次，无额外 15 秒首等候；管理端最后密码/公钥核验沿同一流程。
原九次真实 IPv4 未就绪仍优先归 `FAILED_OOB_IPV4_READINESS`，末尾只读核验继续留证，但不再写。

只读检查中，指纹已核一致为 `CHECKED_HOST_KEY_REFRESH_PENDING`（需关注，不算设备失败），
不一致或无法核实为 `FAILED_TARGET_HOST_KEY_CHANGED`；两者都不删除、不重试。逐台 `host_key`
为列表，可同时保存跳板与管理端事实；pending 的 result 为 `refresh-pending`、removal 为 null，
成功为 `refreshed`，明确区分 `verified` 和 `operator-forced-unverified`。不保存原始 SSH 告警。
上述本机合成验证不替代 `TC-REAL-I004-HOSTKEY-REFRESH-001`；现场卡仍 OPEN / NOT RUN。

## 辅助脚本（手工准备，不由流程调用）

辅助脚本以 `helper-` 开头，必须同时满足：不被仓库其他脚本调用或导入、自己不导入仓库模块；`--help` 在任何动作前无副作用地返回；只做人工准备或验证，不写仓库或项目里其他脚本要读的项目文件、锁、台账或配置。它们跟踪版本并随 upload/sync 分发，但不属于 initial-setup、load 或 UFM 的自动流程。辅助脚本只做语法、help 和引用普查，**行为未经测试验证**，必须由人审阅并授权手工运行。

`helper-prepare-eth-jump.sh` 帮助准备 CSV 中 `type=eth_jump` 的跳板，以 `cumulus` 用户登录。文件权限为 0644，用 `bash` 运行；先在交互终端查看帮助：

```bash
bash helper-prepare-eth-jump.sh --help
bash helper-prepare-eth-jump.sh [ib.csv] [publickey_dir] [--keys-only]
```

默认输入是当前目录的 `./ib.csv` 和 `./publickey`，读取其中有效、非空的 `*.pub`。默认模式安装公钥并修复持久 PATH；`--keys-only` 只安装公钥，不修改跳板持久的 `~/.bashrc`（准备会话仍设置临时 PATH）。口令从 `/dev/tty` 交互读取，不支持无人值守调用。

运行的外部效果必须由操作者事先确认：

- 管理服务器缺少 `sshpass` 时，会以 root 或 sudo 使用 apt 安装，必要时更新 apt 索引；要求 Ubuntu/Debian。
- SSH 使用 `StrictHostKeyChecking=accept-new`，管理服务器上操作者的 `~/.ssh/known_hosts` 可能新增跳板主机密钥。
- 跳板上会创建 `~/.ssh` 并设为 0700，创建或追加 `~/.ssh/authorized_keys` 并设为 0600；默认模式还在 `~/.bashrc` 第一行写入 PATH。
- 改已有文件前分别保留 `~/.ssh/authorized_keys.prepare_eth_jump.bak` 和 `~/.bashrc.prepare_eth_jump.bak`；已有备份不覆盖。回退由人检查并使用这两份备份恢复，仓库流程不代为回退跳板。新建文件原先不存在时可能没有对应备份。

这些跳板准备操作属于 owner 明确授权的手工辅助脚本例外，不扩大 initial-setup 等流程修改跳板的权限。README 本身不随生产包或 sync 部署，现场还应保留发布说明中的用法、备份名和未经行为验证的限制。
