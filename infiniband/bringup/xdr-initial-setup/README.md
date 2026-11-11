# XDR IB 交换机初始配置

## 在整体架构中的位置

`initial-setup.py` 让新装的 NVOS IB 交换机第一次可以被管理：它按项目的 CSV 和 P2P 找到每台 IB 接在哪台
Ethernet OOB Leaf 的哪个口，从这台 Leaf（或 Leaf 上联的 Spine）经 IPv6 link-local 登录 IB，完成初始设置、
管理口地址和网关、主机名、DNS/NTP/时区和公钥，最后从管理服务器直连核对。之后的 NVOS ZTP、备份和监控都以此为前提。
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

1. 读输入：`ib.csv` 里 `type=ib` 的是候选 IB；`type=eth`、`ethernet`、`eth_jump` 等 Ethernet 设备提供 OOB 登录地址。
   P2P 给出每台 IB 管理口（`eth0`、`mgmt`、`management`、`bmc` 都算管理口）连在哪台 Ethernet 的哪个口。解析结果写进
   目标缓存（版本 5），输入没变时直接复用。
2. OOB 登录方式：每台要用到的 Ethernet 先用公钥试一次（`BatchMode`，最多 5 秒）；公钥被拒的才要口令，先问
   「是否全部使用同一个口令 [Y/n]」，回车或 y 只输一次，n 则逐台输入。经管道给口令见「`--credentials-fd`」一节。
3. 先采集全部 OOB 快照，再处理 IB：每台 Ethernet 只采集一次，取实际主机名（必须与 CSV 里这个登录地址对应的主机名
   一致，短名和同名 FQDN 算一致）、`nv show interface`、`ip -d link show`、`bridge fdb show`、`ip neighbor`，
   原样存成快照文件；某台 Ethernet 连不上或认证失败，只影响接在它下面的 IB。
4. 逐台判断 IB 能不能登录（只用快照，不再登录 Ethernet）：
   - P2P 对应的 `swpX` 在 `nv show interface` 里的第 3 列 Oper Status 必须是 `up`；不是就跳过这台，不查 FDB、不登录；
   - 端口是 bond 成员时改查 bond master；在 FDB 里取这个口学到的动态 MAC（`permanent` 的本机 MAC 不算）；
   - CSV 填了 `eth0_mac` 时与 FDB 的 MAC 比较，不一致就跳过这台，不登录 IB；
   - 用 MAC 在 `ip neighbor` 里找 IPv6 link-local 地址和所在的 VLAN/SVI；`ifquery <SVI>` 里写了 `vrf <名字>` 就用这个
     VRF，否则用 `default`；neighbor 表里没有时，只在 CSV MAC 与 FDB 唯一对上时按 EUI-64 推出一个候选地址，候选不等于
     已核实的登录。
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
   4. **IPv4 就绪**（只在 `--apply` 时）：从同一台跳板、同一 VRF 用 IB 的 eth0 IPv4 登录核对，最多 3 次，每次之前等 10 秒。
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

### NVUE 逗号合并的接口和 fnm 接口（I-005）

`nv config show -o commands` 会把设置相同的接口合成一行、用逗号连接，例如
`nv set interface eth0-1,fnm1 link state up`。脚本读回配置时先把这类行拆成每个接口一行
（`eth0-1 …`、`fnm1 …`），之后的检查、补缺、核验和待提交检查都只看拆开后的行；不带逗号的行
原样保留，包括单独的 `eth0-1` 行。

- `eth0`、`eth1`、`eth0-1` 照常记录 link、type、地址和网关；写在逗号行里也按同样的规则检查，
  link 不是 up、type 不是 eth 时照旧拒绝。
- 算作与管理口无关的接口：`eth2` 以上、`ethA-B`（A≥2）、`swp`/`ibp`/`bond`/`vlan` 加数字的各写法、`lo`，
  以及 `fnm<数字>`。**接口普查之前只认 fnm**：别的陌生接口名（例如 `ib0`）和越过 eth1 的范围（例如
  `eth0-2`）仍然让这台设备的读回不合格，这台设备失败，在网络阶段之前拒绝：已配置的设备不做任何改动；
  未配置的设备（主机名为空或 `NVOS`、没有地址和网关）在 `--apply` 时已经跑过 Initial，Initial 的两项设置
  （auto-save、ZTP config-save）已写入并保存，网络和之后的阶段不做。只读检查不写设备。
- 报错文字不变；报告和设备日志里另有一行
  `LOCATION: readback line <行号>, interface <接口名>, setting <设置项>`，只写行号、接口名和设置项，
  不写地址等值。行号按设备返回的原始读回计算。
- 不修改设备上的 fnm 配置。

## 输入文件

### ib.csv

支持项目标准 `devices_config.csv` 格式，至少需要以下相关列：

```text
hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw
```

- IB：`eth0_ip`、第一个 `netmask`、`eth0_gw` 必填。
- IB 的 `eth0_mac` 可选（经 Spine 登录时必填）；支持冒号、短横线、Cisco 点分格式或连续 12 位十六进制。
  提供后与 P2P 指定 OOB Leaf 接口学到的 FDB 动态 MAC 比较，不一致时这台不登录、不配置，提示 CSV MAC 可能有误或接错了口。
  未提供或填写 `NA` 时不做这项比较，Summary 里列出没有 MAC 的设备。
- IB：设置了 `eth1_ip` 时，第二个 `netmask` 和 `eth1_gw` 必须有效；第二个 netmask 为空时沿用第一个 netmask。
- `eth0_gw` 必须属于 eth0 网段，`eth1_gw` 必须属于 eth1 网段。
- Ethernet（含 `eth_jump`）：`eth0_ip` 是登录这台交换机的地址。
- CSV 中重复出现的两个 `netmask` 列按位置分别对应 eth0 和 eth1。
- IB hostname 和 eth0/eth1 IPv4 地址必须全局唯一；hostname 必须符合标准 DNS hostname 格式，接口地址不能使用网段地址
  或广播地址。
- gateway 可以由多台 IB 设备共享，但不能与任何 IB 接口地址重复；同一 IPv4 子网不能声明不同 gateway。

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
- 没有 global 时也能 `--apply`：Infra Services 阶段记 SKIP，其余照做；IB 要求强制改密时因为没有可核对的目标密码而拒绝这台。

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

### 常用参数

| 参数 | 说明 |
|---|---|
| `--version` | 打印版本串后以 0 退出，不读输入、不加锁、不写报告 |
| `--project-dir <项目>` | 按项目自己的文件名读输入（见上表） |
| `--ib-csv`、`--p2p` | 显式指定 CSV、P2P |
| `--eth-user`、`--ib-user` | Ethernet 用户（默认 `cumulus`）、NVOS 用户（默认 `admin`） |
| `--oob-spines <名字>[,<名字>...]` | 指定可以当跳板的 Spine（CSV 里的 `eth_jump` 名字）；默认短名以 `oob-spine` 开头的 `eth_jump` |
| `--connect-timeout <秒>` | SSH 连接超时，1～600，默认 10 |
| `--max-workers <n>` | worker 上限，1～16，默认 16；只能调低 |
| `--task-timeout <秒>` | 每台 IB 的期限，1～86400，默认 1800，不含等操作员输入的时间 |
| `--verbose` | 终端也打印完整的设备日志块和阶段事件；不加时终端只打进度和 Summary，报告始终完整 |
| `--force` | 只补缺的 Network 字段，不覆盖冲突 |
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

Leaf 上不需要整棵代码树，也不需要 PyYAML；目标缓存要先在管理服务器上生成（版本 5），用 `--execution-mode ethernet`
时缺缓存或缓存校验不过直接报错。脚本按下面的同目录布局拷，`tools/` 下不放 `__init__.py`，也不放 `project_contract.py`、`operator_identity.py`：

```text
<目录>/initial-setup.py
<目录>/tools/credentials_fd.py      Leaf 上用 --credentials-fd 时
<目录>/tools/device_identity.py     用 --credentials-fd 且 fd 里有 jump_passwords 时
```

不用 `--credentials-fd` 时只要 `initial-setup.py` 一个文件。`<目录>/tools/` 存在时脚本按这个布局 import；同时又在仓库
布局里（`<仓库>/tools/device_identity.py` 存在）、或两种布局都不成立、而运行又要用到 tools 模块时，以 2 退出并写出两种
布局各要的文件，不猜。Leaf 上本地运行不认项目，也不判身份。

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

- 拒绝都在运行锁之前、以 2 退出，提示写明项目属于谁、当前是谁和可行的办法；sudo 的 `SUDO_USER`、`SUDO_UID` 无效，或项目
  属主在 passwd 里查不到，也拒绝。
- 切到 U 执行：root 父进程用 `runuser -u U -- env -i …` 以同一个 Python 解释器重新执行本脚本、参数不变，并等它结束，
  按子进程的退出码退出（子进程被信号结束时是 128+信号号）；Ctrl-C 和 SIGTERM 转发给子进程。父进程不拿运行锁。
- 子进程的环境只有这些：父进程环境里有的 `PATH`、`LANG`、`LC_ALL`、`TERM`；`--ib-initial-password-env` 指定的变量
  （默认 `NVOS_INITIAL_PASSWORD`），加 `--factory-default-admin` 时另有 `NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD`（父进程环境
  里有才带）；`HOME`（U 在 passwd 里的家目录）、`USER`、`LOGNAME`（都是 U）；标记变量 `HTTP_ZTP_ROOT_PARENT=1`
  （子进程据此不再切换）。`--credentials-fd` 的 fd 原样交给子进程读。
- **已知限制**：上面这些环境变量是以 `名字=值` 写在 `runuser` 的命令行参数里的，切换期间同机用户用 `ps` 能看到。所以 root
  运行时，环境里不要有 `--ib-initial-password-env` 指定的变量（默认 `NVOS_INITIAL_PASSWORD`）或
  `NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD`，初始密码改用交互输入或 `--credentials-fd`。经 sudo 运行时 sudo 默认会清掉这类
  变量，`sudo -E` 或 `sudo 变量名=…` 会把它们带进来。本版不改这一点。
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
| 0 | SUCCESS：全部 IB 完成要求的设置并通过管理服务器直连核对；`--version`、`--help`、`--plan`、`--generate-json` 正常结束也是 0 |
| 1 | FAILED：脚本或公共流程出错（运行中项目输入被改、worker 异常、批次停止、操作员拒绝首次改动确认等） |
| 2 | 入口错误（参数、输入校验、`--credentials-fd` 缺键或不合法、身份拒绝、运行锁以外的守卫错误），或 INCOMPLETE：正常跑完但还有设备没做完——某台失败或跳过、只读检查发现要配置、CSV 里有 IB 没有 P2P 管理链路、没有做管理服务器直连核对 |
| 75 | 运行锁被占（另一个 initial-setup 或升级在跑），什么都没做 |
| 128+n | root 运行、切到项目属主执行时，子进程被信号 n 结束 |

2 有两种意思（入口错误、执行中有设备没做完），按报告和 `summary.json` 的逐台结果区分。Ctrl-C 按的时机不同，结果也不同：
执行阶段按下，整次停下、FAILED、以 1 退出；在口令提示处按下，以 2 退出；在 OOB 快照阶段按下，进程被 SIGINT 结束
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
- `initial-setup-targets.json` 和 `initial-setup-targets.json.sha256`：CSV/P2P 解析后的目标缓存（版本 5）。CSV、P2P、管理端
  `01-global.yaml` 和公钥的内容、生成器源码和 Python 运行时身份都没变、校验文件也对得上时直接复用，否则重新生成；回拨
  mtime 掩盖不了字节变化。管理服务器上缺当前 global 时缓存失效；OOB Leaf 上可以用管理服务器预先烘进缓存、仍通过来源校验的
  配置，Leaf 上不需要 YAML 文件或 PyYAML。旧缓存（版本不对或没有校验文件）会重新生成。用 `--target-cache <路径>` 指定
  别的文件时，校验文件是同名加 `.sha256`。
- `initial-setup-ethernet-snapshots/`：每台 Ethernet 的 `<主机名>.snapshot.txt`（采集时间、CSV 主机名、实际主机名、登录 IP、
  执行位置，以及 `nv show interface`、`ip -d link show`、`bridge fdb show`、`ip neighbor` 的原始输出），走 Spine 判断时的
  `<主机名>.addresses.json`，以及 `spine-jump-routes.json`。每台采集成功后原子覆盖旧文件，失败时不留半成品。用
  `--snapshot-dir <目录>` 指定别的位置。`--plan` 和 `--generate-json` 不访问设备，不生成快照。

link、FDB、neighbor 和接口 VRF 是设备的实时状态，每次运行都重新采集。只读检查不写设备配置，但会更新上面这些本地文件，
SSH 的 `known_hosts` 也可能新增主机密钥（`StrictHostKeyChecking=accept-new`）。

## 安全规则

- 未指定 `--apply` 时不执行首次改密、任何 `nv set` 或 `nv config apply/save`；只生成本地 JSON、报告、快照，并执行只读
  设备命令。
- `--apply` 在第一台实际变更前确认；拒绝时整次停下、不改设备（以 1 退出）。`--apply --yes` 明确跳过交互确认。
- Network 字段只缺一部分或与 CSV 冲突时，这台在任何写入之前拒绝；`--force` 只补缺、不覆盖。设备上有不明的待提交改动时
  不写。
- 一台 IB 匹配多条管理链路、端口没有动态 MAC、MAC 没有唯一的 IPv6 link-local neighbor，或 CSV 地址无效时，明确报错且
  不配置这台。
- 改密或写入结果不确定时停下这台、标为要人工核对，不自动重放。
- 初始密码、目标密码、当前密码和 OOB 口令都不打印、不写进报告和 JSON。
