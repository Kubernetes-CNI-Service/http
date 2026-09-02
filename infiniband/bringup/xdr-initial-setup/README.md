# XDR IB 交换机初始配置

## 在整体架构中的位置

本工具位于 IB 设备首次可管理化阶段：它利用项目 P2P 和 OOB Leaf 的二层邻接，在常规 NVOS
ZTP/备份/监控之前完成 Day-0 管理入口。它不替代 `11-load.py` 的配置生成与服务启动，也不与
固件升级脚本共享状态。整体场景与数据边界见根目录 `USER_MANUAL.md`。

`initial-setup.py` 可以在管理服务器或 Cumulus Ethernet OOB Leaf 上运行。它利用
P2P、bridge FDB 和 neighbor 表定位尚未初始化的 NVOS IB 交换机，再从对应 OOB Leaf
通过 IPv6 link-local 地址登录并完成 Day-0 管理配置。本工具与 `bringup` 目录中的固件
升级脚本没有依赖关系。

脚本也可以直接在任意一台 P2P 中的 Ethernet OOB Leaf 上运行。默认 `auto` 模式会把
本机短 hostname/FQDN 与 CSV 比较：本机对应的 OOB Leaf 命令直接执行，其他 OOB Leaf
仍通过 SSH 访问。因此同一份输入可以包含多个 Ethernet 交换机，并由一次执行统一处理。

## 工作流程

1. 读取 `ib.csv`，以 `type=ib` 的设备作为候选设备；同时读取 `type=eth` 或
   `type=ethernet` 设备的 OOB 登录 IPv4。
2. 从 P2P 查找每台 IB 设备的管理连接。IB 端口名 `eth0`、`mgmt`、`management`、
   `bmc` 均视为同一种管理连接。
3. 在处理 IB 前先遍历所有 P2P 对端 Ethernet。每台分别提前收集 hostname、
   `nv show interface`、`ip -d link show`、`bridge fdb show` 和 `ip neighbor`，保存在
   脚本本地内存中；后续 IB 判断不会重复执行这些整机命令。实际 hostname 必须与 CSV
   中该登录 IP 对应的 Ethernet hostname 一致；短主机名和同名 FQDN 视为一致。
4. 再逐台处理 IB：在本地保存的 `nv show interface` 输出中精确查找 P2P 对应的
   `swpX`，将完整状态行写入执行报告。
   严格使用第 3 列 `Oper Status`，不使用第 2 列 `Admin Status`。只有 Oper Status 为
   `up` 才继续；down、未知、无法解析或接口不存在时跳过该 IB 设备，不在本地 FDB、
   neighbor 快照中查找该设备，也不执行 VRF 查找或登录。
5. 对 Oper Status=up 的目标，先从 `ip -d link show` 判断 P2P 的 `swpX` 是否为 bond
   成员口。普通端口或直接加入 bridge 的端口仍使用 `swpX` 查询 FDB；只有其 master
   接口被详细信息明确识别为 bond 时，才改用 bond master（例如 `swp36 → bond43`）
   查询本地 FDB 快照中的动态 MAC。然后用 MAC 在本地 neighbor 快照中找 IPv6
   link-local 地址及其 VLAN/SVI 接口。FDB 中的 `permanent` 本机 MAC 不作为 IB 设备
   MAC。如果 CSV 提供了
   `eth0_mac`，此时立即与 OOB Leaf 在该 P2P 端口学习到的动态 MAC 比较；不一致时该
   IB 设备记为失败并停止处理，不查 VRF、不登录 IB，也不执行任何配置。
6. 执行 `ifquery <VLAN/SVI接口>`：如果配置中有明确的 `vrf <名称>`，后续使用该
   VRF；否则使用 `default`。
7. 从 Ethernet 交换机执行：

   ```bash
   ip vrf exec <vrf> ssh -6 admin@<IPv6-link-local> -B <VLAN/SVI接口>
   ```

8. 新 NVOS 首次登录默认用户为 `admin`，但脚本不再内置初始密码。在线检查前从
   `NVOS_INITIAL_PASSWORD` 读取，变量不存在时只在交互终端隐藏输入；自动化必须显式提供环境
   变量。实验室/初装可加 `--factory-default-admin`，此时只读取
   `NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD` 或隐藏提示，同样不会把值写入源码、argv 或日志。
   只有指定 `--apply` 并通过最终确认时，脚本才允许完成强制改密，把新密码设置为该 Ethernet
   交换机的登录密码，然后使用
   新密码重新连接。检查模式遇到强制改密会立即取消并跳过该设备。
9. 通过 `nv config show -o commands` 检查 `eth0`、`eth1`、两个 gateway 和
   hostname。只有这些字段全部未配置，并且 hostname 为空或 `NVOS` 时，设备才有资格
   配置；任一字段已有值则整台设备跳过，绝不局部覆盖。
10. 从 CSV 配置 `eth0_ip/eth0_gw` 和 `eth1_ip/eth1_gw`。NVUE 的 `eth0-1` 表示
   eth0 到 eth1 的接口范围：两个 gateway 相同时生成一条 `interface eth0-1 ipv4
   gateway`；不同时分别生成 `interface eth0` 和 `interface eth1` gateway。随后配置
   hostname，执行 `nv config apply`、`nv config save`，重新读取配置进行验证。
11. 最后从同一台 Ethernet 交换机、同一 VRF 通过 IB 设备的 eth0 IPv4 地址验证 SSH。

发现阶段的单台设备失败不会阻止其他设备继续检查。设备发生实际变更后，如果配置复查或
IPv4 SSH 验证失败，脚本会停止配置后续 IB，避免扩大影响。脚本最后汇总 configured、
skipped 和 failed；存在失败时退出码为 1，输入或启动错误时退出码为 2。

## 输入文件

### ib.csv

支持项目标准 `devices_config.csv` 格式，至少需要以下相关列：

```text
hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw
```

- IB：`eth0_ip`、第一个 `netmask`、`eth0_gw` 必填。
- IB 的 `eth0_mac` 可选；支持冒号、短横线、Cisco 点分格式或连续 12 位十六进制。
  提供后，脚本直接与 P2P 指定 OOB Leaf 接口的 `bridge fdb show` 动态 MAC 比较。若不一致，
  该设备记为失败，不登录 IB 且不会执行配置；错误会提示 CSV MAC 可能有误，或设备可能连接
  到了错误的 OOB Leaf 接口。未提供或填写 `NA` 时保持原有行为，不执行 MAC 一致性检查。
- IB：设置了 `eth1_ip` 时，第二个 `netmask` 和 `eth1_gw` 必须有效；第二个 netmask
  为空时沿用第一个 netmask。
- `eth0_gw` 必须属于 eth0 网段，`eth1_gw` 必须属于 eth1 网段。
- Ethernet：使用 `eth0_ip` 作为管理服务器登录该交换机的地址。
- CSV 中重复出现的两个 `netmask` 列按位置分别对应 eth0 和 eth1。
- IB hostname 和 eth0/eth1 IPv4 地址必须全局唯一；hostname 必须符合标准 DNS hostname
  格式，接口地址不能使用网段地址或广播地址。
- gateway 可以由多台 IB 设备共享，但不能与任何 IB 接口地址重复；同一 IPv4 子网不能
  声明不同 gateway。

### P2P

支持以下格式：

- 原始 `.xlsx` 工作簿；脚本自动查找含两组 `name + port/HCA/port` 列的工作表；
- 项目生成的 `*-lldpq.dot`；
- 含 `A-Node/A-Port/Z-Node/Z-Port` 或
  `SrcDevice/SrcPort/DstDevice/DstPort` 列的 CSV；
- 空白分隔的 P2P log：前两个字段为源设备、源端口，最后两个字段为目的设备、目的端口。

LLDPq 中的纯数字 Ethernet 端口（例如 `15`）自动转换为 Cumulus 接口名 `swp15`。
同一物理链路正向/反向重复、端点连接自身，或同一设备端口连接多个不同对端都会使输入
校验失败。

## 使用方法

建议严格按照以下三个步骤执行。

### 第一步：生成并检查目标 JSON

```bash
python3 initial-setup.py --generate-json
```

该步骤强制重新解析当前目录中的 CSV 和 XLSX，执行 hostname、IPv4、gateway 以及 P2P
重复性和合法性检查，然后生成：

```text
xdr-initial-setup-logs/initial-setup-targets.json
xdr-initial-setup-logs/initial-setup-targets.json.sha256
```

该步骤不访问 Ethernet 或 IB 设备，也不生成在线执行报告。完成后确认输出的 IB 数量和
P2P management link 数量一致，并人工检查 JSON 中每台 IB 的目标地址、gateway、
Ethernet 对端和 `swpX`。可以验证文件完整性：

```bash
cd xdr-initial-setup-logs
sha256sum -c initial-setup-targets.json.sha256
```

macOS 也可使用：

```bash
cd xdr-initial-setup-logs
shasum -a 256 -c initial-setup-targets.json.sha256
```

存在任何输入错误时先修正 CSV/XLSX，再重新执行本步骤。

### 第二步：只读在线检查


```bash
python3 initial-setup.py
```

该步骤引用通过完整性保护的目标 JSON，提前采集每台 Ethernet 的 hostname、接口、
详细 link、FDB 和 neighbor 快照，再逐台发现和只读登录 IB，检查当前 eth0、eth1、
gateway 和 hostname。
它不会执行首次改密、`nv set`、`nv config apply` 或 `nv config save`；遇到需要首次改密
的 IB 会取消并跳过。

该步骤生成或更新：

```text
xdr-initial-setup-logs/initial-setup-report.log
xdr-initial-setup-logs/initial-setup-ethernet-snapshots/<Ethernet-hostname>.snapshot.txt
```

执行后重点检查 `ERROR`、`SKIP` 和最终 Summary。只有拓扑、接口状态、MAC/IPv6 映射及
当前配置结果符合预期，才进入第三步。

### 第三步：确认并执行配置

```bash
python3 initial-setup.py --apply
```

`--apply` 不会在脚本启动时立即确认。脚本先完成 Ethernet 快照和只读发现，到第一台
真正需要产生设备变更的 IB 时，才显示该 IB、Ethernet、端口和变更原因，并提示：

```text
Authorize this change and subsequent eligible IB devices? [y/N]:
```

首次确认可能发生在强制修改初始密码前，或第一台无需改密但需要执行 Day-0 配置的设备
前。拒绝则立即停止且不产生设备变更；确认一次后后续合格设备不重复确认。`--yes` 表示
预先确认，因此仅适用于已经完成演练的自动化场景。

每台 IB 配置完成后，脚本必须依次通过 NVUE 配置复查和从对应 Ethernet/VRF 发起的目标
IPv4 SSH 验证，才会标记 `SUCCESS` 并继续下一台。任何配置后验证失败都会停止后续 IB
配置，避免扩大影响。

### `--plan` 是否需要

标准三步流程不需要 `--plan`。第一步已经完成全部离线输入校验并生成可审查 JSON；第二步
还会显示相同的设备映射并执行只读在线检查。

`--plan` 仅作为可选辅助模式保留：它生成/引用目标 JSON、显示映射并写入报告，但不访问
任何设备。当只想快速查看映射而暂时不做在线检查时可以使用：

```bash
python3 initial-setup.py --plan
```

`--generate-json` 不能与 `--plan` 或 `--apply` 同时使用。旧名称
`--generate-json-only` 继续兼容，但新操作文档统一使用 `--generate-json`。

默认从执行命令的当前目录自动查找输入：CSV 优先使用 `ib.csv`，XLSX 优先使用
`p2p.xlsx`；标准文件名不存在时，分别接受唯一的 `.csv` 和唯一的 `.xlsx`。查找不递归，
并忽略隐藏文件、Excel `~$` 临时文件以及名称包含 `TBD` 的文件。如果同类型存在多个
候选，脚本列出文件并要求通过 `--ib-csv` 或 `--p2p` 明确指定，不会自行猜测。显式
`--p2p` 仍支持 XLSX、DOT、CSV 和空白分隔 log。

`--apply` 默认要求最终确认；自动化执行可加 `--yes`。Ethernet 默认用户为 `cumulus`，
IB 用户为 `admin`，可分别用 `--eth-user` 和 `--ib-user` 修改。

执行位置控制：

```bash
# 默认：本机 hostname 匹配某台 Ethernet 时本地执行，否则按管理服务器处理
python3 initial-setup.py --execution-mode auto

# 明确在管理服务器运行，所有 Ethernet 均通过 SSH
python3 initial-setup.py --execution-mode management

# 明确在 Ethernet 上运行；自动匹配失败时指定本机对应的 CSV hostname
python3 initial-setup.py --execution-mode ethernet \
  --local-ethernet-hostname NM1FL08SH04OOBLE03
```

无论本机还是远端，每台 Ethernet 的 interface/link/FDB/neighbor/VRF 只采集一次，
并独立验证 hostname。
每台 Ethernet 分别提示一次密码；本机执行时该密码不用于登录本机，而是供首次 NVOS
在 `--apply` 模式下强制改密使用。某台 Ethernet 访问或身份验证失败不会阻止其他
Ethernet 继续处理。

脚本默认把全部输出集中在当前目录的 `xdr-initial-setup-logs/` 下。该路径由 DAY0 setup
链接到当前项目的 `99-output-ib_nvl/bringup/xdr-initial-setup-logs/`，切换项目时自动切换归档，包括：

- `xdr-initial-setup-logs/initial-setup-targets.json`：CSV/P2P 解析后的设备和链路映射。如果它比 `ib.csv` 和
  P2P 文件都新、记录的源文件绝对路径一致、缓存版本有效，并且通过配套的
  `initial-setup-targets.json.sha256` 完整性校验，后续运行直接引用；否则自动重新生成。
  校验针对原始文件字节，人工修改任意字段、空格或换行都会使缓存失效。旧缓存没有校验
  文件时也会重新生成。可用 `--target-cache <路径>` 指定其他文件，校验文件相应追加
  `.sha256` 后缀。即使内容没有变化，只要信息文件在校验文件之后又被手工保存或 `touch`，
  也会重新生成。
- `xdr-initial-setup-logs/initial-setup-report.log`：每次运行覆盖，包含设备映射、MAC/IPv6、VLAN/SVI、VRF、
  当前配置、计划或执行的命令、验证结果和错误。可用 `--report <路径>` 指定其他文件。

link、FDB、neighbor 和接口 VRF 是设备实时状态，每次运行仍重新采集。相关文件都不包含密码。

实时执行时，每台 Ethernet 的完整采集结果还会原子写入：

```text
xdr-initial-setup-logs/initial-setup-ethernet-snapshots/<Ethernet-hostname>.snapshot.txt
```

每个文件包含采集时间、CSV hostname、设备实际 hostname、登录 IP、执行位置，以及
`nv show interface`、`ip -d link show`、`bridge fdb show`、`ip neighbor` 的原始输出，
不包含密码。每次成功完成该 Ethernet 的全部采集后覆盖旧文件；采集或写入失败时不会
留下半成品。可用
`--snapshot-dir <目录>` 指定其他保存位置。`--plan` 和 `--generate-json` 不访问设备，
因此不会生成 Ethernet 快照。

## 安全规则

- 未指定 `--apply` 时不执行首次改密、任何 `nv set` 或 `nv config apply/save`；只生成
  本地 JSON、报告、快照，并执行只读设备命令。
- `--apply` 在第一台实际变更前确认；用户拒绝时立即停止且不修改设备。`--apply --yes`
  明确跳过交互确认。
- hostname、eth0、eth1 或任一 gateway 已设置时，整台设备跳过。
- 一个 IB 设备匹配多条管理链路、一个端口没有动态 MAC、MAC 没有唯一 IPv6
  link-local neighbor，或 CSV 地址无效时，明确报错且不配置该设备。
- 首次密码、新密码和 Ethernet 密码均不会打印或写入报告。
