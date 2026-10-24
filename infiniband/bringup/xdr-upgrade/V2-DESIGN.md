# IB 交换机升级 v2：落地设计（2026-10-23）

本文描述 `upgrade2.py` 及其模块实际怎么工作。设计来自 owner 2026-10-23 的讨论，经过一轮独立对抗式评审；
评审结论已经并入正文。真实设备验收 NOT RUN（`test_cases/REAL_ENVIRONMENT.md` 的 `TC-REAL-IBSW-V2-001`）。

## 1. 为什么另起引擎

2026-10-22/23 的 CPLD 批量升级中，107 台没有下发、19 台 UNKNOWN，其中 10 台事后确认已到目标版本。
从代码路径和耗时推断，主因是每台下发前预检的 120 秒预算（`_COMPONENT_PREFLIGHT_SECONDS`）耗在了本机全局锁
`_LOCAL_REQUEST_LOCK` 的排队上；这一点是推断，不是测量。v1 还有两个结构性问题：
- 预算计入本机排队时间；
- 观察循环绑在在途名额和全局证据检查上。

owner 的判断是：ztp-server 上的并发不是问题，大部分时间花在设备重启后的等待。v2 让节奏只由设备决定。

## 2. 模块分层（以后 nvl-sw 可以复用）

| 层 | 文件 | 说明 |
|---|---|---|
| 通用 | `tools/fleet_engine.py` | 主进程事件循环、worker 池、证据、进度、汇总；通过 `Family` 接口调用设备族 |
| 通用 | `tools/fleet_probe.py` | 两个探测队列的纯状态机，支持「预期不重启」的作业 |
| 通用 | `tools/fleet_distribution.py` | P2P 分组、接力调度、错峰直拉、ztp-server 拉取闸门 |
| 通用 | `tools/fleet_link.py` | ztp-server 出口速率检测和分档 |
| 通用 | `tools/fleet_ssh.py` | paramiko 会话：主机密钥固定、先密钥后密码、命令超时 |
| 通用（交换机上运行） | `tools/fleet_fetch_helper.py` | 取包助手：HTTP 或 scp（只用密码），校验 sha256 后改名 |
| IB 专用 | `tools/ibsw_v2_device.py` | `IbFamily`（组件顺序、包、步骤、金丝雀、渲染）和 `LiveOps`（对一台交换机的全部操作） |
| IB 专用（交换机上运行） | `infiniband/bringup/xdr-upgrade/ibsw-v2-check.sh` | 通用只读检查脚本，经 SSH stdin 执行，不留文件 |
| 入口 | `infiniband/bringup/xdr-upgrade/upgrade2.py` | 命令行、输入、速率检测、凭据、运行守卫 |

- v1 只复用纯函数：
  - 版本、固件、健康表解析（contract）；
  - `select_os_path`、`select_os_canaries`、`compare_commands`；
  - `_bios_upgrade_needed`、`_cpld_upgrade_needed`、`render_declared_step`；
  - 版本和健康判定（observer 里的 `_assess_*`、`_require_upgrade_health`）、owned runner；
  - 只依赖 sftp 的 `_read_keys`、`_replace_keys`、`merge_authorized_keys`。
- 不使用 v1 的 leaf/scope 和证据锁。`fleet_ssh` 的运行时版本固定与 v1 相同，测试保证两边一致。

新设备族接入时提供三样东西：一个 `Family` 子类、一个 ops 对象、一个检查脚本。只改配置、不重启的作业
（`effect == "NONE"`）走同一套探测：脚本退出 0 就交回验证。

## 3. 流程

```
入口：每台的 HTTP 地址 [HTTP] 与速率检测 [LINK] → P2P 分组 [GROUPS] → 问密码、校验密码 → 主进程
主进程：全部预检（检查池） → 按组件 os → bios → cpld 逐阶段：
  金丝雀（逐台、走完所有跳数、从 ztp-server 直拉，拉取优先）
  ∥ 分发（与金丝雀并行；OS 在 <10G 时按 OOB leaf 接力，否则直拉；BIOS/CPLD 一律直拉）
  → 已暂存且金丝雀已通过、在途名额有空 → 升级 worker：复查、上传、写前记录、启动 → upgrading Q
  → 探测 → READY → 检查 worker 验证（必要时修复缺失配置）→ 下一跳 / 下一组件 / 完成
```

- **金丝雀**：OS 用 v1 的最小路线覆盖；BIOS/CPLD 取 CSV 顺序第一台需要升级的设备。金丝雀没通过，
  该组件其余设备记 BLOCKED，分发也随即停止。
- **组件顺序**：与 v1 一样，os → bios → cpld 分阶段推进；BIOS/CPLD 要求设备已在最终 OS。
- **多跳 OS**：每一跳单独做一轮分发；同一跳后到的设备等 60 秒凑成一批。

## 4. 预检与验证

- **预检**（检查脚本一次取回）：
  - 身份（hostname + eth0 MAC）、boot_id、开机时长、设备时间、账号；
  - 版本、固件、健康；
  - 配置导出和 diff；
  - 能力（bash、nohup、python3、curl、scp、sha256sum）；
  - `/home/admin` 剩余空间、各步骤目录、已暂存包的 sha256。
- 另外从 ztp-server ping 一次：ICMP 已确认全部放通，不通记 FAILED（PING_UNREACHABLE）。
- **升级模式**下先用密码会话确认恢复密码可用。管理公钥不在 authorized_keys 里时先写
  `access-bootstrap.json` 再导入，然后用密钥重新登录核对，最后保存 `authorized_keys.before`。
- **密码校验与输错保护**（2026-10-24 现场日志之后）：
  - 入口问到密码时（`--upgrade` 或 `--password`），在任何预检之前，对第一台在 TCP/22 有响应的选中设备做一次
    只用密码的登录，只执行 `true`，不写任何东西。TCP/22 不通、SSH 连不上、主机密钥未固定或不符的设备跳过
    （这些情况下密码根本没有发出）；一台都没有响应就继续，由预检报告不可达。结果记在 `plan.json` 的 `password_check`。
  - 交换机明确拒绝密码记 `PASSWORD_REJECTED`，与密钥被拒的 `AUTH_REJECTED` 分开。被拒时提示重输，最多 3 次
    （与 v1 的「Attempt 2/3」相同）；第 3 次仍被拒就退出，退出码 2，提示什么都没改。
  - 引擎兜底：预检中第一次出现 `PASSWORD_REJECTED` 就 HOLD。不再启动新的预检，已在运行的预检照常跑完；
    尚未预检的设备记 SKIPPED（`PASSWORD_REJECTED_HOLD`），这些设备上什么都没写；拒绝密码的设备记 FAILED
    （`PASSWORD_REJECTED`）；汇总写明密码被拒、被跳过的设备没有写入。引擎从不重试密码。
  - 密钥被拒仍是 `AUTH_REJECTED`，探测、取包和验证照旧先用密钥、被拒再用密码。回退的密码被拒时，
    探测仍按 auth_fail 处理（回到 ping）；验证记 UNKNOWN（`VERIFY_PASSWORD_REJECTED`），不重试。
  - 依据：10-24 的 v1 CPLD 日志里，第一轮升级有 118 台进入 CPLD 步骤。v2 的预检在每台需要升级的设备上都开一个
    密码会话，一次输错就会在这么多设备上各失败一次密码登录，有触发账户锁定的风险（推断），整批也会失败；
    v1 在第一次明确拒绝、任何密钥或安装写入之前就停下重问。
- **下发前复查**（同一会话）：
  - 身份；组件仍需要升级；BIOS/CPLD 要求最终 OS；
  - 健康（`--force` 可越过）；
  - 配置导出非空，diff 为空；
  - 暂存包 sha256 与原件一致；
  - authorized_keys 只增不减；
  - BUSY/PENDING。
- **验证**（检查池优先级最高，600 秒）：
  - 身份、boot_id 不变；
  - 版本等于本跳目标；
  - 配置比对 PASS；只缺少可安全重放的行时，先写 `repair-requested.json`，再 patch → apply → save，然后复核；
  - 健康不变差；
  - 最后新开一个密钥会话，复核 boot_id（FINAL_KEY_ACCESS_CHECK）。
- 验证不通过记 UNKNOWN，与 v1 一样。只有一个例外：某条查询报 `COMMAND_TIMEOUT` 或 `CHANNEL_FAILED`，而且该次尝试还没写
  `repair-requested.json` 时，主循环计时 30 秒后把整个验证重跑一次。规则如下：
  - 每一跳最多重试一次；等待期间不占检查 worker，设备仍占在途名额；
  - 设备带 `VERIFY_RETRIED` 警告，timeline 记一条 `verify_retry`；
  - 第二次仍失败记 UNKNOWN（`VERIFY_<code>`）；
  - 以下情况都不重试：已请求修复、其他错误码（AUTH_REJECTED、PASSWORD_REJECTED、HOST_KEY_*、OUTPUT_LIMIT 等）、判定不通过、
    ops 没有给出 `repair_requested`（按已请求处理）。

## 5. 防重复下发

- **BUSY**：交换机上还有 `.ibsw-*/runner.sh` 或 `step.sh` 的进程。
- **PREVIOUS_INSTALL_PENDING**：本次开机以来某个步骤目录出现过安装后的标记（`INSTALL_REQUESTED`、`CPLD_BURN`、
  `CPLD_REFRESH`、`IBSW_COMPONENT_STAGE=`、`IBSW_EXPECTED_EFFECT=`）。判断依据：
  - v2 的目录看 `launch.record` 里记录的 boot_id；
  - v1 的目录看 `execution.stdout` 的修改时间是否晚于开机时间。
- 两者都在预检和下发前各查一次，命中就记 REVIEW_REQUIRED，不下发。
- **写前记录**：发出启动命令前先落盘 `dispatch.json`（REQUESTED）。写不成功就停止整批（HOLD）。
- 启动结果不确定时按「可能已启动」处理，进入探测，本次运行内绝不重发。

## 6. 探测（owner 2026-10-23）

- **upgrading Q**：交接后立即 ping，之后每 30 秒一次。一次探测发 3 个包，全丢才算失败；`ping` 本地出错不算重启。
  失败后等 1 分钟进入 rebooting Q（原为 3 分钟；boot_id 没变会回到 upgrading Q，所以提前探测是安全的，见第 11 节）。
  每 2 分钟用 SSH 读 boot_id 和步骤状态：
  - boot_id 变了：立即进入 rebooting Q；
  - 安装前失败：只按白名单判定，见下；
  - 请求安装后返回码非 0：只记警告，继续探测，验证通过仍记 UPGRADED；
  - 主机密钥不符：记 REVIEW_REQUIRED；
  - 密钥被拒：改用密码会话读取，暂不恢复。
- **安装前失败白名单**：
  - 最后一个 `IBSW_STAGE` 属于 PACKAGE_DOWNLOAD、WAIT_DOWNLOAD_RECORD、PACKAGE_READY、IMAGE_FETCH、BIOS_FETCH；
  - 没有 `IBSW_COMPONENT_STAGE=`，也没有 `IBSW_EXPECTED_EFFECT=`；
  - 绑定头和退出记录都吻合。

  只有满足全部条件才记 FAILED（可以重跑）。CPLD 烧写失败永远不算安装前失败。
- **rebooting Q**：每 15 秒 ping → TCP/22 → 同一个 SSH 会话读 boot_id、nvued、`nv show system version`：
  - 连接失败回到 ping；
  - boot_id 没变就回到 upgrading Q；
  - nvued 或 CLI 未就绪，30 秒后重试 SSH 步骤；
  - 密钥被拒用密码会话完成，第 5 步成功后恢复 authorized_keys，并用密钥重新登录确认。
- **上限**（累计、不因反复而重置）：下发到就绪 60 分钟；upgrading Q 30 分钟（REBOOT_NOT_OBSERVED）；
  就绪检查 15 分钟（NVUE_NOT_READY，从重启后第一次报告 nvued/CLI 未就绪的 SSH 检查算起）。超限记 UNKNOWN，
  并继续占用在途名额。就绪检查原为 10 分钟，10-24 的 v1 日志里 57 台次中有 7 台次超过 600 秒、最长 718 秒（见第 11 节），
  所以改为 900 秒；60 分钟和 30 分钟不变。
- **验证时又重启**：放回 rebooting Q，由设备期限兜底。
- 探测状态只在主进程里迁移。探测线程（默认 16 个）只执行动作；每台设备同一时刻只有一个动作，过期结果丢弃。

## 7. 分发（owner 2026-10-23）

- **每台交换机的 HTTP 地址**（owner 2026-10-24）：
  - `common.mgmt.http.address` 可以是一个 IPv4，也可以是 IPv4 列表：Apache 可以在多个地址上监听，每个 ztp-server
    网络一个，这些网络通常互不路由。每个地址按项目合同（`validate_service_endpoint`）校验，重复的去掉；
    本分支不改 01-global 的 schema 和 `project_contract`。
  - 对每台交换机在本机执行 `ip route get <交换机 eth0_ip>`（不带 `from`），取 `dev` 和 `src`。候选是配置的 HTTP
    地址中位于这个出口上的（`ip -o addr show dev <dev>`）：
    - `src` 在候选里就用 `src`；否则只有一个候选就用它（例如 HTTP 地址是这个口的第二地址）；
    - 多个候选而 `src` 不在其中：`HTTP_SERVICE_ADDRESS_AMBIGUOUS`；没有候选（这个网络上没有 HTTP 监听）：
      `HTTP_SERVICE_ADDRESS_NONE`；没有路由：`HTTP_SERVICE_ADDRESS_NO_ROUTE`。
  - 这三种设备只做只读预检（不做 access bootstrap）；需要升级时记 FAILED，原因里写设备名和出口；不写任何东西，
    也绝不改用另一个网络上的地址。不需要升级的照常记 AT_TARGET。
  - 包的 URL 按每台自己的地址拼，端口和路径不变；接力时从 ztp-server 拉的那台也用它自己的地址；`--method scp` 不变。
    v1 的策略读取只接受一个地址，所以列表时先用第一个地址生成 URL，再在取包时换成该设备自己的地址。
  - 入口打印一行 `[HTTP]`：每个出口、所用地址和设备数；没有可用地址的设备各打一行 `[HTTP] WARN`。
    `plan.json` 的 `http` 记下配置的地址和每台的地址、出口、src、原因。
- **速率检测**（`fleet_link`）：
  1. 配置的 HTTP 地址至少要有一个是本机地址，否则按未知处理；不在本机的地址给出警告；
  2. 出口来自上面同一次 `ip route get <交换机>`（不带 `from`）；
  3. 从出口逐层找到物理口：
     - bond：主备模式取主用口；layer2 哈希且经网关时取最慢成员；其他情况把 up 的成员相加；
     - bridge：不读 bridge 自身速率，排除 veth/tap，多个物理成员时查 FDB，查不到取最慢；
     - VLAN/macvlan：取下层接口；
  4. 虚拟机网卡、非以太网、读不到的速率都判为未知。未知按 1G（接力）处理；
  5. 多个出口时按最慢的出口决定（保守）；没有可用 HTTP 地址的设备不下载，它们的出口不参与判定。`[LINK]` 逐个列出
     出口、速率、设备数和所用的 HTTP 地址；某个出口上没有配置的 HTTP 地址时给出警告。
- **分档**：

  | 速率 | 方式 | 错峰窗口 | ztp-server 同时拉取 |
  |---|---|---|---|
  | < 10G 或未知 | 接力 | — | 链路 Gbps 取整（至少 1） |
  | 10G – < 100G | 直拉 | `60 × ceil(N/16)` 秒 | 接口 Gbps × 0.8 |
  | ≥ 100G | 直拉 | `60 × ceil(N/32)` 秒 | 不限 |

  N 是本轮需要这份镜像的设备数，不含金丝雀。窗口上限 3600 秒。`--method scp` 时，从 ztp-server 发起的
  拉取开始时间至少间隔 0.25 秒（sshd `MaxStartups`）。
- **接力**：
  - 每个 OOB leaf 一个队列；没有持有者也没有在途传输时，由一台从 ztp-server 拉；
  - 任何一台校验通过立即成为持有者，每个持有者同时最多供 4 台，新任务派给负载最轻的持有者，优先选没试过的；
  - 失败处理：
    - 接收者最多尝试 3 次；
    - 同一持有者出现 2 次源侧错误就退役；
    - 在任何一次交换机间传输成功之前，若已失败 4 次且涉及至少 2 个源，判为系统性问题，停用交换机间接力，全部改从 ztp-server 拉（熔断）；
  - 某组接收者全部完成后，这组持有者停止接新传输；在途传输结束才放行升级（OS 重启可能清空 `/home/admin`）；
  - P2P 里找不到的设备归入「未知」组，可以从任意未排空的组拿。金丝雀永远不当持有者。
- **交换机之间只用密码**：
  - 密码就是本次运行唯一的 admin 密码，预检时已在每台验证过，经 SSH stdin 交给助手；
  - 源设备的全部主机密钥行写进临时 known_hosts（`StrictHostKeyChecking=yes`）；
  - scp 选项为 `PreferredAuthentications=password,keyboard-interactive`。
- **取包助手**：
  - 每次用唯一的临时文件，size 和 sha256 都对上才改名，已有同 sha256 的文件直接复用；
  - 错误按 source、receiver、unknown 分类，scp 的终端输出只在本地扫描、不回显；
  - HTTP 沿用 v1 的 curl 参数和重试规则：4 次，每次 600 秒。

## 8. 证据与并发

- 运行目录 `xdr-upgrade-v2-logs/<UTC>_upgrade-v2_<32hex>/`（`--project` 时在项目的 `99-output-ib_nvl/bringup/` 下）：
  - `plan.json`、`packages.json`、`events.jsonl`、`run-report.json`；
  - `devices/<主机>/` 下的 `precheck.json`、`access-*.json`、`authorized_keys.before`、`distribution-*.json`、
    `dispatch.json`、`before-<stage>.commands`、`timeline.jsonl`、`verify-<stage>.json`、`repair-*.json`。
- 设备证据由该设备当前的执行者写，每台一把锁，没有跨设备锁；写盘先写临时文件，再 fsync 和改名。
- 运行守卫与 v1、initial-setup 共用 `/tmp/http-ib-bringup.runtime.lock`。
- **汇总里的「MANAGEMENT KEY REJECTED」**（2026-10-24）：预检时管理公钥被拒的设备单独列出，只报告、不写任何东西。
  `run-report.json` 的 `key_rejected` 每台一行，`group` 取值：
  - `NO_INSTALLATION`：不需要安装（AT_TARGET）。不做 access bootstrap，所以公钥没有改，带 `--upgrade` 重跑也不会补上；
    汇总给出 `ssh-copy-id -i <管理公钥> <用户>@<地址>`，或以后的 access 修复工具；
  - `PASSWORD_NOT_TRIED`：没有输入密码（`--plan` 未带 `--password`），密钥被拒后没有密码可回退，预检记 FAILED AUTH_REJECTED；
    汇总提示带 `--password` 重跑；
  - `OTHER`：其余（需要安装的设备由 `--upgrade` 的 access bootstrap 在安装前补上公钥），列出类别。
- 启动时把文件描述符软上限提到 min(硬上限, 4096)。

## 9. 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--plan` / `--upgrade -y` | plan | plan 只读，不写交换机 |
| `--os --bios --cpld --all` | 全部 | 组件 |
| `--server-link` | 自动检测 | 1G…400G |
| `--method http\|scp` | http | 交换机从 ztp-server 拉包的方式 |
| `--in-flight` | 32 | 下发到验证完之间的设备数 |
| `--check-workers` / `--upgrade-workers` / `--probe-workers` | 16 / 8 / 16 | 检查只读 SSH，2026-10-24 起 16；升级 worker 和 `--in-flight` 不提高（同时重启很多 spine 是 fabric 风险） |
| `--relay-fanout` / `--relay-transfers` | 4 / 32 | |
| `--p2p` | 项目里的 p2p.xlsx | OOB 分组来源 |
| `--local-dir` | /home/admin | 交换机上的包和步骤目录 |
| `--progress-seconds` | 30 | 进度块间隔 |

退出码：0 全部完成；3 有未完成；2 HOLD（含预检中密码被拒）或入口的密码 3 次都被拒；75 运行守卫被占用；130 中止。

## 10. 测试

测试域 `fleet-upgrade-v2` 共 9 个模块，全部在本机运行，不连真机：

| 模块 | 内容 |
|---|---|
| `test_fleet_link` | 分档公式；物理口；bond 各模式；带 veth 的 bridge；FDB；VLAN over bond；未知按 1G；多出口；覆盖；多个 HTTP 地址：每台用自己网络上的地址、路由查询不带 from、[LINK] 列出每个出口；单个地址照旧；网络上没有 HTTP 地址、地址不唯一、没有路由都失败关闭；第二地址 |
| `test_fleet_distribution` | P2P 分组；48 台一组四轮且只拉一次服务器；新持有者立即服务；闸门上限与间隔；重试、退役、熔断；排空后放行；直拉错峰与轮转 |
| `test_fleet_probe` | 安装中、首次 ping 失败、两次 ping 之间重启、误判打回不重置停留、各类状态、三个上限（默认 60/30/15 分钟）、v1 日志最慢的 718 秒 NVUE 就绪仍在上限内、过期结果、不重启作业；ping 不通 1 分钟后进入 rebooting Q（停机 70 秒的设备比 3 分钟时早交回，boot_id 未变仍回 upgrading Q 且不交回） |
| `test_fleet_ssh` | 进程内 paramiko 服务端：密钥、密码回退、主机密钥固定（含哈希条目、@revoked）、命令超时、与 v1 规则一致；密码被拒为 PASSWORD_REJECTED（不算类重启），密钥被拒仍为 AUTH_REJECTED |
| `test_fleet_engine` | 中性 Family + 模拟设备群：金丝雀先行、组内接力、持有者服务期间不重启、直拉、在途上限、预检分类、只出计划、写前记录失败 HOLD、停止、不重启作业和两跳；验证超时重试一次（默认 30 秒、等待期间检查池空闲；已请求修复、未说明、其他错误码和判定不通过都不重试；类重启错误仍回 rebooting Q）；预检密码被拒即 HOLD（之后不再启动预检、在跑的跑完、其余 SKIPPED PASSWORD_REJECTED_HOLD、汇总说明、其他预检失败不 HOLD）；检查 worker 默认 16、升级 worker 8、在途 32；汇总的密钥被拒清单（不需安装的给出 ssh-copy-id、没有密码的说明未尝试密码、只报告）；没有 HTTP 地址的设备只读预检、需要升级记 FAILED、不取包不下发 |
| `test_ibsw_v2_device_scripts` | 检查脚本（stdin 执行、读 stdin 的命令吃不掉脚本、步骤目录状态）；取包助手（HTTP 重试、内容不符、空间、目录不安全、scp 只用密码） |
| `test_ibsw_v2_device` | 安装前失败白名单；BUSY/PENDING；规划与渲染；单台模拟交换机从预检到验证（导入密钥、真实 v1 组件脚本和 runner、重启丢密钥后恢复、修复缺失配置、证据无密码）；验证查询超时或通道失败时异常带 `repair_requested`（修复请求前为假、之后为真）；输错密码在任何写入前被拒（回退会话和导入会话两种）、密钥被拒仍回退到密码、探测仍报 auth_fail、密码校验只用密码登录且只跑 `true` |
| `test_ibsw_v2_workflow` | 6 台模拟交换机、1G 接力、两跳 OS、v1 金丝雀规则、不可达与已在目标 |
| `test_ibsw_v2_entry` | `--help`；参数检查；运行守卫；`--plan` 只读；经入口完整升级；证据无密码；输错一次重问后正常升级（错误密码只试一次、只在一台上）；三次都错退出且没碰任何设备；TCP/22 不通的设备不参与校验；没有设备响应时继续并报告不可达；`--check-workers` 默认 16、上限 32；已在目标但密钥被拒的设备在汇总里给出 ssh-copy-id 且公钥未被改动；`--plan` 不带密码时汇总说明未尝试密码；两个网络各一个 HTTP 地址时每台从自己网络的地址下载、路由查询不带 from；所在网络没有 HTTP 地址的设备失败关闭且没有任何写入 |

模拟交换机（`test_cases/ibsw_v2_switch_sim.py`）真实执行检查脚本、取包助手、v1 组件脚本和 owned runner。
`nv`、`curl`、`scp` 等由桩程序代替，安装后会模拟重启、换 boot_id、nvued 稍后就绪。`connector_for(凭据)`
像 sshd 一样核对密码，错误密码返回 PASSWORD_REJECTED，并记录每次密码登录。

## 11. 现场需要确认的事项

- `/home/admin` 在 OS、BIOS、CPLD 重启后是否保留；
- NVOS sshd 用 password 还是 keyboard-interactive；交换机上的 `scp -O` 和 `/usr/bin/python3` 是否可用；
- CPLD 烧写的实际耗时与 30 分钟停留上限的关系（v1 日志的结果见下面的实测）；
- OS 安装后主机密钥是否变化；
- `nv action fetch … file://` 的去向和磁盘需求（预检按镜像大小的 2 倍检查）；
- ztp-server 的实际接口栈与 `[LINK]` 判定是否一致；`--method scp` 时 sshd 的 `MaxStartups`；
- 配了多个 HTTP 地址时，`[HTTP]` 给每台选的地址是否就是它所在网络上 Apache 监听的地址。

### 2026-10-23 v1 现场日志实测

- CPLD 从下发到观察到重启约 11 分钟（三台分别为 674 s、678 s、652 s），30 分钟停留上限够用；
- 重启到 nvued 运行约 80–120 s；nvued 到 NVUE 就绪约 2–4 分钟，10 分钟就绪检查上限够用（10-24 的更大样本推翻了这一条，见下）；
- 下发到就绪约 15 分钟；
- 每台 CPLD 重启后管理公钥都被拒，需要走密码回退并恢复 authorized_keys；
- `/home/admin` 是否保留，日志无法判断，仍待确认。

### 2026-10-24 v1 CPLD 现场日志实测

只记汇总，不记设备名和地址。

- **就绪检查**：从重启后第一次 SSH 连上（WAIT_REBOOT 之后的第一个 CHECK_NVUED）到 NVUE_READY，各轮合计 57 台次：
  中位 152 s，p90 655 s，最长 718 s；超过 600 s 的 7 台（7 台都升级并验证成功），超过 720 s 的 0 台。
  v2 原来的 10 分钟就绪检查会把这 7 台误记 UNKNOWN（NVUE_NOT_READY），所以改为 900 s。
- **下发到 NVUE 就绪**：第一轮 63 台最长 1598 s，第二轮 53 台最长 1479 s，60 分钟设备期限够用；
  CPLD 烧写到 WAIT_REBOOT 最长 672 s，30 分钟停留上限够用。两者都不变。
- **密码**：第一轮升级有 118 台出现 CPLD 步骤记录。v2 原来的预检会在每台需要升级的设备上各开一个密码会话，
  一次输错就是这么多次失败登录；v1 在第一次明确拒绝时停下重问。由此加了入口的密码校验和引擎的 HOLD（第 4 节）。
- **重启后等多久再探测**：WAIT_REBOOT 之后第一次 SSH 连上（第一个 CHECK_NVUED）两轮各 29 台，最早 67 s / 76 s，
  中位 123 s / 114 s。rebooting Q 原来在 ping 不通 3 分钟后才开始，改为 1 分钟；ladder 的 ping 间隔 15 s 不变。
- **检查并发**：v1 这几轮升级都用 `--parallel-limit 16`，预检候选 192 台。v2 的预检和验证都是只读 SSH，
  检查 worker 默认改为 16；升级 worker 8、在途 32 不变。
- **密钥被拒但不需要安装**：最后一轮（没有任何安装任务）第一次预检有 18 台管理公钥被拒，回退的密码也被拒
  （PASSWORD_PREFLIGHT_REJECTED），v1 提示「Attempt 2/3」；重输密码后的第二次预检里这 18 台都通过，说明第一次是输错。
  这些设备不需要安装，v1 和 v2 都不会去补它们的公钥，所以 v2 的汇总单独列出并给出修复方法（第 8 节）。
