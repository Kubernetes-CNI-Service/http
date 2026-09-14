# Ubuntu 22.04/24.04 Docker 管理服务器

Docker generic image 与项目 upload/shared/project-image 制品不是同一个包；完整关系和
`2026-12-vb-gb300` 操作矩阵见
[《四类交付制品与 2026-12 部署流程》](../../docs/deployment/BUNDLE_WORKFLOWS.md)。

本目录把 Apache、ISC DHCP、ZTP monitor、Switch collection worker 和 manual ZTP worker
放在同一个 Ubuntu 24.04 容器，由 Supervisor 管理。支持 `arm64` 与 `amd64`，运行时使用
host network；既不使用 privileged/NET_ADMIN，也不挂载 Docker socket 或 host PID namespace。

这是 Docker/Supervisor 专用生命周期，与 Native/systemd 互斥。同一轮选择本模式后，操作员只
使用 `infra/docker/deploy.sh`；禁止在宿主运行 `11-load.py --start-services`、启用宿主
Apache/ISC DHCP，或使用 `systemctl` 管理容器内服务。`hostctl.py` 内部以 `--skip-infra` 调用
公共 load 逻辑不等于允许宿主手工执行该参数。

宿主既可以是远端管理服务器，也可以是 Mac 上把 USB/UTP adapter 直通后的 Ubuntu VM；两者使用
完全相同的 rootful Linux Docker、host-network、init/deploy/reload-network 合同。macOS 本身和
Docker Desktop 不属于本运行时，Mac 只负责配置准备、全量测试和受控传输。完整位置/后端矩阵见
[`docs/deployment/README.md`](../../docs/deployment/README.md)。

## 边界

- 宿主机负责通过 Netplan 或既有网络管理系统配置物理 NIC、bond、VLAN 和地址。容器只读取
  `ip -d -j link show` 与 `ip -j -4 address show`，不会修改接口。
- DHCP listener 是项目 `02-dhcp-subnet_config.csv`、当前地址和可选安全上限共同推导出的
  0..N 个逻辑接口。每次 dhcpd exec 前再次核对 ifindex、接口名和地址前缀。
- `/var/www/html/.deployment.lock` 是 sync、load、reload-network、unload 和容器管理入口共用的事务锁。
  `hostctl.py` 在同一锁内执行 prepare、继承锁 FD 的 `11-load.py`、服务检查和 activation commit。
- Apache 只监听推导出的 `ztp_service_ip:80`，不会监听 `0.0.0.0` 或所有宿主地址。
- 只有成功 load 且 parent release、当前 global/devices/subnet/P2P/policy、DHCP 配置和服务健康
  全部一致时才写 activation marker。容器重启会重新发现 NIC；输入漂移则保持服务停止。
- activation marker 同时绑定 `ethernet/eth.csv`、`infiniband/ib.csv`、`nvlink/nvsw.csv`、各自
  `monitor/*.csv` 静态 alias，以及三个 collector 的 info/link/cronjob 输出 symlink 的逐级 target
  和最终项目路径；缺失、逃逸、变成普通文件或指向另一项目都会 fail closed。
- Docker 部署分为三层：稳定的 Ubuntu 24.04 infra image、独立发布到 `/var/www/html` 的受测
  upload release，以及宿主持久化的 key/state/log/auth。image contract `3` 把实际安装到
  `/opt/http-ztp` 的控制器和配置、Monitor auth helper、Apache V2 policy、共享 listener planner，
  以及 build-time mutable template 集合视为 image-coupled；这些字节变化必须重建镜像。项目输入
  和其他 live 代码可以比镜像更新，但 live 全树必须先与自己的
  `deployment-source-manifest.json` 逐字节一致，且 `runtime-contract.json` 必须明确兼容 image
  contract `3`。contract `2` 只允许身份匹配的旧容器清理，不能再启动、probe、load、恢复或用来
轮换凭据。这样不能用旧 image 绕过新 release 的完整来源校验，也不再要求每次项目数据或普通
  代码变化都重建基础镜像。

### ZTP Monitor watch 与 PID 边界

Supervisor 启动的 ZTP Monitor 在同一进程内固定 project/scope、setup manifest、active
inventory、current release，以及 `current-release.json`、项目 `01-global.yaml`、
`02-devices_config.csv` 和 active `p2p-air.json` 的字节身份。下一轮前发现任一漂移会永久退出，
由外层生命周期按完整 authority 重新建立进程；这不是跨进程持久 pin。只有明确命名的 runtime
transport 与报告发布故障可在同一进程内重试，最多连续五次。每次失败先写脱敏 unhealthy
sidecar，再从 last-good 报告重建带告警的 `monitor.html`，不会推进 `latest`/报告；成功轮次
清零预算。重复日志限流也仅存在于当前进程，摘要周期为
`max(300, 10 * max(watch, 5))`。

容器 activation 的 PID writer 与 Monitor cleanup 共用持久 sibling
`.ztp-monitor.pid.lock`。锁文件必须是当前 euid 所有、`0600`、single-link regular file，发布和
清理在同一 advisory exclusive lock 内完成；锁永不删除。PID 发布失败会在任何 chown/后续服务
动作前回滚自己的记录；Native writer 还会有界终止并回收已生成的子进程。该边界只保证遵守同一
协议的官方 writer/remover 串行，不声称抵抗绕过锁并直接替换路径的并发 root。

### Monitor cache authority N3 处置

已受损或有缺陷的 `www-data` 可反复放入同一碰撞 contaminant inode；
`same-identity breaker N=1→2→3` 会使 cache 发布 fail closed 并造成可用性拒绝。
`N=3 is not proof of an attacker`，也不是自动修复授权。`automatic repair loops are forbidden`：
日常 provision/deploy/load/health/guardian/CGI 只能 attest 且不清 breaker。取证只保存安全时间戳、
classification、stopped state 和 inode/type/mode/owner/hash metadata；绝不保存 payload、credential 或
Authorization bytes。Native 如需恢复，只能在 Apache 已确认停止后运行
`sudo ./infra/infra-setup.sh --recover-monitor-authority`；Docker 唯一恢复入口是
`sudo ./infra/docker/deploy.sh recover-monitor-authority`，完成后容器仍保持 stopped，只能按其打印的
`sudo ./infra/docker/deploy.sh deploy` 后续指令恢复。操作员必须
`never manually unlink/chmod/rewrite` authority、breaker 或 recovery marker；若再次 wedging，保持
服务停止并调查 `www-data`/CGI，不得盲目重复 recovery。每次隔离验收只做一次 stopped-writer
recovery，并要求 `exactly one fixed warning`；随后重复同一个 N=1→2→3 注入，以证明
`re-wedging remains possible`，而不是把一次恢复误报成永久修复。

## 初次部署

先从项目电脑受控写入：

```bash
python3 tools/tar-for-upload.py <project> <target> --runtime docker --deploy
```

CUX-03：禁止对 live `/var/www/html` 手工执行 `tar`、rsync 或复制覆盖；
`--deploy` 必须通过归档内绑定的 `tools/deployment_prewrite_guard.py` 在共享锁内停止精确受管
容器并提交来源状态。省略 `--runtime` 会按 `native` 处理，不会建立 Docker owner 或执行容器
quiesce，所以 Docker 首次部署和更新都必须显式传 `--runtime docker`。随后由宿主既有网络管理
配置 ZTP 地址。一个 NIC、多个独立 NIC 或同一
trunk 上的 VLAN 子接口都可使用；NIC 数量不写入 global 或 devices CSV。

宿主必须是 Ubuntu 22.04 或 24.04，并已安装本机 rootful Docker 与 `iproute2`（wrapper 使用
`ss` 做端口冲突检查）。无论宿主版本如何，Dockerfile、image contract label 和容器内运行态都
继续固定 Ubuntu 24.04，不能把宿主 22.04 误当成容器 base OS。wrapper 只接受 root 所有的
`/var/run/docker.sock`、`default` context 和 Linux
rootful daemon；`DOCKER_HOST`/非默认 context/TLS remote endpoint 及 rootless daemon 会被
fail closed，避免在未知远端误建、误删同名容器。Compose 插件是可选项；wrapper 在没有
`docker compose` 时自动使用等价的 plain `docker build/run/exec`。

### 固定的 root 管理 SSH identity

Docker 日常管理 SSH 账号固定为宿主 `root`，唯一 host authority 是
`/root/.ssh/id_ed25519` 与 `/root/.ssh/id_ed25519.pub`；容器使用的持久副本固定为
`/var/lib/http-ztp-container/ssh/id_ed25519` 与对应 `.pub`，再只把这个 service 目录 bind 到
容器 `/root/.ssh`。wrapper 不接受用户、HOME、key path 或环境变量 override，也不会挂载整个
宿主 `.ssh` 目录。

`deploy`、`deploy-preloaded`、`deploy-project-preloaded` 和 `load` 会在 deployment lock 内、第一项
容器 lifecycle 写入前 reconcile：两边都不存在时只在 host authority 生成 Ed25519 key 后复制；
一边存在且有效时逐字节复制到缺失侧；两边是同一 identity 时零写入。半对、错误权限/owner/link、
RSA、加密 key、public/private 不匹配或两边 fingerprint 不同都会 fail closed，既不覆盖也不修补。
`doctor` 只执行 read-only `check`；Supervisor 的 `11-load.py` 永不生成 key，且本功能不负责轮换、
吊销或删除 key。

冲突时先停止部署，保留两边 metadata，并通过受信通道分别核对 public-key fingerprint 和来源。
不得手工复制或删除 `id_ed25519`，也不得用 `chmod`、软链接或重建同名文件绕过检查；按批准的
备份/恢复流程确定唯一 authority 后再完整重跑 `doctor` 和部署。upload、sync、generic/project
image 与诊断/evidence 都排除任意大小写的 `.ssh` 目录和 private key 内容，输出只允许 bounded
action 与 fingerprint，不包含 private bytes。

该保证的 trust boundary 是由 `hostlock` 串行化的官方 writer，以及 root:root、`0700`、随机命名的
generation staging 目录。helper 会在 pre-publication、两次 leaf publication 之间和 pre-cleanup
重验 held stage 的 exact set 与 identity。Linux 没有 conditional unlink-by-inode API；因此
non-cooperating concurrent root 在此边界之外：它 already has strictly stronger capabilities，可绕过
hostlock、ptrace/改写 canonical authority、mount 或删除任意文件，最终 stat→unlink nanorace
adds no capability。private mount namespace is not used；不得把本保证误述为能够抵抗恶意
concurrent root。

```bash
cd /var/www/html
# AIR mini simulation：一次生成完整、私有的 runtime 配置
sudo ./infra/docker/deploy.sh init --project <project> --scope air --mini
sudo ./infra/docker/deploy.sh doctor
sudo ./infra/docker/deploy.sh deploy
sudo ./infra/docker/deploy.sh status
```

首次在线：`init → doctor → deploy → status`。`deploy` 已经 build/recreate、执行统一 load、激活并
完成 health-check；成功后不要追加一次重复 `load`。

参数化 `init` 是新部署的首选入口。AIR 自动固定 `switch=eth`；Production 可执行
`sudo ./infra/docker/deploy.sh init --project <project> --scope prod`，默认选择 `switch=all`。
需要收窄平台、调整监控周期或显式限定 DHCP listener 时，可追加 `--switch eth|ib|nvl|all`、
`--monitor-interval`、`--dhcp-interface-allowlist` 或 `--dhcp-relay-ingress`。命令以 mode `0600`
原子创建被 Git/upload/sync 排除的 `infra-runtime.conf`，目标已存在时拒绝覆盖。无参数 `init`
仅保留为兼容入口：复制 neutral template 后仍需人工审核和编辑。

### 旧 `infra-runtime.conf` 迁移

新版 wrapper 在 `doctor`、部署、load、网络重规划和状态检查前都会稳定读取
`infra-runtime.conf`，并要求它是 root:root、mode `0600`、single-link regular file。旧部署若仍是
`0644`，不要删除或覆盖身份不明的配置。先在服务器只读核对类型、所有者、硬链接数和权限：

```bash
sudo stat -c 'type=%F owner=%U:%G links=%h mode=%a' -- \
  /var/www/html/infra/docker/infra-runtime.conf
```

只有输出明确为普通文件、`root:root`、`links=1`，且管理员已经复核现有内容属于本部署时，才执行：

```bash
sudo chmod 0600 -- /var/www/html/infra/docker/infra-runtime.conf
sudo ./infra/docker/deploy.sh doctor
```

若它是软链接、多硬链接、非 root 所有或来源不明，立即停止；保留类型、owner、mode、link count
和 SHA-256 证据，通过批准的备份/迁移流程处理。不要用 `init` 强行替换：`init` 会拒绝覆盖任何
现有目标，避免把另一个部署或并发操作的配置静默改掉。

当交换机当前系统版本必须保留、且本轮只验证和发布配置时，可以显式执行：

```bash
sudo ./infra/docker/deploy.sh deploy --no-upgrade
# 已有与当前 source receipt 精确匹配的 immutable image 时：
sudo ./infra/docker/deploy.sh deploy-preloaded <IMAGE_ID> --no-upgrade
```

`--no-upgrade` 只跳过交换机系统镜像的存在性检查，并把全部 bootstrap 生成为不安装系统镜像；
它不会跳过项目输入、配置生成、DHCP、release、Supervisor、health 或 source/image identity
校验。该参数只属于 `deploy`、`deploy-preloaded` 和 `deploy-project-preloaded` 内置的 load 阶段，
不能传给 `doctor`、`build`、`image-export`、`load`、`reload-network`、`health` 等其他动作。

参数化 `init` 生成的 `infra-runtime.conf` 包含：

```dotenv
HTTP_ZTP_PROJECT=<project>
HTTP_ZTP_SCOPE=air
HTTP_ZTP_SWITCH_SCOPE=eth
HTTP_ZTP_MINI=enabled
HTTP_ZTP_MONITOR_INTERVAL=30
HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=
HTTP_ZTP_DHCP_RELAY_INGRESS=
HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass
TZ=Asia/Shanghai
```

`HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST` 只是安全上限，不是 listener 来源。留空时仍只选择项目数据
与当前 service IP/prefix 精确匹配的接口，不会选择管理口、NAT 口或 Docker bridge。若项目
只有 DHCP-only/relay pool，必须用 `HTTP_ZTP_DHCP_RELAY_INGRESS` 显式列出实际接收 relay
请求的 1..N 个接口；否则 fail closed。两项均接受逗号或空格分隔的逻辑接口名。
`HTTP_ZTP_SCOPE` 同时约束配置生成和 monitor，不能只缩小监控而继续生成另一环境。
`HTTP_ZTP_SWITCH_SCOPE` 可选 `all|eth|ib|nvl`：AIR 只允许 `eth`，Production 未填写时默认
`all`。`HTTP_ZTP_MINI=enabled` 等价于容器内 load 的 `--mini`，只允许 AIR/eth，并使用项目根
固定的 `04-air-mini-devices.txt`；它不会接受容器外任意路径。适合 AIR simulation 的最小配置为：

```dotenv
HTTP_ZTP_SCOPE=air
HTTP_ZTP_SWITCH_SCOPE=eth
HTTP_ZTP_MINI=enabled
```

此时 `hostctl.py` 在同一部署锁内调用的命令包含
`--deployment-scope air --switch eth --mini --ztp-monitor-scope air`；parent release、runtime plan、
activation marker 和 health-check 都绑定这组三项选择，旧的全量/Production 发布不能冒充当前结果。

wrapper 会先把默认值、生成范围、监控间隔和上述接口列表规范化，再以显式环境变量创建容器；Compose
与 plain Docker 使用同一份规范值。

首次启动前，宿主 TCP 80 和 UDP 67 必须空闲。wrapper 只报告冲突，不会擅自停止宿主服务；
确认旧 Apache/ISC DHCP 不再需要后，由管理员在宿主停止它们再重试。

CUX-02：独立 DHCP 生成仅用于开发预览。生产必须由 `deploy.sh deploy`/`deploy-preloaded`
内置的 load，或在没有 source write 且受管容器仍在运行时由 `deploy.sh load`，
让 `hostctl.py` 在同一事务中
绑定 parent/child release、DHCP staging、动态 listener、Apache endpoint 和五个 Supervisor
program；禁止在宿主运行 `systemctl`、复制 `dhcpd.conf` 或单独启动 dhcpd。
当 wrapper 使用单平台 `--switch` 时，内置 load 的 DHCP 子事务只替换该平台的 host 文件；
未选平台文件保持原字节/inode，manifest 仍绑定三族实际声明数与四个输出 hash。候选或 manifest
失败会恢复事务前全部 DHCP 项目输出，不会把空的跨平台 host 文件带入后续 activation。

## 服务器部署场景矩阵

| 场景 | 受支持的 Docker 操作 | 关键边界 |
|---|---|---|
| 首次在线部署 | `init → doctor → deploy → status` | `deploy` 已包含 build、统一 load 和 health |
| 首次离线部署 | 核对 OCI tar/完整 image ID 后执行 `deploy-preloaded <IMAGE_ID> → status` | 不 build/pull，不在成功后重复 `load` |
| AIR mini | 配置 `HTTP_ZTP_SCOPE=air`、`HTTP_ZTP_SWITCH_SCOPE=eth`、`HTTP_ZTP_MINI=enabled` 后 deploy | 只生成 AIR/Ethernet/mini 清单绑定的配置 |
| Production | 配置 `HTTP_ZTP_SCOPE=prod`，按需选择 `all/eth/ib/nvl` 后 deploy | scope、switch scope、release、plan 和 activation 必须一致 |
| 源码或项目输入更新 | `sync-code.py ... --runtime docker` 后重新 `deploy`，或核验新身份链后 `deploy-preloaded` | 项目或源码有写入时禁止 `load` |
| unload/隔离恢复 | 原因已修正、没有 source write 时执行 `load → health → status` | 复用运行中的受管控制容器并重新提交 activation |
| Service IP 换接口 | Service IP 从接口 A 移到接口 B 且网络稳定后执行 `reload-network → health → status` | 只重写动态 listener plan 并重启受管服务；不重新生成项目、YAML 或 DHCP 制品 |
| 宿主或容器重启 | 先执行 `health → status`；自动 resume 不通过时保存证据并按原因选择 `load` 或 deploy | 不复用过期接口快照，不手工拉起单个业务进程 |
| DHCP relay / DHCP-only | 预先配置 `HTTP_ZTP_DHCP_RELAY_INGRESS`，然后 deploy | ingress 必须明确且位于安全接口上限内 |
| 停止并保留数据 | `unload` 保留控制容器；`down` 删除受管容器 | 两者先打印 project/scope/container ID 及删除/保留范围，只接受 literal `yes` 或显式 `--yes`；宿主持久目录保留，foreign container 不会被删除 |

### AIR 拔线模拟：移动 Service IP

这个场景没有项目或源码写入。开始前先保存 `status`、`runtime-plan.json`、当前 dhcpd PID/argv，
并确保 `HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST` 留空，或在最初创建容器前已经同时允许接口 A 与 B。
如果为了加入接口 B 而修改 `infra-runtime.conf`，这是容器运行合同变化，必须重新 `deploy`，不能
在旧容器上执行 `load`。

由 simulation/宿主网络工具把同一个 Service IP 从接口 A 移到接口 B；项目不会修改 NIC 或
Netplan。必须先确认旧接口已没有该地址、新接口只有一个精确地址、接口为 UP、路由已经稳定，
然后执行：

```bash
cd /var/www/html
sudo ./infra/docker/deploy.sh reload-network
sudo ./infra/docker/deploy.sh health
sudo ./infra/docker/deploy.sh status
```

`reload-network` 在共享 deployment lock 内核对现有 image/source、parent release、DHCP、
published runtime 与 activation
authority，确认只有所选 listener 的接口名、ifindex 和 fingerprint 改变后，撤销旧 start authority、
停止旧业务进程并发布新 runtime plan，以接口 B 启动服务。它不运行 `11-load.py`，不重新生成
项目、YAML、DHCP 或 release 制品，也不 build/recreate 容器；完成两阶段 health 后才提交新
activation。rebuild/quarantine/guardian fault、半提交状态、输入或 endpoint/network 集合漂移都
会在写入前阻断，并要求使用相应的 `deploy` 或完整 `load` 恢复路径。
不得运行宿主 `systemctl restart isc-dhcp-server`，不得直接执行 `supervisorctl restart dhcpd`；
这两种做法都会绕过新 runtime plan、listener fingerprint、Apache
endpoint、release 和 activation 的一致性验证。若 Service IP 同时出现在两个接口、接口 B 不在
allowlist、接口 DOWN/tentative 或观察窗口内路由变化，事务会在提交 activation 前 fail closed。

## 日常操作

项目输入或普通源码更新先从项目电脑显式选择 Docker runtime：

```bash
python3 tools/sync-code.py <project> --host <target> --runtime docker
```

Docker tar/sync 成功写入会停止精确受管容器并提交 `stop + rebuild-required` 状态；下一步必须执行
`deploy` 重新 build/recreate。若已有与当前 live 源码身份链匹配且经验证的预加载镜像，则重新执行
`deploy-preloaded <IMAGE_ID>`。不得在 source write 后执行 `load`。
Docker sync 固定使用远端 root rsync receiver；sender 显式保留 archive 的递归、链接、权限、时间
和特殊文件语义，但不发送 owner/group。跨版本命令行不得注入 GNU `--chown`、`--usermap` 或
`--groupmap`，因为 macOS `openrsync` 与 Ubuntu rsync 3.2.x 会把这类 receiver 映射拒绝为重复
user-affecting 选项。传输完成后，同一个 deployment lock holder 只针对当前 source manifest 精确
登记的对象及 manifest 本身执行 no-follow `root:root` 收敛与复核，再发布 source receipt；不会
递归改变远端额外文件。Native sync 保持既有 ownership 行为。不要用手工 `chown -R` 修复混合
来源，旧目标应重新执行一次受控 Docker sync 并核对 source receipt。

```bash
# 仅限没有 source write 且需要重新生成/恢复完整发布（如 unload/隔离恢复）
sudo ./infra/docker/deploy.sh load

# 仅限已激活 generation 的同一 Service IP 换到另一合格接口
sudo ./infra/docker/deploy.sh reload-network

# 检查动态 plan、Supervisor、dhcpd 精确 argv、Apache listener 和 CGI hash
sudo ./infra/docker/deploy.sh health
sudo ./infra/docker/deploy.sh status

# 查看 PID 1/Supervisor 输出；服务文件日志在持久目录
sudo ./infra/docker/deploy.sh logs

# 撤销 load 发布但保留容器控制面
sudo ./infra/docker/deploy.sh unload

# 停服务并删除固定名容器；所有持久数据仍保留
sudo ./infra/docker/deploy.sh down
```

`unload` 与 `down` 无论交互确认还是 `--yes`，都会在首个 Docker/runtime/activation 写入前打印
project、scope、immutable container ID 和精确的 `[DELETE]`/`[RETAIN]` 范围。交互输入只接受逐字节
小写 `yes`；EOF、`YES`、空字符串和带前后空格的输入均取消且零写入。`down` 还会把打印并确认的
container ID 作为 `--expected-owned-id` 交给 hostlock；hostlock 在同一 deployment lock 内、任何
stop/rm/activation clear 之前核对当前容器。确认窗口中 A 被替换为 B 或消失时会 fail closed，B 与
activation 均保留。容器内 `hostctl unload` 继续只由外层已确认入口调用，并向 Native
`13-unload.py` 精确传递一次 `--yes`。

单独的 `load → health/status` 仅用于没有 source write 且受管容器仍在运行，例如 `unload` 后重新
激活或失败/隔离恢复。Service IP 只换接口且现有 generation 仍可信时使用
`reload-network → health/status`。任何 Docker source write 都执行 `deploy` 重新 build/recreate，
或在重新验证预加载镜像身份链后执行 `deploy-preloaded`；成功后只检查 `status`，不要追加 `load`。
build 读取源码的整个时段
也持有同一 deployment lock，避免与 sync 拼出混合镜像。失败事务会删除 activation marker，并尽力停止
全部五个服务；任一停止失败会聚合报错，不能伪装成成功。

`load`、`reload-network`、`health`、`status`、`unload` 和 `doctor` 会先核对 contract-3
managed/HTTP-root labels、唯一精确的 `/var/www/html` RW bind、唯一精确的 `/etc/http-ztp` RO
auth bind 以及当前规范化环境。配置文件与现有容器不一致时必须执行 `deploy` 重建，不能在旧容器
上混用新配置。`logs` 和 `down` 仍可用于恢复；`down` 可在精确身份下清理 contract-2 旧容器，
但不会在其中执行任何代码。所有后续 Docker 操作只使用该次验证取得的 immutable container ID，
不会跟随被复用的名字。

容器把通用 `/tmp` 挂载为 `noexec`。需要交互式密码回退时，Switch collection 只会在入口
预建且校验为 root 所有、`0700` 的 `/run/http-ztp/askpass` 中创建短生命周期
`SSH_ASKPASS` helper；`HTTP_ZTP_ASKPASS_TMPDIR` 是固定运行边界，不应改到 `/tmp` 或持久目录。
单轮秘密只进入 inode 绑定的 `0600` FIFO，`0700` helper 一次读取；helper 文件、argv、环境、
状态和日志都不保存明文密码，FIFO 与 helper 在该次采集结束时按持有的 inode 身份删除。

密码分支还要求 OpenSSH 8.5 或更高版本，并按“项目 + scope + target”在项目
`.ssh-known-hosts` 下持久 pre-pin。首次连接的无秘密 `ssh-keyscan` 属于 TOFU，必须在受信管理网
或带外核对指纹。实际认证使用 `StrictHostKeyChecking=yes`、root-trusted `/usr/bin/printf`
`KnownHostsCommand`、精确 `HostKeyAlgorithms`、`CheckHostIP=no` 和 `UpdateHostKeys=no`；AIR 与
Production 可以使用同一用户名和密码，但不会合并 host-key pin 身份。key-only 分支原有的兼容
策略不变。host key 改变会在 askpass/sudo 之前拒绝，并只给出精确 pin 的唯一修复命令。

Apache、dhcpd 或 worker 异常退出时 Supervisor 会重新进入 image receipt 与 activation/precommit
authority 验证后再恢复；显式的事务 stop 不会触发重启，且清除 authority 后迟到的 restart
也无法进入实际服务。rsyslog 的 `dhcpd.log` 与 `syslog` 每 5 分钟检查一次，达到 20 MiB 后保留
8 代压缩副本；同一策略也覆盖持久 `/var/log/apache2/*.log`，避免持续运行耗尽宿主磁盘。

常驻 runtime guardian 每 10 秒只读检查运行态。普通检查采用“短锁读取 activation generation →
锁外限时完整 health → 短锁确认 generation”，不会让卡住的外部命令长期占用 deployment lock。
连续 3 次失败后，它会在共享锁内执行一次有硬超时的最终复检，仍失败才清除 activation marker、
写入持久 `quarantine.json`，并按 worker → DHCP → Apache 的顺序停止五个
业务服务。guardian 不会停止自身，也不会隐式重新启动已隔离的服务；Docker 源码或项目输入
发生受控写入后必须显式执行 `deploy.sh deploy`（或重新验证后执行 `deploy-preloaded`）；只有
没有 source write 且容器仍在运行时，才以 `deploy.sh load` 恢复 inactive/quarantine。marker 缺失
且五个业务服务都处于安全终态（`STOPPED`/`EXITED`/`FATAL` 且 Supervisor PID 为 0）是正常
inactive 状态，不会触发误告警。锁忙表示另一个合法
事务正在运行，不累计失败；不安全的 lock inode/type 则写入 `guardian-fault.json` 并令容器健康
检查失败。quarantine 不会因瞬时恢复而自动清除，只有新的成功 load 才恢复业务服务。

## 控制 CGI 的安全边界

默认 Apache V2 策略要求访问 `/monitor/monitor.html` 时以 `nvis` 或 `cumulus` 登录。页面和三个
canonical `/monitor/control/*` URL 位于同一 Basic protection path；支持的浏览器在首次成功后
自动复用凭据，后续页面操作不会再次弹出登录框，但服务端仍认证每个控制请求。旧 `/cgi-bin/*`
控制 URL 只保留为旧页面升级窗口的认证兼容入口。same-origin、固定动作和 request ID 是额外
防线，不替代身份认证。

凭据文件在宿主 `/var/lib/http-ztp-container/control-auth` 下持久保存，目录以只读方式挂载到
容器 `/etc/http-ztp`；recreate、preloaded deploy 与 reload-network 都不会重置已轮换记录。轮换
必须持有部署锁并使用宿主入口，秘密只从终端读取：

```bash
sudo ./infra/docker/deploy.sh rotate-auth nvis
sudo ./infra/docker/deploy.sh rotate-auth cumulus
```

`status` 中的 `control_auth.factory_records_active=false` 只表示文件不再逐字节等于 factory records，
不证明两名用户都已轮换。Basic over plain HTTP 仍可被嗅探或重放，因此本合同只适用于隔离、
ACL 保护的可信管理网；它不关闭 TLS/mTLS blocker，也不得暴露到共享网段或 Internet。

Monitor 的 helper-status cache 另存于宿主
`/var/lib/http-ztp-container/monitor-auth`，以读写 bind 固定到容器
`/var/lib/http-ztp-monitor-auth`。它是宿主生命周期状态：load、unload、down、recreate 和
deploy-preloaded 都保留；CGI 只会使用 lifecycle 预置并验证过的固定 root、`status.lock` 和
`monitor-auth` 私有目录，绝不创建或修复这些 authority 对象。该状态不进入 upload/package、
image 或 diagnostics；authority 不安全时容器和 Apache fail closed。

## 持久目录

| 宿主目录 | 容器目录 | 内容 |
|---|---|---|
| `/var/www/html` | `/var/www/html` | upload 项目、公共代码、生成与发布结果 |
| `/var/lib/http-ztp-container/runtime` | `/var/lib/http-ztp` | runtime plan、activation marker |
| `/var/lib/http-ztp-container/control-auth` | `/etc/http-ztp`（只读） | Monitor Basic 用户 bcrypt 状态 |
| `/var/lib/http-ztp-container/monitor-auth` | `/var/lib/http-ztp-monitor-auth`（读写） | 持久 helper-status cache、breaker 与固定锁 authority |
| `/var/lib/http-ztp-container/dhcp-etc` | `/etc/dhcp` | 事务安装后的 DHCP 配置 |
| `/var/lib/http-ztp-container/dhcp-lib` | `/var/lib/dhcp` | leases |
| `/var/lib/http-ztp-container/ssh` | `/root/.ssh` | 管理服务器 SSH identity/known hosts |
| `/var/lib/http-ztp-container/logs` | `/var/log/http-ztp` | Supervisor、DHCP、worker 日志 |
| `/var/lib/http-ztp-container/apache-logs` | `/var/log/apache2` | Apache access/error 日志 |

这些目录互不嵌套，避免 Docker bind mount 遮蔽父目录。真实 `infra-runtime.conf` 被 git、
sync-code 和 tar upload 共同排除；只有无拓扑信息的 `container.env.example` 会传输。

## 构建与离线边界

`deploy.sh build` 默认从本机 Docker cache/registry 取得 `ubuntu:24.04`，并在 build 中通过 APT
安装依赖。完全离线服务器应事先在同架构联网主机从准备上传的同一份源码 build，并用组织批准的
OCI image 传输流程导入；当前仓库的离线 APT 快照尚不能替代 Docker base image 和缺少的
Supervisor 依赖。运行阶段不依赖 Internet。

离线导入必须使用显式的 `deploy-preloaded` 动作和完整 immutable image ID，不能只依赖可被重打标的
image tag。在联网、同架构的可信构建机上，从具备可信
`infra/docker/deployment-source-manifest.json` 的源码树运行（输出目录必须是源码树外的绝对路径，
父目录已存在且目标不得已存在）：

```bash
sudo ./infra/docker/deploy.sh image-export /root/http-ztp-generic-amd64
```

`build-export` 只是 `image-export` 的兼容别名。两者均不读取 `infra-runtime.conf` 或项目输入，
只 build、两次核验 immutable generic image/source contract 并执行 `docker save`；不创建、启动、
停止、load 或激活服务容器。输出目录为 root 私有 `0700`，严格包含：

- `http-ztp-ubuntu-24.04.tar`：稳定 infra image，mode `0600`；
- `image-metadata.json`：image contract、架构、来源 manifest 和完整 image ID，mode `0600`；
- `SHA256SUMS`：上述两份文件的摘要，mode `0600`。

generic bundle 不含 upload archive 或 installer，也不含 switch image/apps/firmware。项目电脑必须
另外使用 `tar-for-upload.py --runtime docker --relay-bundle DIRECTORY` 生成独立 upload release；
按需再用 `package-shared-artifacts.py` 生成 shared bundle。完整四包流程见
[《四类交付制品与 2026-12 部署流程》](../../docs/deployment/BUNDLE_WORKFLOWS.md)。只要 live release
合同兼容且 image-coupled 字节未变，原 immutable generic image 可以复用；coupled 闭包变化时必须
重新 `image-export`。

必须通过批准介质分别复制完整 generic 和 upload 目录，而不是只抄录 tag。目标服务器先逐目录
核对摘要；upload installer 会把自己与归档内副本、source manifest 和 embedded guard 做哈希绑定，
不能从未经验证的归档中先解出自己，也不能手工 `tar` 覆盖 live root：

```bash
cd /path/to/copied-upload-bundle
sha256sum --check SHA256SUMS
sudo python3 ./deploy-upload-archive.py ./PROJECT-upload.tar.gz --runtime docker --verify-only
sudo python3 ./deploy-upload-archive.py ./PROJECT-upload.tar.gz --runtime docker

cd /path/to/copied-generic-image-bundle
sha256sum --check SHA256SUMS
image_id=$(python3 -c 'import json; print(json.load(open("image-metadata.json"))["image_id"])')
sudo docker load --input http-ztp-ubuntu-24.04.tar
sudo docker image inspect "$image_id" >/dev/null
```

随后在已由 installer 受控应用 release 且已完成 `init`/`doctor` 的 `/var/www/html` 执行；项目
archive 可以晚于 image，不要求两个 manifest 摘要相同：

```bash
sudo ./infra/docker/deploy.sh deploy-preloaded \
  "$image_id"
sudo ./infra/docker/deploy.sh status
```

首次离线：`init → doctor → deploy-preloaded <IMAGE_ID> → status`。`deploy-preloaded` 已执行统一
load、激活与 health-check，不能紧接着再次运行 `load`。

目标端的 wrapper 不会 build、pull 或使用 Compose。它先核对宿主/runtime/source authority，创建或
验证持久 auth 状态，再在共享 deployment lock 内只移除身份匹配的旧受管容器；contract-2 仅能走
这条不执行旧容器代码的清理路径。随后才检查完整 image ID、Linux/宿主架构、Ubuntu 24.04 image
contract label 3、Entrypoint/Cmd/root user、工作目录、healthcheck 和固定环境，并使用
`network=none`、read-only rootfs、read-only `/var/www/html` bind 与 `cap-drop=ALL` 的临时容器核对
image-coupled authority；同时独立核对 live `deployment-source-manifest.json` 与 live source tree。
创建新容器前还会再次验证 auth 状态和 runtime compatibility，并始终按该 immutable ID 用 plain
Docker 启动；正式 entrypoint 在启动锁内再执行同一合同。旧容器一旦安全清理，后续 image/probe
失败会保持 inactive 并要求修复后重试，不会复活 contract-2。任一步都不会把同名 foreign
container 当成受管容器，也不会通过 tag 降级继续。

image ID 与源码 receipt 解决的是内容/配置一致性，不替代制品来源认证；tar 仍须使用组织批准的
签名、校验与传输流程。`deploy` 的默认行为保持在线 build，不会隐式采用已加载镜像。

### 离线身份链与断点

每个箭头都要保存上一项的精确摘要/ID，任一不匹配立即停止：

```text
已通过门禁的 image build source
  → image 内 source manifest + contract label 3 → OCI tar SHA-256 + immutable image ID

独立演进的已通过门禁的 live release
  → upload archive SHA-256 + archive source manifest + matching external installer
  → live source manifest自校验 + runtime contract兼容 + image-coupled记录匹配

上述两个独立分支汇合
  → deploy-preloaded probe receipt
  → live source receipt + container ID/labels/binds/platform
  → activation generation + Supervisor/HTTP/DHCP evidence
```

失败重试按 checkpoint 继续：

| 已确认 checkpoint | 重试时保留 | 下一步 |
|---|---|---|
| upload archive/overlay 已验证 | 原归档、manifest、live owner | 不再次覆盖；继续 image 导入或部署 |
| `docker load` 与 image ID 已验证 | immutable image ID | 不再次 load；继续 `deploy-preloaded` |
| probe receipt 已验证 | image ID 与 receipt | 修复下一项身份/运行配置后重试部署 |
| container identity 已验证 | 精确 container ID | 重试原 `deploy`/`deploy-preloaded` 并复核 checkpoint；不手工拼接 load，也不按名称删除或替换 |
| load 已提交 | activation generation | 执行 health、HTTP、重启恢复和证据采集 |

名字、tag、mtime 或调用者自报 hash 都不能代替链中证据。身份不匹配的同名容器是 foreign
container；wrapper 必须拒绝删除，不能用 cleanup 绕过。

构建上下文固定使用仓库根目录。仓库根 `.dockerignore`（legacy builder 使用）必须与
`infra/docker/Dockerfile.dockerignore`（BuildKit 使用）逐字节一致；两者采用先排除全部、再只放行
容器运行闭包的规则，项目、镜像、输出、凭据和宿主运行状态不会进入 build context。upload 包和
`sync-code.py` 都会传输根 `.dockerignore`，因此管理服务器无论使用哪种 builder 都保持同一边界。

## 诊断与恢复

`activate.py plan/status` 与 `healthcheck.py` 全程只读：它们重新规划但不重写 runtime plan 或
Apache 配置，并忽略无关 veth 的增删，只比较所选 listener 的 ifindex/name、MAC、link kind、
VLAN ID、parent、IPv4 prefix、direct/relay/DHCP-only 集合、endpoint、项目与 release
hash、实际 dhcpd argv、Apache listener 和三个 CGI。发生故障时先保存：

```bash
sudo docker inspect http-ztp
sudo docker logs --tail 300 http-ztp
sudo cat /var/lib/http-ztp-container/runtime/runtime-plan.json
sudo cat /var/lib/http-ztp-container/runtime/quarantine.json 2>/dev/null || true
sudo cat /var/lib/http-ztp-container/runtime/guardian-fault.json 2>/dev/null || true
sudo tail -n 300 /var/lib/http-ztp-container/logs/dhcpd.log
```

不要用 `--privileged`、NET_ADMIN 或手工追加 dhcpd 接口来绕过 planner。仅把同一 Service IP
移到另一合格接口、没有 source write 且当前 activation 仍可信时，执行
`deploy.sh reload-network`；需要完整恢复受管发布时执行 `deploy.sh load`。项目输入或
源码写入后必须执行 `deploy.sh deploy`（或重新验证后执行 `deploy-preloaded`），让完整事务重新验证并激活。

## 验收边界

本地 contract/mock 通过只证明静态协议。Ubuntu VM 还必须保存 OCI/upload 身份、真实
`docker load`、container labels/binds/platform、动态 listener、Supervisor 五个业务 program、
HTTP 公开/拒绝矩阵、容器重启前后同一 activation generation 与日志 append delta。只有物理
环境才能证明 host-network DHCP DORA、交换机平台 option、MAC/hostname/scope 身份、YAML apply
receipt 和设备重启闭环。未实际执行的层级不得写成 PASS；对应案例见
`test_cases/REAL_ENVIRONMENT.md`。
