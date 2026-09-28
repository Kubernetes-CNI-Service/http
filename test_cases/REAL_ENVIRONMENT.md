# Real-environment acceptance cases

这里保存不能在本机隔离测试中安全、真实地完成的验收案例。它们不是自动化回归的替代品；
对应解析、事务和失败分支仍应在 `test_*.py` 中使用 fixture 自动覆盖。

四类 bundle 的边界和 `2026-12-vb-gb300` 场景选择见
[《四类交付制品与 2026-12 部署流程》](../docs/deployment/BUNDLE_WORKFLOWS.md)；下面只登记必须在
Ubuntu、Docker、adapter、网络隔离或真实设备上取得的证据。

## TC-REAL-RUNNER-PREFLIGHT-001 — 操作系统 loopback 限制与选测早拒绝

- 类型：scenario / real-environment；对应 PF1–4；完整真实 OS 矩阵是 macOS 与 Linux 各自一份
  loopback 允许证据和一份拒绝证据；单一 OS 的两种权限状态不能关闭另一 OS 的行。
- Status: OPEN / NOT RUN（真实 sandbox/namespace 权限切换；合成 audit-hook 拒绝不冒充 OS 证据）。
- 自动化：`test_runner_preflight.py`，固定历史 Git blob、真实 throwaway Git 和 runner CLI，
  clean/staged/unstaged/untracked/ledger-only、Git 失败、bind 成功/拒绝/关闭、只读/suite/fallback/watch。
- 风险与目标：防止长测试运行后才发现必需的 loopback 权限缺失；涉及 runner → shared authority →
  unittest → ledger 边界。不连接设备、远端、生产服务；不创建持久 listener 或 sshd。
- 前置条件：双方绑定的已审阅干净候选、受管 Python/依赖环境、独立临时 clone；记录候选/测试/
  manifest/ledger SHA256。由操作员提供一份拒绝 AF_INET bind 和一份允许 loopback 的本机环境，
  不修改生产防火墙或全局安全策略；不得用 skip/force、ledger-only 例外或削弱断言代替。
- 步骤：分别在两种环境对相同候选执行 `--suite ztp-runtime --preflight`；记录完整 argv、平台/
  sandbox 身份、exit/stdout/stderr。拒绝环境再执行该 suite 的实际 runner；必须在 unittest 子进程
  出现前报 EFF E-1。对 `--list-suites`、`--all --list`、`--check --require-full` 记录无新增 bind。
- 预期与证据：允许环境只完成一次 `127.0.0.1:0` AF_INET/TCP bind 后关闭；预检不启动测试，
  ledger 前后逐字节一致。拒绝环境退出 2、明确 scoped rerun，不算通过/skip；子进程与 socket
  观察证据由本机外部观察器提供。check 的原证明结果独立保留；能力通过不能关闭 full/check、H 或 R2。
- linked-worktree 行：在真实 `git worktree` 运行会以独立 EFF E-3 要求回到 main checkout；不把
  authority 的 `.git/index` 合同改写为 linked-worktree 支持，也不以此结果冒充 clean PASS。
- 故障注入与清理：分别使用 OS 权限拒绝与允许，不连接/监听；检查探针 FD 无残留，仅清理本案
  自建临时 clone、外部观察记录与缓存。保留哈希绑定证据；重复执行不改变源码或批准文件。

## TC-REAL-IMAGE-CONTEXT-001 — 镜像 COPY 成员与物理树拒绝边界

- 类型：integration / real-environment；对应 IMAGE-CONTEXT-SAFETY H1–H4 / AM-1–AM-9。
- Status: OPEN / NOT RUN（legacy builder、Ubuntu 双架构正式镜像；本机最小合成 BuildKit 证据另记，不能代替准入）。
- 自动化：`test_image_context_safety.py` 独立 literal ALLOWED controls、producer 表驱动的 runtime
  fixture（与实际 setup/activation 消费者核对）、镜像专用 physical guard、
  Dockerfile → activate CLI、live 项目允许、preloaded 内嵌树检查。禁止从实现选择结果生成预期。
- 前置：只允许专用本机 Docker context 的 Unix socket 与内建 docker driver；权限不足、远端
  context、缺少 buildx 必须失败，不回退真实仓库构建。不得提供私钥、项目输入或生产目录。
- 本机步骤：显式执行 `HTTP_TEST_SYNTHETIC_DOCKER=1 python3 -B -m unittest -v
  test_cases.test_image_context_safety.SyntheticDockerMembershipTests`。测试临时生成无害文件名
  marker，分别读取三份 ignore 规则；每份各测试全部声明运行时绑定的普通文件、指向合成
  项目的 resolving symlink 和 dangling symlink 三种形态，名字/目标字符串来自 producer
  表，不读取 live project/target 内容。同时放入模板 `99-output*`、lock、history、多层/
  混合大小写凭据与空 `.ssh`、`*-sample`、日志/状态子树。
  generated 边界：同一 image-only host-state 词表驱动 ignore 和 gate；`.setup_manifest`、
  container/desired/runtime state、DHCP hosts、monitor/monitor.html、REFERENCE_ONLY_SUBTREES
  及 zip 均拒绝。named 子树入口和后代均拒绝，中性父目录不算 manifest 成员；无项目身份
  的空 `__pycache__` 壳是 directory-only residual，文件/链接不能借后缀不入选而获豁免。
  真实 package helper → activate 生成该合成 live tree 的 manifest；外置 Dockerfile 仅
  `FROM scratch` 和 `COPY . /`。本地输出 terminal（文件/软链接对象，不含目录壳）扣除
  唯一载体 `infra/docker/deployment-source-manifest.json` 后，必须同时精确等于 package
  manifest 的路径集合与独立 ALLOWED；空 `.ssh` 及所有 named 禁止子树入口也不得保留。
  随后真实 activate CLI
  必须通过 physical + manifest 检查，且 manifest 字节不变。任一额外成员都失败。
  BuildKit 专用 ignore 分支故意把 root ignore 设置为全排除，验证专用文件确实生效。
- legacy：在支持 legacy builder 的专用本机复用同一合成目录与两份 root ignore 副本；使用
  `DOCKER_BUILDKIT=0`，记录 builder/engine/OS/架构、构建及导出退出码和实际成员清单。
  不支持 legacy 的新引擎不是 PASS；不得为验证它而改宿主配置或降级 Docker。
- 正式 Ubuntu：经授权的干净公开 source tree 构建必须通过镜像专用 gate；另在合成镜像树中
  加入 manifest 未列出的项目目录或凭据名，要求 physical gate 在 live 比较之前拒绝。
  live 同路径中合法 DAY0 项目不能被 image-only 规则误拒绝。两架构、镜像/source exact digest
  及验证日志必须独立绑定；本机合成 COPY 不证明正式依赖安装、服务或真实设备工作。
- 证据：完整命令/退出码、三份 ignore 与 candidate SHA256、输入 literal 清单、实际导出清单、
  engine/buildx/平台身份、拒绝与正向结果。默认 unittest skip 明确是未执行，不是准入证据。
- 历史本机记录（2026-09-17；仅旧 clean-shaped fixture，不证明上述 live-shaped 矩阵）：
  Docker Desktop Engine 29.4.2，buildx v0.33.0-desktop.1，内建
  docker driver / BuildKit v0.29.0，Unix socket context `desktop-linux`；三个合成上下文的
  精确文件成员断言通过（1 test / 3 subtests）。原始证据由双日志绑定，不作为 legacy、Ubuntu
  双架构正式镜像或服务准入 PASS。上下文名选择错误、inspect 不支持 format 的两次前置失败
  已单独保留，未放宽任何文件成员断言。
- 历史本机修订记录（2026-09-18；仅旧 17 路径 fixture，不证明 producer 完整性或 AM-7–AM-9）：
  独立 17 路径普通文件/软链接矩阵共六组，真实 COPY 成员与
  导出树 physical + manifest 校验均通过。首次发现 `finished-history/**` 留下空目录导致
  六组 gate 拒绝；补充目录本身拒绝后重跑，保留失败与成功原始日志。
  大小写 marker 使用不同父目录，先断言全部 75 个 literal 输入真实存在，防止 macOS
  大小写别名合并；该 fixture 断言曾复现 75 对 71 的碰撞，修正后须重新测量 COPY。
  最终矩阵证据不关闭
  legacy、Ubuntu 双架构正式镜像或生产服务门禁，exact candidate 与证据 hash 由双日志绑定。
- 清理/风险：临时上下文和 local export 由 TemporaryDirectory 回收；不启动容器、不打业务 tag、
  不使用网络。可能留下本机仅含合成 marker 的 build cache；不得执行全局 prune。
  历史 image/export 的潜在污染仍待逐对象清点，任何重建、删除或撤回另需精确授权。

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

## TC-REAL-REQ10B-DAY0-KEYS-001 — Day-0 服务与公钥的真实管理边界

- 类型：scenario / real-environment；对应需求 10B.5–10B.8、10B.11 及 B10-8。状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。这张卡只登记 owner AIR/prod 验证阶段需要取得的证据；本卡、离线 direct/workflow 通过或草稿本身均不授权现在连接、配置、重置任何设备、服务、Docker 或生产环境。
- 自动化先决：当前 exact candidate 的 `test_req10b_services_keys_contract.py`、`test_req10b_services_keys_workflow.py`、`test_req10b_global_link_contract.py`、`test_req10b_global_link_workflow.py` 和完整 manifest 映射已通过 Codex 落地整树 full/check；Claude 后续在逐字节未变整树上的 `--no-approve` full 已通过。真实测试不代替这些门禁。记录 HEAD/tree、全受管路径清单与摘要、平台/Python/NVOS 版本、命令选择、两轮 full 证明身份，不以旧候选或项目目录名代替逐字节绑定。
- 风险与目标：证明项目切换时 setup/unsetup 的两层 IB 公钥链接不会遗留旧项目 key，管理端 P1 生成的 v4 target cache 对每把 key 的内容、指纹和来源有约束；OOB Leaf 上的 Ethernet P2 不需要 PyYAML、`01-global.yaml` 或 `ssh-keygen`；真实 `NestedResponder` 只安装到目标 IB 的 `authorized_keys`，不改写项目 `mgmt-server.pub` 或笔记本 key，也不把单把私钥的回连结果冒称所有 key 可回连。
- 前置条件：owner 对**精确**隔离 AIR simulation 或可恢复的测试交换机、管理服务器、OOB Leaf、目标 IB、项目输入快照及操作窗口另行书面 go；不得默认指向生产设备。先冻结设备身份、当前管理连通性、`nv config show -o commands`、IB `~/.ssh` 和 `authorized_keys` 的安全元数据/指纹、setup manifest、两层链接 `lstat/readlink`、target cache 元数据、审计日志与恢复点。使用本案临时生成的管理和笔记本测试 key；私钥只留在各自受控主机，原始私钥、公钥全文、完整 cache 和 `authorized_keys` 不回传，只回传允许的 SHA-256/SSH 指纹、mode、owner、计数及脱敏差异。事前确认独立恢复路径、保留现有登录方式与断连回退责任人；不满足即 BLOCKED，不尝试破坏性负例。
- 正向步骤 1（setup/切换）：在已授权的测试项目 A 中经正式 load/`01-a-setup.py` 注入、发布非空 `laptop.pub`、`mgmt-server.pub` 与一把额外 `.pub`，保留一个 0 字节占位。记录 `ztp/config/publickey` 与 `infiniband/publickey` 中同名链接的来源、目标和 manifest；`infiniband/bringup/xdr-initial-setup/publickey` 必须是 Git 跟踪的相对桥 `../../publickey`。切到独立项目 B（不同 key 集）后，两处 setup 托管目录都只保留 B 的非空 key 链接，A 的过期链接消失；运维自建普通文件/非本轮托管对象保持原样。缺少一级项目链接或公钥时，公钥阶段明确记 skipped，不妨碍合法 Day-0/服务阶段。只读确认 `mgmt-server.pub` 仍由 load 准备、initial-setup 未写该项目文件。
- 正向步骤 2（P1/cache）：在管理端通过受支持入口生成 v4 target cache；逐个源 `.pub` 以独立 `ssh-keygen -l` 校验其**每一行**，再比较 cache 中的 key 内容摘要/指纹与冻结源，不回传 key 全文。替换或新增任一 `.pub`（在隔离测试项目）后，证明旧 cache 被判 stale 并重建，目标只得到新 key 集；0 字节、格式坏、混合一条有效加一条 `ssh-keygen` 无效的 key，以及旧版本/篡改 cache，均须在任何 IB 授权文件写入前拒绝或明确跳过，不能借另一行有效而通过。删除 `01-global.yaml` 只使服务阶段按合同跳过，不使 Day-0 或可用公钥安装崩溃。
- 正向步骤 3（真实 P2/安装）：在已授权隔离 OOB Leaf 使用由管理端生成并验证的 v4 cache 走真实 Ethernet P2；该叶无项目 `01-global.yaml`、PyYAML 和 `ssh-keygen` 可用时仍须按 cache 完成受支持服务命令与 key 安装，且以受控命令审计证明确实未调用 `ssh-keygen`（不能仅凭 PATH 声称未调用）。对一台已完成 Day-0 的 IB 重跑：Day-0 不重写，服务阶段仍补齐缺失的 DNS/NTP/timezone；服务阶段作为独立 apply/save 事务，失败仅记该设备并继续其他设备，且不回滚已生效的 Day-0 地址/hostname。对全清/仅服务项清除两种恢复状态分别留证；设备差异值按 B10-9 只报告，不以 `--force` 覆盖。真实 `NestedResponder` 进入正确 IB 用户会话，把两把固定 key 和额外 key 按 key identity 装入 `authorized_keys`，`.ssh` 为 0700、文件为 0600、既有未知行/注释/选项保留。重复运行和只改注释不得产生重复 identity；原子发布中断不得留下部分文件或临时文件。
- 验证边界：只有本机确有对应私钥的管理 key 可从管理服务器执行真实纯公钥回连并比较目标身份；笔记本 key 与其他无本地私钥的 key 只能判“已安装、未验证”，除非 owner 另在持有其私钥的主机明确授权独立回连。不得为做验证复制笔记本私钥到管理服务器、OOB Leaf、cache、日志或证据包。连接失败、错误目标身份、未按 identity 去重、权限错误或原有授权行丢失均 FAIL/BLOCKED，不得用报告文本降格为 PASS。
- 负例及恢复：在隔离项目分别测试错项目链接、悬空/恶意链接、普通文件占位、旧 key 残留、cache 摘要/版本/源 mtime 不匹配、单行坏 key、IB 登录中断、`authorized_keys` stage/rename 故障及重复运行；每一例保存操作前后允许的文件身份/摘要、命令退出码、设备身份和事务日志，证明错误时不改写其他项目、其他设备或既有授权文件。不得对生产 key 或真实保留登录路径注入故障。最后以正式 `02-unsetup.py`/受支持恢复流程清理本案 setup 托管两侧链接和测试 key，保留运维自建对象；逐项复核 manifest、cache、IB 授权文件、设备配置、连通性和恢复点。无法确认恢复则保留隔离并报告 BLOCKED，不做盲目删除。
- 判定与证据：分别列出 setup双目录、cache P1、Ethernet P2、真实 NestedResponder、管理私钥回连、笔记本安装但未验证、负例、unsetup/恢复的 PASS/FAIL/NOT RUN；任一子项未运行不得汇总整卡 PASS。保存完整 argv/exit、脱敏 stdout/stderr、时间线、前后 SHA-256/SSH 指纹和权限、设备/NVOS/平台身份、cache 版本、源和目标项目绑定、独立见证签名；不保存密钥材料。此卡不关闭 AIR/prod 其他服务、ZTP、Docker、H、F01 或 release 门禁。

## TC-REAL-REQ10C-AUTO-001 — 自动部署与同 UID crontab 静默验证

- Type: real-environment / owner-authorized isolated AIR-management validation; requirement REQ10C §10C.1–10C.9, dependent on REQ10B key/service stage.
- Status: OPEN / NOT RUN. Hermetic tests do not satisfy real cron UID, OOB Leaf, or IB device claims.
- Risk: `--auto` can install a 10-minute user crontab and retain `auto.env` containing credentials; it can modify a test IB switch and OOB Leaf. Never run against production or uncontrolled user crontab.
- Preconditions: owner explicitly selects an isolated management host, test project, OOB Leaf and IB devices; records authorized user/uid, rollback access, exact CSV/P2P hashes, current device states, and a protected evidence directory. First confirm the landed whole-tree Codex and same-byte Claude validation-only full proofs plus the local REQ10B stage tests. For AIR/prod validation only, the owner-authorized ISSUE-0016 exception may show exactly three executed FAILs in the non-cooperating same-UID writer tests; all other failures/errors/new skips or a missing/stale validation-only full proof STOP. This exception does not assert concurrent crontab safety or authorize final production publication. The **real** REQ10B service/key stage remains part of this owner-run validation, not a pre-validated fact. Preserve initial user crontab, project state, device config, and credential-file metadata without copying secret values into evidence. One intentionally foreign crontab line is preserved as a negative control.
- Same-user crontab writer exclusion: before **each** REQ10C install, unattended auto-removal, and `02-unsetup.py` cleanup, inventory every other process, automation, service, and operator session that can invoke `crontab` for the same UID. For an unattended run, keep the external exclusion continuously in force from enrollment until its auto-removal completes; a one-time check at setup cannot witness an unknown future cleanup instant. Record writer owners, identities, quiescence start, and a witness that their crontab **writes remain fully silent for every entire read–modify–write interval**; keep the exclusion in force through the final `crontab -` completion and before/after byte comparison. The project-owned `auto-crontab.lock` only serializes this project's three operations and cannot exclude noncooperating writers. If any other writer cannot be held silent, becomes active, or its state is unknown, STOP before the operation (or mark an in-flight result unproven and preserve evidence); do not infer exclusivity from a second `crontab -l` read or a post-write check. For the unattended mode, release the external exclusion only after the final auto-removal and foreign-entry comparison are recorded; for separately authorized unsetup, release it only after that cleanup transaction and comparison.
- Positive sequence: first interactive `--auto` handles currently ready IB; if all CSV IB are already configured it exits without cron or secret file. Otherwise it prints forced-password-change and credential-retention warnings, installs exactly one own `*/10` line under the invoking UID and creates one owner-only `0600` `auto.env`. During subsequent no-TTY invocation, a newly available OOB Leaf is key-installed using its first-login password; later logins prefer key and use the authorized password fallback only on key failure. An IB device becoming reachable is configured Day-0, then services, then key; every round takes fresh OOB interface/network and candidate/cache provenance. When all CSV IB are configured, only the own cron line and own `auto.env` are removed, foreign crontab entries and unrelated files remain unchanged.
- Fail-closed sequence: inject symlink/hardlink/wrong-owner/world-readable/oversized/duplicate/unknown-key `auto.env`; each stops before network or device mutation. Inject one transient port/key failure (later round retries) and one partial/terminal Day-0 state (same input does not repeat unsafe mutation; changed CSV/P2P bytes trigger re-evaluation). Launch two overlapping rounds and prove one cannot perform any device operation while the other holds the lock. Induce crontab write/cleanup failure and prove visible non-success with recoverable owned state. Inject no valid `O_NOFOLLOW`/`O_CLOEXEC` support only in the hermetic environment, because changing a real host's OS flags is not a safe physical action.
- Evidence: exact command/exit-time/PID/uid, redacted stdout/stderr and cron log with no secret values, before/after `crontab -l` byte hashes and own-line count, the three separate same-user writer-inventory/quiescence/restore receipts, `auto.env` `lstat` type/mode/uid/nlink/size/hash only, CSV/P2P and cache origin hashes, OOB/IB nonsecret fingerprints and config diffs, stage-order receipt, lock contention trace, negative-control foreign-entry byte equality, clean-up receipt. Bind each to the same landed candidate and selected device identities.
- Cleanup: stop own watcher and remove only the own crontab entry; invoke real `02-unsetup.py` scoped to the test project, verify owned state deletion and foreign retention; restore isolated device config and original crontab from the protected baseline; destroy test credential file without publishing its contents. Any cleanup failure remains OPEN and blocks validation.
- Automated coverage intended: REQ10C direct `test_req10c_auto_contract.py` plus multi-real-script `test_req10c_auto_workflow.py`; candidate direct/workflow tests are locally ported; exact landed full proofs and owner real-environment execution remain OPEN.

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
- 手工操作回执的目录重绑定验证仍为 **OPEN / NOT RUN**：仅在隔离 0700 项目副本和
  同账号测试写者可完全静默的前提下，记录 `manual-ztp.py`、`12-ztp-monitor.py`、
  `result.json` 及父目录的 inode/SHA256；在回执临时文件刷盘后、发布前把该 run 目录
  改名并将原路径重绑定到隔离攻击目录。预期发布 fail closed，攻击目录没有正式
  `result.json`，monitor 不将其计为新一轮；正常回执仍可被 monitor 读取。
  保存命令、退出码、目录链与 monitor 输出；只清理本案私有副本，不触碰当前项目、
  真实设备或生产回执。风险是服务侧可能把错误回执当成真实手工操作结果。

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

## TC-REAL-AIR-FW-PORTS-001 — 动态 AIR 防火墙端口启动策略

- 状态：**NOT RUN / REAL_ENV REQUIRED**。准备一次性 AIR VM，节点名至少覆盖 `fw-01-north`、
  一个非防火墙 `myfwbox` 和一个零 `swp` 防火墙；P2P 拓扑由受管导入流程生成，保存 CSV、P2P、
  AIR JSON/DOT 与 effective default 的 size/SHA-256，不连接 Production 数据面。
- 步骤与预期：对 `fw-01-north` 配置两个实际 `swp` 链路，执行正式 AIR 生成与发布，确认最终
  NVUE 配置仅为 effective default、hostname 及这两个端口的 `type: swp`/`link.state.up`；零端口
  防火墙无接口片段，`myfwbox` 不被识别为防火墙。随后分别加入 splitter/breakout、重复端口和无效
  端口名，必须在 staging 发布前 fail closed；显式非 `fw` CSV template 必须按模板分派而不因名称覆盖。
- 单端链路（REQ-2 / REQ-14 依赖修复）：用真实 P2P producer 生成一个 `swp` 对
  `unconnected`，以及 ZTP server 对 `outbound` 的链路；固定 AIR JSON size/SHA256 后执行
  consumer。前者仍须生成该真实端口的 `type: swp`/`link.state.up`，后者不能合成交换机或
  ZTP server YAML；未知标记或双 sentinel 必须失败。离线 direct/workflow PASS 不替代 VM
  内应用后的 link-state 验证。与 9/10 历史发布比较时单列 REQ-2 接口策略差异，不混入 REQ-14。
- 证据、清理与风险：保存脱敏 generator/publisher 输出、air-config-manifest、最终 YAML hash、VM 内
  `nv config show` 与端口 link-state；不得保存凭据或真实 Production 地址。负例后从 VM 快照恢复并销毁
  staging/release。错误地启动未声明端口可能改变仿真连通性，只允许在隔离 AIR VM 验证。

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
  各自进入 10 分钟冷却，且一个冷却不会阻断另一类型。分别给“持续收集”和“持续备份”设置各自
  范围内的不同周期并启用；两者必须独立等待自己的同类型冷却，然后可以并行产生新的 Switch
  归档和 YAML backup，随后各自进入下一轮 scheduled。持续收集只接受 10–240 分钟，持续备份只接受
  60–1440 分钟，且两条车道的默认值分别等于 10 与 60。确认四个按钮的解释与按钮相邻：手工项
  为“单次执行；开始后不可中断”，持续项为“周期执行；停止只取消后续轮次”。两个手工按钮在
  点击后均显示运行中且不可用，直到各自任务收口；不得出现手工停止动作。
- 周期 authority 与边界证据：分别在 Native 服务和 container worker 中记录实际加载的
  `<HTTP_ROOT>/tools/project_contract.py` 路径、owner、mode、size/SHA-256，并证明 worker 消费其
  `MIN_CONTINUOUS_INTERVAL_MINUTES`、`MAX_CONTINUOUS_INTERVAL_MINUTES` 及由它们乘 6 导出的备份边界，
  不存在本地 fallback。分别实测收集 9、10、240、241 与备份 59、60、1440、1441：边界外 fail
  closed，边界值接受并精确转换为分钟乘 60；同时证明 CGI、worker 与生成页面消费/渲染同一 authority，
  页面 JavaScript 依据各自输入框的已渲染 min/max 校验，而非共享 10–1440 字面量；同时证明
  `switch_collection_gate.py` 的 collection cooldown、worker 的 YAML backup cooldown 和这个
  admission floor 是三个独立量，不能互相派生或共享状态。
- 互斥与安全证据：持续模式只禁用同类型手工按钮。直接构造同类型的同源 POST 必须返回 409，
  跨类型 POST 必须仍可下发。记录 collector argv、`/proc/<pid>/environ`、worker 状态/日志和 Unix socket
  元数据，确认密码不在 worker/collector argv、任何子进程 environment、状态文件、日志
  或 HTTP 响应中；单轮 SSH 密码只进入 inode 绑定的 `0600` FIFO，askpass 环境只含 FIFO
  路径和 inode 身份。证据不保存 POST body、FIFO payload 或任何子进程 environment 原文。
  收集时间间隔 9、241、备份时间间隔 59、1441，以及 0、非数字、重复字段、超长/换行密码都必须
  fail closed。
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

## TC-REAL-MONITOR-AUTH-HELPER-PIN-TRANSITION-001 — 控制凭据 helper 的 pin 升级与回滚

- 状态：**NOT RUN / REAL_ENV REQUIRED**。只在 owner 批准的隔离、可回滚 Ubuntu Native 与
  Docker contract-3 管理 VM 执行；本机单元与 workflow 不能证明安装过渡期的服务状态。
- 前置条件：绑定候选 HEAD/tree、完整交付包和已安装包身份，并独立计算
  `tools/control-auth.py` 的 SHA-256。旧包 helper/pin 为
  `5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038`；新包 helper/pin 为
  `f5cea5266ab808250b718250a8a73d7d6f6452a199b97fa500643d7ed9e988db`。
  同时留存五处生产 pin 的脱敏位置/值、现有服务健康状态和 auth 文件的
  inode/hash/mode/owner；不得记录密码、Authorization 或 auth 文件内容。
- 步骤：先停止外部控制流量并冻结并发安装/部署，在 VM 快照的隔离副本分别制造“旧 helper +
  新 pin”和“新 helper + 旧 pin”两种 mixed-version 组合。确认 Native load/setup/teardown、
  Docker activate 与 Monitor control CGI 各自的真实 hash 门禁拒绝不匹配组合，不能靠动态计算
  helper hash、改写 pin、禁用验证或复制 auth 文件跨越拒绝。恢复快照后，仅以已批准的完整
  交付/部署事务一起安装新 helper 与五处新 pin；重新计算已安装 helper SHA，验证
  validate/status、Native 与 Docker 启动/控制入口和已轮换凭据仍保持原有语义。
- 回滚与判据：对新包启动/健康失败只恢复**整份旧包及其旧 pin**或 VM 快照，绝不单独回滚
  helper 或某一个消费点；若恢复后的 helper/pin 仍不一致，服务保持安全停止并标记 BLOCKED。
  auth 文件不是代码回滚对象，不复制、不覆盖、不 chmod；通过只读 validate/status 和原有
  凭据的脱敏状态证明其身份与权限连续。保存 exact 版本/hash、五处拒绝/通过结果、服务状态、
  回滚时间线及清理后快照身份；清理仅限隔离 VM 和脱敏证据。未实测升级、两种拒绝与回滚
  不得宣称本案例通过，更不能将其用于生产首测。

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
- PK1 清理完成：在同一 disposable Linux root fixture 上保留原 held-pipe 子进程断言，固定重复
  100 次并保存全部结果。启动前要求 SIGCHLD=SIG_DFL，helper 是私有 Popen 的 sole reaper；不得
  自行改变 disposition。Linux WEXITED|WNOWAIT|WNOHANG waitid 在同一期限内观察退出，不能
  poll/wait/communicate/waitpid 提前回收锚点；缺少平台接口在启动前拒绝。增加真实 same-session
  晚加入子进程：kill#1 后、未回收锚点仍在时加入 leader group，确认 kill#2 真正终止它，之后才 wait。
  保存两个组信号、非回收退出事件、reap、最终 signal0 ESRCH 的顺序证据。macOS 对照还验证
  kqueue 的 exact ident/filter/EV_ERROR 与晚注册 ESRCH+正向 PID0 锚点，以及 zombie-only 组
  kill#2 返回 EPERM 后仍须完成 reap+ESRCH。错误事件/锚点丢失/过期时禁止第二次组信号。
  确认父进程已退出但后代仍持有 pipe 时，超时后直接子进程已 wait、整个
  owned process group 的 signal0 返回 ESRCH；观察退出、两次信号、wait 与 helper 自身 10ms 轮询
  共用最多 2 秒期限。Darwin kqueue 使用剩余期限；reap 使用 `Popen.wait`（内部退避可达 50ms），
  不是整个流程都以至多 10ms 间隔检查。EPERM 是未确认，
  不能算 group 消失；持续 EPERM/group 可见至期限，或其它观察错误，都必须报 bounded-cleanup
  错误，同时证明 selector/pipes 关闭；首次 publication 前的 bounded-command 失败必须证明
  未发布 canonical key pair。post-link 验证或稳定性复核失败可能留下 canonical leaves，须记录
  具体阶段并保留现场，不自动 unlink/回滚，不以失败退出证明零写入。退出观察失败后 reap 再超时
  时须保留最初 cleanup 原因的异常链。macOS fixed100 仅证明本机进程语义，不替代本 Linux/root 门禁；不因失败增加等待阈值、
  跳过原断言或反复跑到绿色。清理仅限本 fixture 的已确认 PID/group，保留失败证据，不碰其它进程。
  group SIGKILL 返回 ESRCH 后不再发组信号；锚点回收后亦只观察，不向可能复用的数字 PGID
  发信号。POSIX 只在 group 非空期间保留 PGID；此保证不覆盖主动切换 session 的后代。
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

## TC-REAL-FINISH-NATIVE-001 — Native finished-project 完整归档与 stop-only

- 状态：**NOT RUN / REAL_ENV REQUIRED**。仅在可回滚的 Ubuntu 22.04/24.04 Native 管理 VM 上执行；
  项目须已通过正式 load，Apache、DHCP、Monitor 与 worker 均健康。先冻结 exact source/release/setup、
  服务 PID/argv、DHCP leases、项目树、日志、`/var/lib/http-ztp-finish` 与可用空间证据。
- 步骤与预期：先执行只读 `plan`，再以同一 transaction 执行 finish；在 pre-stop 完成后制造一项
  项目输出和一项日志变化。证明 pending 在共享 deployment lock 内先提交，`13-unload.py --stop-only`
  只停止四类 writer，final delta 精确记录 create/replace/delete，最终 bundle 可重验且状态为
  `FINISHED_BACKUP_VERIFIED_RUNTIME_STOPPED`。项目、publication、DHCP 文件、软件包与 infra 均保留；
  unsetup 只作为未执行的精确建议输出。
- 证据、清理与风险：保存脱敏 argv/exit、阶段 receipt、服务前后状态、bundle size/SHA-256、component
  manifest、delta inventory、权限与 deletion plan；不得保存密钥、token 或密码明文。测试后只按受管
  setup/load 流程恢复 VM 快照，不手工清 pending/lock；错误停止真实服务会中断 ZTP，禁止在生产首测。

## TC-REAL-FINISH-DOCKER-001 — Docker identity-bound deactivate 与持久状态保留

- 状态：**NOT RUN / REAL_ENV REQUIRED**。一次性 Ubuntu 24.04 local-rootful Docker VM，contract-3
  容器已正式 deploy/load；记录 immutable container/image ID、labels、environment、所有 bind、Supervisor
  child、activation/precommit、项目与 `/var/lib/http-ztp-finish` 的 stat/hash。不得在外来同名容器上执行。
- 步骤与预期：验证 Compose 与 plain-run 均只有一个宿主/容器同路径
  `/var/lib/http-ztp-finish` RW bind；运行 plan/finish，确认 `deploy.sh stop <transaction>` 只对已重验的
  immutable ID 调用 hostctl deactivate。Supervisor 业务服务停止，activation/precommit 清除；控制容器、
  image、所有 bind 数据与 finish receipt 保留。逐项替换 CID、managed/http-root label、finish bind source/
  destination/RW 后重试，必须在首次 stop/clear 前 fail closed。
- 证据、清理与风险：保存脱敏 inspect、mount、Supervisor、receipt、bundle SHA 与 stop 时间线；不保存
  auth/cache payload。每个负例从 VM 快照恢复；成功案例只在人工审核后可另行执行建议的 `deploy.sh down`，
  finish 自身不得执行。容器身份判断错误会停止错误服务，只允许在隔离 VM 验证。

## TC-REAL-FINISH-RELAY-001 — finished bundle 可信中转与本机 import

- 状态：**NOT RUN / REAL_ENV REQUIRED**。准备不可由本机直连的隔离管理 VM、可信中转机和 macOS 审阅机；
  三端时钟、平台、可用空间和目标路径已记录，传输只使用受控临时目录。
- 步骤与预期：在管理 VM 完成并重验 bundle；逐跳复制到中转机和本机，每跳记录稳定 reopen 后的 size/
  SHA-256，不解包、不重打包。macOS 先 review-only，再显式 `--finish` 发布到不可变
  `Finished-projects/<project>/<record-id>`，确认 reconstructed-final 与冻结 inventory 一致、同 bundle 幂等，
  单字节篡改或同 record ID 异内容均拒绝且不降级 legacy import。
- 证据、清理与风险：保存三跳摘要、import report、inventory/mode 与无 Git/upload/sync 泄漏证明；删除
  中转和本机临时副本但保留受管 finished record。传输对象含私有配置/密码散列，必须使用 ACL 受限路径，
  不得上传公共制品库或记录 payload 内容。

## TC-REAL-FINISH-OFFLINE-RESTORE-001 — 离线 finished record 到新 DAY0 项目恢复

- Case ID：`TC-REAL-FINISH-OFFLINE-RESTORE-001`；类型：real-environment / disaster-restore /
  failure-injection；状态：**NOT RUN / REAL_ENV REQUIRED**。本机合成测试与 relay-import 案例只证明
  局部合同；前一案例停在 immutable record 发布，并未证明新项目的离线恢复。
- 前置条件：仅在 owner 批准的一次性、断网 VM 和独立私有可擦写磁盘上操作，使用虚构项目、
  无客户配置/凭据的固定夹具及快照；确认没有网络路由或真实管理服务，禁止将测试盘挂到生产主机。
  冻结同一候选 HEAD/tree、源码、测试、manifest、runner 完整证明、源项目树、目标空 DAY0、
  finished 状态目录、文件系统类型/容量/权限和各目录前像。测试操作者保留独立恢复通道，
  并把负例所需的文件、符号链接和故障注入限制在可回滚 VM/私有盘内。
- 正向步骤与预期：在隔离源 VM 用受管合成项目完成真实 finish，独立重验 bundle 与 pre-stop/final
  delta；断网后逐字节复制 bundle 到私有盘和恢复 VM，每跳稳定重开并记录 size/SHA-256，不重打包。
  在恢复 VM review-only 后将 bundle 导入唯一不可变 `Finished-projects/<project>/<record-id>`，
  再由正式显式 rehydrate 入口生成新的 DAY0 项目名。独立枚举 record inventory 的每项
  path/type/mode/size/SHA-256、目录/链接语义，与新项目逐项对应；记录源 bundle、import receipt、
  immutable record、rehydrate receipt、目标项目及 parent 目录的 inode/大小/摘要和时间线。
  核对默认配置与历史记录的选择：新项目只恢复受支持的 default/history，既有记录及目标项目不被
  覆盖，源项目、finished record、默认项与历史条目的摘要保持前像；新 DAY0 存在不等于可 load。
- 负例与故障注入：分别在隔离副本篡改/截断 bundle、修改 record 单条内容或 mode、制造同名目标
  冲突及 staged 目录 symlink-swap；在 stage 创建 `O_CREAT`、文件复制、fsync、目录 fsync 和
  原子发布边界中断。每例须在任何错误目标写入或 receipt 完成前 fail closed：目标若原本存在则
  inode/字节不变，外部哨兵不变；新目标失败后不得留下貌似完成的项目。并发重试只可按受管幂等
  合同处理，不允许手工改 receipt、批准账本或借早期局部 GREEN 消除同 UID 竞态缺口。
- 证据、清理与风险：保存脱敏命令、退出码、断网证明、每跳和逐项摘要、inode/mode、receipt、
  注入点、前后快照与删除清单；不保存原始配置、私钥、密码、token 或客户拓扑。每个负例恢复 VM/
  私有盘快照；正向结束后按受管步骤删除新建测试项目和传输副本，核对源/record/default/history
  前像及无临时 stage、外部写入和后台进程残留。本案例绝不运行 load、sync、服务启动或生产动作。
  任一文件身份、竞争窗口、故障拒绝、默认/历史项或清理证据缺失均保持 OPEN/BLOCKED；D57/D58
  stage-rebind 修复与同树全量证明另行验证，本卡不宣告它们已通过。

## TC-REAL-FINISH-RESUME-001 — 阶段故障恢复不重复停止或发布

- 状态：**NOT RUN / REAL_ENV REQUIRED**。在上述 Native 与 Docker disposable VM 各执行一次；为每个阶段
  准备可审计的一次性 failpoint，先记录服务、component inode/SHA、pending 与 completed receipt。
- 步骤与预期：分别在 pre-stop archive、pending commit、runtime stop、final delta 和 bundle finalize 后
  中断进程/SSH；只用原 transaction ID 执行 resume。已提交 component 与最终 bundle 必须逐字节复用，
  stop 事件只发生一次，no-replace 发布不覆盖既存对象；其他 transaction 必须报告 owner 后阻断。
  bundle 已发布但 pending 未清的案例只能重验 bundle/runtime 后清理 pending。
- 证据、清理与风险：保存每次故障前后阶段 JSON、inode/size/SHA、stop counter、服务状态和 resume 输出；
  不手工改 receipt 或 ledger。每个 failpoint 从快照恢复，确认无临时对象、锁 holder 或错误运行态；断电/
  kill 可能延长停机，禁止在生产或无回滚环境执行。

## TC-REAL-FINISH-LARGE-001 — 大项目容量预算与有界停机窗口

- 状态：**NOT RUN / REAL_ENV REQUIRED**。一次性 Ubuntu 管理 VM，使用不含真实秘密的代表性大项目副本，
  覆盖大型 `99-output-*`、backup、日志和可选 shared artifact；记录文件系统类型、free blocks/inodes、吞吐、
  项目精确 tree hash 和服务基线。
- 步骤与预期：先制造低于所需 staging+final reserve 的容量，plan/finish 必须在首个正式 component 写入和
 任何 stop 前零写入拒绝；恢复足够容量后运行完整 finish，证明大体积 pre-stop archive 在服务在线时完成，
  停机窗口只含 pending/stop/delta/final verification。显式 include 与默认 inventory-only 两种 shared artifact
  模式分别核对；临时双份、最终 size 与预测误差均记录。
- 证据、清理与风险：保存脱敏容量估算、df/statvfs、各阶段时长、bundle/component size/SHA、writer 停止
  窗口与最终空间；不保存大 payload 内容。删除仅测试生成的私有 stage/bundle 并恢复 VM 快照，确认项目和
  服务基线；容量耗尽可能影响宿主其他服务，必须使用独立文件系统/VM，禁止在共享管理服务器执行。

## TC-REAL-BACKUP-PERMISSION-001 — 采集器与 feedback 同身份权限边界

- 状态：**NOT RUN / REAL_ENV REQUIRED**。在可回滚的 Ubuntu 管理 VM 与项目电脑各执行一次；不得使用
  真实生产备份树做首次验证。管理服务器由正式 root worker 驱动采集器并以 root 运行 feedback；本机两者
  都以 joeyyang 运行。www-data 只读取树外状态 JSON，不授予备份树访问权。
- 步骤与预期：在 `umask 022` 下完成一轮 AIR 和一轮 Production 备份，验证批次/族目录均为 0700、所有
  文件均为 0600、每个 YAML 为当前采集身份拥有的 single-link regular file；随后以同一身份通过受管 sample
  link 运行 feedback 并确认 Production 与 AIR 证据均被读取。再以不同的非特权身份只读运行 feedback，必须
  明确报告 `backup-identity-mismatch`，不得把不可读 Production 证据当成不存在而让 AIR 静默胜出。
- 历史清扫：先在树外 root-private 0700 state 目录生成 exact manifest，保存公布的 SHA-256 后再显式 apply；
  中途终止后只用同一 manifest+journal 显式 resume。保存前后 dev/ino/uid/gid/mode/size/mtime/ctime/hash、逐项
  append-only journal 和全树独立扫描结果；所有 YAML mode 不得宽于 0600，且“宽于 0600 并含
  `hashed-password`”计数必须为 0。任何新文件、symlink/hardlink、owner/content 漂移都应在 chmod 前阻断并
  要求重新 inventory；不得自动 rollback 到更宽权限。
- 清理与风险：只保留脱敏 manifest/journal 摘要，不保存 YAML 内容或密码散列；从 VM/fixture 快照恢复，
  不手工修改真实历史树。身份配置错误会改变 feedback 的权威证据选择，因此任何错误都阻断后续优化流程。

## TC-REAL-BACKUP-RETENTION-001 — 历史批次迁移、逐设备去重与 last-copy 封顶

- 状态：**NOT RUN / REAL_ENV REQUIRED**。只在现网备份树的只读快照及其隔离可写副本上执行；真实树
  首次只允许 prepare migration inventory，不执行 approve、dedup 或 prune。记录 canonical root、顶层
  symlink identity、三类历史批次名、环境归属、批次/family/YAML 的 type/dev/ino/uid/gid/mode/nlink 与
  exact tree digest；不得记录 YAML 内容或密码散列。
- 步骤与预期：在隔离副本上 prepare 后人工核对 `20260624_111542` 的 Production 归属，再 approve；两步
  间分别注入内容、mode、link 与 owner 漂移，必须拒绝。用 `20260824_1542`/`20260831_2137` 实测关系证明
  46 个相同设备只删除旧副本、8 个不同设备双份保留，新增/离线两方向均不删除。以 cap=100 对四批运行时
  不得产生 last-copy 告警；仅在第二份隔离副本的测试常量 cap=3 下，必须钉住并命名
  `20260624_111542` 及其 104 个唯一旧设备身份，同时删除可淘汰批次。production CLI 不得出现 cap 参数。
  中断 journal 后重跑必须只调和已记录 identity，不能删除 rebound 路径；所有剩余 YAML 不宽于 0600，
  所有受管目录不宽于 0700，owner 不变。
- 清理与风险：保留脱敏 report、journal、批次/设备计数与前后 tree digest，销毁两个可写隔离副本；真实树
  只有 owner 另行批准后才可 approve 与执行。错误环境归属或 last-copy 判断会永久删除不可再生配置，任何
  inventory/hash/identity 不一致都必须阻断，禁止手工改 migration inventory 或事务 journal。

## TC-REAL-SPLITTER-PROFILE-001 — 部分 lane 接线下的 8x 硬件接受性

- 类型：real-environment；需求：REQ-14 / D-32。状态：**NOT RUN / OWNER-RULE ACCEPTED**。
  M-14a 由 owner「P2P 已写出 8 个子接口即默认设备接受」规则关闭；M-14b 已按该规则以工作簿测量
  关闭。二者不再构成实现或发布的新硬件窗口门禁，但不得把该规则或本机自动化标为物理验证 PASS。
  本项只记录尚未执行的可选现场验证与已接受残余，不重新打开 M-14a/M-14b。
- 自动化：`test_splitter_profile_breakout.py` 与 `test_splitter_profile_breakout_workflow.py`。
  本机只解析 P2P、生成临时 YAML、验证 filler/description，不连接或修改交换机。
  load 的严格默认/显式 legacy 路径另由 `test_load_release_transaction.py` 与
  `test_xlsx_zero_row_workflow.py` 覆盖；转录 fixture 与私有真实输入证据分开，不冒充物理验证。
- 风险与目标：硬件或 OS 若拒绝 8x，会在 apply 时才暴露；模式切换可能中断该 cage 全部现有链路。
  成功标准为目标硬件接受 8x / lanes-per-port=1，已接线 lane 保持预期链路、未接线 lane 不伪造邻居。
- 前置条件：仅在 owner 另行批准的可回滚实验交换机执行，具备独立 console/OOB；记录型号、OS、
  目标 cage、当前模式、物理接线与配置摘要。输入必须绑定确切 workbook、源码和已审定生成 YAML
  SHA-256，不能以 AIR 支持情况替代实机证据。
- 生成前置证据：记录 workbook、inventory、port map、LLDPQ DOT 及其 template、description intent、
  splitter sidecar、AIR policy、所选 AIR JSON、CSV/设备模型及源码摘要。旧列布局必须明确使用
  load `--p2p-legacy-columns`（producer `--legacy-columns`），不得自动降级或跳过错误 sheet。
  项目已声明的自连接 rewrite 只改变 AIR edge，LLDPQ 保留设计链路；真实 main()、临时
  generate_all()、正式 load 与设备 apply 分层记录。合成空 CSV 或显式选择旧 JSON 的离线
  对账不能关闭真实 CSV、JSON 选择及 basename 绑定残余。
- 步骤：先只读核对四个目标 cage 的 8 条声明及生成 8x；记录现有接口/邻居状态后，在批准窗口使用
  受管部署流程应用配置；检查全部 8 条子接口、已接线 lane 连通性、未用 lane 的最小配置与无虚假邻居；
  核对保存及重启后的模式（重启须单独获准）。若设备拒绝，保存拒绝与连通性证据，不伪造成功回执。
- 证据：脱敏型号/版本、前后模式、接口和邻居状态、NVUE 返回码、生成/运行态配置摘要及回滚结果；
  不在公共测试仓库保存客户拓扑、配置值或凭据。
- 故障与清理：在实验环境保留不支持模式的拒绝案例；通过独立 console 恢复原配置并核对全部原链路。
  仅清理本项生成的临时制品，保留脱敏报告。不在生产设备首测，也不由测试 runner 自动下发。

## TC-REAL-REQ14-ACTIVE-PROVENANCE-001 — 09:15 工作簿到当前发布的逐源绑定

- Case ID：`TC-REAL-REQ14-ACTIVE-PROVENANCE-001`；类型：real-input / local transaction /
  scenario；状态：**PARTIAL / PRIVATE REAL-INPUT POSITIVE + NINE NEGATIVE PASS;
  SOURCE-YAML FULL-PARENT PRIVATE PASS; LIVE RUNTIME OPEN**。
  历史 4,536 条 sidecar 与 436 个
  parent 的对账已经完成，不由本案重开；本案也不以 8x 硬件接受性作为新门禁。合成 direct/workflow
  测试、旧日期的 AIR/DOT、或从当前 YAML 反推预期值，都不能替代真实 09:15 source-to-release 证明。
- 2026-09-25 私有正向证据：一次性隔离 09:15 Stage H 的 P2P、DHCP、Cumulus child、publisher、
  parent 五步均 exit 0；真实 sidecar 4,536 条、child 两组各 539 份 YAML、432/436 原 parent
  不变与 4/436 预期变动、当前 parent receipt/provenance 均经冻结 oracle 核对。完整私有收据
  SHA-256 `bfc4144da8a6b049fc5c2e501acfeb6bcb2400ac21658ad1f3394f2717fb06a1`；
  原件/候选 43+7 文件、15 条 stage 链接及隔离外 sentinel 后像一致。未写 live、设备或生产。
  本项仅关闭本地真实输入正向子门禁，不证明 AIR/prod、整树验收或部署许可。
- 2026-09-25 私有负向证据：从上述冻结 Stage H 独立复制的 11 个一次性副本中，C0
  无变异 `publish=False` 验证和 C1 精确 `source_yaml_b64` 直接正控通过；N1–N9 九个
  负例均在直接溯源和完整父流程中以对应 `LoadError` 拒绝，父回执与隔离外 sentinel
  逐字节不变。覆盖错误 profile、缺失/等长改写 LLDPQ、同字节改 workbook basename、
  等长改 inventory/port mapping、child YAML 冲突、伪造 metadata 摘要、内部摘要一致但
  source YAML 与 child 发布字节不一致。脱敏汇总报告 SHA-256
  `9336a3bc779708ad11504784986f0b50b07b60747c8f9247995d0a22ac65386a`；
  原始正例树和回执后像仍与冻结身份一致。N4 证明新 basename 的派生 sidecar 缺失时
  fail closed，不单独证明密码学 basename 绑定；C1 仅是直接正控，须与下述 C2 完整父流程
  正向提交分别计数，不能把本地负例通过写作 REQ-14 验收。
- 2026-09-25 私有 source-YAML 完整父流程正控：另一个一次性隔离 C2 副本仅改设备 CSV
  的合法 source/fields 摘要与同一设备在 P2P sidecar 中的 13 条 profile；原 sidecar 其余
  4,523 条顺序和内容不变。直接溯源与复制的 parent validate→prepare→commit 均 exit 0，
  新 parent receipt 的 source-YAML 摘要仅绑定该设备的已发布 child 字节；原 104 台发布
  设备全部不变，generator profile 仅移除该设备，其余 103 台逐项不变。最终持久变更
  限定为隔离副本的 CSV、sidecar 与 parent receipt 三个文件，原正例树及隔离外 sentinel
  仍逐字节不变。脱敏 C2 收据 SHA-256
  `72985e000ab0a6f2862f5d84ed9486d1752e15e1efa7eef7408711f04377ccd9`；
  新私有 parent receipt SHA-256
  `a1d8a6726f8e158a6bd77d132934748e145e6aea12c942375fde22683368680d`。
  这只关闭本地 source-YAML 完整父流程正控，不证明当前 live 09:15 runtime 发布、AIR/prod、
  整树验收或部署许可；上述真实环境门禁继续 OPEN。
- 前置条件与隔离：只在 owner 已授权的本机私有隔离项目副本操作，不改 live dirty root、原始工作簿、
  当前发布链接或设备。先以 inode、大小、SHA-256 绑定所选真实工作簿及其项目根 basename、
  `p2p.xlsx` 相对链接文字、inventory、port mapping、LLDPQ template、generator/load 源码、
  manifest、候选 HEAD/tree 与隔离副本前像；固定显式 legacy-columns 选择。缺任一输入、
  链接逃逸或候选未冻结即 STOP。客户工作簿和拓扑原文仅留在私有证据域。
- 正向链：对隔离副本运行真实 P2P producer，再运行真实 Cumulus child generator 与 parent
  load publisher，不用手写 sidecar、DOT、child manifest 或 parent current-release 冒充生产者。
  逐字节冻结 `*-lldpq.dot`、`*-splitter-profiles.json`、所选 workbook/inventory/port mapping、
  发布 child YAML/manifest、parent current-release；独立解析 sidecar 的 source_workbook 与四个
  source SHA、每个相关 `(device,parent,profile)`，并与发布 YAML 的 breakout 和来源行对应。
  四个已知目标 parent 变化须由事先保存的真实输入 oracle 判定，其他 parent 不变；记录
  prod 与 with_desc 两组各 539 份实际 YAML consumer 覆盖，以及 432/436 不变、
  4/436 有意变动的独立比较结果，不能把
  历史 4,536/436 对账当作本次发布结果。parent release_id 必须绑定本次 source identity，
  消费者只能选择该次发布的 child/parent，不能选 09/06 DOT 或 09/10 AIR 旧制品。
- 负例与事务：在可丢弃副本中分别于 child 生成后、parent commit 前替换合法形状但错误
  profile 的 sidecar、移除或同大小改写 LLDPQ、更换同字节不同 basename 工作簿、改写
  inventory/port mapping、使 child YAML 与 sidecar profile 冲突，均须在 parent 提交前
  fail closed 且旧 current-release 字节不变。单独用合法 `source_yaml_b64` breakout
  作正例：只有 CSV source/fields 摘要及发布 child 字节一致时才允许无 generator sidecar；
  伪造或陈旧 metadata 不得成为绕过途径。故障注入不得写真实项目或生产设备。
- 证据与清理：记录脱敏 argv、退出码、各检查时间、文件 stat/SHA、源行定位、前后
  release identity、拒绝原因和隔离副本清理核对；保留原始客户输入仅在私有受控域，不把
  拓扑正文或凭据写入公共日志。此案证明本地真实输入的生成/发布来源，不证明 AIR/prod
  设备接受性；任一链条或拒绝断言缺证据时保持 OPEN。

## TC-REAL-CONFIG-SYNC-001 — 受保护完整配置同步与会话连续性

- 状态：**NOT RUN / REAL_ENV REQUIRED**。自动化仅在隔离 fixture 中验证规范化门禁、完整回执、
  preview/confirm 指纹、固定 `nv config replace` 命令与页面状态机；未连接或修改真实交换机，不得把
  direct/workflow GREEN 当作真机 replace、ACL 连通性或 NVUE 持久化证据。
- 前置条件：可回滚的 Cumulus/NVOS 实验交换机，已通过能产生 trusted full-replace receipt 的受管 ZTP
  流程完成配置；管理面有独立 console/OOB 恢复路径。冻结设备身份、当前 `nv config show`、startup、
  receipt、latest 专属 YAML、release binding、eth0/SSH/全部 AAA 用户和 control-plane ACL 的脱敏摘要。
  AIR patch/baseline receipt 不得伪造成 full prior；没有完整 B 的设备只验证明确拒绝。
- 步骤与预期：先生成仅改变 hostname/ACL 等非保护字段的新配置，经 CLI 与页面分别完成只读 preview，
  核对确认前设备字节和会话均不变；确认文案必须明确“本机手工配置若未出现在新生成配置中，将被删除”。
  执行一次 `--replace-config`，验证只出现 `nv config replace`、apply、save，状态依次为同步中/已同步，
  startup 与 latest 规范化一致且原 SSH 会话及新登录可用。随后逐项改变 eth0、ssh-server、AAA role、单/多
  用户 hash、新增/删除用户，注入 patch receipt、缺失 AAA、损坏 prior、运行态漂移、preview 后 receipt/
  release/current 变化和设备 ZTP 正在运行；全部必须在首次 replace 前以区分原因拒绝。ACL 变化按 owner
  已接受风险允许进入执行，但必须通过 console 同时观察 SSH 是否被 ACL 中断。
- 证据、清理与风险：保存脱敏后的 operation/trigger ID、状态时间线、原因码、value-free changed paths、
  receipt/release/current/expected SHA-256、NVUE exit、apply/save 与重连结果；不得保存配置值、密码散列或
  SSH 凭据。每个负例从交换机/VM 快照恢复；成功例使用受管生成/replace 流程恢复原配置并再次验证
  startup 与登录。完整 replace 会删除未生成的现场配置，ACL 变化可能立即中断 SSH，因此首次只能在有
  console/OOB 和可回滚快照的实验设备执行，禁止在生产交换机首测。

## TC-REAL-COLLECTION-CYCLE-001 — AIR/Production cycle、进程绑定与真实制品

- 状态：**NOT RUN / REAL_ENV REQUIRED**。本机自动化已用真实 coordinator 子进程、匿名 context/result
  FD、私有 lifecycle records 和 SIGKILL 验证 live-HOLD→dead-`cycle_crashed`→下一 sequence；fixture
  collector 及合成 inventory/sidecar 不构成真实交换机、真实 archive 数量或真实 IB/NVLink 内容证据。
- 前置条件：仅在隔离管理 VM 与批准的可回滚实验交换机执行，冻结源码/测试/manifest SHA-256、项目
  identity、scope、所选 inventory 和 `monitor/status/collection-cycles` 前置树摘要；为 coordinator 及
  全部 family child 提供独立进程观测和有界 TERM/KILL 清理能力，不使用生产设备或生产凭据。先独立
  冻结每个 slot 的 CSV、AIR inventory/lease/JSON、Production lease/log 或 journal-derived rows 的
  SHA-256，并确认 cron.lock 从无采集 plan 阶段连续持有至 full 阶段；动态来源不具备可信预运行快照时
  必须退回 nonqualifying v1，不能补写 v2。Production 未提供显式 DHCP log 时必须由管理 VM 在 cron
  前成功读取并冻结 journal 原文字节，之后只以该私有 log 快照驱动 runtime resolver；resolver 脚本、
  lease 或 AIR JSON 缺失均不得等同于“零动态设备”。
- 步骤与预期：分别运行 AIR、Production 和 all scope，证明实际 slot 顺序、每个真实 collector 的一次
  执行、archive/CSV/info/link 的真实数量和内容类别、inventory binding、专用 coordinator PID/boot/start
  identity，以及 completion 早于 cooldown/UI success。核对私有 plan/context FD 在全程不被替换、
  seek 或重新读取动态源，验证 v2 sidecar 的有序 slot/role、输入快照散列、archive/manifest 身份及
  worker 独立资格判定；伪造 digest、路径逃逸、跨阶段源变更和 archive 失败均不得发布 v2 权威证据。
  另在 launch 后分别保持 coordinator 存活、令
  process inspection 不可用、再 SIGKILL；前两者必须 HOLD 且所有 durable bytes 不变，只有精确 dead
  binding 才能发布 `cycle_crashed`，其后新 cycle 使用下一 sequence。busy/cooldown/取消须证明 witness、
  records 与 sidecar 逐字节不变。
- 发布父目录隔离负例：只在上述可回滚 VM 的私有 status 副本中，分别把 `monitor/status`
  换成指向隔离哨兵目录的符号链接、把 `.publish.lock` 换成指向哨兵文件的符号链接
  或硬链接，
  以及在发布前重绑可见的 `monitor/status` 路径。前两例必须在发布前拒绝且哨兵字节
  不变；重绑例不得把权威 sidecar 发布到**新绑定**的可见目录。若重绑发生于最终
  路径检查之后，只允许 FD 绑定的原目录承接 rename；发布后路径复核必须拒绝并清理
  该次写入，不能把它当作当前可见目录的成功证据。记录发布前后父目录 dev/ino、
  sidecar 摘要、拒绝类别和哨兵摘要；先停
  止本案 collector，再从快照恢复私有 status 树。此故障注入绝不在 live/生产
  `monitor/status`、共享服务或真实客户项目执行。
- 证据：只保存脱敏 identity、sequence、cycle_id、PID/boot/start 摘要、record/tree SHA-256、slot/outcome
  计数、冻结输入/plan/sidecar SHA-256、archive 成员类别与退出码；不得保存设备输出、拓扑正文、密码、
  私钥或客户地址。AIR 无 IB/NVLink
  的事实不得推广为 Production 内容为空，fixture v1 nonqualifying 结果不得宣称 artifact authority。
- 清理与风险：停止 coordinator 进程组并核对无遗留 collector，保留只读脱敏 records 报告后销毁隔离
  status/artifact 副本，从 VM/交换机快照恢复。错误 kill 目标、PID 复用或不完整 archive 可能造成错误
  crash 判定或证据丢失；任何 process binding/cleanup/真实制品不确定均记 BLOCKED，不得降级为 PASS。

## TC-REAL-REQ13-PASSWORD-001 — 占位密码拒绝、受控轮换与真实设备登录

- 状态：**NOT RUN / REAL_ENV REQUIRED**。本机与 AIR 自动化只证明占位符识别、失败顺序、完整/部分
  轮换后的 load 门禁结果；不得据此宣称 Cumulus、IB 或 NVLink 真机认证成功。
- 前置条件：仅在批准的凭据轮换窗口及可回滚实验设备上执行，具备独立 console/OOB、当前凭据撤销方案、
  三个平台的受管测试账户和审计批准。绑定源码、测试、manifest、项目输入与设备身份 SHA-256；任何证据
  不得记录明文密码、密码散列、私钥或可复用认证材料。
- 步骤与预期：从三平台均含占位符的隔离项目开始，确认无更新参数的 load 在生成、复制、密钥准备和
  服务变更前拒绝并只列出平台与修复命令；仅轮换一个平台后必须继续拒绝其余平台。随后在批准窗口完成
  三平台轮换，同一次 `--update-passwords` load 应通过该门禁；部署到实验设备后分别验证 Cumulus、IB、
  NVLink 新凭据可登录且占位符/旧测试凭据不可登录。任一平台未验证即保持 OPEN/BLOCKED，不得降级。
- 证据、清理与风险：保存脱敏的平台名、命令退出码、门禁阶段、轮换事务摘要、设备身份和登录成功/拒绝
  结果，不保存 secret/hash。结束后立即通过受管流程再次轮换或撤销测试凭据，恢复设备快照并验证原有
  管理访问。错误轮换可能锁死管理面，因此无 console/OOB、撤销步骤或审批时禁止执行，更不得在生产首测。

## TC-REAL-REQ12-NVOS-DEFAULT-001 — NVOS family release default 与降级应用

- 状态：**NOT RUN / REAL_ENV REQUIRED**。本机与 AIR 自动化只证明 IB/NVLink family 选择、发布字节、
  child/parent manifest 绑定、预取顺序和失败关闭；不得据此宣称真实 NVOS patch、保存或登录成功。
- 前置条件：批准的可回滚 IB 与 NVLink 实验设备各一台，独立 console/OOB，已按受管流程轮换的测试凭据，
  可控制的 HTTP 404 与 NVUE apply-failure 注入点。绑定源码、测试、manifest、global、设备身份和 release
  SHA-256；任何证据不得记录明文密码、密码散列、私钥或可复用认证材料。
- 步骤与预期：分别对 IB 与 NVLink 强制专属 MAC YAML 404，再强制专属配置 apply 失败；证明 bootstrap
  预取并只 patch 当前 release 的 <code>default_ib.yaml</code> 或 <code>default_nvl.yaml</code>，timezone、DNS、
  NTP 与 family 凭据来自正确输入，receipt 分别为 <code>default</code>/<code>fallback_default</code>，且另一
  family 的值从未出现。删除或损坏所选 family artifact 时，fallback 必须拒绝，不能访问中性 default。
  成功 patch 后核对 config-save、重启持久性和轮换凭据登录；任一设备未完成即保持 OPEN/BLOCKED。
- 证据、清理与风险：保存脱敏设备型号/版本、release/manifest SHA、HTTP 请求 basename、NVUE exit、
  receipt source_kind、配置字段存在性和登录成功/拒绝结果，不保存值或 secret/hash。恢复专属配置与原始
  故障注入，撤销或再次轮换测试凭据，验证两台设备管理访问和 startup 配置。错误 family 或失败 patch
  可能锁死设备，因此无审批、console/OOB、回滚快照和凭据撤销步骤时禁止执行，更不得在生产设备首测。

## TC-REAL-DHCP-BANNER-FILTER-001 — rsyslog 语法、横幅抑制与运行证据保留

- Status: OPEN / NOT RUN。自动化用独立语料证明七类已测 ISC 启动横幅被匹配、未知横幅式变体会触发
  stale-filter 检测、`Listening on`/`Sending on`/DHCP/ZTP 事件不匹配，且样本窗口残留横幅字节不超过
  5%；本机没有用目标镜像中的 rsyslog/dhcpd 真进程解析或重载该配置，不得把静态 GREEN 当成现场 PASS。
- 前置条件：只在隔离 Ubuntu Docker 管理 VM 和测试项目执行，绑定 image/source manifest、容器 image ID、
  `rsyslog-dhcp.conf`、dhcpd 配置及日志目录的 SHA-256；保留可恢复快照，不读取或保存租约中的客户地址、
  hostname、MAC 或凭据正文。
- 步骤与预期：先用目标镜像的 `rsyslogd -N1` 验证语法；启动受管服务并重启 dhcpd，记录专用日志增量，
  七类横幅均不得落盘，而 listener、发送路径和一轮合成 DORA/ZTP 诊断事件必须逐类出现。再注入一条
  未知但横幅式的安全测试消息，stale-filter 诊断必须命名它而不能扩大过滤；按同一明确窗口计算横幅
  字节占比，结果必须不超过 5%。同时核对 10 秒 guardian 使用 serving/liveness 模式、30 秒 Docker
  healthcheck 仍执行 `dhcpd -t` 与 `apache2ctl configtest`，两者故障隔离语义不变。
- 证据、清理与风险：只保存脱敏后的 rsyslog 语法退出码、消息类别/计数、窗口总字节与横幅字节、探针
  argv/退出码和配置摘要，不保存原始租约或设备身份。恢复日志与服务快照并确认无测试消息残留。过滤过宽
  会删除故障证据，过滤失效会重新造成噪声与轮转压力；任一类别无法证明时保持 OPEN/BLOCKED。

## TC-REAL-REQ11-SHARED-ATTRIBUTION-001 — 共用地址事后身份归属与持久缓存

- 状态：**NOT RUN / REAL_ENV REQUIRED**。本机自动化仅用合成 SSH 身份结果验证每周期每个不同共用
  地址至多一次未决探测、恰一清单行匹配、逐行缓存调和、第三方来源往返与原子私有写入；不得把这些
  fixture 宣称为真实 AIR/Production 共址设备、第三方 provider 或现场 SSH 认证 PASS。
- 前置条件：仅在 owner 批准的隔离管理 VM 和一对可回滚的 AIR/Production 实验交换机执行；两台设备
  使用相同管理地址但具有不同 hostname 与管理接口 MAC，并有独立 console/OOB。冻结源码、测试、
  manifest、两份清单输入、known_hosts 与设备身份的 SHA-256；凭据只经受管 SSH agent/identity 使用，
  不写入证据。
- 步骤与预期：先清空本项私有归属 sidecar，在两行均缺少 HTTP/DHCP 所有权时运行一轮，证明只对共用
  地址发起一次未决身份探测，远端 hostname、指定接口与 MAC 精确匹配恰一行后才允许该行完整采集并
  原子持久化 provenance。切换地址实际 holder 后，较新的精确事后证据必须推翻旧绑定；注入 hostname
  与 MAC 分属两行、零匹配、多匹配、SSH 失败和第三方来源时，均须显式显示失败且不得把结果写入他行。
  修改无关清单行须保留仍成立绑定；删除、改 MAC 或改地址须逐行丢弃冲突绑定，mtime-only 变化不得失效。
- 证据、清理与风险：仅保存脱敏的 source/source_kind、输入与 sidecar 摘要、观测时间、地址代号、匹配
  行代号、探测次数与失败类别，不保存客户地址、hostname、MAC、设备输出或凭据正文。结束后停止隔离
  monitor，核对无遗留 SSH/collector 进程，删除本项隔离 sidecar 并恢复 VM/交换机快照。错误归属会造成
  AIR/Production 串写，是 fail-closed 门禁；任一真实身份信号或清理不确定即保持 BLOCKED。

## TC-REAL-SERVICE-ENDPOINT-001 — 本机 HTTP service endpoint 与真实接口绑定

- 状态：**NOT RUN / REAL_ENV REQUIRED**。本机自动化已验证共享 endpoint 值对象、默认端口、九个调用
  锚点、恶意地址拒绝和 Apache 渲染逐字节兼容；mock 的 `ip`/`ifconfig` 输出不能证明目标管理 VM 的
  实际接口枚举、路由源地址或 Apache bind 成功。
- 前置条件：仅在批准的隔离 Linux 与 macOS 管理 VM 各执行一次；VM 具有一个可回滚的非 loopback、
  非 link-local IPv4，且允许临时运行 Apache configtest。冻结源码、测试、manifest、接口清单及路由
  摘要；不得使用生产设备、生产地址或生产服务端口。
- 步骤与预期：分别从仓库外任意 cwd 导入并运行 `infra/deploy_infra.py`，确认显式本机地址通过、未分配
  单播地址与 loopback/link-local/multicast/all-ones 均在任何网络或文件写入前拒绝；再由真实路由推导
  同一地址。Native 与 container renderer 对同一地址必须生成既有逐字节 listener 配置，Apache
  configtest 通过且只绑定该地址的 port 80；停止/恢复接口后必须 fail closed，重复地址只要求至少一个
  本机接口持有。
- 证据、清理与风险：保存脱敏的平台版本、cwd、接口/路由命令退出码、候选地址类别、listener SHA-256、
  configtest 与 bind 结果，不保存客户地址或完整接口清单。恢复 Apache 与接口快照并确认无 listener、
  route 或进程残留。错误接口归属会把 `/apps` 指向不可达或错误主机；任一真实枚举、路由或 bind 证据
  缺失均保持 OPEN/BLOCKED，不得把模拟测试宣称为现场 PASS。

## TC-REAL-ETH-JUMP-ZERO-CONFIG-001 — jump host schema admission 与零配置产物

- 状态：**NOT RUN / REAL_ENV REQUIRED**。本机 direct/workflow 已验证安全的 `type=eth_jump` 行可通过
  两个 schema gate，配置意图字段会 fail closed，两个 generator pass 会逐实际类型计数，且 YAML、DHCP、
  ZTP publication、Day-0 monitor、Switch Status HTML、collection gate/worker、diagnostics、backup/yaml-collect
  与 manual ZTP/reset inventory 均不为该行产出设备制品或目标；三个真实 collector 入口也不会向该行部署
  `sw-info.sh`。这些 fixture 不能证明真实跳板机在受管 load 前后逐字节未变。
- 前置条件：仅在 owner 批准的隔离项目和可回滚实验跳板交换机执行；CSV 中该行须具有唯一 hostname、
  可用管理 IPv4，template 与 VLAN/SVI/BGP/bond/peerlink/VRL/EVPN/DHCP-relay 配置意图字段为空或 NA。
  冻结源码、测试、manifest、CSV、global、P2P 与跳板机 running/startup 配置摘要 SHA-256；具备独立
  console/OOB 和恢复快照，不使用生产项目或生产凭据。
- 步骤与预期：先记录跳板机 running/startup 配置、DHCP reservation、已发布 YAML/MAC 链接及 manual
  ZTP/reset inventory；运行正式隔离 load，并分别核对 Cumulus 与 NVOS generator report 均把该行命名为
  `type=eth_jump` 的显式排除项。运行后该 hostname 不得出现在任何设备 YAML、DHCP reservation、ZTP
  publication、Day-0 monitor、Switch Status HTML（hostname 出现次数必须为零）、collection gate/worker、
  diagnostics、backup/yaml-collect、reset/manual inventory 或向设备发起的监控、备份、配置、复位命令中；
  Ethernet、InfiniBand、NVLink 三个 collector 均不得向该主机 `scp sw-info.sh`，且跳板机 running/startup
  配置摘要必须与前像一致。另在隔离副本逐项填入配置意图
  字段，两个 schema gate 都必须在任何生成、网络或设备写入前拒绝。
- 证据、清理与风险：保存脱敏的 gate 结果、逐类型排除计数、各制品目录/manifest 摘要、设备前后配置摘要、
  网络命令计数和回滚结果，不保存配置正文、地址、MAC、凭据或客户拓扑。销毁隔离输出并恢复设备/VM
  快照。`_EXCLUDED_CONFIG_TYPES` 是防止未来 whitelist 扩展的显式计数信号；当前阻断仍由 downstream
  type whitelist 承担，不得把 frozen-set 成员误报为唯一安全机制。任何制品、设备摘要或命令不确定均
  记 BLOCKED，不得弱化为警告。

## TC-REAL-HTTP-PORT-001 — 非默认 HTTP 端口的 AIR 管理服务闭环

- Case ID：`TC-REAL-HTTP-PORT-001`；名称：非默认 HTTP 端口的 AIR 管理服务闭环；类型：
  real-environment / scenario；对应需求：REQ-14 port P2；适用平台：隔离管理 VM、AIR 实验交换机。
- 状态：**NOT RUN / REAL_ENV REQUIRED**。自动化 direct/workflow 仅证明配置渲染和 CGI 请求语义，
  不能冒充真实 Apache bind、DHCP DORA、设备 bootstrap 或现场端口可达性。
- 前置条件：仅由 owner 在批准的隔离管理 VM 与可回滚 AIR 实验交换机执行；准备一份
  `common.mgmt.http.port=8080` 的非生产项目和一份缺省端口对照项目，独立 console/OOB、
  可回滚 Apache/DHCP 配置及设备快照。冻结 candidate HEAD/tree、源码、测试、manifest、
  global YAML、生成配置与服务监听地址摘要；先确认 8080 未被占用，不使用生产地址、凭据或设备。
- 步骤与预期：在隔离项目完成正式 load，分别检查 native/container Apache renderer 生成的
  `Listen`、`VirtualHost` 与 `CONTROL_SERVICE_PORT` 一致，`apache2ctl configtest` 成功且只在
  指定服务 IPv4 的 8080 监听；DHCP option 239/67、manual ZTP URL、NVOS JSON 与 bootstrap
  三个目标 URL 均指向相同 `http://<SERVICE_IP>:8080` origin。用真实实验交换机完成一次 DHCP
  与 bootstrap 读取，核对实际 HTTP 请求抵达该 listener；三条 CGI 分别验证正确 Host/Origin/
  SERVER_PORT 被接受，错端口、错 host、错 origin 在动作执行前拒绝。缺省对照项目仍用 80，
  且不输出额外 `SetEnv`。另注入 8080 已占用、Apache configtest 失败、DHCP 发布失败和设备无法
  回连，均须显式阻断，不能回退到错误端口或悄然继续。
- 证据：只保留脱敏的完整命令、退出码、端口/listener 与网络请求计数、配置/制品 SHA-256、
  Apache/DHCP 状态、失败注入和回滚时间线，不保存客户地址、设备输出、凭据或原始租约。
  每条请求须绑定请求端与监听端的端口证据，不能仅凭配置文本宣告通过。
- 清理与风险：恢复 Apache/DHCP、接口和实验交换机快照，确认没有 8080 listener、租约、
  测试进程或发布制品残留；复跑缺省 80 的最小可达性。端口错配会使设备无法启动配置，
  错 listener 可能暴露管理服务；真实闭环、故障拒绝或清理任一缺失均保持 OPEN/BLOCKED。

## TC-REAL-HTTP-ADDRESS-001 — 独立 HTTP 地址与多接口归属的真实服务门禁

- Case ID：`TC-REAL-HTTP-ADDRESS-001`；类型：real-environment / scenario / failure-injection；
  对应 endpoint/address convergence 与 REQ-14 port；状态：**NOT RUN / REAL_ENV REQUIRED**。
  本机 direct/workflow 只证明解析、计划、写前拒绝和配置字节，不能证明真实接口归属、Apache bind、
  Docker/Supervisor 启停及健康检查。
- 前置条件：仅在 owner 后续批准的隔离 Native 与 Docker 管理 VM 中运行；每台具备可回滚的接口、
  Apache/容器/项目快照、独立控制台及不与生产互通的两枚单播测试 IPv4。冻结同一干净候选的
  HEAD/tree、源码/测试/manifest/ledger、global YAML、接口名称与 ifindex、地址/路由、服务配置
  摘要；记录 80 与非默认 8080 的端口占用前像。不得使用生产地址、凭据、设备或服务。
- 正向矩阵：分别运行没有 ZTP endpoint 的 `common.mgmt.http.address` HTTP-only 项目，以及 HTTP
  地址与 ZTP endpoint 相等和不等的项目。Native 与 Docker 均须只生成精确的 `Listen <IP>:<port>`
  集合：相等只一条，不等各一条；HTTP-only 只启动 Apache，不产生 DHCP/ZTP worker、DORA 或
  bootstrap 发布身份。两种后端的实际 listener、服务集、precommit/committed marker、健康检查
  与 HTTP 回读必须一致；默认端口仍为 80，8080 不得回退 80 或 wildcard。
- 归属与拒绝矩阵：记录指定 HTTP 地址的**全部**观测接口及其 ifindex、up/down/可监听资格、
  不合格原因和配置的接口 allowlist。无 allowlist 时至少一个可监听 owner 方可通过；配置
  allowlist 时至少一个可监听 owner 须在其中，且所有其他当前可监听 owner 也须在其中。
  两个允许且可监听 owner 通过；允许+仍可监听但不允许的 owner 在任何服务/文件/网络写入前拒绝；
  允许+down 或其他不可监听 owner 可以通过但须记录两者；零可监听 owner、未分配地址、
  loopback/link-local/multicast/unspecified/all-ones、错误端口及接口顺序变化均验证确定性的
  fail-closed 或等价结果。ZTP endpoint 的原有全局唯一规则不因 HTTP 重复归属而放宽。
- 故障注入与证据：分别在解析后、服务启动前、Apache bind、健康检查及接口漂移时注入失败，
  核对没有错误 listener、过期 marker、部分启动的 DHCP/ZTP worker 或未回滚服务。保留脱敏
  命令/退出码、完整 owner 类别/ifindex、配置和制品 SHA-256、实际监听及 HTTP 请求计数、
  前后服务状态与回滚时间线；不保存客户地址、原始设备输出或凭据。任何真实绑定、owner 上限、
  健康或清理证据缺失即保持 OPEN/BLOCKED，不能以本机 mock PASS 代替。
- 清理与风险：停止仅本案创建的隔离服务并恢复接口、项目、Apache/容器快照；独立确认没有
  测试端口 listener、进程、路由、租约、临时发布物或 marker 残留。错误 HTTP owner 可能将
  管理服务暴露在未经允许的接口；无完整清理证据不得复用环境。

## TC-REAL-DHCP-OPTIONAL-001 — 显式 DHCP 开关的发布与服务隔离

- Case ID：`TC-REAL-DHCP-OPTIONAL-001`；类型：real-environment / scenario；对应需求：
  DHCP-optional；适用平台：owner 批准的隔离 Ubuntu 管理 VM、可回滚 HTTP/DHCP 服务。
  状态：**NOT RUN / REAL_ENV REQUIRED**。本机 direct/workflow 证明发布身份和调用分支，
  不能代替真实服务、文件系统及网络隔离的观察。
- 前置条件：在隔离项目准备启用与禁用两份明确写有
  `common.mgmt.dhcp-server.status` 的 global；冻结同一候选 HEAD/tree、测试与 manifest、
  输入文件、当前发布记录、HTTP 根目录五个 DHCP 制品及 Apache/DHCP 服务状态的前像和摘要。
  保留独立 console/OOB 与回滚快照，不使用生产设备、客户地址、凭据或租约。
- 禁用路径：执行经全量证明的正式 load，核对新 parent `schema_version=2`、
  `release_basis.dhcp_status=disabled` 与 canonical `release_id`，且无 `components.dhcp`。
  即使旧的四个 DHCP 输出及 manifest 存在，也不得读作本次发布证据、生成、覆盖、安装或启动 DHCP；
  五项字节与 mtime 应保持前像，`isc-dhcp-server`/容器 `dhcpd` 不得 active。
  Apache、HTTP endpoint、ZTP 静态发布及非 DHCP monitor/VM 检查必须继续成立，
  不得把“没有 DHCP 文件”误当成禁用意图。
- 启用对照：切回显式 `enabled` 并重新正式 load，核对 parent status、DHCP component、
  当前 manifest 和四个输出摘要、服务 listener/接口、HTTP endpoint 与发布身份同代；
  旧 v1 parent 只可按严格 enabled 合同读取，不得解释为 disabled。
  两个模式之间不得沿用前一模式的 release_id 或混合不同代制品。
- 故障与拒绝：在隔离副本分别注入 parent status/release_id 与当前 global 不一致、
  global 输入摘要漂移、禁用记录夹带 DHCP component、启用记录缺 component/输出摘要、
  stale manifest、DHCP 端口占用以及 Apache 检查失败。前五项必须在消费或服务动作前拒绝；
  后两项必须保持服务安全停止或回滚，不得退回另一模式、放松 HTTP/worker/source 证明，
  也不得改写已有 DHCP 文件来制造通过证据。
- 证据与清理：保存脱敏命令、退出码、时间线、模式字段、release/输入/五制品摘要及 mtime、
  Apache/DHCP 服务 PID/argv、监听端口、HTTP 可达性与拒绝点；不保存客户数据或原始租约。
  恢复项目、服务、接口、文件及隔离 VM 快照，逐项核对前像。任一服务实测、故障拒绝、
  证据或清理缺失均保持 OPEN/BLOCKED，不得以本机测试 GREEN 代替现场验收。

## TC-REAL-REQ15-P2P-001 — 工作簿选择与旧列布局的真实语料核对

- Case ID：`TC-REAL-REQ15-P2P-001`；对应 REQ-15 / R15-1..16。状态：**NOT RUN / REAL_ENV REQUIRED**。
  合成 direct/workflow 证明排序、链接、无覆盖归档与单份传输，不证明客户工作簿列含义，也不代替 AIR/prod 验证。
- 前置条件：在隔离、可回滚的项目副本中绑定 HEAD/tree、四份治理文件、manifest、loader、producer、
  0915 P2P 与两个现代对照工作簿的真实路径/大小/SHA-256；先核对 `p2p.xlsx` 是否为项目根目录内相对链接。
  不在 live dirty root、生产服务或客户设备上运行生成/部署。保留隔离副本前像及清理清单。
- A/B：旗舰 0915 工作簿只在显式 `--p2p-legacy-columns` 时向 producer 传入一次精确
  `--legacy-columns`；移除开关须在 `OOB Fabric` 表头检测处失败，改成 `--legacy-columnsX` 也须失败。
  不得自动重试、跳过 sheet、推断零行或默认启用旧列。
- C/D：不带开关的 `2026-06-vb-b300`、`2026-07-vb-gb300-staging` 对照分别保持 **1994**、
  **338** 条；stderr 不出现 `WARNING: --legacy-columns 使用固定列`。将任一预期数改动 ±1 应使该断言 RED。
- E/F：对自动表头可成功识别的工作簿，带/不带旧列开关的生成输出须逐字节一致；对自动识别失败且
  fallback 落到错误字段的隔离负例，必须有独立断言 RED 并阻止错误拓扑进入 DOT/AIR。旧项目 A 的
  87 条错位链接与旧项目 B 的 3008 条 `#ERROR!` 不是“legacy 成功”证据。
- 选择/传输：重复验证根目录版本/日期/mtime 裁决、旧版显式钉选、`p2p.xlsx: 旧 -> 新` 变更行、
  非空 canonical 无覆盖归档及摘要、tar/sync 仅含解引用的选中真实工作簿；部署记录同时绑定路径与摘要。
  同版本日期/mtime 全等、坏日期、逃逸链接、缺失 canonical 或无原子无覆盖原语必须在输出发布前拒绝。
- 证据、清理与风险：保存脱敏命令、退出码、行数、stderr、生成制品摘要、所选路径/摘要与负例的阻断点；
  不保存客户工作簿或拓扑正文。销毁隔离生成物、恢复链接/占位文件和权限并核对前像。旧列开关在某些
  客户表上可把显式错误变成看似成功的错误链路，任何负例未阻断或证据不全均保持 OPEN，不得因日期临近放行。
- 旧记录迁移：先在隔离副本保存旧 `schema_version=1` current-release 前像，确认缺少
  `input_sources.p2p` 时手工部署门禁 fail closed；重新运行正式 load 后，确认新记录为 schema 2、
  含显式且与当前 global 绑定的 `dhcp_status`；`input_sources.p2p.path` 是项目根目录真实选中工作簿名
  而非 `p2p.xlsx`、其摘要与真实字节一致，
  且该字段参与 release_id。对两份字节相同但文件名不同的候选重指 canonical，旧记录也必须拒绝；
  不得把旧/新 current-release 混用，也不得以手工改写 release_id 代替重新 load。

## TC-REAL-REQ16-GENERATION-REPORT-001 — 实际发布公钥报告与两文件故障窗口

- Case ID：`TC-REAL-REQ16-GENERATION-REPORT-001`；类型：real-environment / transaction / scenario；
  对应 REQ-16 R16-9。状态：**NOT RUN / REAL_ENV REQUIRED**。本机
  `test_generation_report_contract.py`、`test_generation_report_workflow.py` 与相关 load 事务测试
  只验证隔离合成输入和调用次序，不证明真实 Native/Supervisor 路径、权限、服务状态或断电恢复。
- 风险与目标：报告可能把计划中的空占位、另一项目的链接或过期父 release 说成「本次实际使用」；
  `current-release.json` 与 `generation-report.json` 是**两个独立原子替换，不是一个原子事务**。
  父记录已提交而报告仍缺失/陈旧时，检查器必须拒绝，受管服务不得因普通报告提交失败而启动；
  后续由持有 deployment lock 的**完整** load 重跑重建。报告仅证明本地实际发布的公钥身份，
  **不证明持有私钥、设备已安装该密钥或旧设备密钥已撤销**。
- 前置条件与输入：只有 owner 明确授权后，分别在可回滚的一次性 Ubuntu Native 管理 VM 和
  rootful Docker/Supervisor VM 内执行，使用不含客户秘密的隔离项目、两把不同的有效公钥、
  可观测且可恢复的服务和 VM 快照；真实生产服务/设备不用于故障注入。先绑定同一干净落地树的
  HEAD/tree、manifest、helper、`11-load.py`、setup、测试及 full-proof 身份；逐项保存项目目录、
  `ztp/config/publickey/{laptop,mgmt-server}.pub` 两条**实际发布链接**、各自同名项目根常规公钥叶子、
  `99-output-ztp/{current-release,generation-report}.json` 的路径、链接文字、owner/EUID、mode、
  inode、大小、SHA-256 和服务/PID/监听前像。确认同一运行时内 reporter 使用的 published-dir
  与 setup 发布目录逐字相同；目录属主或 `/var` 路径别名不合合同时 STOP，不能为通过而改权限。
  owner 已裁定：既有有效公钥与 HOME 不一致时拒绝，原有公钥逐字节不动；
  RSA-only 管理服务器 HOME 在 PRE 范围内 fail closed，不读取 RSA 私钥。本案仍须实测
  实际发布链接、两文件故障窗口与 Linux 笔记本/管理服务器角色事实，不得据此宣告验收。
- 正向步骤与预期：在每种后端的隔离项目完成获准的正式 load，再在**同一运行时**用显式
  published-dir 执行 `tools/generation_report.py inspect PROJECT --json`；分别对两条发布链接落到的
  项目公钥叶子用固定 `/usr/bin/ssh-keygen -lf` 独立取得 OpenSSH SHA256 指纹，不读取私钥。
  父记录必须是已验证 schema 2，其 release_id 可由既定 release basis 重算；报告只在
  `project/99-output-ztp/generation-report.json`，具有 schema 3、固定 record_type、相同的
  project/release_id/generated_at 与按 laptop、management 排序的两条 type + SSH wire-blob 指纹。
  检查器成功输出必须与报告记录一致；项目根旧 ad-hoc schema-2 同名文件保持逐字节不变。
  独立 macOS/config-only 与 `--dry-run` 隔离对照不得声称或生成两把实际管理/笔记本公钥报告。
- 拒绝、故障注入与重复执行：只在可回滚 VM/项目副本中分别制造空管理公钥占位、跨项目/错角色/
  回弹的发布链接、单把公钥轮换、父 release 身份改变、缺失或畸形/未知版本报告、symlink/FIFO/
  hardlink 目的地；检查器须非零，不能回退读项目根 ad-hoc 文件，外部哨兵不变。分别在报告
  stage 前、**父 commit 后报告 commit 前**、报告 replace 与目录 fsync 失败处注入中断/故障；
  保存每个 checkpoint 的父/报告前后身份和服务状态。父已提交而报告缺失/旧代的窗口必须
  fail closed，不能宣称两文件同时回滚；普通提交失败须保持服务安全停止。修复输入后完整持锁
  重跑，报告与父记录、当前发布公钥重新收敛；重复运行不得复制私钥或替换无关文件。
- 证据、清理与风险：在 0700 私有证据目录保存脱敏 argv、退出码、时间线、OS/backend/EUID、
  HEAD/tree、manifest/full-proof、链接文字与 stat、文件 SHA、两个独立公钥指纹、checkpoint、
  deployment-lock 身份、服务 PID/监听状态和恢复前后比对；原始报告/负例制品若必须留存则 0600
  且只在受控证据域，不回传原始 JSON、公钥行、客户配置或任何私钥字节。恢复一次性 VM 快照和
  测试服务，逐项核对前像；不删除/覆盖真实健康密钥，也不以人工写报告代替正式 load。
  公钥指纹、项目名、release_id、时间是可经 HTTP 暴露的运维元数据，需实测访问边界并按 owner
  的披露策略处置；任一后端未测、故障拒绝或清理证据缺失均保持 OPEN/BLOCKED。

## TC-REAL-REQ16-HOST-ROLE-001 — Linux 工作站、管理服务器与 Service IP 暂缺

- Case ID：`TC-REAL-REQ16-HOST-ROLE-001`；类型：real-environment / role / workflow；
  对应 REQ-16 R16-1。状态：**NOT RUN / REAL_ENV REQUIRED**。现有 Ubuntu 24.04
  Docker 合成 HOME 探针和 direct/workflow 测试不是物理角色或真实部署证明；本案与
  `TC-REAL-REQ16-GENERATION-REPORT-001` 互相不能替代。
- 前置条件：仅在 owner 授权的可回滚一次性 Ubuntu 24.04 工作站 VM、Native 管理 VM、
  rootful Docker/Supervisor VM 中执行，分别绑定干净最终 HEAD/tree、manifest、CLI help、
  exact full-proof 状态、OS/backend/EUID、声明角色、Service IP/接口计划、deployment lock
  和 VM 快照。使用两个独立合成 Ed25519 key pair 与 0700 一次性 HOME/项目；观察者不打开
  私钥，旧真实公钥只可 stat，绝不当 fixture 读取、写入或复制。不得碰生产主机或真实 cron。
- 拒绝 N1：Linux 上 `11-load.py` 与 standalone `01-a-setup.py --create` 的缺失、无效及
  与 delegated context 冲突的角色必须在合成公钥、模板、发布链接、Monitor、服务写入前
  非零停止；记录明确角色错误而非无关配置错误。逐项比对合成叶子字节与 inode/mode/mtime、
  服务 PID/监听和锁前后像；把 Linux OS 单独当 server 的旧行为作为应被拒绝的反例。
- 工作站 W1：在明确支持的隔离 Linux 工作站范围内声明 workstation，完成配置准备且只从
  该合成 HOME 准备 `laptop.pub`，不读取或创建管理服务器 HOME 公钥、不委托 server setup、
  不启动 Apache/DHCP/Monitor。若实际平台范围不支持完整 Linux workstation load，必须
  记录早期明确拒绝，W1 保持 NOT RUN/OPEN，不得把拒绝算作正向通过。
- 服务器 S1：Native 管理 VM 显式声明 management-server，即使配置的 Service IP 暂不可用，
  仍以 server 角色准备合成管理公钥并委托持锁 setup，保留项目原有独立笔记本公钥；服务
  就绪门禁安全停止。恢复隔离网络后按同一角色完整重跑。分别测新公钥和已有有效公钥；
  冲突公钥必须原样保留且拒绝，不能降格成 workstation。
- Docker D1：受管 `deploy.sh` → `hostctl.py` → 容器 `11-load.py` 的真实子命令必须固定携带
  management-server 角色，不从环境变量或宿主 HOME 猜测；Supervisor 的 root identity
  配对与公钥证明保持原有合同，容器 load 不生成 SSH 私钥。删除子命令角色参数须使测试失败。
- 故障、证据和清理：分别注入角色缺失/冲突、公钥冲突与服务 IP 暂缺；保存脱敏 argv、退出码、
  时间线、独立合成公钥指纹、安全 stat/SHA、服务 PID/监听、网络状态、锁和快照恢复回执。
  只修角色声明或隔离网络后持锁重试，验证无重复 append 或无关覆盖。恢复 VM 快照并逐项核对
  前像；任一 N1/W1/S1/D1 帧未测、失败或恢复证据不足时本案保持 OPEN。

## TC-REAL-ISSUE-0001 — Cumulus 14 角色 DNS/NTP VRF 真机验证

- Case ID：`TC-REAL-ISSUE-0001`；类型：real-environment / scenario；对应缺陷：ISSUE-0001；
  自动化：`test_cases.test_v2_generation_flow.V2GenerationWorkflowTests.test_issue0001_all_fourteen_roles_honor_independent_dns_and_ntp_vrfs`
  与 `test_issue0001_global_to_render_missing_vrf_falls_back_to_mgmt`；适用平台：隔离 Cumulus
  实验交换机及管理 VM。状态：**NOT RUN / REAL_ENV REQUIRED**。
- 风险与目标：模板可能在 YAML 层显示正确 `vrf`，但实际 DNS 查询或 NTP 同步走错 VRF。
  本机 direct/workflow 的 14 角色渲染不能代替设备数据面验证。
- 前置条件：owner 批准的可回滚隔离项目；至少一台可分别承载典型普通角色、原硬编码角色和
  `oobofoob` 动态角色的实验设备，独立 console/OOB；可区分的 DNS 与 NTP 服务端点及 `mgmt`、
  `DNS-CONTROL`、`NTP-CONTROL` 测试 VRF。冻结 candidate HEAD/tree、global、CSV、manifest、
  生成 YAML 与设备前像 SHA-256；不使用生产地址、凭据或服务。
- 步骤与预期：用显式非 `mgmt` 的 DNS/NTP VRF 做正式隔离 load，核对 14 角色生成 YAML
  的每个 DNS server VRF 和 NTP 顶层 VRF；在代表设备上观测真实 DNS 查询和 NTP 同步均从
  指定 VRF 出口到达对应测试端点。随后在隔离副本移除两项 global VRF，重新生成并验证
  14 角色均退回 `mgmt`，代表设备的真实流量亦转回 `mgmt`。两次运行都核对 Docker、
  管理接口及租户 VRF 未被 ISSUE-0001 意外改写；错误或不可观测必须保持 BLOCKED。
- 故障注入、证据与清理：在隔离设备断开目标 VRF 路由，确认 DNS/NTP 不会静默从其他 VRF
  成功；保存脱敏命令、退出码、路由/接口/抓包计数、服务端接收记录、生成配置摘要和回滚
  时间线，不保存客户拓扑或凭据。恢复配置、测试服务与设备快照并核对前像。真实设备
  运行、故障拒绝或清理任一缺失时不得把本机 GREEN 误称为真机验收。

## TC-REAL-REQ7-LOCAL-RECOVERY-001 — Stage-L 本地证据冷启动与离线恢复边界

- Case ID：`TC-REAL-REQ7-LOCAL-RECOVERY-001`；类型：transaction / real-environment / offline-restore；对应需求 7 的 C-6 持久化、故障/竞态注入及恢复。状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。自动化先决为 `test_cases.test_issue_tracker_local_recovery` 与 `test_cases.test_issue_tracker_local_recovery_workflow` 的独立进程 direct/workflow，不能以其 GREEN 代替本卡。适用平台为 owner 明确批准的隔离管理 VM/卷，不是当前 live 项目或生产 tracker。
- 风险与目标：进程死亡后的磁盘 generation 可能有 INTENT 而无 RECEIPT，或有可见但未完成恢复屏障的 RECEIPT；复制到另一介质时 dev/ino 凭据通常改变。恢复者不得把这些情况推断成在线可发布资格、补造 RECEIPT、删除未决证据、重用旧锁令牌或重放 Google/在线写入。
- 前置条件与输入：先有同一逐字节落地整树的 Codex 全量证明及 Claude `--no-approve` 全量结果；owner 再指定可丢弃的隔离 VM、独立私有 0700 证据目录、恢复负责人和独立回滚快照。记录平台/Python/文件系统/挂载与卷身份、HEAD/tree、manifest/ledger、C-6/K-store 源码及 direct/workflow SHA、项目与发布根的原始 `lstat`/SHA、LK-P 锁所有者；不得包含真实客户 workbook、在线凭据或生产卷。缺少排他维护窗口或快照即 STOP。
- 正向步骤：在同一隔离卷用真实 `tracker_writer` 创建 (a) 无 INTENT、(b) 已 fsync INTENT/准备文件但故意终止写进程、(c) 已正式 commit 的三个 generation；关闭所有进程后由全新 Python 进程持单一 LK-P 执行只读冷发现。独立比较磁盘 STATE/MANIFEST/INTENT/RECEIPT、准备/发布对象的 dev/ino/size/SHA 与返回三态；(a)(b) 只能为 UNRESOLVED，(c) 只能为 RECEIPT-PRESENT-NOT-ELIGIBILITY。重复发现前后所有对象的字节、inode、权限、名称及数量不变，也无在线请求。
- 故障与竞态：仅在隔离卷分别注入 INTENT 后 `SIGKILL`、RECEIPT 发布/目录 fsync 故障、第二进程争用 LK-P、STATE/MANIFEST 缺损、伪造 RECEIPT、generation 或 quarantine 符号链接、孤儿 quarantine 项及名称交换；每例必须 HOLD、保留原始字节和拒绝证据，不能由另一进程补造成功状态。把同一隔离树逐字节复制到**另一**卷并记录 dev/ino 变化；旧 RECEIPT 凭据不匹配时必须 HOLD。跨介质正向迁移若需要，必须另有 owner 批准的凭据重绑定协议及独立测试，不能把普通 byte-copy 的失败改写成 PASS。
- 证据与判定：保存每次完整 argv、退出码、进程/锁/挂载身份、注入点、前后对象清单和 SHA、可见 RECEIPT 与实际 fsync 结果、只读返回状态、未发在线请求的独立观察、卷快照/恢复日志。分别报告冷启动正例、故障/竞态负例、跨卷 HOLD、回滚核对为 PASS/FAIL/NOT RUN；任一缺失时本卡仍 OPEN。全程不动真实 crontab、服务、设备、Google 或生产数据。
- 清理：按已批准隔离 VM 快照恢复或只删除本案逐一列出的临时项目/证据副本；先验证前像，保留故障证据与完整回滚收据。不能用全局清理、删除真实 tracker 或手改 ledger/RECEIPT 作为收尾。

## TC-REAL-DHCP-PUBLISH-REBOUND-001 — DHCP 候选发布目录改绑

- Case ID：`TC-REAL-DHCP-PUBLISH-REBOUND-001`；类型：real-environment / transaction / race；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。本机先决测试为 `test_cases.test_dhcp_switch_scope_preservation` 的父目录改绑 direct 与真实生成流程用例，以及 `test_cases.test_dhcp_switch_scope_preservation_workflow`；其 GREEN 不等于本卡通过。
- 前置条件：仅在 owner 批准的可丢弃 Ubuntu 24.04 管理 VM 和隔离 DHCP 项目副本中运行，先冻结 HEAD/tree、manifest、全量证明、项目/输出目录及服务的前像、真实写者静默窗口和快照。两个目录必须是单独的私有 0700 测试目录，攻击者同 UID 只操作本案副本，不碰 `/etc/dhcp`、服务或真实项目。
- 步骤与预期：分别在持有输出父目录描述符后、分配 stage 前，候选 stage 已写入而发布前，以及第一次 replace 期间，把项目 DHCP 输出父目录移到隔离名字并将原路径改绑至另一个私有目录；后者预置同名 stage 和带独立哈希的外部哨兵。正式生成应非零拒绝；分配前改绑不得在外部目录留下空 stage；外部哨兵字节/inode 不变，已移走目录的旧输出保持可恢复，回滚和 stage 清理只触碰持有的目录描述符，不通过改绑路径清除外部对象。正常无竞态运行的 conf/hosts/manifest 则须保持事务一致和原有 mode。stage 内容写入仍使用路径，故没有可核验的真实写者静默时不得把此卡视为同 UID 任意竞态免疫。
- 证据与清理：保存脱敏 argv、注入时序、退出码、父目录及 stage/目标的 dev/ino/模式/SHA、服务 PID/监听前后像、回滚和目录清理记录。恢复 VM 快照并逐项核对哨兵与原始 DHCP 前像；任何中途写入外部目录、混代 manifest、无法证明写者静默/恢复或未实测状态均保持 OPEN，绝不用于真实 DHCP 切换。

## TC-REAL-DHCP-INVENTORY-REBOUND-001 — DHCP 运行时盘点发布目录改绑

- Case ID：`TC-REAL-DHCP-INVENTORY-REBOUND-001`；类型：real-environment / transaction / same-UID race；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。自动先决为 `test_cases.test_dhcp_runtime_reassignment` direct、`test_cases.test_full_flow_integration` workflow 与 manifest 绑定；本机 GREEN 不构成真机通过。
- 前置条件：只在 owner 批准的可丢弃 Ubuntu 24.04 管理 VM、私有 0700 项目副本及隔离输出目录执行；冻结 HEAD/tree、父目录与盘点 JSON 的 dev/ino/mode/SHA、服务/进程前像和快照，确认其他同 UID 写者全程静默。不得写 `/var/lib/dhcp`、真实项目或服务目录，不得把测试输出放到 Web 发布路径。
- 步骤与预期：在写盘点暂存文件后、原子替换前改绑可见输出父目录；外部目录预置同名暂存和目标哨兵。真实 `ztp/dhcp_runtime_inventory.py --output` 应非零拒绝，外部哨兵字节/inode 不变，已移走目录的旧盘点可恢复，失败暂存与备份不得遗留或逃逸至改绑目录；无竞态正例须发布合法 JSON、0644 mode 并清除暂存。记录 argv/exit、注入时序、目录和文件身份、前后 SHA 与独立写者静默见证。结束后用快照恢复并逐项核对；无静默见证、外部写入、旧目标不可恢复或未实测均保持 OPEN。

## TC-REAL-NVOS-CVT-REBOUND-001 — P2P CVT 验证工作簿发布目录改绑

- Case ID：`TC-REAL-NVOS-CVT-REBOUND-001`；类型：real-environment / generated-evidence / same-UID race；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。自动先决为 `test_cases.test_topology_consistency` direct 与 `topology_inventory_and_lldp_identity` 多脚本 workflow；本机定向 GREEN 不构成真机验收。
- 前置条件：只在 owner 批准的可丢弃 Ubuntu 24.04 VM、私有 0700 项目副本与隔离输出目录执行。记录 HEAD/tree、输入 P2P 与输出目录 dev/ino/mode/SHA、原工作簿及 `.bak` 前像、其他同 UID 写者静默见证与可恢复快照；不得触碰 live 项目、服务发布目录、真实设备或生产数据。
- 步骤与预期：用真实 `p2p-to-validation.py` 生成可解析 CVT；在暂存后、发布原子替换前，将原输出父目录移走并把可见名称改绑到预置同名暂存/目标哨兵的外部私有目录。脚本必须非零拒绝，外部哨兵字节和 inode 不变，原目录中的旧 CVT 与备份可恢复；无竞态正例须保持旧字节于 `.bak` 并发布与输入对应的新 CVT。保存脱敏 argv/exit、注入时序、前后 SHA/身份、回滚与清理记录；恢复快照并核对。若外部写入、旧目标丢失、缺静默见证或未实测，保持 OPEN；不宣称对任意不合作同 UID 写者免疫。

## TC-REAL-DOWNLOAD-ARCHIVE-REBOUND-001 — 项目下载归档发布目录改绑

- Case ID：`TC-REAL-DOWNLOAD-ARCHIVE-REBOUND-001`；类型：real-environment / packaging / same-UID race；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。本机先决为 `test_cases.test_download_cli_contract` 与 `test_cases.test_upload_package_contract` 的父目录改绑、stage 替换及并发无覆盖 direct，和 `package_sync_load` 多脚本 workflow；本机 GREEN 不构成管理服务器验收。
- 前置条件：只在 owner 批准的可丢弃 Ubuntu 24.04 VM 与私有 0700 项目副本运行，指定待打包 DAY0 副本及位于其外的两个私有输出目录；先记录最终整树 HEAD/tree、测试证明、输入、输出父目录、同名目标与外部哨兵的 dev/ino/mode/SHA、卷快照及同 UID 写者静默见证。不得写 `/var/www/html`、真实客户项目或生产下载目录。
- 步骤与预期：分别在归档校验之后、发布之前改绑可见父目录，并在外部目录预置同名 stage/目标哨兵；另在保持父目录不变时替换暂存 inode、并发创建无 `--force` 的最终目标。`tar-for-download.py` 的项目及 `--all-day0` 模式、`--full-workspace` 和共享上传包入口分别执行，均须非零拒绝，外部和并发目标字节/inode 不变，不能打印假 `[OK]`；无竞态正例须产出可重新打开的 tar.gz、准确 mode（项目下载 0644、共享包 0600）与摘要，`--force` 仅替换受控同目录普通文件。共享上传包仍须独立通过正式全量证明门禁；本卡不授权实际上传或部署。
- 证据、清理与风险：保存脱敏 argv/exit、注入时序、父目录及 stage/目标身份、归档摘要、源数据前像、恢复与快照核对；仅清理本卡隔离目录。若缺 writer 静默、外部哨兵变化、归档身份或恢复证据不全，则保持 OPEN。此实现持有目录/暂存描述符并在发布前重验，不宣称抵抗任意不合作的同 UID 写者在最后一次重验和发布之间的竞态。

## TC-REAL-IB-INFO-LINK-REBOUND-001 — IB 分析输入链接的发布目录改绑

- Case ID：`TC-REAL-IB-INFO-LINK-REBOUND-001`；类型：real-environment / input-provenance / same-UID race；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。自动先决为 `test_cases.test_ib_analysis_domain.IbInfoLinkPublicationTests` 和 `offline_network_analysis` 多脚本 workflow；隔离本机测试通过不能证明真实分析目录与服务写者边界。
- 前置条件：只在 owner 授权的可丢弃 Ubuntu 24.04 VM、私有 0700 项目副本和独立输出目录执行；先保存 HEAD/tree、manifest/full-proof、ib-info 来源与旧绝对链接、输出目录/哨兵 dev/ino/mode/SHA、服务/分析进程状态、同 UID 写者静默见证及快照。不得碰真实项目的 `99-output-p2p`、客户 IB 快照或生产设备。
- 步骤与预期：用真实 `tools/ibdiagnet-analyze-tool/analyze.py` 对隔离 ib-info 源做正常发现，旧绝对链接须转成同源相对链接，新输入须创建正确相对链接；然后在暂存链接建立后、替换旧链接前，把可见输出目录移走并改绑到含同名暂存/目标哨兵的外部私有目录。应非零拒绝，外部哨兵字节/inode 保持不变，已移走目录的旧输入仍可辨认/恢复；不得把被改绑的路径展示为成功来源。记录精确 argv/exit、链接文字、源与目标的身份和摘要、目录重绑时序、前后服务状态及回滚。
- 清理与风险：恢复 VM 快照并逐项核对前像，只清理本案隔离目录。此实现将链接创建/替换约束在持有的输出目录描述符并重验可见目录；它不保证最后一次核验与发布之间面对任意不合作同 UID 写者的原子隔离，也不替代 REQ7 的受保护 IB 完成见证。缺 writer 静默、外部哨兵变化、旧链接无法恢复或未真机执行时保持 OPEN。

## TC-REAL-REQ7-IB-LOCAL-SOURCE-001 — 本地 IB 拓扑报告逐字节见证（不授予 cycle 资格）

- Case ID：`TC-REAL-REQ7-IB-LOCAL-SOURCE-001`；类型：real-environment / integration / input-provenance；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。本机自动化先决为 `test_cases.test_req7_ib_provenance`、`test_cases.test_req7_ib_provenance_workflow`、`test_cases.test_issue_tracker_ib_runtime` 与 `test_cases.test_issue_tracker_ib_runtime_workflow` 的 direct/workflow GREEN；这些本地结果不代替真实 IB 输入见证。
- 前置条件：只用 owner 许可的隔离 0700 stage 和经脱敏的真实 09:15 P2P、inventory、port map、splitter、profile 与 iblinkinfo 输入，或可丢弃 Ubuntu 24.04 Docker/VM 中的授权副本。先记录输入来源、权限、dev/ino/size/SHA、操作者、工具版本、候选 HEAD/tree、manifest/full-proof 状态及同 UID 写者静默窗口；不得写 live 项目、生产 UFM、真实 crontab 或管理服务器。
- 步骤与预期：真实转换器产生 CVT 和六源 provenance，真实 IB validator 产生报告和侧车，报告解码应保留 Missing 的空 actual、Miswired 的字面 actual。每次仅改变 P2P、CVT、iblinkinfo 或 profile 中一项的字节并恢复原 mtime，本地见证必须 fail closed；恢复前像后通过。向 `require_completed_ib_cycle` 传入看似合格的 prod cycle dict、UFM receipt 或 ACK 仍必须拒绝，不得写 `99-output-monitor`、修改模板或作网络发送。
- 证据、清理与风险：保存脱敏精确 argv/exit、输入/输出及侧车 SHA、负例拒绝、权限、前后目录清单和独立回滚核验；只清理该私有 stage 或恢复 VM 快照。若缺真实授权输入、writer 静默、前像/回滚证据、或有任何 live/生产副作用，保持 OPEN。此卡只证明本地报告边界，绝不证明受保护 collection cycle、K-window、三面板 QualifiedSet 或 C6 发布。

## TC-REAL-REQ7-IB-CYCLE-BINDING-001 — IB 报告接入受保护完成周期

- Case ID：`TC-REAL-REQ7-IB-CYCLE-BINDING-001`；类型：real-environment / protected-cycle / Stage-L；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。候选已有受保护生产者、worker/emitter 九角色边界、完成周期的只读重放、绑定真实本地 K 设置的 IB-only 只读窗口，以及从实读本地工作簿按计划 A/Z 节点作 W1 跳过的只读预览；早期 `test_cases.test_collection_ib_cycle_binding_workflow` 的九角色组合采用受保护重放函数替身，K/W1 正向归约也替换了受保护报告读取，不能证明根保护。后续独立 hermetic 工作流接入本地受保护九角色、三面板 C5/C6，但远端 UFM 检索仍为确定性替身，且未用 owner 管理的正式模板。三角色周期仍只诊断六角色缺口；任一本地绿色结果不得计作本卡现场验收。
- 前置条件：在 owner 另行批准的隔离 Ubuntu 24.04 VM 与可丢弃项目副本完成真实三面板采集，并记录 worker、completion、evidence/envelope、六个角色、F01 归档及安装态 attestation 的字节身份、根目录权限、writer 静默和快照。真实 UFM、生产 tracker、live 项目及 crontab 不在授权范围内。
- 步骤与预期：只有同一完成周期、同一项目、同一目标、同一 CVT 与真实安装态 attest 的报告可形成非自证的 IB source；替换任一 role、sidecar、完成摘要、输入或路径，或仅提供本地 receipt/ACK、复制九角色、改变 CVT 但保留 mtime，都必须拒绝。K 个连续合格周期要按同一 expected topology 逐周期重放，活动键只取交集且使用最近周期字面 actual；不同 issue type、拓扑漂移、Whitelist A/Z 命中和无历史均须按合同拒绝或保持冷态，不得凭伪造 dict 进入本地工作簿。
- 证据、清理与风险：保存脱敏启动/完成记录、角色与 sidecar 摘要、逐步故障注入、拒绝日志、目录前后快照及恢复核验；只在隔离 VM 回滚。本卡未实测或当前候选未接入 worker/F01/三面板正式消费点时一直 BLOCKED，绝不宣称 REQ7 Stage L 或 owner AIR/prod 已验收。

## TC-REAL-UFM-PRE-SOURCE-BRIDGE-001 — UFM 输入身份和本地归档的真实来源边界

- Case ID：`TC-REAL-UFM-PRE-SOURCE-BRIDGE-001`；类型：real-environment / input-provenance / local-archive；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。本机自动化先决为 `test_cases.test_ufm_input_contract`、`test_cases.test_ufm_collection_contract`、`test_cases.test_ufm_collection_agent` 与真实双脚本 `test_cases.test_ufm_local_archive_workflow` 全部 GREEN；这些测试不证明远端 UFM、安装态身份、受保护周期或 REQ7 Stage L。
- 前置条件：只在 owner 许可的隔离私有 0700 stage 或可丢弃 Ubuntu 24.04 VM 内，使用经授权的 UFM 输入副本；真实 UFM、live 项目、客户设备、管理服务器和生产 crontab 不在本卡授权范围内。登记候选 HEAD/tree、测试/manifest 身份、全量证明状态、操作者、隔离根及 CSV/global/lease/归档输入的 dev/ino/mode/size/SHA、工具版本、同 UID 写者静默与快照。任何真实远端连接需另行书面授权及主机密钥钉扎，不能由本卡推定。
- 步骤与预期：先让只读发现入口以一台及两台合成当前 DHCP lease 绑定 UFM CSV 与 `servers.ufm`，仅输出 `discovery_only`，明确 `ssh_identity_verified=false`、`license_mac_verified=false`、`vip_configured=false`；重分配、过期、重复、截断租约与无效 YAML/CSV 均非零拒绝且无 JSON 产品。随后在隔离节点副本运行本地 contract/agent，核对唯一单文件归档、成员/路径/mode/摘要与不变输入；篡改暂存、符号链接/祖先改绑、重复 run-id、超大成员和中断必须无外部写入、无成功 receipt。仅本地归档或人工复制 receipt 不得进入 worker 的六角色，也不得提升 IssueTracker 合格集。
- 证据、清理与风险：保留脱敏精确命令/退出码、拒绝类别、归档前后 SHA 与 inode、外部哨兵身份、权限、目录前后清单、writer 静默和快照回滚比对；只删除本卡隔离产物或恢复 VM 快照。若权限/静默/来源/恢复证据缺失，保持 OPEN。此卡不替代 D-70 真实远端 before/after SHA、独立 SSH host pin/current lease/安装态 attestation，也不解除 `TC-REAL-REQ7-IB-CYCLE-BINDING-001` 的 BLOCKED。

## TC-REAL-UFM-REMOTE-SOURCE-001 — UFM 管理身份、钉扎传输与归档来源

- Case ID：`TC-REAL-UFM-REMOTE-SOURCE-001`；类型：real-environment / remote-identity / pinned-transport；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本地先决为 `test_cases.test_ufm_jump_transport`、`test_cases.test_ufm_jump_transport_workflow`、`test_cases.test_ufm_identity_binding`、`test_cases.test_ufm_collection_archive_retrieval`、`test_cases.test_ufm_identity_binding_workflow`、`test_cases.test_ufm_remote_producer` 与 `test_cases.test_ufm_remote_producer_workflow` 全部 GREEN；合成 runner 的 GREEN 绝非远端实证。
- 前置条件：另获 owner 对可丢弃 UFM VM、跳板与管理网的逐节点、逐命令授权；目前无此授权，不得执行真实 SSH/SCP。先由独立渠道批准准确 known_hosts SHA 和真实主机密钥、当期 DHCP lease/CSV/global、已批准的远端 Python/agent/contract SHA、root 持有且 0600 的安装态、远端写者静默、备份/快照及回滚负责人；记录候选 HEAD/tree、全量证明、所有输入和输出 dev/ino/mode/size/SHA，不向公开日志写凭据或客户地址。
- 步骤与预期：只在授权范围以 key-only、`StrictHostKeyChecking=yes` 经固定跳板观测准确 hostname/management MAC/IP；重分配、过期/截断 lease、变更钉扎密钥或项目输入必须在任何 vendor agent 命令前拒绝。对已批准安装态逐路径观测 root 所有权、非组/世界可写及三个精确 SHA；调用固定绝对 Python+agent，仅用一次受控 run-id，验证远端最终文件在拉取前、后 SHA 一致、本地归档及身份重新验证一致。远端源变化、中断、半成品、路径改绑、目标并发占用必须无成功 receipt、无外部写入；不重试未知结果。
- 证据、清理与风险：保存脱敏 argv/exit、独立 host-pin 来源、lease/SSH/安装态前后摘要、远端前后及本地归档 SHA、负例拒绝、写者静默、节点和目录身份、快照恢复核验。只在批准的可丢弃节点卸载本卡产物并核对前像；不写生产 UFM/live 项目/真实 crontab。授权或任一物理证据缺失仍为 BLOCKED/NOT RUN；本卡即使完成也只证明归档来源，不证明六个 worker-owned IB 角色、受保护三面板同周期、REQ7 Stage L 或线上发布。

## TC-REAL-UFM-LOCAL-PIPELINE-001 — 本地 UFM 归档、IB 分析与展示来源

- Case ID：`TC-REAL-UFM-LOCAL-PIPELINE-001`；类型：real-environment / analyzer / display-sync；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本机先决为 `test_cases.test_ufm_collection_pipeline` direct 与 `test_cases.test_ufm_collection_pipeline_workflow` 多脚本全绿；当前候选的 24/24 本机通过只满足自动化先决，不替代真实来源、写者静默或恢复见证。本卡属于 F01 完整产品的后续验证；REQ7 PRE 仅可采用已独立证明的最小来源桥接，不得据此提前宣布 F01 完成。
- 前置条件：仅在 owner 明确批准的隔离 0700 stage 或可丢弃 Ubuntu 24.04 VM、经过授权的脱敏 UFM 归档和 P2P/CVT 副本上执行；保存候选 HEAD/tree、全量证明、归档/分析工具/项目目录/监控输出及外部哨兵的 dev/ino/mode/size/SHA、服务状态、同 UID 写者静默及快照。不得连接真实 UFM、写 live 项目或生产监控发布路径。
- 步骤与预期：用真实归档→分析器→receipt 的固定路径走正常一次，再分别在 receipt 前修改 P2P/CVT/日志、在同步时替换归档/父目录、重复 run-id 和跨项目复用；均须非零拒绝且原产品和外部哨兵不变。setup 管理的 `99-output-ufm` 仅允许精确项目目标的链接，遇已有普通文件应拒绝不覆盖；HTML 三面板只能展示本地逐字节验真的 receipt，任何缺失/篡改/旧周期一律显示未知而非成功。
- 证据、清理与风险：保留精确命令/退出码、归档、报告、receipt、页面与链接前后 SHA/身份、故障注入和恢复核对；仅回滚隔离副本。本卡未实测或完整 direct/workflow 有 RED 时保持 BLOCKED。页面展示不授予生产周期资格。

## TC-REAL-REQ7-IB-PRODUCER-001 — 受保护的 IB 生产者完成见证

- Case ID：`TC-REAL-REQ7-IB-PRODUCER-001`；类型：real-environment / protected worker-cycle / Stage L；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本机先决为 `test_cases.test_collection_ib_producer` direct、`test_cases.test_collection_ib_producer_workflow` 真实 worker/emitter 多脚本流程及 UFM 来源桥接全绿；单独 14/14 direct 或合成 runner 不能证明远端执行、受保护三面板或 Stage L。
- 前置条件：只在 owner 授权的可丢弃 Ubuntu 24.04 VM、私有 0700 项目与已获独立远端授权的 UFM 测试节点上运行；先核对 root 0600 安装态、known_hosts 钉扎、当期 DHCP lease、真实 P2P/CVT sidecar、远端 agent/contract/Python SHA、受保护 0700 attestation 目录与 worker 唯一写者静默。保存 HEAD/tree、proof、设备/服务/输入及目标 dev/ino/mode/size/SHA、快照及回滚责任人。不得改生产 UFM、真实 crontab 或 live 项目。
- 步骤与预期：让唯一 worker 为同一个 prod cycle 执行固定跳板、远端 before/after SHA、拉取、真实 IB 分析、六个独立角色和 no-overwrite root attestation；emitter、完成记录和 Stage L 消费点必须逐字节重放同一 cycle。分别替换根记录、租约、host pin、P2P/CVT、归档、报告、receipt、attestation 和任一角色后应 fail closed，旧周期/调用方字典/三角色周期均不得晋升。
- 证据、清理与风险：保存脱敏精确 argv/exit、前后身份/摘要、worker/emitter/protected-cycle 三方原始证据、负例及快照恢复核验；只回滚获准的隔离对象。远端授权/静默/任何保护证明缺失或未实测，保持 BLOCKED，不把本卡或本地测试视为 AIR/prod 验收。

## TC-REAL-REQ7-SWITCH-PROD-SOURCE-001 — ETH/NVLink 生产来源只读 K 窗口

- Case ID：`TC-REAL-REQ7-SWITCH-PROD-SOURCE-001`；类型：real-environment / protected-cycle / read-only source；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本机自动化先决为 `test_cases.test_issue_tracker_switch_info_source`、`test_cases.test_issue_tracker_switch_info_source_workflow`、`test_cases.test_issue_tracker_switch_runtime`、`test_cases.test_issue_tracker_switch_runtime_workflow`、`test_cases.test_issue_tracker_stage_l_consumer` 与 `test_cases.test_issue_tracker_stage_l_consumer_workflow` 的 direct/workflow 全绿；合成归档和 worker/emitter 测试不能证明真实交换机、受保护根或整套 Stage L。
- 前置条件：仅在 owner 单独授权的隔离 Ubuntu 24.04 VM、私有 0700 项目和经脱敏的真实 ETH/NVLink `info`、link 归档、CSV、inventory 与动态发现输入副本运行。记录同 UID 写者静默、worker/emitter 唯一写者、K 与 Whitelist 工作簿、HEAD/tree/full-proof、各输入及输出的 dev/ino/mode/size/SHA、快照和回滚负责人；不得连接生产设备、写 live 项目、真实 crontab 或线上 tracker。
- 步骤与预期：真实 worker/emitter 为两个连续 prod 周期冻结目标计划、子结果及完成记录；只读消费必须分别重建 ETH/NVLink 两类 Switch 来源、字面异常值和明确不适用项，以同一项目/K/Whitelist 归约，且 `qualified=false`、无 workbook/manifest/RECEIPT/在线写入。只有在同一受保护周期真实存在并可重放 IB report 九角色时，Switch 两来源加 IB 的只读绑定才可返回 `qualification_not_implemented` 的 HOLD 见证；**这仍缺独立 ETH Cabling 面板，绝非完整三面板 Stage L**。本地工作流中替换受保护 IB report 解码器的组合测试不能当作该实测。逐项替换 inventory、动态行、冻结计划、任一 info/link/IB report 角色、完成记录、K 或 Whitelist 后必须 HOLD，旧见证重验不得通过；同内容但不同受保护周期不得误判为 replay。IB 报告缺失时仍须全局 HOLD，不得以两个 Switch 来源代替其他面板。
- ETH Cabling 独立来源补充：在隔离授权环境以真实 prod worker/emitter 生成含第四个 activity role 的完成周期，按周期身份重建冻结 topology、DOT、inventory、alias、目标计划、运行时行和报告；只读 reader 返回逐条 ETH 链接观测状态且 `qualified=false`。本地三面板资格层另经重放才按 analyzer sheet 分组生成 Missing_Links/`Link Down` 或 Miswired_Links/`Mis-wiring` 的 C5 意图；只读 reader 自身不授予该权力。缺少第四 role、冻结 DOT/报告漂移、周期/sidecar 漂移必须 HOLD。若没有经独立重算的 P2P→LLDPQ 派生角色，`derivation=None`，即使 activity 行存在也不得称完整 ETH Cabling 面板，更不能执行本地工作簿或线上写入；本地合成 worker/emitter 绿色不能替代该真实见证。
- ETH Cabling K/W1 补充：在两个连续且来源完整的真实 prod 周期设置 K=2，按预期 A/Z 和完整状态、观察值逐值求交，仅向只读见证返回连续未变的问题值；观察值改变即不得沿用旧值。实读本地模板 `Whitelist` 任一端命中时只给含真实端点及匹配规则原文的可审计 skip，不进入后续候选；规则原文缺失或重放变化必须 HOLD，不能从排除结果反推或合成。改变 K、模板字节、任一冻结输入、旧见证或归档身份必须 HOLD。只读归约及 hermetic 正向仍非真实环境验收，本卡继续 BLOCKED/NOT RUN。
- 三来源组合补充：同一隔离真实完成周期必须同时具有 ETH/NVLink Switch、ETH 链接第四 role/P2P 派生和 IB 受保护报告九角色，三者 K/完成摘要/K 设置/W1 模板必须一致；任一角色缺失或不同周期均 HOLD。新增 hermetic 正向工作流使用本地受保护九角色 producer、真实 worker/emitter 完成记录和真实 K/Whitelist 重放，并可测试三面板 C5→C6；它仍以确定性检索替身代替远端 UFM，使用测试工作簿而非 owner 管理的正式模板，不能当成本卡真机或正式工作簿验收。本卡没有真实角色、正式输入与写者静默证据时保持 BLOCKED/NOT RUN。
- 证据、清理与风险：保留脱敏精确命令/退出码、周期和来源摘要、拒绝原因、前后目录/服务状态、写者静默与独立快照恢复核验；仅回滚隔离副本。真实格式或保护链未证明、发生任何外部写入或没有授权时保持 BLOCKED/NOT RUN。本卡只证明只读来源，不能解除 `TC-REAL-REQ7-IB-CYCLE-BINDING-001` 或本地 C5/C6/线上发布门禁。

## TC-REAL-REQ7-STAGE-L-C5-C6-001 — 受保护三面板到正式工作簿本地凭证

- Case ID：`TC-REAL-REQ7-STAGE-L-C5-C6-001`；类型：real-environment / protected-cycle / local-transaction；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本机自动化先决为 `test_cases.test_issue_tracker_ib_runtime`/`_workflow`、`test_cases.test_issue_tracker_switch_runtime`/`_workflow`、`test_cases.test_issue_tracker_stage_l_consumer`/`_workflow`、`test_cases.test_issue_tracker_manifest`/`_workflow`、`test_cases.test_issue_tracker_local_workbook`/`_workflow` 与 `test_cases.test_issue_tracker_local_workbook_commit`/`_workflow` 的 direct/workflow 全绿；只有同一逐字节候选的正式 Codex/Claude 两轮全量结果才可进入本卡。自动化正向夹具不等于远端真实来源、正式模板或线上写入。
- 前置条件：owner 另行授权隔离 Ubuntu 24.04 VM、私有 0700 stage、可丢弃项目与卷快照、唯一 LK-P 写者和可核验的同 UID 外部写者静默；选定 owner 管理的正式 `Issue_Tracker_Template_v1.xlsx`，逐字节记录其 dev/ino/mode/size/SHA 与 `Whitelist`/14 张工作表结构，不把模板搬入 Git，也不改 live/生产或线上 tracker。记录 K 设置、同周期受保护九角色 IB、ETH 第四 role/P2P 派生、两类 Switch inventory 中的 type/template 身份、完整 producer/worker/emitter root attestation 与完成记录的前像。缺任一来源、权限、回滚或全量证明即 STOP。
- 步骤与预期：在隔离副本连续完成所需 K 个 prod 周期；独立重放所有 role、完成摘要、K、W1、模板及来源时间，三面板必须只在来源完整时生成稳定 activity_key/operation_id；C5 manifest 仅含经重放的 upsert 意图和可审计 W1 skip，IB 活动键、ETH 真实端点、Switch 原始记录 ID 与各自匹配规则不得混同。持同一 ACTIVE token 将正式模板或前一个有效 RECEIPT 所绑定的工作簿投影至 ETH Cabling、IB Cabling、ETH&IB Switch 和 Update_History；被 W1 跳过项须在 preview、provenance 与 Update_History 可见，历史行绑定 C5 manifest_id 及受保护来源 UTC，且不得写回被排除的业务行。先 INTENT 再本地 XLSX RECEIPT，逐字核对 manifest_id、published SHA 与原始工作簿。无候选且无新 skip 或幂等重放不得意外创生代次；Priority 人工值、公式、其他表、旧凭证不得被静默覆盖。本地 RECEIPT 不授予线上发布资格。
- 负例与证据：分别漂移任一 IB 角色/attestation、ETH 派生、Switch type/template、K、W1、正式模板、操作员编辑 witness、既有 RECEIPT/发布文件，并在准备/INTENT/RECEIPT 与 fsync 边界注入失败；必须 fail closed、保留未解决 INTENT 且不得伪造 RECEIPT 或线上写入。真实 root worker 完成周期后还须核对 N=1 默认、显式 N 到期/未到期、禁用线上但本地独立、全局策略中途变化、来源 HOLD 与状态文件不可写时既不产生未授权本地代次也不改写采集结果。C-23 须另外核对同一 boot 上第二个及后续新周期只在相对 N 个唯一完成事件与共享最小间隔同时满足后准入，积压只投影当前合格集合、不补发历史 generation；跨 boot、时钟倒退、同周期重放、第二条 admission 缺失/篡改、C6 后但 admission fsync 前故障均 HOLD。还要直接调用底层 C6 路径尝试绕过共享准入，证明不会产生第二个无见证 RECEIPT。手动与重试路径也须证明共用同一 limiter；当前保守 HOLD 不能代替正向准入，这些现场证据未齐不得称 C-23 完成。`local_applied` 只表示本地 RECEIPT，不是在线 GO。保存脱敏 argv/exit、前后 inode/size/SHA、manifest、故障点、代次、负例拒绝、目录清单、写者静默和独立快照回滚比对；只恢复隔离副本。任何真机来源/正式模板/恢复证据缺失或尚未执行时保持 BLOCKED/NOT RUN；本卡完成也不替代 owner 单独裁定的 Stage O 在线编辑与发布。
- C-23 持久 C6／共享准入不一致的人工恢复（**NOT RUN / 不能自动修补**）：在隔离可丢弃项目与卷快照内，先验证唯一 LK-P 写者及同 UID 外部写者静默；分别见证 C6 RECEIPT 后无事件目录、事件目录不完整／不连续、事件无 C6 RECEIPT、代次集合不匹配、存储事件不能绑定 C6／周期、末事件不能绑定已发布 C6 六种终态；尤其在 C6 RECEIPT 持久化后、共享准入事件 fsync 前注入故障。预期 worker 状态 `reason=local_c6_terminal_admission_state` 且 `terminal_detail` 精确描述命中的条件，该 state root 的所有后续自动、手动及重试准入均 HOLD；重复完成周期 ID 与暂时 I/O 错误不得被错误标为终态。保留 RECEIPT、INTENT、已发布 XLSX、未匹配或缺失的事件目录及其原始 inode/size/SHA 和错误状态，不删除、不回填、不重命名、不复用旧代次，也不把已有 RECEIPT 猜成许可。操作员只读封存整个 state root、来源完成证明、模板与策略身份及隔离卷快照；若业务必须继续，须由 owner 另行明确批准从已核验来源建立**新的**项目/state 身份，再在独立私有 stage 重走正式验证与两轮全量门禁。原 state root 保持终止 HOLD 并留存审计，不在原目录内“修复”历史；未经另行授权不得用于 live、AIR 或生产。记录故障注入点、封存前后哈希、写者静默、拒绝路径、新旧身份隔离及快照清理证明。此卡未实测或 owner 未授权重建时，不得宣称恢复能力或 C-23 真实环境验收。
