# Real-environment acceptance cases

## TC-REAL-F02-LOCAL-GENERATION-001 — 本地配置代次的持久化与部分回放拒绝

- 方法 V2 后端补充（NOT RUN）：在另行授权的隔离存储中验证 ZTP/initial-setup 的
  私有 method receipt 与 replace-config V1 来源/schema 不能互借；非法方法来源必须
  在目录、锁及 journal 写入前拒绝。核对 V2 本地 pending → success/failed、旧观察
  不能撤销新代、receipt/replaceable pair 回放拒绝、10 个 fsync 故障点的 pending/HOLD
  和原像保留；独立 2270/14134 B canonical 最大正例接受、16 KiB 有限 wire 上界及
  任意低于正例的退化界不能通过 ACCEPTED。ZTP monitor 方法接入已补本地 direct 和
  真实周期流程，但 initial-setup 接入与完整方法生命周期仍 OPEN，不将本机
  合成 writer/reader 或 collector 边界 fixture 当作真机完成。
- ZTP 方法周期补充（NOT RUN）：在另行授权的隔离项目/设备核对所有采集任务
  提交前已持久发布本设备 pending/veto 严格整数代次；当前 parent、child
  manifest/marker、global/CSV 和本设备 YAML 的哈希/身份在同一次非交互 BatchMode
  采集前后仍相同。实际变更 DNS/NTP/timezone/key、替换当前发布 YAML 或 latest
  后，旧日志/收据不得晋升 config_apply、overall 或 handoff。保存完整命令/退出码、
  身份与受限 live/source 摘要、前后目录/文件身份及 journal/receipt 原像；恢复
  隔离项目与设备配置并确认无残留写者。本卡仍 NOT RUN，不授权真实设备写入。

- 类型：transaction / real-environment / isolated management filesystem；状态：**OPEN / NOT RUN**。本机先决为 `test_config_sync_authority.py` direct 与 `test_config_sync_authority_workflow.py` 的真实 manual writer → generation journal 流程；它们不证明真实设备、断电或整卷恢复。
- 前置：另行授权的可恢复隔离管理 VM/卷、脱敏项目和唯一受管写者；冻结 HEAD/tree、源码/测试/manifest、Python/平台身份、文件系统、UID/mode 与输入 SHA。禁止使用 live/AIR/prod、实际设备或真实服务。独立 S5 后端按 owner 窄豁免保持 owner-waived，不计 PASS。
- 步骤：执行真实配置写入前观察 pending/veto 及严格递增整数；确认后以同会话 BatchMode 身份和 live digest 产生本代回执，再使下一轮预检失败、交互身份不足或 teardown，旧成功不得重新成为当前。只读 preview 不得铸造或撤销代次。分别重放 journal、witness、writer witness 或旧 replaceable pair，必须拒绝并保留原像；合法 schema-v1 最大 journal 正例为独立 1852 B，有限读取上界 2048 B，低于正例的退化界必须拒绝，不能截断。
- 故障与证据：在受控临时文件 fsync、rename、目录 fsync、HOLD 删除及最终目录同步边界注入崩溃/错误/名称交换；重启后只能保留 HOLD/未知，不补造成功。记录完整 argv/exit、原始 traceback、物理日志顺序、前后 inode/size/SHA、owner/mode、目录清单和清理路径。最终同步时替换 journal/witness 也必须拒绝、保留外来对象并重新保留 HOLD。
- 消费端步骤：真实 worker 接纳后再撤销或启动下一代 pending，旧回执字节虽保留也不得继续晋升；篡改自身 generation/命名空间/摘要或 summary/target generation 均拒绝。读取 summary 期间换代必须在最终代次复核时撤销正向返回；移走本地历史后只读查询不得重建历史。保存 writer → worker 两端身份、回执原像和每次查询结果；本机 workflow 不替代本卡现场执行。
- 项目 teardown：在另行授权的隔离副本执行正式 unsetup，确认 V1/V2 旧成功在托管链接/清单删除前撤销，代次不增加且原回执保留；dry-run 不改动，缺失或不安全历史、HOLD、新写者/设备集合变动必须拒绝并保留链接/清单。保存前后完整目录身份、journal/witness/锁摘要、argv/退出码与服务/cron 清理见证；故障时保留隔离项目并按已授权恢复流程处理，不重放旧成功。本机 backend → unsetup 临时目录流程仅替代 runtime/cron 前提，不代替现场执行；本卡保持 NOT RUN。
- 同连接观察：在精确授权的隔离设备上验证 post-apply 的 hostname、所选 endpoint MAC 与 live NVUE 由同一次 BatchMode SSH 返回；两次连接之间的目标替换不得通过旧身份探针授权。缺少协议头、MAC/hostname 不符或 NVUE 非零退出使当前代 failed/veto，旧成功不得回放恢复。保存原始受限证据、同连接 argv/退出码和 journal 前后像；本机私有 shell 与 writer workflow 不等于现场执行，本卡仍 NOT RUN。
- 九阶段传输观察：在授权隔离设备核对 monitor 原 BatchMode SSH 的 live NVUE v1 frame 与实际命令退出，保留尾部换行及原始文本 SHA256；缺失、重复、截断、非零和不同连接的输出不得提供成功摘要。无 NVUE 的适用设备保留 unavailable/failed 诊断，不因此伪造配置收据或更改健康分类。该传输字段不是本地代次或完成权威；现场卡仍 NOT RUN，本机仅执行私有 fake SSH/remote shell。
- 配置 result v1：成功对象为闭合 23 字段，失败对象为闭合 16 字段且不携带成功证明；独立最大 canonical 正例 14331 B、固定有限读取预算 16384 B。在现场副本检查未知版本/成员、非严格类型和超限原始文件（含空白填充）拒绝且保留；退化预算小于最大合法正例时不得声称接受。保存 writer/worker 原始像与 journal 对应摘要，本机最大正例和真实 writer → worker 测试不替代本卡 NOT RUN 状态。
- 后台状态：成功状态保存自身证明后，使回执丢失或本地权威撤销，再重启 worker 并恢复原回执；该代旧成功须保持持久撤销。下一合法同源更高代次才可替代否决，不受旧状态未来墙钟影响。记录状态与 journal/receipt 三方原像、撤销记录及重启后结果；断电期间未持久化的状态不得猜作成功，本卡仍 NOT RUN。
- 观察者撤销竞态：在 worker 读取旧权威后、持写锁比较之前，让唯一受管配置写者启动新代次；旧代 compare-and-revoke 必须不改动新代次。旧状态仍精确绑定当前代时，撤销须持久写入本地 journal；回放旧状态与旧回执仍不得恢复成功。仅在本卡隔离副本故障注入，保留三方前后像和锁内比较结果。
- 状态发布耐久性：在隔离卷对 worker 状态的文件 fsync、原子替换、目录 fsync 边界注入断电或错误；已有像保留原字节/权限，首次发布失败不得遗留新成功。同步期间置换暂存文件为符号链接、硬链接、其他文件或改变权限，或置换最终状态，必须拒绝并保留外来对象，不回退覆盖它。本机 direct 与真实 writer → worker 的 I/O 故障注入已覆盖这些拒绝路径，但本卡断电执行仍 NOT RUN；留存持有 FD 与命名对象的前后身份、原始故障和恢复后状态。
- writer 发布耐久性：同样在 result/summary 的持有 FD、暂存命名对象、rename 和目录 fsync 边界注入置换/失败；不得采用或清除外来对象，已有像回退须保留原字节和权限，新建父目录项必须逐级同步。真实 result stage 被换成外来链接后，journal 只能维持 pending/veto，不得晋升成功。记录目录链、各持有/命名对象身份、前后像及拒绝路径；断电现场仍 NOT RUN。
- 发布权限边界：在隔离副本把旧 result/worker 状态或最终父目录改为 group/other 可写，或由另一受授权测试 UID 持有；发布必须拒绝并保留旧字节、inode 与权限，不得 chown/chmod 修补证据。文件同步后才改变父目录权限也须拒绝；worker 不允许请求可被其他主体写入的新状态 mode。本机以私有目录、真实 chmod 与模拟当前主体覆盖这些边界，不等于现场多 UID 验收；本卡仍 NOT RUN。
- 范围与清理：journal、witness 和持锁 writer witness 在同一恢复域；**不抵御三份镜像一起或整机/整卷回滚**，不得宣称独立防回滚后端。仅恢复隔离卷与自建对象，保留故障证据，核对原像与无残留写者。此卡 NOT RUN 不阻断 owner 授权的本地开发，但不构成发布证明或 F02 整体完成。

## TC-REAL-ISSUE-0007-ROLE-LINK-001 — J2 模板不强制物理链路 FEC/MTU

- Case ID：`TC-REAL-ISSUE-0007-ROLE-LINK-001`；类型：real-environment / Cumulus NVUE / link behavior；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。本机先决为 `test_cases.test_issue0007_role_link_contract` 的独立 direct 和 `test_cases.test_issue0007_role_link_workflow` 的真实生成器→发布脚本工作流 GREEN；本机合成通过不证明设备对省略字段的行为。
- 前置条件：仅在 owner 另行授权的可恢复隔离 Cumulus VM/交换机和脱敏项目副本执行。冻结精确 HEAD/tree、输入、生成 YAML、设备 NVUE/链路前像、平台及端口能力、服务状态、快照和回滚责任人；不得连接生产网络、真实客户设备、live 项目或真实 crontab。先确认验证端口允许短时中断。
- 步骤与预期：对八种角色各生成至少一份配置，分别覆盖普通 SWP、bond 成员、BGP 口、适用的非 localbond 分支和 breakout 父口；核对 23 个原纯 `fec: auto`/`mtu: 9216` 的模板块均不再产生 `link`，其 `type` 保留，12 个 breakout 模板块及渲染后的 `lanes-per-port` 保留。用真实发布入口验证 MAC 链接，再在隔离设备检查 `nv config show`、NVUE apply 退出码及链路状态；记录省略后的实际设备行为，不预设设备默认 FEC/MTU，也不把某个设备平台结论推广到其他型号。
- 证据、清理与风险：保存脱敏命令/退出码、配置与发布文件 SHA、端口和设备型号、应用前后 NVUE/链路状态、快照和恢复核验；仅回滚隔离对象并核对前像。任一角色/分支缺失、设备行为不明、无法恢复或未真机执行时保持 OPEN，不授权 AIR/prod 发布。

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
- 自动化先决：本卡现场验证前，必须先取得当前 exact candidate（同一逐字节未变整树）的 `test_req10b_services_keys_contract.py`、`test_req10b_services_keys_workflow.py`、`test_req10b_global_link_contract.py`、`test_req10b_global_link_workflow.py` 和完整 manifest 映射的 Codex 落地整树 full/check 证明，以及 Claude 在该逐字节未变整树上的 `--no-approve` full 结果；任一证明缺失、过期或树字节不一致即 STOP。真实测试不代替这些门禁。记录 HEAD/tree、全受管路径清单与摘要、平台/Python/NVOS 版本、命令选择、两轮 full 证明身份，不以旧候选或项目目录名代替逐字节绑定。
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

## TC-REAL-F02-2-001 — 每设备配置方法与执行者绑定

- 对应 F02-2；本地 direct 为 `test_dhcp_optional_contract.py`，跨真实脚本场景为
  `test_eth_jump_transport_workflow.py`。状态：**NOT RUN / REAL_ENV REQUIRED**。
- 前置条件：owner 分别批准的隔离 ETH、IB、NVL、server/UFM 目标及对应执行者，
  保存项目 CSV、每设备声明方法、实际执行器与启动前设备状态的 SHA256/身份快照。
- 对兼容方法分别留存设备级执行收据；对 ETH 声明 initial-setup、NVL 声明
  尚未实施的 initial-setup、IB 声明 ZTP 却进入 initial-setup 的反例，
  确认写入前拒绝且不产生伪成功。新增方法须先审查执行器兼容性再扩展矩阵。
- 清理：撤销隔离项目产生的候选配置、临时收据与临时账号，复核目标状态；
  不触碰 Production 设备。风险：错误方法可能覆盖设备配置或误报成功，
  本卡不授权真机执行。

## TC-REAL-F02-6-001 — 当前轮九阶段证据与交接一致性

- bootstrap 来源观察：私有真实固定 helper → 同一次完整 collector remote shell →
  共享 V1 decoder 已覆盖成功和持久 HOLD，来源 YAML 与 live 观察互不替代。真机 **NOT RUN**。
  精确授权后记录固定 noninteractive helper 命令、SSH 会话身份、helper/receipt/YAML
  owner/mode/no-follow、原始响应与完整退出码、当前本地代次和 live 摘要；缺失/拒绝/HOLD
  不得借旧来源晋升或阻断独立健康采集。清理只处理本案临时证据，不改历史成功文件或
  他方 pending writer；风险是旧 bootstrap 来源被误作当前配置成功，本卡不授权设备操作。
  来源 MAC 和清单身份须为合法 12 位或六组冒号格式，畸形输入不得归一化成有效身份。
  私有 manual/monitor 共同 decoder 反例已覆盖；真机仍 NOT RUN。

- 来源消费否决：私有 analyzer → JSON → HTML/机器流程覆盖本次来源缺失、严格布尔、
  摘要重放、原始 YAML 漂移及后续失联；来源必须同时绑定当前 BatchMode/live 和
  inventory 主接口，失败不借旧九阶段成功、不降低既有 failed。来源变化须产生独立
  快照，报告不保存原始 YAML 或新代次。真机 **NOT RUN**；精确授权后保留完整响应、
  同会话身份/摘要、前后报告与快照。沿用本卡清理和风险限制；这不替代本地代次与
  当前配置应用的因果证明，也不授权设备、服务或其他写者操作。

- 未采集当前轮：在精确授权后暂时禁用本案 SSH 采集或构造无采集资格的目标，保留旧
  九阶段成功快照；新报告须明示未验证的当前观察，overall/HTML/机器不得借旧阶段
  放行。恢复后仅凭实际同会话 BatchMode 身份和 live 证据再判定，保留旧快照及前后
  字节/inode/摘要。私有真实 load → 离线监控 → JSON → HTML workflow 已登记；真机
  NOT RUN，不因此取得设备/服务权限，不新建收据/代次或清除他方写者历史。

- 显式新观察否决：独立 direct 与真实 analyzer → report → HTML/机器 workflow 覆盖
  无手工配置 journal 的当前失败观察、闭合 schema、严格布尔、inventory 接口身份和
  digest；旧九阶段成功不得掩盖失败，所选 eth1 正例保留。真机仍 NOT RUN，需精确
  授权后保留实际 BatchMode 会话、原始 live 摘要与前后快照；不得据此铸造代次或应用
  成功，也不得清除原负向历史。与本案有关临时对象按原取证/清理合同处理。
  显式候选接口身份必须为合法映射；畸形的 falsy 值不能被当作没有映射而借主接口
  晋升。私有负例与合法空映射正例已登记，真机仍 NOT RUN。

- 类型资格：私有 direct 与真实报告写入 → HTML/机器判据 workflow 已证明 server/UFM、
  未知/空类型的九阶段成功声称不能成为 Switch/host 完成或类型组交接；六类已支持
  交换机正例保留。真实 server/UFM 部署属于既有独立合同，本地反例不取得远端权限，
  不放行尚未实施的 eth_jump schema，也不构成真实设备验收，仍 NOT RUN。

- 第二轮总体状态一致性：私有 direct 覆盖九阶段各自缺失、无效、无时区及过期时间，
  真实监控报告写入 → HTML/机器判据 workflow 核对总体不成功、无交接、诊断与旧快照
  保留，以及新鲜可比证据恢复。该本地证据没有铸造配置来源收据或真机代际；真机
  当前轮各阶段来源仍须另取证，仍 NOT RUN。

- 离线静态入口：私有真实 load → release → validate_monitor_mode → monitor_once
  已覆盖可信 disabled 无 DHCP 文件、传入但不读取的旧路径、enabled 正反例和入口后
  release 模式切换。离线绝不访问设备或服务、不放行完成交接；该本地证据不等于
  真机验收，真实目标仍 NOT RUN，也不因此取得文件移除、服务或设备权限。

- 独立健康分类：对分别受授权的 ETH/IB/NVL、没有本轮 ZTP 完成的合法监控目标，运行
  已有信息采集 → 页面流程，核对新鲜 OK、Not OK 和缺健康证据各自显示健康/异常/未知；
  九阶段未完成、配置收据缺失不能阻断该分类，也不能因此自动变成 overall success 或
  触发 handoff。保留完整信息文件、采集身份/时间、页面和九阶段 report；失败后确认本案
  临时锁清理，不清除历史来源。私有真实 shell workflow 已登记在
  `test_ztp_group_handoff_display.py`；真机仍 NOT RUN，本条不授权采集或设备操作。

- DHCP 模式跨真实 load/release → 监控轮次的静态路径：在单独授权的隔离部署机将当前
  parent release/global 置为 disabled，并保留旧租约/日志，再移走仅本案旧来源副本；两轮
  监控均不打开本地 DHCP 日志/租约，不查询 DHCP 服务，仍对同一静态设备做独立 SSH
  和 Apache 观察。恢复 enabled 的受管 release 后正向核对 DHCPACK 与服务观察。
  留存来源 open/argv 见证、report.dhcp_status、归属 input_digests、前后 inode/size/SHA，
  不因 disabled 凭空放行九阶段/handoff。本机 `test_config_sync_authority_workflow.py`
  已有实际 load/monitor_once 私有流程；真机步骤仍 NOT RUN，不授权服务切换。

- 对应 F02-6；自动化 direct 为 `test_ztp_group_handoff.py`，跨真实脚本场景为
  `test_ztp_group_handoff.py` 与 `test_ztp_group_handoff_display.py`。状态：**NOT RUN / REAL_ENV REQUIRED**。
- 前置条件：owner 单独批准的隔离项目、受控交换机及采集窗口；保存监控脚本与页面生成器的
  SHA256、设备启动 ID、服务器本地轮次边界、九阶段来源收据和采集器启动前状态。
- 先产生 `complete=skipped`、未应用的 DNS/NTP/timezone/key、缺时间戳与上一轮旧阶段证据；
  逐一留存 `report.json`、HTML 页面和交接状态，均不得显示完成或启动该类型采集。
- 再完成同一轮九阶段并留存各阶段时间、来源与 `success_index`；允许有界手工时钟偏差，
  超界仅在精确命令日志 SHA256 与本轮 HTTP/bootstrap 证据共同绑定时接受。页面与机器
  判据必须同时转为完成，且该类型采集只执行一次；篡改摘要或把旧阶段伪造成当前索引须拒绝。
- 历史负例：已有快照不可读、JSON 非对象、devices 非列表、大小写重复主机，以及四个
  身份/晋升/轮次否决字段为 0/null/空串/容器，均不得因假值或后续轮询显示完成、开启采集。
  留存原损坏字节、连续两轮 JSON/CSV/Markdown 与 HTML 否决诊断；只在隔离项目注入，
  不清除真实历史来制造首轮。此增补仍 NOT RUN，本地临时目录回放不能替代现场证据。
- 保存采集命令/退出码、归档、交接签名和重启后的幂等结果。只清理本案私有项目/测试产物，
  不清理线上采集状态。风险：错误晋升会提前触发真实设备采集；本卡不授权执行。

## TC-REAL-F02-7-001 — 配置同步的同会话身份与 live-state 晋升

- 对应 F02-7；状态：**NOT RUN / REAL_ENV REQUIRED**。前置条件是 owner 单独批准的隔离
  Switch/host、受控项目和可回滚窗口；记录脚本/发布配置摘要、目标身份和启动前 live-state，
  不读取或归档私钥。server/UFM 不作为 Switch Status 设备或类型组 handoff 成员。
- 在同一配置同步执行会话中，保存 apply/save 命令退出码、随后非交互 BatchMode 再认证的
  目标 IP/接口/host-key 证据、`nv config show` 原始 SHA256 和去不可观测字段后的语义比对。
  只有再认证同一目标且 live-state 与发布配置匹配，才允许生成可晋升收据和成功状态。
- monitor 自己的同一次 BatchMode 采集须记录唯一 hostname/MAC frame、完整 hostname、
  选定管理接口 MAC 和当次 live digest；核对没有 eth1 的设备仍可按 eth0 取得观察，
  过渡 hostname、重复 frame 和错误接口不可取得配置证明。观察字段本身不是当前代次
  的持久成功收据，本卡仍为 NOT RUN，未授权真实设备操作。
- 当前 manual-config-sync 消费端另外核对采集前本地 generation、唯一安全当前回执及
  当次独立身份/live 摘要；在采集、读取回执后与 compare-and-revoke 边界分别启动新
  pending 写者，旧观察不得撤销新代或显示旧成功。关闭采集和既有 pending 不改写写者
  历史；漂移、缺回执、权限错误与重复当前回执须否决并保留原字节。匹配回执仅允许
  config_apply，不借旧日志完成九阶段；保留 report/HTML/handoff 与 journal 前后证据。
  本地自动化为 `test_config_sync_authority_workflow.py`，含真实 monitor_once/report 写入；
  上述真机并发、持久化与显示联动仍 NOT RUN，测试注入只在私有副本，清理不触及线上状态。
- 独立来源：bootstrap helper 缺失时，当前安全手工回执和该轮自身 BatchMode/live
  一致仍可显示 config_apply；不得放行 complete/HTML/handoff。畸形代次、摘要漂移、
  来源不匹配和非严格布尔仍拒绝，既有 failed 保留。私有实际 writer/collector/report
  自动化已覆盖；真机 **NOT RUN**，沿用本卡授权、留证、清理和风险限制。
- 分别注入交互密码认证、再认证失败、身份/路径变更、空 live-state、实际配置漂移、旧收据
  重放与收据摘要篡改；这些情况即使命令曾返回 0，worker 和页面也不得晋升成功。
- 保存 result/summary、worker 状态、页面与归档的前后摘要及拒绝原因。只清理本案隔离
  项目副本，设备配置按事先批准的回滚源恢复并复核；风险是错误成功会掩盖实际配置漂移。

## TC-REAL-F02-PUBLICATION-HOLD-001 — 应用/升级前撤销与监控负向否决

- 对应 F02-8/9；类型：transaction / integration / real-environment；状态：**NOT RUN / REAL_ENV REQUIRED**。
  本地 direct：`test_ztp_applied_receipt.py`、`test_monitor_stack_review.py`；多真实脚本 workflow：
  `test_manual_applied_config.py` 的 bootstrap→固定 helper→manual reader / monitor analyzer。
- 目标与前置：仅在另行精确授权的可丢弃 Cumulus/IB/NVL 设备及 SN/VX 升级环境执行；
  先记录 HEAD/tree、源码/渲染脚本/镜像 SHA、root 身份与文件系统、原收据/YAML/日志的
  inode/模式/大小/SHA、可恢复镜像和配置快照、单写者窗口与恢复责任人。禁止在在线设备注入。
- 步骤/预期：见证首个 NVUE 写入或 onie-install/reboot 前受控 HOLD 的文件与目录 fsync；
  在后续 staging、数据/收据 rename、最后目录 fsync 和 guard 清理边界注入失败。原收据即使
  与新 YAML 同字节也不得可信，helper 不输出成功，manual 不晋升，monitor 的 config_apply/
  complete 及 HTML/机器判据不显示成功。既存或被替换的外来 HOLD 保留并在写入前拒绝；
  只有本次 held 身份完成持久发布后才清理。旧 saved 日志、未知状态、不安全来源不可清除新 HOLD。
- 故障/证据/清理：保存脱敏命令/退出码、物理日志顺序、写入与刷盘故障点、前后文件身份、
  重启后 guard 保留及只读拒绝证据。只按授权快照回滚镜像与配置；不得为恢复成功删除 HOLD。
  本地安装/重启采用受控替身，真机仍 NOT RUN；负向 guard 不替代设备 generation/veto、
  同会话 BatchMode/live digest、回放/回滚拒绝或 F02 整项验收，也不授权生产发布。

## TC-REAL-F02-8-001 — 设备收据持久化、断电边界与读取身份

- 对应 F02-8；状态：**NOT RUN / REAL_ENV REQUIRED**。本地 direct 为
  `test_ztp_applied_receipt.py`，真实脚本 workflow 为
  `test_bootstrap_config_fetch_workflow.py`；两者不能替代隔离设备文件系统的断电验证。
- 前置条件：owner 另行批准的可恢复隔离 Cumulus/NVOS 设备或同文件系统特性的 VM；冻结
  HEAD/tree、bootstrap 模板及渲染脚本 SHA256、Python/coreutils 版本、设备文件系统类型、
  旧 `last-success.yaml`/`receipt.env` 的 inode/大小/SHA256、root 属主和权限，以及完整快照。
  不在 AIR/Production、真实客户设备或在线项目注入故障。
- 正向：写入 schema-1 最大合法 608 字节收据及匹配 YAML，确认固定 helper 原样接受，
  `fsync` 暂存文件、数据 rename 后目录和收据 rename 后目录均成功；检查 single-link、0600、
  受管 0711 目录及同源摘要。上界须由 schema 重新核算，不把本卡数值推广到后续版本。
- 拒绝：在暂存 fsync、数据目录 fsync 和收据目录 fsync 各边界分别故障注入并恢复快照；
  检查旧收据不被静默晋升、临时文件清理、旧收据／新 YAML 不匹配时读取失败。
  超限和上界低于合法正例时拒绝且不截断；软／硬链接、属主／权限错误、旧收据重放、
  generation 回退或撤销后再出现旧成功均不得取得当前权威。
- 证据与清理：保存脱敏命令/退出码、fsync/rename 顺序、故障注入点、文件身份与摘要、
  helper 输出和恢复后前像；只恢复隔离设备快照。当前仅大小、fsync、硬链接和管理端
  闭合 schema 的本地切片已验证；generation/veto、回放／回滚拒绝及本卡真机步骤均保持 OPEN。

## TC-REAL-F02-INITIAL-METHOD-001 — initial-setup 非交互配置观察

- 状态：**NOT RUN / REAL_ENV REQUIRED**；本地 direct 为
  `test_req10b_services_keys_contract.py`，真实脚本 workflow 为
  `test_req10b_services_keys_workflow.py`。本地只在隔离目录执行替代 SSH 的真实 shell，
  不连接真实设备；管理 main 的本地 pending/观察/发布/撤销已覆盖，不关闭消费端或 F02。
  本地消费端原语另验证 current-era latch → fresh observer 投影 → monitor/HTML 完成拒绝；
  monitor_once 本地入口另验证显式输入、前后绑定、晚期漂移、旧代撤销和较新写者保留；
  runtime/release 与远端 I/O 使用隔离替代，真机仍须核验真实项目输入与本轮实际 BatchMode 观察。
  本地 cache/parser 只消费同一次 owned/no-follow held 读取捕获的有限不可变像；
  cache/CSV/P2P/global/公钥在捕获后换绑外部文件或 FIFO 的负例不得重新打开该路径，
  必须拒绝本轮资格、保留外部字节、不创建方法权威；真机仍保持 NOT RUN。
  本地实际 unsetup 入口持排他部署锁，受管 initial CLI 必须在叶脚本输出/设备操作前拒绝；
  正常入口持共享部署锁直到方法收据撤销与报告清理结束，异常退出后释放锁。
  真机还须验证 load/setup/unsetup 与受管入口的互斥窗口，不据本地锁联测宣称已运行。
- 前置：owner 精确授权的可恢复 IB 隔离设备、管理主机和输入项目；冻结 HEAD/tree、
  CSV/P2P/global/cache/公钥摘要，管理私钥 owned 0600 single-link，固定 eth0 MAC/IP，
  已授权的 initial-setup 操作；只通过显式项目的管理入口和逐 IB `config_method=initial-setup`
  获取 V2 方法权威，原单文件离线入口不提供该权威。NVL 在支持合同建立前显式拒绝。
  非缺省布局须通过 `--tool-inputs` 显式绑定项目内 global/publickey 目录，留存目录身份、
  原像与摘要；不执行其中的代码，外部或不安全目录在输出/设备操作前拒绝。
- 正向：保留原独立密钥登录探针；再用 public-key-only BatchMode 的同一会话读取
  hostname/eth0 MAC、`nv config show -o commands`、当前 authorized_keys。逐项核验
  本设备 Day-0、DNS/NTP/timezone 和所需公钥，不凭交互日志或旧收据晋升。
- 负向：独立制造一项配置/公钥漂移、会话失败、输入中途变化、管理密钥替换；
  必须保持未知/失败并撤销同代当前成功，不补造 bootstrap/complete/handoff。
  保存完整脱敏输出、退出码、当前代次与绑定摘要；私钥内容和密码不得进入证据。
- 风险与清理：本观察只读，制造漂移及执行 initial-setup 写入属于另行授权的设备操作。
  只恢复所批准隔离目标的配置/公钥前像；本地方法文件不能宣称抗整卷回滚。

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
  对应 F02-5 独立 HTTP 来源、endpoint/address convergence 与 REQ-14 port；状态：**NOT RUN / REAL_ENV REQUIRED**。
  本机 direct/workflow 只证明解析、计划、写前拒绝和配置字节，不能证明真实接口归属、Apache bind、
  Docker/Supervisor 启停及健康检查。
- 前置条件：仅在 owner 后续批准的隔离 Native 与 Docker 管理 VM 中运行；每台具备可回滚的接口、
  Apache/容器/项目快照、独立控制台及不与生产互通的两枚单播测试 IPv4。冻结同一干净候选的
  HEAD/tree、源码/测试/manifest/ledger、global YAML、接口名称与 ifindex、地址/路由、服务配置
  摘要；记录 80 与非默认 8080 的端口占用前像。不得使用生产地址、凭据、设备或服务。
- 正向矩阵：分别运行没有 ZTP endpoint 的 `common.mgmt.http.address` HTTP-only 项目，以及 HTTP
  地址与 ZTP endpoint 相等和不等的项目。Native 与 Docker 均须只生成显式 HTTP 地址对应的
  单条 `Listen <IP>:<port>`，即使 ZTP endpoint 不同也不得为其另开 HTTP listener；DHCP
  地址来源与 HTTP listener 身份仍各自独立。HTTP-only 只启动 Apache，不产生 DHCP/ZTP worker、DORA 或
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

## TC-REAL-REQ19-INFRA-LOG-RECOVERY-001 — 项目日志恢复与跨设备迁移边界

- Case ID：`TC-REAL-REQ19-INFRA-LOG-RECOVERY-001`；类型：real-environment / transaction / disaster-recovery / scenario；对应 REQ-19 R19-2、R19-2a、R19-3、R19-3a、R19-4、R19-5、R19-7a。状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本机 `test_cases.test_req19_infra_log_contract` direct 与 `test_cases.test_req19_infra_log_workflow` 多真实脚本 workflow 是自动化先决，不能代替真实文件系统、断电和现场日志归属见证；本卡迄今未运行。旧聚合只读盘点记录的是实现前 `infra/logs` 存量，不是本卡的恢复或跨设备验收。
- 风险与目标：`infra/logs` 的真实目录迁移跨越 `01-a-setup.py`、`infra-setup.sh`、`check_infra.py`、`deploy_infra.py` 的写者/读者边界。掉电、目标重名、恢复凭据损坏或跨设备硬链接失败可能造成日志丢失、重复归属，或将旧项目日志标成新项目。目标是证明失败时原目录与可核验恢复证据仍在，不覆盖已有目标；只有完整迁移后才可宣称项目归属。
- 前置条件与输入：仅在 owner 另行书面授权的一次性、隔离、可回滚 Ubuntu Native 管理 VM 与无客户数据的两个合成项目上执行；若拟支持 Docker/独立挂载卷，须对该实际后端另取证。先绑定干净候选 HEAD/tree、manifest、测试与正式验证证明、OS/文件系统/挂载身份、EUID、deployment lock、服务/写者 PID、VM 快照和恢复责任人。`infra/logs` 初始为含顶层及嵌套普通文件的真实目录，目标 `<项目>/99-output-infra` 仅含模板 `.gitkeep`；另准备含已知不同 SHA-256 的目标重名负例。两个项目、源目录与项目输出目录的路径、`st_dev`/inode/mode/owner 及脱敏文件清单先独立记录。整个读—迁—校验—重指窗口须停止其它日志写者；不能在生产、live 项目、客户设备或真实 cron 上故障注入。
- 同设备正向：在源与目标 `st_dev` 相同的隔离卷上，先允许无项目的 `infra-setup.sh` 写入真实 `infra/logs`；随后执行获准的 setup/load。核对 `.logs-migration.json` 在首次文件转移前已持久发布，清单和源身份与前像一致；完成后 `infra/logs` 为词法与解析目标都指向当前项目真实 `99-output-infra` 的规范链接，目标各文件大小/SHA-256 等于独立前像，原目录备份 `.logs-migration-source` 与凭据按提交阶段安全结清。`check_infra.py` 的 `log.file=logs/<basename>` 保留词法路径，同时 `log.owner.project` 绑定项目；`deploy_infra.py` 写入本项目。切到第二项目后旧日志仍只在第一项目、绝不移动或重归属。
- 故障与恢复：只在 VM 快照副本上，于凭据发布前后、首个/第二个文件转移、目录改名后建链前、建链后 manifest 提交前，以及 `finalizing` 清理期间分别注入进程中断/断电并冷启动。每个 checkpoint 保存退出码、时间线、`infra/logs` 类型、`.logs-migration.json` 与 `.logs-migration-source` 的身份/内容摘要、两侧逐文件 SHA-256、manifest 和服务前后像。待决凭据或孤儿 `.logs-migration.*` 存在时写者与采集者须 fail closed；恢复或重试须按绑定项目身份进行，不覆盖目标、不把未核验副本删除；无法自动恢复时保留原目录和证据、停止操作并交 owner 判定。重名、链接/特殊源对象、悬空/外部日志链接、凭据不符及恢复路径竞争均须在越界写入前拒绝；unsetup 不得掩盖待决迁移。
- 支持范围裁定：2026-10-07 owner 明确要求 **限定同文件系统、跨设备明确拒绝**。该裁定只限定真实目录迁移，不改变规范链接重指不移动旧项目内容的合同，不授权真实挂载、VM 或生产操作。本地 direct/workflow 验证源根、源父目录、目标根与两侧嵌套对象的设备身份；跨设备必须在凭据发布和首次转移之前以明确 `EXDEV` 拒绝，空源目录也拒绝，不产生新迁移凭据、备份或已提交项目链接，源字节及 inode 保留。拒绝后项目前写者与采集者仍可使用真实日志根并报告未归属。已存在的中断迁移凭据不能删除或绕过，恢复和清理仍须依绑定身份及原合同进行。
- 跨设备边界：在同一隔离 VM 的两个真实挂载文件系统上证明源与 `99-output-infra` 的 `st_dev` 不同，验证上述 fail closed 拒绝及源保留；不得用 mock 出的 `EXDEV` 或设备身份代替真实现场证据。本卡仍为 BLOCKED / NOT RUN / REAL_ENV REQUIRED，未运行。记录真实 errno、源与目标清单/SHA-256、凭据和链接状态，重试不得覆盖或误归属。跨设备正向迁移不在裁定后的支持范围内，拒绝证据不得称作跨设备正向成功；同设备断电恢复仍需按前述授权另行执行，不能手工复制、删凭据或以禁用错误掩盖缺口。
- 证据、清理与风险：在私有 0700 证据目录保存脱敏 argv、退出码、时间线、HEAD/tree/manifest/proof、`st_dev`/inode/mode/owner、链接词法及解析目标、receipt 阶段、文件名与大小/SHA-256、服务/写者静默证明、快照恢复回执；不回传日志正文、客户配置或凭据。仅恢复隔离 VM 快照与合成项目，逐项核对目录、服务、挂载和链接前像；证据未充分封存前不得删除残留源或目标。任一同设备故障窗口、跨设备结果、项目归属、清理或 owner 授权缺失，均保持 **BLOCKED / NOT RUN / REAL_ENV REQUIRED**，不授权 AIR/prod 发布。

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

## TC-REAL-R22-DHCP-C2-TRANSACTION-001 — C1 私有候选至父 release 提交

- Case ID：`TC-REAL-R22-DHCP-C2-TRANSACTION-001`；类型：real-environment / transaction / service；状态：**OPEN / NOT RUN / REAL_ENV REQUIRED**。自动先决为 `test_cases.test_load_release_transaction` 的 C1 私有候选、C2 拒绝、发布失败和旧 inode 回滚 direct，以及 `test_cases.test_dhcp_optional_workflow`、`test_cases.test_dhcp_switch_scope_preservation_workflow` 多脚本 GREEN；本机结果不是本卡 PASS。
- 前置条件：仅在 owner 明确批准的可丢弃管理 VM 与隔离项目副本执行；冻结 HEAD/tree、manifest、正式 full proof、C1/C2 源码与测试 SHA，保存五个受管输出、父 release、当前服务/监听/租约的 dev/ino/mode/mtime/SHA 前像和可恢复快照。非协作同 UID 写者须在整个窗口静默；不得触及真实 `/etc/dhcp`、客户项目或线上服务。
- 步骤与预期：先验证健康 A 父 release 可激活；将合法 subnet 输入改为 B，执行真实 `11-load.py`→`c1-generate_dhcp.py`→`90-c2-generate_configs.py`。在 C1 完成、C2 前注入受控拒绝，五个公开输出及 A 父 release 内容、inode、mtime 均应保持不变，B 只能在私有 0700 候选中，服务仍保持原健康态。再次运行正常链，检查五个 B 输出与新父 release、实际 Native `/etc/dhcp` 安装及 `dhcpd -t` 对齐；分别注入 C2 失败、DHCP 第 2 个文件替换失败、父 release 验证失败，逐项证明 A 的原 inode/字节恢复、无混代 manifest、私有候选清理且未启动半成品服务。
- 证据、清理与风险：保存脱敏精确 argv/exit、锁与写者静默见证、C1/C2/父 release 时间线、五文件和候选目录前后身份/SHA、服务与监听前后像、注入点、回滚日志；按 VM 快照恢复并逐项核对 A。若需触碰真实服务、缺独立快照/正式证明/写者静默、未实际验证 Native 安装，保持 OPEN，不能以本机测试代替真机证据。

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
- 来源及输出祖先身份扩展（仍 **NOT RUN**）：在隔离副本保留正常归档→真实分析器→收据流程，分别于持有归档读取期间及收据发布前替换归档或项目输出的上级目录；覆盖符号链接回指原 inode，以及真实上级目录替换但原归档/直接父目录或项目 inode 不变。输出目录链须从分析开始保持到发布结束，reader 读取期间也须保持原链。须拒绝成功收据，原归档逐字节保留，receipt reader 与 HTML 不得展示成功。逐级 FD/no-follow 本机证据只证明本地检测；它不提供非协作同 UID 写者在最后检查后任意改名的原子防护，现场仍须记录写者静默。没有省略原有自动化用例，也未以模拟替换冒充断电或设备验收。
- ibdiagnet 扩展（仍 **BLOCKED / NOT RUN**）：`test_cases.test_ufm_ibdiagnet_pipeline` direct 与 `test_cases.test_ufm_ibdiagnet_pipeline_workflow` 用合成设备归档走真实本地分析器；现场须另由 owner 授权已脱敏的真实 `ibdiagnet2` 归档及匹配 CVT，确认归档仅含单个 `artifact/` 快照、无链接/遍历/重复路径，记录压缩前后大小、成员与归档 SHA、分析报告/sidecar/receipt 的 inode/size/SHA。分别以受控坏归档、缺失 `ibdiagnet2.net_dump`、同 run-id 重放、分析期间输入漂移及写者冲突见证无成功 receipt；隔离 stage 与项目快照需可回滚且不碰真实 UFM、live 项目或生产监控。此本地卡不授权远端 ibdiagnet 执行、周期任务或 UI 按钮，也不证明 REQ-F01 完整落地。

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

## TC-REAL-REQ7-FIXED-PRIVATE-INPUTS-001 — 固定路径单次 held-FD 私有输入

- 当前项目／计数联动补充（**NOT RUN**）：在实际 ACTIVE LK-P 与全表 owner 下，单次 held 项目 FD 读取 `01-global.yaml`，重核原 inode/stat/name，消费固定 allowlist FD 读取器，不接收 caller document/path 或环境覆盖。目标／N／原 allowlist 字节变化、撤销、缺失、读中改写或替换均 HOLD；计数前拒绝不新增意图，计数后失败保留 UNKNOWN 与原件，不重新组批。本地真实 C5/C6 ETH／IB 六次计数故障流程和项目锁／固定 FD workflow 只合成读取边界 root 元数据；原 C6 使用本机真实身份。现场另获隔离读取／故障注入权限后留存双锁、当前策略／allowlist 身份、完整屏障顺序和退出码；只撤销自有故障，不修复／删除真实原件或 UNKNOWN。native root、RO bind、实际在线发送和整项仍须另证。

- Case ID：`TC-REAL-REQ7-FIXED-PRIVATE-INPUTS-001`；类型：real-environment / native identity / read-only bind；对应 C-1/C-2/C-10/C-11；状态：**NOT RUN / REAL_ENV REQUIRED**。自动化 `test_issue_tracker_credential_shape` 与 `test_issue_tracker_credential_fd` 的 direct 和真实策略／枚举 workflow 仅在拥有的临时树中重映射根目录 open、合成 uid 0 元数据；不代表真 root 身份或真实 RO bind。
- 前置条件与权限：owner 另行明确授权可丢弃 Linux 容器／VM、私有固定目录与假凭据副本、卷快照、唯一 root worker 和回滚负责人；记录精确源码／测试／manifest／Python／平台及同树证明。未获授权不读取真实凭据，不改挂载、文件属主或权限，不启动容器或服务，不碰 AIR/prod/live；真机未运行不作为本地主树推进门槛。
- 步骤与独立预期：在授权隔离副本检查 `/var/lib/http-ztp-container/service-account/` root 0700、`cre.json` 与 `issue-tracker-spreadsheet-whitelist.json` root 0600、nlink 1 和同路径 RO bind。非 root 必须在任何 open/read 前拒绝；每级祖先无链接、root 所有且非组／世界可写。相对 held-FD 打开，单次有界 read 后重核文件与每条祖先名字绑定；FIFO、坏权限、硬／软链接、超界、短读、读中修改／替换、关闭失败和缺失内核 flag 均拒绝且不修复、不回退、不重开路径。环境 ADC／私有路径变量不能重定向。
- 解析与流程预期：原始 Google 下载件仅作为严格有界 mapping 输入；固定 token endpoint／Sheets scope，非默认 universe、delegation、额外 claims、未知字段与重复 JSON 字段拒绝。白名单仅接受精确顶层字符串数组；空数组合法但拒绝所有目标，项目 enabled 配置不能创造枚举，策略或原始字节变化拒绝旧绑定。此部件不验证私钥签名、不导入 SDK、不刷新令牌、不授予发送许可；SDK、传输、真实目标和 Stage O 另证。
- 证据、故障与清理：只保留脱敏目录／文件／FD 身份、单读调用计数、输入长度／摘要、精确命令与退出码、权限／绑定负例、原像与恢复核验。凭据字节、令牌、私钥、邮箱及匹配值不得进入日志／异常／公开状态；不回传私有 mapping。仅回滚获准的隔离卷快照，核对原件与外部哨兵不变；现场权限、RO bind 或回滚证据缺失仍 NOT RUN。

## TC-REAL-REQ7-SDK-DEPENDENCIES-001 — 精确依赖闭包的两架构镜像核验

- Case ID：`TC-REAL-REQ7-SDK-DEPENDENCIES-001`；类型：real-environment / dependency / image-build；对应 REQ7 C-14 / T6-A。状态：**NOT RUN / REAL_ENV REQUIRED**。自动化 `test_req7_dependency_contract.py` direct 与 `test_req7_dependency_workflow.py` 真实校验库 → activation/runner 流程仅证明本地策略/锁及元数据，不代表 SDK 鉴权、Linux wheel 已执行或整个 REQ7 完成。
- 平台、前置条件与权限：仅另获 owner 精确授权的一次性 Linux CPython 3.12 aarch64 / x86_64 构建环境；准备当前干净 HEAD/tree、manifest、适用同树 full proof 和回滚快照。没有授权不得 build/start/reload/deploy，不读真实凭据或线上表，不操作宿主服务。
- 步骤与独立预期：分别从当前政策/锁以 wheels-only / no-deps / require-hashes 构建，保存实际选中的六个 artifact 文件名/SHA256、Python/SSL/平台和分发版本；执行 build-time `verify-python-runtime`、`verify-req7-python-runtime`，比对固定独立六包版本和两架构 artifact 预期。注入错误版本、未知架构、缺包、外部来源、篡改 hash，须在 SDK 导入和服务启动前拒绝；改变 image-coupled 策略/锁后旧镜像须拒绝匹配新 live 源码。
- 证据：保存脱敏命令、完整日志/退出码、前后 stat/inode/大小/SHA、构建上下文和镜像身份、两次源码快照、失败类别及 SDK/网络/服务未启用见证。没有两架构的完整实际结果时保持 NOT RUN，macOS 元数据 PASS 不能替代本卡。
- 故障注入、清理与风险：版本/锁/来源错误不能放宽、回退到 sdist、自动安装未锁闭包或修改 ledger。仅回滚本卡的一次性隔离构建产物并对比原快照；不删共享镜像、真实项目、凭据或宿主依赖。风险为供应链漂移、架构 artifact 不兼容和误启用在线服务；核验成功仍不授予 Stage O/发布权限。

## TC-REAL-REQ7-ONLINE-CANDIDATE-ROWS-001 — 精确字面列、保留序号及位移检测

- Case ID：`TC-REAL-REQ7-ONLINE-CANDIDATE-ROWS-001`；类型：real-environment / index-addressed API / preservation；对应 C-8/C-17/C-20/C-26；状态：**NOT RUN / REAL_ENV REQUIRED**。本地 `test_issue_tracker_online_cells`、`test_issue_tracker_online_nv_ids`、`test_issue_tracker_online_rows` 同时包含 direct 和真实工作簿投影／源行校验／字面请求 workflow；其纯候选不建立在线读、模板、目标、预留或发送权威。
- 前置条件与权限：只有完整 Stage L 的鉴权／受控传输／锁／journal／History／fence／UNKNOWN 证明和另获 owner 的 Stage O 副本授权、人工编辑合同、精确枚举、实际 Python／SSL／CA 身份、快照与回滚责任后，才可在批准的一次性副本执行真实请求。目前这些上线条件未完成，不打开网络、不读真实 Google 表格、不改线上表、不宣称整个 REQ7 完成。
- 输入与独立预期：逐批校验正式本地模板的 14 sheet 同名同序与原始 row-2 多行 header；用显式候选列与精确矩形 userEnteredValue／FORMULA 读建立稳定业务键，重复 active key 拒绝。Switch 有限预留行只在 F、B/C、J..U 都空且未预留时可选，保留 A 的 NV ID、D/E/G/H 公式与 I3 公式／I4:I5002 空余；容量耗尽不造行。实际 ETH/IB Cabling A 列及所有保留预留共同决定下一 NV 序号，无固定魔数、无自动回收，UNKNOWN 拒绝新规划；纯规划尚未实现持久化预留，现场须另证。
- 写入与回读预期：Switch insert 只写 B/C/F/J/K/L/N、update 只写 L；Cabling insert 用 appendCells，update 只写 G/M/N/S/T 与可选 AC；所有值为 literal stringValue、fields=userEnteredValue。只用精确连续 updateCells start 或显式 appendCells sheetId/rows，不写 range/tableId／公式／人工列，不整表覆写。本地 NOOP 仅是 supplied read 的 OBSERVED-SATISFIED-AT-READ，不是 APPLIED／历史代次回执；本地 workbook 无变化不能删掉完整在线业务意图。
- 位移与不确定性：写前任何一个 A:U cell／row index 改变拒绝；fake 按文档的 index-addressed 请求实际应用后，工具列不等于 intended literal 或任一保留／公式／人工 cell／row index 不一致报 CONFLICT，原已应用图像仍保留，绝不假称回滚／未写入。该检测非 CAS，只是 best-effort；真实请求后仍需完整 C-19 原始 journal、enrollment、History／fence 与全 outcome／audit 集合证明。纯单元格、序号与行比较不替代这些证明，也不清除 UNKNOWN。
- 证据、故障与清理：保存脱敏 exact tree／命令／退出码、模板与只读矩形摘要、预留／attempt journal、字段与坐标、前后图像、完整 audit/outcome 集合和负例；注入占用、人工编辑、移行／排序、坏 typed 值、部分观察、重号、容量耗尽与 UNKNOWN，确认拒绝且原始证据不变。只退役批准的可丢弃副本及恢复隔离快照；不宣称生产回滚、真机通过或完整在线发送已实现。

## TC-REAL-REQ7-ONLINE-TARGET-001 — 精确目标枚举与每次准入重核

- Case ID：`TC-REAL-REQ7-ONLINE-TARGET-001`；类型：real-environment / fixed-path authority / local-only preflight；对应 C-2/C-7；状态：**NOT RUN / REAL_ENV REQUIRED**。本地 direct `test_issue_tracker_online_target` 与多真实脚本 `test_issue_tracker_online_target_workflow` 只验证纯枚举及真实项目策略校验器，不读取真实凭据、打开网络或签发发送许可。
- 前置条件：owner 另行明确批准的隔离 Linux VM、可恢复快照、唯一 root worker 与固定 `/var/lib/http-ztp-container/service-account/issue-tracker-spreadsheet-whitelist.json`，真实 root/0700 祖先、常规 root/0600 单链接文件及宿主/容器同路径只读 bind 身份；完整 C-1/C-11 held-FD 加载器、C-12/C-14 传输证明和同树全量证明须先完成。纯字节摘要不建立文件来源权威；缺任一项保持 NOT RUN，不用临时或配置内白名单代替固定权威。
- 步骤与独立预期：白名单格式固定为顶层 JSON 字符串数组，逐字比较合法 ID，不从配置、嵌套元数据、通配符或大小写归一化生成条目；空数组合法但拒绝全部，重复条目/JSON 键、非字符串、非有限数字、编码和大小错误拒绝。每次尝试重新校验 schema v2 项目策略及当前枚举；禁用或撤销为 STOP，目标、策略或枚举字节变化拒绝旧绑定，不重定向。记录只有类别、计数、布尔、摘要及受限文件身份，不回显 ID 或凭据。此纯绑定本身不能允许发送，也不改变本地工作簿。
- 故障与证据：在授权隔离副本验证读取前后身份交换、祖先/权限改绑、revocation、目标/枚举变化；持久 SEND-INTENT/retry 集成未完成前不得声称这些负例已有在线流程证明。保留精确 HEAD/tree/命令/退出码、held-FD 身份与前后 SHA、无网络/本地修改的见证和拒绝阶段。
- 清理与风险：仅回滚该隔离 VM 快照和明确 run-owned 非证据文件，不删除 credential、journal、INTENT/RECEIPT 或历史证明；禁止触碰生产、真实在线表和未授权服务。真实加载器/传输/恢复链任一未证实时不激活线上发布。

## TC-REAL-REQ7-MANUAL-UI-001 — 三面板手动预览与二次确认

- Case ID：`TC-REAL-REQ7-MANUAL-UI-001`；类型：real-environment / browser / Apache CGI / local-only；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。自动化先决为 `test_cases.test_issue_tracker_manual_ui` direct、`test_cases.test_issue_tracker_manual_ui_workflow` 多真实脚本 workflow，以及同一逐字节树的正式全量证明。当前 `build_html()` 的生产默认不输出按钮、对话框或 CGI URL；显式测试态验证前端及 K 意图经过真实 CGI/私有队列/worker/LK-P/settings 链，**不**部署、不开放路由、不构成可用的发布按钮。K 控件初始为空且禁止保存，仅精确查询回执才启用；浏览器通过专用 Accept 协商十进制字符串以免大整数被 JSON 舍入，worker 内部仍严格整数。保存消耗已核验 revision 并撤销旧预览；丢失、畸形或不绑定本次 K/revision 的回复保留未知、禁止自动重试，取消后的晚到查询不得恢复写入授权。Node DOM/fetch 为本地确定性替身，不计作真实浏览器或 Apache 验收。
- 前置条件：只有在另行获 owner 书面许可的可丢弃 Ubuntu 24.04 VM 与私有 0700 项目快照中，完成 `TC-REAL-REQ7-MANUAL-CGI-QUEUE-001` 的 Apache 独占 CGI 身份/root worker/受保护 C5/C6 接入，并由 worker 返回完整逐源文件名、UTC 时间戳与摘要、新增/更新/跳过计数、行摘要，才可启用 UI 候选。先记录 HEAD/tree/full-proof、生成器及发布页面 SHA、源与目标 dev/ino/mode/size/SHA、模板与 K revision、路由及 worker 权限和回滚责任人；不得碰生产 Apache、真实项目、真实 crontab、线上表或 owner 的 v3.1 验证树。
- 步骤与预期：在真实浏览器分别打开 Switch Status、Eth Link Validation、IB Link Validation，确认每个面板仅有本面板的按钮；浏览器只发同源 `{action,panel}` preview，收到服务端完整预览后才显示目标 sheet、源文件/时间戳/摘要、可操作/新增/更新/跳过计数与行摘要并启用独立的“确认本地发布”按钮；确认请求只传 `{action,panel,token,confirmation}`，不传行、项目路径、来源摘要、凭据。取消、切面板、页面刷新、token 过期、错面板、缺字段、源漂移、服务端 HOLD、CGI/worker 不可用及 C6 后响应丢失均不得由浏览器重放或显示成功；未知须提示检查受保护状态而非再点一次。确认只在本地 RECEIPT 经 worker 明确核实时显示本地成功，在线 Stage O 状态始终单列为禁用。K 从 UI 改变的服务端持久化/历史审计须有独立实现和证据；本地候选通道不能证明生产服务或在线 K 审计已完成。
- 本地完整预览先决补充（仍 **NOT RUN**）：纯内存单面板投影以绑定工作簿的实际 `Update_History` 新增行为区分 Insert/Update，不把 C5 的通用 upsert 当成新增；跳过计数包含未变化合格行和本面板 W1 排除，W1 单列。行摘要绑定完整候选、manifest 和工作簿前像。未安装的完整 broker 候选在同一 LK-P 下重开本面板实际源文件，返回路径、UTC 与 SHA，并将完整源 stat 身份、manifest、工作簿前后像和计数摘要绑定到一次性 token；确认时及 C6 锁内分别重新校验。真实 producer/worker/emitter 三来源、生成页面 Node DOM/fetch、实际 CGI/私有队列/worker/C6 本地流程覆盖完整三面板预览、一次本地 RECEIPT、旧工作簿 token 拒绝及确认后源 stat 竞态拒绝；纯预览无 generation/RECEIPT 或网络动作。生产默认页面仍无控件/URL，旧最小 broker 不能替代完整候选，真实浏览器、Apache 独占 UID/root 服务安装和现场输入仍未验证，不得开放生产确认。
- 证据、清理与风险：保存脱敏浏览器网络记录、页面/CGI/root 状态、逐字段显示、前后源/工作簿/RECEIPT SHA 与权限、所有负例、同 UID 写者静默与快照恢复核验；仅撤除获准隔离 VM 的测试资源。完整后端预览、独占身份、真实浏览器或回滚证据任一缺失时保持 BLOCKED/NOT RUN；本卡不授权生产按钮、Stage O 或最终发布。

## TC-REAL-REQ7-MANUAL-CGI-QUEUE-001 — 手动面板 CGI 到 root 私有队列

- Case ID：`TC-REAL-REQ7-MANUAL-CGI-QUEUE-001`；类型：real-environment / Apache / root-worker / local-only；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本机先决为 `test_cases.test_issue_tracker_manual_channel`、`test_cases.test_issue_tracker_manual_listener` direct，两个对应多真实脚本 workflow，以及现有 Stage L/C5/C6 全量同树证明。当前 Linux listener 和 worker-owned C5/C6 适配均只是**未安装的库级接点**；本地合成测试可连接 broker、私有队列与受保护 C5/C6，但尚无真实 root 服务启动、Apache 路由或获授权的受保护项目回调。macOS 夹具模拟的 `SO_PEERCRED` 不是真实内核 peer 证明，自动化 GREEN 不代表可部署。
- 前置条件：owner 另行批准可丢弃 Ubuntu 24.04 VM、私有 0700 项目与快照、独立真实 root worker、固定 Basic Auth 主体 `nvis`/`cumulus`、本机 HTTP 同源服务地址及最小权限 Apache 路由。CGI 必须使用**独占、非登录且不能由其他同 UID 作业冒用**的 Unix UID/GID；root listener 以 Linux `SO_PEERCRED` 严格比对该 UID/GID，证明的是 CGI **进程**而非 HTTP `REMOTE_USER`，主体归属仍依赖 Apache 的 Basic Auth/同源配置，此残留不得说成密码学逐用户认证。先保存 HEAD/tree/full-proof、CGI、route、root-owned 0750 socket 父目录及其不可写祖先、root-owned 0660 socket、root-owned 0700 queue 及全部不可写祖先、项目输入、C5/C6 模板与受保护 cycle 的 dev/ino/mode/SHA，记录唯一 worker 与同 UID 外部写者静默；不得连接线上 tracker、生产 Apache、真实项目、真实 crontab 或 owner 的 v3.1 验证树。
- 步骤与预期：在完整安装生命周期和独立 root worker 落地后，使用真实 Apache CGI 以两个主体各验证单面板 preview、一次 confirm、本地 C6 RECEIPT 和只读状态；浏览器请求只能含 panel、action、一次性 token/确认，不能含工作簿行、项目路径、来源摘要或凭据。分别模拟未认证、跨源、重复参数、错主体/错面板、篡改 token、来源或 selected-decision 漂移、token 到期、worker 重启、Linux peer-credential 缺失/错误 UID/GID、socket 缺失、socket/queue 权限或祖先改绑、队列记录损坏、不同 pending job 串结果、C6 后但队列完成回执前崩溃；必须 fail closed，按当前 job ID 精确取件，claim 后未知结果不得自动重放，所有负例无第二个本地 RECEIPT、无在线写入。Stage O 在线编辑保持禁用。
- 回执负例补充：若 C6 回调返回的本地结果只有成功标志、缺失或篡改 generation/manifest/发布文件摘要、含在线成功状态或多余敏感字段，则 worker 对已 claim 的任务保持 `unknown_after_claim`，CGI 不向浏览器回显本地成功；须以受保护 C6 journal/RECEIPT 人工核对，不得按该请求自动重试。本机 direct/workflow 注入仅是先决证据，不替代真实 Apache/root 故障注入。
- K 设置通道补充（真实环境仍 **NOT RUN**）：`settings` 仅查询受保护最高 revision；`set_k` 只接受 panel、正整数 new_k、expected_revision 和 32 位十六进制 request_id，主体与事件时间由可信 CGI/worker 提供，浏览器不能传 actor、principal、时间、路径或来源。独立 root worker 必须在同一 LK-P 下使用已初始化的 settings/event/outbox/current 链，核验精确重复请求只返回原事件且不重写，不同 payload/主体复用 ID 或陈旧 revision 拒绝，K 超过现有周期仍显示 pending。K 设置尝试撤销旧预览；事件提交后 pointer/barrier 故障必须保留 `unknown_after_claim` 和尾部证据，不回显成功、不自动重试、不回退旧 K。记录原始请求、可信主体、事件/current/outbox 摘要、锁排他与故障阶段；不向线上发送审计，也不安装或启用本机 root/Apache 服务。
- 证据、清理与风险：保存脱敏请求/响应、精确命令/退出码、所有 root/Apache 身份与权限、queue 记录/receipt 与工作簿前后 SHA、故障注入点、同 UID 写者静默及快照恢复核验；仅清理获准 VM 隔离产物并确认原状态。若 CGI 路由/worker/C5-C6 未接、任一真实权限或恢复证据缺失，此卡保持 BLOCKED/NOT RUN；本卡不授权生产发布或 Stage O。

## TC-REAL-REQ7-PER-KEY-STATUS-001 — 逐键连续性与本周期本地回执状态

- Case ID：`TC-REAL-REQ7-PER-KEY-STATUS-001`；类型：real-environment / protected-cycle / status / local-only；对应 REQ7 O-4、C-25；状态：**NOT RUN / REAL_ENV REQUIRED**。本地自动化覆盖 `test_issue_tracker_per_key_status_contract`、`test_issue_tracker_per_key_source`、`test_issue_tracker_switch_per_key_source`、`test_issue_tracker_ib_per_key_source`、`test_issue_tracker_receipt_snapshot`、`test_issue_tracker_stage_l_status_per_key_contract` 及其各自 workflow，和 `test_issue_tracker_publish_runtime` direct/workflow；本地结果不代表现场根保护、真实来源、生产 UI、Stage O 或整个 REQ7 已验收。
- 目标与边界：逐键 K 连续性来自真实受保护 worker/emitter/IB producer 完成角色，而非调用方字典、全值相同、release ID 或历史归档数量。ETH 以实际期望 P2P 摘要和已验证边集为锚，IB 显式绑定期望拓扑摘要；同键实际对端或测量变化保留连续性但采用最新业务值，期望端点变化、重复键、非合格周期和漂移必须拒绝。qualified subset 不隐藏其他 pending 键，最新不 active 项不计入待发布故障。
- 前置条件、权限与输入：另获 owner 对可丢弃隔离 Ubuntu VM、私有 0700 项目、模板和卷快照的精确授权；记录正式模板、K 事件链、W1、根/生产者身份、源码/测试/manifest/Python/平台与同树证明，确保唯一 LK-P writer 和外部同 UID 写者静默。没有授权不安装服务，不碰 AIR/prod/live/线上表、真实 crontab、SSH/UFM 或 root 身份。真机未执行不作为本地主树推进门槛，但本卡始终如实 NOT RUN。
- 步骤与独立预期：在受保护 K 个连续成功且 fresh 的周期内，安排 A 键 K/K、B 键 1/K，再让同 A 键实际对端改变；A 的最新业务值进入来源集合、B 显示 pending、恢复项 observed=0。分别改变无关配置、真实期望 P2P 输入和 IB topology authority，验证前者不清零、后两者不可伪装为普通 cold start。删除隔离快照内一个完整旧周期的记录，状态明确 `archive_sequence_gap`，未知 published/skipped/pending 均为 null，不伪报 0；部分未终结或格式损坏仍 fail closed，不误报正常 cold start。
- 回执与状态预期：执行真实 C5→C6→共享 admission 后立即读取 worker 落盘 JSON，当前周期 local SEND UNIT 的 published=1，而非沿用提交前的 0；下一周期无新回执时不得累计旧周期。RECEIPT 缺 admission、K/W1/模板/来源漂移、C6 之后身份变化均 HOLD，保留原证据，不回填凭证、不猜测计数；local_applied/本地计数绝不授予在线发送权。
- 历史原件观察补充（仍 **NOT RUN**）：在上述新周期无新 C6 的状态下，`read_local_receipt_history` 可返回旧周期原 admitted RECEIPT，而 current-cycle published 仍为零。必须实际持有唯一 LK-P，读取共享准入／受保护完成窗口，执行原 generation recovery，并保持 admission、generation 四件、原发布 XLSX 与 settings/events/outbox/current 的目录／文件身份及字节贯穿读取。逐个注入相同字节的原件／目录替换、原件缺失、未终结凭证及已撤销 owner，全部 HOLD 且不得补写、回填或授予发送资格；保存每项原始 stat/inode/SHA 与前后证据。历史观察明确 `RECEIPT-HISTORY-PRESENT-NOT-ELIGIBILITY`，不证明旧周期 R2 的真实来源重放、当前新鲜准入、全局次数、FIFO settlement 或 Stage O；不得拿本卡本地观察消除在线 UNKNOWN。清理只恢复本案已授权隔离副本的原像并验证，不修改或修补真实原件。
- 故障注入、证据与清理：保存脱敏命令/退出码、完整日志前后 stat/inode/大小/SHA/收尾、每周期来源/角色摘要、K/W1 身份、MANIFEST/INTENT/RECEIPT/admission、状态文件与工作簿前后摘要和独立预期。注入 late SHA、expected peer、重复键、周期缺口、不同 K、回执不一致和状态文件写入失败，核对无未授权代次或线上副作用。仅回滚本案隔离 VM/卷快照并验证前像；不删除或修补终态生产证据。任何现场来源或清理证据缺失保持 NOT RUN，本卡不替代三面板正式模板和 Stage O 的单独验收。

- 原始旧 C6 来源回放补充（**NOT RUN / REAL_ENV REQUIRED**）：在本卡原精确隔离副本授权下，保留正常 K=2 原 C5/C6 后新周期无 C6、关键读核边界、代表性中断、冷恢复与失败安全状态；必须从实际 admission/MANIFEST 定位原窗口并重放 native ETH/IB/Switch 来源，仍核当前完整周期链、K/W1/策略、原 generation recovery 与全部原件 FD/stat/名字/字节。缺失原收据、错误 owner/K/W1、原 MANIFEST 或当前 high-water 同字节替换均 HOLD，视图返回前撤销；零新代次/收据/计数/发送/补件/删除，当前 published 不累计旧 C6。证据保留前后原件身份/SHA、精确树/命令/Python/平台/退出码、完整收尾与物理顺序，清理只回滚获授权的自有副本。上述场景全部保留，无省略或合并；替代证据为独立 direct 和真实受保护 K=2→C6→新周期→只读 native 回放自动化，确认范围沿用 owner 本轮验证纪律。真实 Cloud、设备/卷、断电、默认在线 worker、旧 R2/M=6/FIFO/COMPLETE 仍未验证，不标通过；原现场授权、必要研发确认与生产门禁保持有效，不扩权。

## TC-REAL-REQ7-STAGE-L-C5-C6-001 — 受保护三面板到正式工作簿本地凭证

- 旧手动单面板原件回放补充（**NOT RUN / REAL_ENV REQUIRED**）：在原卡另获授权的精确隔离副本中保留正常三域 native 来源→手动单面板 C6→后续新周期、关键原件读取边界、代表性中断、冷恢复和失败安全状态。全域摘要不裁剪，只把 W1 决策与评估标签对照原 MANIFEST 的选定面板；未选面板明确未评估。分别验证缺失决策、错误面板、缺失/矛盾标签、摘要漂移、额外字段及非法 K 均 HOLD，原周期本地计数为 1、新周期为 0，无原件补写、收据重建、计数、网络或权限授予。保留实际 admission/四件/generation recovery/worker 链/K/W1/模板 FD/stat/完整字节及前后 SHA、精确树/命令/Python/平台/退出码和完整日志；清理只恢复获准自有副本并核原像。保留场景全部执行，无省略或合并；替代证据为三面板独立投影 direct 与真实 worker/emitter/C6/新周期/native 回放本地 workflow；残余风险为真实 root/卷/断电、Cloud、M=6/FIFO/COMPLETE 未验证，仍不标通过。确认范围沿用 owner 本轮验证纪律，原现场授权、研发确认及发布门禁不变，不扩权。

- Case ID：`TC-REAL-REQ7-STAGE-L-C5-C6-001`；类型：real-environment / protected-cycle / local-transaction；状态：**BLOCKED / NOT RUN / REAL_ENV REQUIRED**。本机自动化先决为 `test_cases.test_issue_tracker_ib_runtime`/`_workflow`、`test_cases.test_issue_tracker_switch_runtime`/`_workflow`、`test_cases.test_issue_tracker_stage_l_consumer`/`_workflow`、`test_cases.test_issue_tracker_manifest`/`_workflow`、`test_cases.test_issue_tracker_local_workbook`/`_workflow` 与 `test_cases.test_issue_tracker_local_workbook_commit`/`_workflow` 的 direct/workflow 全绿；只有同一逐字节候选的正式 Codex/Claude 两轮全量结果才可进入本卡。自动化正向夹具不等于远端真实来源、正式模板或线上写入。
- 前置条件：owner 另行授权隔离 Ubuntu 24.04 VM、私有 0700 stage、可丢弃项目与卷快照、唯一 LK-P 写者和可核验的同 UID 外部写者静默；选定 owner 管理的正式 `Issue_Tracker_Template_v1.xlsx`，逐字节记录其 dev/ino/mode/size/SHA 与 `Whitelist`/14 张工作表结构，不把模板搬入 Git，也不改 live/生产或线上 tracker。记录 K 设置、同周期受保护九角色 IB、ETH 第四 role/P2P 派生、两类 Switch inventory 中的 type/template 身份、完整 producer/worker/emitter root attestation 与完成记录的前像。缺任一来源、权限、回滚或全量证明即 STOP。
- 步骤与预期：在隔离副本连续完成所需 K 个 prod 周期；独立重放所有 role、完成摘要、K、W1、模板及来源时间，三面板必须只在来源完整时生成稳定 activity_key/operation_id；C5 manifest 仅含经重放的 upsert 意图和可审计 W1 skip，IB 活动键、ETH 真实端点、Switch 原始记录 ID 与各自匹配规则不得混同。持同一 ACTIVE token 将正式模板或前一个有效 RECEIPT 所绑定的工作簿投影至 ETH Cabling、IB Cabling、ETH&IB Switch 和 Update_History；被 W1 跳过项须在 preview、provenance 与 Update_History 可见，历史行绑定 C5 manifest_id 及受保护来源 UTC，且不得写回被排除的业务行。先 INTENT 再本地 XLSX RECEIPT，逐字核对 manifest_id、published SHA 与原始工作簿。无候选且无新 skip 或幂等重放不得意外创生代次；Priority 人工值、公式、其他表、旧凭证不得被静默覆盖。本地 RECEIPT 不授予线上发布资格。
- 负例与证据：分别漂移任一 IB 角色/attestation、ETH 派生、Switch type/template、K、W1、正式模板、操作员编辑 witness、既有 RECEIPT/发布文件，并在准备/INTENT/RECEIPT 与 fsync 边界注入失败；必须 fail closed、保留未解决 INTENT 且不得伪造 RECEIPT 或线上写入。真实 root worker 完成周期后还须核对 N=1 默认、显式 N 到期/未到期、禁用线上但本地独立、全局策略中途变化、来源 HOLD 与状态文件不可写时既不产生未授权本地代次也不改写采集结果。C-23 须另外核对同一 boot 上第二个及后续新周期只在相对 N 个唯一完成事件与共享最小间隔同时满足后准入，积压只投影当前合格集合、不补发历史 generation；跨 boot、时钟倒退、同周期重放、第二条 admission 缺失/篡改、C6 后但 admission fsync 前故障均 HOLD。还要直接调用底层 C6 路径尝试绕过共享准入，证明不会产生第二个无见证 RECEIPT。手动与重试路径也须证明共用同一 limiter；当前保守 HOLD 不能代替正向准入，这些现场证据未齐不得称 C-23 完成。`local_applied` 只表示本地 RECEIPT，不是在线 GO。保存脱敏 argv/exit、前后 inode/size/SHA、manifest、故障点、代次、负例拒绝、目录清单、写者静默和独立快照回滚比对；只恢复隔离副本。任何真机来源/正式模板/恢复证据缺失或尚未执行时保持 BLOCKED/NOT RUN；本卡完成也不替代 owner 单独裁定的 Stage O 在线编辑与发布。
- C-23 持久 C6／共享准入不一致的人工恢复（**NOT RUN / 不能自动修补**）：在隔离可丢弃项目与卷快照内，先验证唯一 LK-P 写者及同 UID 外部写者静默；分别见证 C6 RECEIPT 后无事件目录、事件目录不完整／不连续、事件无 C6 RECEIPT、代次集合不匹配、存储事件不能绑定 C6／周期、末事件不能绑定已发布 C6 六种终态；尤其在 C6 RECEIPT 持久化后、共享准入事件 fsync 前注入故障。预期 worker 状态 `reason=local_c6_terminal_admission_state` 且 `terminal_detail` 精确描述命中的条件，该 state root 的所有后续自动、手动及重试准入均 HOLD；重复完成周期 ID 与暂时 I/O 错误不得被错误标为终态。保留 RECEIPT、INTENT、已发布 XLSX、未匹配或缺失的事件目录及其原始 inode/size/SHA 和错误状态，不删除、不回填、不重命名、不复用旧代次，也不把已有 RECEIPT 猜成许可。操作员只读封存整个 state root、来源完成证明、模板与策略身份及隔离卷快照；若业务必须继续，须由 owner 另行明确批准从已核验来源建立**新的**项目/state 身份，再在独立私有 stage 重走正式验证与两轮全量门禁。原 state root 保持终止 HOLD 并留存审计，不在原目录内“修复”历史；未经另行授权不得用于 live、AIR 或生产。记录故障注入点、封存前后哈希、写者静默、拒绝路径、新旧身份隔离及快照清理证明。此卡未实测或 owner 未授权重建时，不得宣称恢复能力或 C-23 真实环境验收。

## TC-REAL-REQ7-SDK-AUTH-TRANSPORT-001 — 固定私有输入、公有 SDK 与原生 TLS 单次鉴权

- Case ID：`TC-REAL-REQ7-SDK-AUTH-TRANSPORT-001`；类型：real-environment / native identity / authentication；对应 C-11/C-14。状态：**NOT RUN / REAL_ENV REQUIRED**。本地先决为 `test_req7_sdk_authentication`、`test_req7_tls_inputs` direct，以及 `test_req7_native_tls_wire` 公有 SDK → 实际 stdlib HTTPS/SSL/HTTP 的多真实脚本 workflow 全绿；合成密钥、根元数据和 loopback DNS 映射不代表实际凭据、CA、DNS 或服务启用。
- 前置条件、平台与权限：只能另获 owner 精确 Stage O 授权后在一次性 Linux 隔离副本执行；先核当前干净 HEAD/tree、manifest、同树证明、已批准两架构依赖与固定 RO bind。当前 `monitor/issue_tracker_sdk_authentication.py` 与 `monitor/issue_tracker_tls_inputs.py` 是未安装库，不安装、不启动、不开放服务、不读取真实凭据、不调用真实 OAuth/Sheets。SDK 构造/导入前须通过依赖闭包；持有固定路径输入 FD，固定 Sheets scope 和 token endpoint，禁止 ADC、delegation、自制 JWT grant 和 SDK 私有重试接点。
- 步骤与独立预期：记录实际 Python/SSL、固定 CA 目录链与单次 held-FD CA 身份，使用新的 TLS 客户端上下文、hostname/CERT_REQUIRED 与固定 OAuth POST；原生 DNS、握手、证书核验、报头和完整有界正文必须纳入固定总预算。代理/环境 CA 变量不得重定向；302/401/429/5xx、第二次 callback、重复报头、冲突 framing、超界、短读、错误 SAN 必须拒绝且不重发/刷新重放，不输出凭据、JWT、邮箱或 token。
- 证据：保存脱敏精确命令与退出码、前后 stat/inode/大小/SHA/旧前缀与 END、源码/测试/manifest/Python/平台身份、真实 DNS/TLS/CA 核验、一次调用计数、持有 FD 与目录名字重核及外部哨兵不变见证。没有完整实际证据仍 NOT RUN；本卡即使通过也不签发写入许可或普通发布证明。
- 故障注入、清理与风险：在授权副本注入依赖/CA/hostname/framing/截止期错误，所有原断言必须保留；只清理本卡拥有的子进程及隔离卷，验证会话不存在和原像恢复。风险为私有信息泄漏、隐藏重试及伪造完整响应，不修改共享 CA/依赖、宿主服务或生产输入。

## TC-REAL-REQ7-TOTAL-ATTEMPT-LOCK-001 — 固定启动器、完整预算与孤儿写者锁

- 固定 mutation 原型补充（**NOT RUN / REAL_ENV REQUIRED**）：`monitor/issue_tracker_send_unit.py` 的完整自洽 C19 原 batch → `monitor/issue_tracker_tls_inputs.py` 单次固定 POST → `monitor/issue_tracker_mutation_rejection.py` 同连接完整拒绝语法观察，仅由拥有的 loopback TLS 夹具本地验证。保持原 1 MiB／1000 requests 和有界 2 MiB framing；无 URL／body／预算覆盖、无 redirect／refresh／resend，200 或未知错误不能证明 APPLIED/COMPLETE。另获本卡精确 Stage O 授权才可验证真实 CA/DNS、固定 child 总 60 秒、双锁、原持久计数单次消费、共享 cadence、隐藏 PROJECT 库存和新鲜准入；当前原型没有 CLI／安装／在线启用权威。保存精确树、stat/inode/SHA、单次 wire、同连接完整 framing 与故障物理顺序；只清理自有隔离副本，风险为重发、伪造完整性或未经准入写入。本地通过不关闭上述剩余条件，不改变真机 NOT RUN。

- 原始读取来源补充（**NOT RUN / REAL_ENV REQUIRED**）：后续解析须重核固定入口实际签发对象、原实际双 owner、原始响应和精确形态/native 参数类型、当前固定目标文件、原 30 秒截止期；复制 completion、单独解码协议、换 owner、过期或文件撤销均拒绝。部署证据须记录该必要来源链和拒绝路径，但该进程内登记不持久、不能证明远端原子性或 mutation/COMPLETE，亦不防御已能任意执行受信 Python 的攻击者。权限、故障清理及风险沿用本卡，不执行真实调用。

- 枚举只读形态补充（**NOT RUN / REAL_ENV REQUIRED**）：同一固定入口现接 Whitelist、模板 identity/headers、活动、插入占用、精确单行、History tail 与固定只读 metadata search；真实 W1/模板/continuity 及 metadata 可见性仍须本卡和相关原有卡的独立授权与现场见证。拥有的原生 TLS 工作流只验证单次 GET/固定只读 POST 与解析边界，不证明其他 PROJECT 隐藏 metadata 使用量完整、发送准入或 COMPLETE。证据与异常清理沿用本卡，原始 30 秒/2 MiB 限额保持不变。

- 固定 History-tail 读取入口补充（**NOT RUN / REAL_ENV REQUIRED**）：`monitor/issue_tracker_history_read_launcher.py` 在实际项目 ACTIVE 与 spreadsheet owner 下，于读取前后重新核策略/固定白名单；固定 `-I -B` child 仅继承两锁、清空环境、私有 stdin、单次原生固定 GET、nonce/path/body 关联完整私有响应，不接受 URL/程序/路径/预算覆盖。部署需另核 native root、隔离解释器、CA/DNS、两锁继承、总预算/输入背压/拒绝终止与策略变化见证。证据、精确授权、故障清理和风险沿用本卡；本地受控 loopback 不证明在线许可、typed History/continuity 或 COMPLETE，此观察不能解除 UNKNOWN。

- 私有输入通道补充（**NOT RUN / REAL_ENV REQUIRED**）：本地实际 stdin pipe 的分段非阻塞写入、EOF、满管道背压和原有总预算到期均纳入监督器；实际子进程输入 → 拥有的 loopback 原生 TLS 单请求 → 完整响应工作流验证正文逐字节一致和父锁保留。部署须另外见证固定 child 的输入协议、无 argv/env/private-log 泄露、背压/提前关闭/总时限故障和继承锁；不提高预算，不把私有输入当 mutation WIRE 或发送授权。证据、精确授权与清理沿用本卡，本地通过不改变真机 NOT RUN。

- 固定 auth-only 入口补充（**NOT RUN / REAL_ENV REQUIRED**）：`monitor/issue_tracker_token_launcher.py` 的真实持锁 → 固定隔离 child → root-only 单次凭据读 → 公有 SDK → 原生 HTTPS 单次请求 → nonce 关联完整私有 token 输出 → 已结束 session 本地工作流，不接受外部程序、URL、凭据路径或预算。合成 root/凭据/CA、明确测试依赖目录与 loopback DNS 只在拥有的夹具边界，不代表 native root/CPython 3.12/两架构部署依赖、真实凭据、CA/DNS 或 Stage O。前置条件仍为本卡独立授权、干净精确树和当前证明。现场必须核隔离 interpreter/已批准依赖可导入且无 ambient fallback、环境清空、borrowed CLOEXEC 锁仅 pass_fds 继承、启动耗时纳入总预算、原 warning 保留、401/503 不重试、私有输出无泄露与父死子存期间 exclusion；证据与清理沿用本卡，不能用本地有界 auth 入口声称 mutation launcher、新鲜准入、COMPLETE 或整个 REQ7 已验收。
- G1 项目认证来源补充（**NOT RUN / REAL_ENV REQUIRED**）：owner 已确认目标专用表、同一 Cloud 项目唯一 metadata 写者的限制，但现有／历史其他 PROJECT metadata 的不存在不能从可见查询推断。`monitor/issue_tracker_sdk_authentication.py` 与固定项目 token launcher 的本地 direct／真实 FD→公有 SDK→原生 TLS→监督 child→原 owner 工作流只验证固定凭据项目来源、原 completion、过期／撤销／项目或字节漂移拒绝；独立 v2 协议不能由调用方 token、摘要或复制对象建立来源。现场前置沿用本卡另行精确授权与保护路径、scope／IAM、真实凭据和 CA/DNS，另须见证目标与 Cloud 项目确实符合限制及原凭据身份；留存脱敏项目／目标绑定、原 FD 身份和摘要、单次 OAuth 与 child 收尾、各拒绝阶段，不记录 token／JWT／私钥。清理仅回收确证自有隔离夹具，不改真实凭据、scope、共享、metadata、服务或项目；残余风险为历史隐藏库存尚未证明、未接入 G1 完整计量／发送门禁。没有缩减原现场场景，不标通过或授予部署／在线操作权限。
- G1 项目来源→实际读取补充（**NOT RUN / REAL_ENV REQUIRED**）：本地固定 SDK／OAuth 来源已与实际监督 Sheets 只读流程相连，启动前、回包后和后续读取消费均复核同一原认证、双 owner、固定凭据与目标／deadline；另一次认证即使同值 token、legacy 真实读或复制对象也不能替代。现场沿用本卡原精确授权，不新增真实凭据／项目／网络操作许可；保留正常只读、凭据或策略撤销、代表性中断及失败后不重试／不误授发送的原场景，留存脱敏原认证—原读取关联与收尾证据，清理仅自有夹具。不合并或省略原现场场景；完整库存／历史排他和 worker 准入未验证，不标 PASS。

- Case ID：`TC-REAL-REQ7-TOTAL-ATTEMPT-LOCK-001`；类型：real-environment / owned process / transaction；对应 C-6/C-14/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。本地先决为 `test_req7_attempt_supervision` direct 与 `test_req7_native_supervised_workflow` 实际慢 TLS 正文及在实际 HTTPS 栈内阻塞的测试 DNS → 实际 30 秒监督器 → 继承临时 flock workflow 全绿；DNS 仅为拥有的阻塞夹具，不使用真实解析端点。本地拥有的假子进程和锁不证明生产固定启动器、真实 root/孤儿写者或在线准入。
- 前置条件、平台与权限：仅另获 owner 精确隔离系统和 Stage O 授权；记录当前树与 Linux 身份、固定审计启动器及已持有 spreadsheet OS 锁。`monitor/issue_tracker_attempt_supervision.py` 当前只监督调用方已拥有的新 session 子进程，不接受 PID/命令、不启动生产服务、不释放锁、不授予重发许可；必须先完成固定启动器、当前策略/枚举/来源/模板准入与 durable SEND_INTENT 集成。
- 步骤与独立预期：时钟必须在启动前开始；token/read/mutation 的完整预算分别 30/30/60 秒，包含启动、DNS、握手、报头、正文。慢读成功不能重置预算；响应 pipe EOF 不代表写者停止；stdout 超界、stderr、非零退出、异常或超时均为 HOLD。只有确认拥有的整个会话结束，才能判定清理完成；无法确认时继续持锁且不能发送下一单元。真实杀死测试副本监督父进程后，继承锁的子进程存活期间其他候选不能取得锁。
- 证据：保存精确命令/退出码、完整物理顺序日志、前后 stat/inode/SHA、启动前 monotonic 时间、阶段耗时、持有锁的 FD/session 归属、截止期、TERM/KILL/reap/会话不存在和父死子存的独立见证。私有响应和诊断不进入公开日志；局部原生慢读 PASS 不代表整个 REQ7 或生产权限。
- 故障注入、清理与风险：注入启动失败、DNS/慢读、pipe 关闭、监督器死亡和无法终止；保持原预算/行为断言。本地夹具已独立复现并修正已回收 leader 的同号存活 group 被误认为信号权限；首次检查之后、异常清理和 TERM/KILL 升级之前也必须重新确认活 leader 的 session/group 归属，不能把首次检查缓存为永久信号权限。真实 PID 重用仍 NOT RUN，必须验证不向该不确定 group 发信号、终止未确认保持 HOLD。实际临时 flock 的终止被拒工作流必须保持其他候选无法取得锁，直到本卡确证拥有的子进程完成清理。只终止本卡确证拥有的隔离会话，不能向外部 PID/group 发信号；清理不确定保持 HOLD，由授权责任人恢复隔离快照并重核锁。不得以 PID 重用、过期锁、超时宽限或重发来隐藏 UNKNOWN。

## TC-REAL-REQ7-ENROLLMENT-JOURNAL-001 — 共享原始 nonce 与 target/History 双见证

- Case ID：`TC-REAL-REQ7-ENROLLMENT-JOURNAL-001`；类型：durable / integration / real-environment；对应 C-6/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。涉及 `monitor/issue_tracker_enrollment_journal.py`、`monitor/issue_tracker_spreadsheet_owner.py`、`monitor/issue_tracker_send_intent.py`、`monitor/issue_tracker_metadata_capacity.py`、`monitor/issue_tracker_tls_inputs.py`。本地合成 root 元数据、实际 fsync/flock 和私有只读响应不能替代真实 Stage O 或完整 REQ7。
- 风险与目标：同 spreadsheet 跨项目只保留一个原始四表 nonce journal，CSPRNG 一次生成，NONCES/HEADER 原像六屏障后才 INITIALIZED；部分 store 缺 marker 必须 HOLD，不能从远端标记反向采纳、重生或修复。target 和 Update_History 都必须原始 SHEET 锚定 DOCUMENT nonce，无缺失／重复／错值；composer 与持久 action 原像保持同 pair。
- 前置条件：本地 direct 与真实 global owner → nonce journal → composer → C-6 action workflow 通过；部署目录已由精确独立授权 provision，native uid=0/root-only 祖先与 mount、Linux 随机源/NOREPLACE/fsync、SDK/Python/SSL/CA 身份实证；Stage O 只用 owner 批准副本。本卡不授权真机、真实凭据、metadata 创建、联网或在线启用。
- 步骤与预期：在批准副本及测试自有状态核四 nonce 不同、进程冷重开保持；逐屏障故障、目录／文件替换／链接、随机失败、改 sheetId 或撤销 owner 均 HOLD 且证据保留；完整只读 metadata 搜索缺 History、PROJECT 可见、SPREADSHEET/ROW 锚点、重复或外来 nonce HOLD；后续仍需独立预算／预留、新鲜准入、固定 launcher 与 COMPLETE。
- 证据：精确 HEAD/tree、manifest、Python/平台、命令和完整日志／退出码，读前后 stat/inode、大小、旧前缀 SHA256、物理顺序／END；只回传摘要和两 nonce_valid 布尔，不输出原 nonce／凭据／token。成功本地观察不是普通发布 full proof。
- 清理与风险：仅清理测试自有临时 root、CA/socket/thread；生产原始 journal/nonce 永不删除／重置。部署冷断电、真实 root 身份、受控只读批准副本和在线 activation 仍 NOT RUN，任何未证条件不能冒称通过。

## TC-REAL-REQ7-ACTIVE-CLOSED-DISCOVERY-001 — 完整活动键与原始 Closed 分类

- Case ID：`TC-REAL-REQ7-ACTIVE-CLOSED-DISCOVERY-001`；类型：real-environment / read-only API / integration；对应 C-3/C-8。状态：**NOT RUN / REAL_ENV REQUIRED**。涉及 `monitor/issue_tracker_sheets_read_plan.py`、`monitor/issue_tracker_sheets_read_decode.py`、`monitor/issue_tracker_tls_inputs.py`；本地私有 loopback TLS 与原始 typed grid fixture 不证明部署环境、全表发现或 REQ7 整体完成。
- 完整容量读补充（NOT RUN）：固定各显式列 `3:5002` 与 GRID rowCount/columnCount 同一次完整 GET；native int 容量 3..5002，Switch 至少 21 列、Cabling 至少 29 列，数据严格剪到实际容量并覆盖末行。溢出/缺容量/多或缺 grid/越界数据 HOLD，不静默分页或扩大阈值。Closed、无关键与末行的原始 A 列全部参与每表 NV 最大值；实际两张 Cabling 读均须成立，不能只凭一张表分配。完整覆盖只代表当次容量内观察，不是新鲜准入、nonce/预留、COMPLETE、CAS 或发送权限。原生全键读 → 精确行矩形 → L-only encoder 仍不联网写入。
- 原像／receipt 更新编译补充（NOT RUN）：完整原始发现派生唯一活动行，精确行 A:U／A:AC 必须保持全部发现列的原始 typed 值不变；原 ID、Status、描述、对侧或坐标漂移 HOLD，不回退选行。真实 C5 + 原始 admitted C6 receipt + 三类表的完整发现／精确行 + History 原像派生全部更新 placements 和 combined preread 摘要，调用方不得覆盖；组批前后重新核验，History 容量不足拒绝。原生私有 TLS 只读到真实 encoder，以及真实 producer／资格／本地 workbook commit／receipt 到冻结 batch 的本地 workflow 不写远端。插入／空闲行和尾预留、durable 业务原像 journal、nonce／模板权威、新鲜准入、launcher、COMPLETE、FIFO／结算和整项验收仍未证明；本卡不新增线上权限。
- 插入位置必要观察补充（NOT RUN）：先完整发现无活动同键，固定 Switch A/B/C/F/J..U 或 Cabling 全 A..AC 逐列读取与原容量同 GET；所有共有原始格子／容量一致。Switch 首个 F/B/C/J..U 无 userEnteredValue 且不在已知预留集合的行，再读精确 A:U 核 preset NV、D/E/G/H 公式和 I 原形；Cabling 在所有列最后占用行之后追加，公式、显式空字符串、0、False 与操作员列也占用，间隙不复用，全部追加需求不得溢出原容量。私有原生 TLS → 位置观察 → 原 literal encoder workflow 不发 mutation，不写公式／参考／操作员列。实际原始预留 journal、完整格式权威、durable 业务原像、来源组批／每次连续性、并发外部编辑、发送和 COMPLETE 仍需闭合；不能把 caller 已知预留集合当成权威或把本卡当成线上授权。
- 风险与目标：必须显式读取 Switch A/F/L/N 与 Cabling A/F/G/K/L/Q/R/U；Status 只有精确原始字面 `Closed` 才排除活动键。保留线上既有 NV ID；重复活动键 CONFLICT，原始 ID／身份／Status 公式、数字或布尔不可强制变为文本。有限窗口未匹配不是全表不存在或插入权限。
- 前置条件：Stage L 本地 direct 和真实 read-plan → 原生 TLS → grid decoder workflow 全绿；另需 owner 的 Stage O 批准副本及只读许可、实际 Linux Python/SSL/CA 和 SDK 治理身份、14 表及精确表头、完整发现范围／真实尾边界的证据。本卡不授权联网、真实凭据读取、修改或在线启用。
- 步骤与预期：在精确批准副本核全活动键、Closed 同键历史、不同 A 侧／issue type／Switch category+component、重复活动键和保留 ID；前后精确行矩形不得被此窗口观察替代。任一缺失／重复 grid、Status 非字面或不完整响应 HOLD；不自动分页、扩大范围、分配或覆盖 ID。
- 证据：精确 HEAD/tree、Python/平台、manifest 与执行命令、完整日志／退出码；读日志前后 stat/inode、大小、旧前缀 SHA256、物理顺序和 END。真实响应须脱敏，不记录 bearer／凭据；记录实际范围、sheetId、窗口、Closed 分类及剩余未证完整性。
- 清理与风险：仅测试自有私有 loopback server、临时 CA 和合成响应；确认 socket/thread/临时文件清理。真实 Stage O 卡仍 NOT RUN，不能用单个窗口零匹配、只读成功或本地 PASS 宣称普通发布证明或发送许可。

## TC-REAL-REQ7-GLOBAL-ATTEMPT-001 — 共享 UNKNOWN 屏障与全局意图计数

- 原历史单元读取补充（**NOT RUN / REAL_ENV REQUIRED**）：在既有精确授权隔离副本中保留正常 count 0..6、UNKNOWN/M=6、缺 STARTED/journal、partial、缺链、同字节名字替换、原 inode 改写、目录位移、FIFO 等特殊文件、每个恢复 fsync 中断、消费者期间漂移及 local/global 原件独立冷恢复。解释前持有全部原件，持续重核原 FD/name/full stat/ctime/SHA；任何不确定均 HOLD，零新增请求，不修补、重编译、重置或删除原证据。保存精确 HEAD/tree/dirty、Python/平台/命令/退出码、完整物理顺序及 END、原字节和原件前后身份、实际零 mutation/permit 与确证自有 FD 清理。该观察仅针对既有单一单元，不授予 successor/NEW 或释放 UNKNOWN/FIFO/高水位/配额；现场清理仍只限精确授权副本，不碰真实锁、计数或未知进程。本地独立 RED、真实文件/fsync/冷进程与跨脚本流程仅为开发替代证据，不能冒充真实 root/Cloud、设备、断电或部署验收。本次没有合并、省略或暂缓原场景，没有新增剩余风险接受确认；现场、断电、设备及在线 worker 仍 NOT RUN，原现场授权、研发确认与生产发布门禁保持有效。

- journal 首次初始化防重建补充（**NOT RUN / REAL_ENV REQUIRED**）：区别于 completion-started，固定 `.journal-started` 必须以 EXCL／NOFOLLOW／CLOEXEC 在首字节前建立；其 file／parent 两个屏障完成且原 FD／命名边／完整 stat 持续持有，才可创建 journal 目录。保留正常首用、zero/partial write、两个见证屏障中断、交接前名字丢失／同字节替换／同 inode 改写、原八个图像屏障、UNKNOWN/M=6 journal 位移及独立冷恢复案例；全部须保持 STOP、原 count/WIRE/UNKNOWN、零新增请求且不重建、补全、覆盖或删除原件。两屏障不替代原八个图像及两个 INITIALIZED 屏障，也不授予 successor/NEW 或释放 FIFO。保存 before/after stat/inode/SHA、实际屏障及命名边物理顺序、完整 END、原本地 C6/intent 与共享 journal 清单及冷进程退出码。清理仅限精确授权隔离副本与确证自有 fixture，保留故障原件并核回滚；不得清除真实 UNKNOWN 或重置计数。本地独立 RED、真实文件/flock/fsync 与跨脚本冷进程仅为替代开发证据，不能冒充真实 root/Cloud、断电或设备验收；没有合并、省略或暂缓原场景，无新增风险接受确认，现场、断电、部署恢复及在线 worker 未验证范围仍 NOT RUN，原现场授权、研发确认与发布门禁有效。

- 启动见证首写边界（**NOT RUN / REAL_ENV REQUIRED**）：NOFOLLOW／CLOEXEC／EXCL 在首字节前建立固定 STOP 名；short write／首个 file fsync 故障须留下固定 partial 见证、无 proof 和原计数 UNKNOWN，不能以未 rename 的临时文件替代防重建边界。独立故障注入实际复现 RED 后保留原断言修正，本地 PASS 不是真实断电证明；原现场场景不缩减，残余风险和现场授权仍如上。
  - 原件交接补充：首写后 stat 绑定 file／parent fsync 与关闭重开后的 reader FD；同 inode 同字节改写或交接前同字节替换必须在 proof mkdir 前 HOLD，留存原件及新计数／请求为零的证据。本地独立 RED 与真实跨脚本流程不关闭现场卡。

- 冷恢复 no-recreation 补充（**NOT RUN / REAL_ENV REQUIRED**）：完成写者须在 proof mkdir 前完成独立 completion-started 见证的 file／parent fsync；两处失败保留见证、无 proof、UNKNOWN 与原次数，不重建或发送。proof 目录被移走后，独立见证仍阻断再次计数、原 WIRE claim、新 journal 和新 proof；live／cold 全程核原 FD／stat／SHA／命名边及 HEADER 绑定，缺失、同字节替换、链接、权限或改写只 HOLD。本地真实受监督 TLS／多脚本／冷进程与原十四个 proof 屏障回归不冒充断电；本次没有合并、省略或暂缓原自动化场景。现场保留正常完成、见证关键提交边界、代表性中断、冷恢复及故障后零新增请求，另获精确授权后记录原件与清理；残余风险为真实断电／设备／Stage O 未验证，状态保持 NOT RUN，原研发确认及发布门禁有效。

- 完成流程 no-resend 补充（**NOT RUN / REAL_ENV REQUIRED**）：原始 WIRE handoff 及每次 live CLAIM 检查拒绝已开始的 completion（含 partial），不创建 dispatch／启动子进程；出现 COMPLETE 标记后不新增原始 ATTEMPT，无效标记也只 HOLD、不作远端证明。独立 direct／双锁 workflow 与真实固定读取→完成落盘→拒绝再次计数／claim 的本地回归保留原 UNKNOWN、计数、journal、proof、预留及 outbox；不释放 FIFO／高水位，不授权在线发送。现场另获精确一次性副本和故障注入授权后留存原件 stat/inode/SHA、计数／claim／completion 物理顺序、实际零新增请求及失败后状态；清理只限自有 fixture。没有省略或合并原场景，真实断电与 Stage O 仍未验证，原门禁有效。

- Case ID：`TC-REAL-REQ7-GLOBAL-ATTEMPT-001`；类型：durable / integration；对应 C-6/C-7/C-14/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。涉及 `monitor/issue_tracker_global_attempt_journal.py`、`monitor/issue_tracker_spreadsheet_owner.py`、`monitor/issue_tracker_send_intent.py`、`monitor/issue_tracker_local_commit.py`。本地合成 root 元数据、原生 fsync／NOREPLACE／独立进程及多脚本流程不是部署或 REQ7 整体证明。
- 风险与目标：共享 spreadsheet 私有目录保存完整 action、wire、原目标/策略/白名单及链式 UNKNOWN 意图；已有单元保守阻断任意项目的新 generation/publish/sheet。M=6 是六次意图，真实尝试上界只有在固定受审 launcher 原子单次消费、每次新鲜准入与没有隐藏重发的完整证明后成立。本库不联网，不证明两份 local/global journal 的原子转移、FIFO 或 COMPLETE。
- 前置条件：owner 另获精确 Stage O/部署授权、共享同 inode 持久根与 root 0700/0600 身份、真实 Linux NOREPLACE/fsync 支持、部署 Python/平台/依赖身份、实际不可变 protected 作业/manifest/nonce、配置白名单、continuity/recovery/reservation 和单次 capability。没有这些前提保持 HOLD；本卡不授权发凭据请求或运行真实 root 写者。
- 步骤与独立预期：初始化的目录 parent/dir 与三个不可变文件/dir 共八个必要原像屏障全部完成后，才写 INITIALIZED marker 及其 file/dir 两屏障；每次计数前从持有 FD 重核并同步原 marker、folder/parent，不补建缺失 marker，不把原像外观完整当成初始化证明。每次 ATTEMPT 的 file/dir fsync 先于返回。注入各屏障/断电、原像漂移、缺链、链接和位移，部分证据必须保留，不补建/接管/重置。六个冷启动进程累加同一计数；第七次及新单元拒绝；任何 UNKNOWN 不被后来的错误或 operator resend 清除。
- 证据：精确 HEAD/tree/dirty、命令退出码、完整日志物理顺序与 END、前后 stat/inode/大小/SHA256、原策略白名单和单位全原像身份、真实 parent/file/dir barrier 顺序、共享 namespace、六次冷启动计数和实际发送对应关系。私有目标/数据不公开；单项、局部或意图计数 PASS 不计为普通 full proof 或真实发送证明。
- 清理与风险：只清理经授权隔离副本与确证自有临时进程；不删除锁、journal、History/fence/预留，不解除 UNKNOWN，不重置计数。无法证明实际尝试边界时只读对账和可见停滞，六次耗尽保持 UNKNOWN。真实断电、Linux/容器 inode 与跨 store 收敛未执行，保持 NOT RUN。

本地 `record_reserved_attempt_intent` 已接通原 enrollment → History 行预算 → actual
metadata 永久 fence quota → Cabling 新增 NV 预留 → durable count → 全原像重核。
缺原像不增加计数，计数后的失败保留 UNKNOWN，不回退、替换或修复；六个冷进程重开
原预留，第七次 HOLD。它仍不授予发送许可，也不证明隐藏 PROJECT 配额、新鲜来源、
FIFO、每次准入／真实单次 wire；部署与真实断电验收准确保持 NOT RUN。

本地原 WIRE 私有交接在双 owner 下先 NOREPLACE/fsync 固化 CLAIM 链再借出
原只读 CLOEXEC FD；同一原次数只消费一次，真实冷进程不能恢复已消费次数。
部分领取、barrier 中断、元数据／inode 漂移拒绝并保留 UNKNOWN，不补建旧前缀。
清理必须关闭仍属本次的原 FD，不关闭重用外来 FD；原 ACTION/WIRE/ATTEMPT
不改变。现场还须见证 CLAIM 与唯一固定子进程及新鲜准入对应关系、断电窗口和
实际 M=6 上界；未执行，仍 NOT RUN，不授予网络或生产写权限。

本地同时借出原 ACTION FD，native 原像边界每个只读 private regular FD 仅一次
pread，检查 mode/uid/nlink/大小和前后身份，原一致性不重编译源文件。真实自有
隔离子进程／TLS fixture 已覆盖完整大批次、私有输入 ≤32 KiB、原 60 秒 TOTAL
慢响应终止、原次数保留 UNKNOWN、父侧双锁和 401 无重发；仅 CA/UID/DNS 合成，
不是现场或生产固定 launcher 的发送准入证明。部署还须验证实际 Linux/SDK/CA
身份、orphan 继承和 shared cadence/新鲜准入；本卡继续 NOT RUN。

## TC-REAL-REQ7-COUNTED-MUTATION-LAUNCHER-001 — 原次数固定子进程监督

- 来源投影重放补充（**NOT RUN / REAL_ENV REQUIRED**）：资格判定内部仅复用自己刚读取的 HOLD 来源来构造候选，公开预览仍重读；返回前完整来源／IB／周期链检查及 Switch W1 matched-rule 重开保留，原读取期限不放宽。现场保留正常发送、末端 W1 漂移、同字节收据替换、原读取过期、代表性中断与冷恢复；未省略或合并任何原场景。替代证据仅为独立 literal direct 与实际多脚本 workflow，不证明真实 Cloud、设备或断电；原授权、证据、确认人、清理及剩余风险要求不变。

- 连续首次计数至启动补充（**NOT RUN / REAL_ENV REQUIRED**）：保留 worker/config/W1、C6、审计、配额原件与实际发行读取的期限跨 durable count、pre-Popen、发送后和退出边界；计数后同字节 C6 收据换 inode、原读取过期须零 child/请求，保留原 count=1/UNKNOWN/consumed CLAIM，已有 UNKNOWN 不能绕过共享重试节奏。独立 direct 与 protected worker→C6→实际 native reads→count→固定 TLS child workflow 仅为本地替代证据；正常、关键提交、代表性中断、冷恢复和失败安全状态全部保留，无场景省略/合并，真实 Cloud/设备/断电仍未验证。保存精确树、原件 stat/SHA、真实请求计数、完整日志及退出码；原授权、必要研发确认、清理、残余风险和确认人要求不变，不构成 G1/发送许可。
- 周期解析复用补充（**NOT RUN / REAL_ENV REQUIRED**）：仅实际 gate 持有且完整 worker records/witness 原件的目录、文件 FD、命名边、stat/ctime 与字节始终一致时复用一次语义解释；每次引用复核全部原件，作用域退出撤销，其他真实来源语义与读取期限不豁免。原件同字节换 inode、目录 ABA、见证原 inode 改写后恢复 mtime、缺失原件及 store/gate 改绑须 HOLD，不修补。全部既有正常、提交、中断、冷恢复与失败安全状态保留，无场景省略或合并；独立 direct 和实际多脚本流程仅为本地替代证据，不证明真实 Cloud、设备或断电。残余风险与精确授权、研发确认、原件证据、仅自有副本清理、确认人及发布门禁沿用本卡。

- 每次语义重放两侧复核补充（**NOT RUN / REAL_ENV REQUIRED**）：在最后一次 pre-Popen 计数/CLAIM 重放返回边界，原 ATTEMPT 同 inode 写后恢复字节/mtime 仍须零 Popen、零 child、零请求，并保留原 UNKNOWN/count/consumed CLAIM；不得只在发送后的检查拒绝。保存复核前后原 FD/stat/ctime/字节摘要和实际请求计数。替代证据仅为独立 direct 与自有 loopback TLS/固定 child workflow；正常流程、关键提交、中断、冷恢复和失败安全状态全部保留，无省略或合并，真实 Cloud/设备/断电未验证，原授权、确认人要求、清理范围及残余风险不变。

- 首次计数解释窗口补充（**NOT RUN / REAL_ENV REQUIRED**）：动作、WIRE、HEADER、INITIALIZED 和完整 ATTEMPT 前缀须在首次解释计数前固定原 FD/身份；在读取返回边界换 inode 或原 inode 写后恢复字节/mtime，均不得发行 live CLAIM 像、Popen 或请求，原计数及 UNKNOWN 保留。独立 direct 与真实固定 native workflow 是本地替代证据，不证明真实设备或断电；本卡正常/关键提交/代表性中断/冷恢复/失败安全状态全部保留，没有省略或合并，原授权、证据、清理、残余风险及确认要求不变。

- dispatch 目录换出再换回补充：与 journal 目录相同，保留原 inode/全部字节但 ctime 改变也须在 Popen 前拒绝，原 CLAIM/UNKNOWN 保留。实际 owned loopback TLS/固定 child 的零请求回归仅为本地替代证据；本卡仍 NOT RUN，保留全部原场景与残余风险、授权和确认要求。

- 计数原件持续持有补充（**NOT RUN / REAL_ENV REQUIRED**）：在另行精确授权的私有隔离副本保留正常原次数→固定启动、关键 CLAIM/启动/发送后边界、代表性中断、冷恢复和失败安全状态。验证 HEADER、INITIALIZED、完整 ATTEMPT 前缀同字节换 inode、原 inode 写后恢复字节及 mtime、journal 目录换出再换回均拒绝；启动前零 child/请求，已发送后 HOLD 且 UNKNOWN/count/CLAIM 不清除、不回退、不补写、不重发，确证 child 终止状态如实保留。保存原 FD/name/完整 stat（含 ctime）、逐字节前后 SHA、实际请求计数、双锁归属、精确树/命令/Python/平台/完整日志和退出码；清理仅恢复获准自有副本，不处理未知 PID。保留全部原场景，无省略或合并；替代证据为独立 direct 与 owned loopback TLS→固定 isolated child→原次数后置检查 workflow。真实部署、断电、在线请求、M6 整体准入/G1/FIFO/COMPLETE 仍未验证，不标通过；确认沿用 owner 本轮验证纪律，原现场授权、研发确认与发布门禁保持有效，不扩权。

- Case ID：`TC-REAL-REQ7-COUNTED-MUTATION-LAUNCHER-001`；类型：native / durable / integration；对应 C-6/C-14/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。涉及 `monitor/issue_tracker_mutation_launcher.py`、global attempt journal、local commit、spreadsheet owner、send unit/intent、TLS 和 attempt supervision。
- 风险与目标：原 CLAIM context 的当前 process-local 对象只能启动一次固定子进程；复制、失效、启动错误不能恢复；实际原 ACTION/WIRE、双锁 FD 继承，凭据仅 bounded stdin，不以调用者 FD/hash tuple 冒充发行证据。原次数不重置，任何不确定结果保持 UNKNOWN。
- 前置条件：owner 精确 Stage O/部署授权、可信受审固定 worker 与部署 Python/SSL/CA/SDK、实际 root 单链接私有原像与锁。新鲜 protected sources/config/W1/template/continuity、shared cadence、G1 全配额和 recovery 必须另在启动器之前闭合；本卡/私有启动器不代替这些门禁，不授权真实联网或 root 写者。
- 步骤与独立预期：验证固定 program/cwd/剥离环境与 ≤32 KiB private input；每个原次数的 durable CLAIM 与实际一次 native request 关联，六次耗尽拒绝第七次；401/3xx/429/5xx、startup/error/slow DNS/TLS/body 不刷新重发。实际 60 秒单调 TOTAL 包括 Popen 到终止及后置检查；无法确认 child/group 结束保持 HOLD，sheet lock 的继承存活不受父失效解除；原映射/次数/策略漂移拒绝。
- 证据：精确 HEAD/tree/dirty、manifest/ledger、命令/Python/平台、完整日志 END 与退出码、前后 stat/inode/大小/SHA256；私有输入无泄漏、真实一次请求/原字节哈希/CLAIM 链、60 秒阶段和确证终止、双 owner FD 与遗留 child 的排斥。成功 ACK 不证明 APPLIED，单项/本地假服务不冒充普通 full proof、整个 REQ7 或真实部署。
- 故障注入与清理：仅经授权的隔离真实服务副本、全量 Stage O 见证；本地只清理自有临时 children/groups/fixtures，不删除锁、原 journal/CLAIM/reservation，不解除 UNKNOWN，不重置次数，不向其他树回流。真实 Linux/生产 orphan/断电和在线 activation 未执行，保持 NOT RUN。

## TC-REAL-REQ7-SPREADSHEET-OWNER-001 — 跨项目持久 OS 锁与继承 FD

- Case ID：`TC-REAL-REQ7-SPREADSHEET-OWNER-001`；类型：native / integration；对应 C-6/C-14/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。涉及 `monitor/issue_tracker_spreadsheet_owner.py`、`monitor/issue_tracker_local_commit.py`、`monitor/issue_tracker_send_intent.py`；本地合成 root 元数据、原生 flock／独立进程／继承 FD 与实际 C-6/action journal 不证明部署身份或整个 REQ7。
- 风险与目标：跨项目相同 spreadsheet ID 必须共用一把持久空锁，非阻塞、无 expiry takeover、无路径／UID／TTL 参数；父退出时先撤销 token，仅 close，继承子进程仍持锁；不删除锁，不用 mtime 或 remote marker 当接管权威。跨主机不支持。
- 前置条件：owner 另行精确授权部署前提和隔离副本 Stage O；受审固定 launcher 与 root worker、唯一主机共享的 `/var/lib/http-ztp-container/issue-tracker` root 0700 目录、每层祖先 root 且无 group/other 写位、锁常规 root 0600/nlink 1/空文件。该库不创建或修复祖先，不能借本卡部署或解锁。host/container 共享同一 inode 的挂载权威必须独立实证；没有共享命名空间便拒绝发送。
- 步骤与独立预期：两个项目的实际 C-6 owner 可各自持有，但同目标全局竞争者必须 HOLD；不同目标可独立进入。固定子进程继承已验证 FD，监督器死亡／上下文退出不释放子持有的锁，直到真实总预算清理证明其退出；新鲜复核每层祖先及锁 pathname/inode。注入链接、位移、额外字节、权限、重启及长时间锁龄均不得修复／删除／接管。
- 证据：精确 HEAD/tree/dirty、命令/退出码、Python/平台与实际挂载、完整日志物理顺序/END、前后 stat/inode/大小/SHA256、实际两个项目 journal 和锁 FD/session 归属、父死子存、竞争拒绝及最后持有者退出后的恢复互斥；私有 ID 不公开。全局 UNKNOWN/FIFO、分配／预留与实际 M=6 单次 capability 另证，不因拿锁视为完成。
- 清理与风险：只回收本卡确证自有的隔离子进程和经授权副本；不删除真实锁、journal、History、fence 或 outstanding reservation，不向不确定 PID/group 发信号；无法证明终止或共享命名空间时 HOLD。真实 root、容器和父死子存 Stage O 前提未执行，保持 NOT RUN。

## TC-REAL-REQ7-REMOTE-HISTORY-MATCH-001 — journal/原始 nonce/fence/全部 History 必要对账

- 冷读原件窗口补充（**NOT RUN / REAL_ENV REQUIRED**）：解析前持有六份 completion 原文件 FD，至 RAW 重放、同步屏障与最终返回持续核 stat/inode/字节／命名边。HEADER 同 inode／同字节改写及同步更新 COMPLETE 的自洽替代也必须 HOLD，保留实际 UNKNOWN／次数和原 journal，不回滚或采用。本地独立 direct 与真实受监督 TLS→双 owner→完成落盘→冷读 workflow 不等于现场验收、断电或 APPLIED。现场需精确原件只读与隔离改写注入授权，留存窗口前后身份、原件摘要、故障物理顺序与冷进程身份；清理只限自有 fixture。未缩减或合并原场景，原前置／风险及其他未运行范围不变。

- 持久原始完成证据补充（**NOT RUN / REAL_ENV REQUIRED**）：实际双 owner 固定 identity/headers/metadata/History 四份完整回应须在整个文件写入期间保持原签发、原期限、当前固定策略与原 journal/nonce/History 身份。独立只增不改 `.completion` 中四份 RAW、HEADER、目录和父目录的十四个前置 fsync 全成功后才写 COMPLETE。逐屏障中断、缺审计、复制对象、同字节 HEADER 替换、尾行摘要漂移、HEADER 后计数变化或期限失效须 HOLD，partial 原样保留，不补建、不覆盖。冷读逐项核固定读取路径原摘要，并从原 RAW 重放严格模板、nonce、永久 fence 和全部 History/原前缀语义；同步重算 RAW/stat/HEADER/MATCHED/marker 也不能使语义错误的 proof 通过。历史 decoder 无凭据，不签发 live HTTP 或远端新鲜性。现场前置须另获原件只读与一次性副本故障注入授权；证据留存完整执行物理顺序、每个原件 inode/SHA、RAW/HEADER/marker 摘要及冷进程回读身份。清理只限自有隔离 fixture，不删真实原件、nonce/fence、预留、UNKNOWN 或计数。冷读只返回 `COMPLETE-PRESENT-NOT-APPLIED` 历史观察；不是 COMPLETE→APPLIED、FIFO/high-water/outbox 结算、发送准入或在线激活证明，仍有非原子读取与隐藏 PROJECT 库存未证明的风险。

- 新鲜计数读门补充（**NOT RUN / REAL_ENV REQUIRED**）：实际固定 identity/headers/W1/metadata 四次原始读取须在原始 C5/C6 计数前后保持双 owner、策略和原期限。W1 ID 与十四表身份匹配，规则等于冻结本地快照，双原 nonce 正确，无已有 fence／可见溢出。复制回应拒绝；期限在 durable 计数之后失效时保留 UNKNOWN 和原计数。现场证据须保留固定请求、原回应摘要、原始预留绑定及故障阶段，清理仅获准隔离副本；非原子读、隐藏 PROJECT、真实业务/History 连续性和 mutation 风险不闭合，不授予发送许可。

- 固定原始读取桥补充（**NOT RUN / REAL_ENV REQUIRED**）：模板 identity/四表 headers、metadata search 和完整 History tail 仅接受受监督固定入口实际签发对象，原双 owner、当前策略、原始参数/正文及原 30 秒期限在匹配前后同时有效。真实拥有的 loopback 测试保留 UNKNOWN，拒绝复制对象、漂移表头、缺少审计、解析后期限到期和策略撤销。现场须独立记录该来源链及四次非原子读取限制；不提升隐藏 PROJECT 库存完整性或授权 mutation/COMPLETE，清理与风险沿用本卡。

- Case ID：`TC-REAL-REQ7-REMOTE-HISTORY-MATCH-001`；类型：integration / transaction / real-environment；对应 C-6/C-19/C-26。状态：**NOT RUN / REAL_ENV REQUIRED**。自动化 `test_cases.test_req7_remote_history_match`；涉及 `monitor/issue_tracker_remote_history_match.py`、global owner/attempt、enrollment、preread、metadata、typed History 和原生 TLS，未安装。本地私有 loopback TLS 与真实自有文件屏障不证明部署身份或整个 REQ7。
- 风险与目标：仅原始 journal、两份原始 nonce、精确永久 fence、所有实际业务及附带审计行与发送前原像同时匹配，才能产生 MATCHED_OBSERVATION；这不是 COMPLETE、APPLIED 或发送许可，不清除 UNKNOWN、容量预留或审计 pending。
- 原件窗口补充（**NOT RUN / REAL_ENV REQUIRED**）：从匹配前到最终 issued-read 门禁完成，持续持有原 global journal、History preread 和 enrollment 的目录 FD，核全部原文件 stat/inode/字节及命名边。解析中或匹配后新增 ATTEMPT、同字节 WIRE/History/NONCES 文件或目录替换均 HOLD，保留实际计数、UNKNOWN 和被替换原件，不回滚／采用。现场须另获精确隔离注入授权，按本卡证据规则保留窗口前后身份和故障阶段；清理只限自有 fixture，真实 journal/nonce/fence 不删除。
- 前置条件与输入：另获 owner 精确 Stage O 一次性副本只读授权和实际固定目录/Python/SSL/CA 身份；已初始化实际全表 owner、原始 enrollment、global action/wire 和发送前完整 raw。真实发送、凭据、部署、结算和受审 launcher 未由本卡授权；缺任何前提保持 NOT RUN。
- 步骤与独立预期：固定原生全尾 GET/metadata search/全尾 GET → 原始 raw 及 before → 已计数 UNKNOWN journal → 两份 nonce与精确 fence → 全行对账。typed 前缀不得改变，容量不得收缩，所有实际业务和审计必须按原顺序完整且无额外行；全 NOOP 不伪造 History。缺 fence UNKNOWN；外来 fence、缺/多/重复/公式/错序行或原像漂移 CONFLICT；部分/截断/重复 JSON/重复 metadata/外来路径 HOLD。
- 证据：当前精确 HEAD/tree/dirty、执行命令与退出码、Python/平台身份、完整日志及 END、前后 stat/inode/大小/SHA256、原始 raw 摘要与全部行匹配数量、实际 UNKNOWN 保留。原始 History、nonce 与 token 私密，不公开；不得将单项观察提升为正式 full proof。
- 故障注入与清理：逐项缺失 journal、marker 或原像，变更 before typed 细胞/空洞、不同 fence ID、两份 nonce错配、额外业务/审计/外来 append、断连及重复回调；只回收确证自有临时目录与进程，不删除真实 journal/fence/nonce、不重置计数、不解锁重发。

## TC-REAL-REQ7-HISTORY-PREREAD-JOURNAL-001 — 不可变发送前 History 原像

- 普通 C6 计数原 namespace 补充（**NOT RUN / REAL_ENV REQUIRED**）：从原链读取前到最终计数后核持续持有 admission、generation 四件、原 XLSX、settings/events/outbox/current 的原目录／文件 FD。同字节 admission 原件替换必须 HOLD，不采用新 inode；前置失败零计数、后置失败保留原次数和 UNKNOWN、原件及替换件、原 quota/outbox。现场沿用原精确授权、前置、清理和风险，保存实际双 owner、所有原件 stat/inode/SHA 和 barrier 物理顺序。本地真实受保护 C5/C6 workflow 不是真机／断电／发送证据；未省略、合并或标通过原场景。共享 retry 新增 INTENT/COUNT 仍由原专用事务核验，本补充不证明旧周期 R2 或整项完成。

- 新鲜完整连续性补充（**NOT RUN / REAL_ENV REQUIRED**）：实际双 owner 和固定原生读取覆盖完整业务／NOOP、发现／占用／原坐标行和全 History，在原始 C5/C6 计数前后比较全部类型化数据／操作者列、容量与尾边界。漏项、重排、复制回应、修改、期限到期或原文件同字节新 inode 都 HOLD；后置失败保留原 UNKNOWN／计数，不重组、不回滚。现场前置须另获原件只读与隔离注入授权，保存实际读取 provenance、原件 inode／SHA、原 wire、全计数链和故障物理顺序，清理仅自有副本。非原子读、无 CAS、隐藏 PROJECT 配额、共享 cadence 和真实 mutation／COMPLETE 仍未关闭；不授权在线操作。

- 原计数联动补充（**NOT RUN / REAL_ENV REQUIRED**）：原始模板 identity RAW 摘要须与 metadata reservation HEADER 一致，不以 JSON 重序列化或语义相等绕过；固定 W1/template/nonces 前后观察是必要条件，不能替代原业务/History journal、真实新鲜读和 COMPLETE。私有 TLS 与真实原 C5/C6 workflow 的全六次计数、计数后到期 UNKNOWN 只属本地见证，现场前置／证据／清理／风险沿用本卡。

- 原 C5 值投影补充（**NOT RUN**）：双 owner 计数必须从受保护 C5 的实际重放结果派生工具列，逐项核原 manifest 全部操作、原业务 wire、NOOP 决策和发送项 UTC；只凭 action/preread 哈希自洽或调用方 typed 行不构成来源证明。缺失／重复／源值或发送时间漂移前置 HOLD 不计数，UNKNOWN 后不重新组批。现场前置需另获受保护源与原 journal 只读及隔离故障注入权限；证据保留原件 inode/SHA、真实重放与计数前后物理顺序。清理仅撤销自有 fixture 注入，不修复或删除真实原件／UNKNOWN；本地独立 Switch 和真实 ETH／IB 多脚本测试不冒称真机通过。

- 原始 C6 计数联动补充（**NOT RUN**）：双 owner 下经真实 recovery／共享 admission／C5 重放，四件 STATE／MANIFEST／INTENT／RECEIPT 的原 inode、SHA、generation、published image 和 manifest 必须在计数前后与冻结 action 一致。缺失／篡改／伪造源前置不计数；后置损坏保留计数及 UNKNOWN，不回退、补建或重新组批。本地 ETH／IB 真实多脚本联测含逐件损坏与计数后漂移；仅 current-cycle 必要观察，旧周期 R2、新鲜准入、实际 M=6／固定 launcher／COMPLETE 仍未证明。真机需另获原件只读及隔离故障注入权限，留存双 owner／inode／SHA／每个原件与计数屏障的完整物理顺序；只撤销自有 fixture 注入，不修复或删除真实 receipt／UNKNOWN。

- 原件计数门禁补充（**NOT RUN**）：每次原始业务 reserved intent 在持久计数前后重核完整业务原件、原 enrollment／History／metadata／适用 BOTH NV，缺失或漂移不补建，前置不计数、后置保留 UNKNOWN。六个实际冷进程／C5-C6 Cabling 本地链不代表真实尝试 M=6、隐藏 PROJECT 配额、当前鲜度或 COMPLETE。需授权真机身份后按本卡屏障／inode／SHA 留证；只清理自有 fixture，不删除真实原件或 UNKNOWN。

- 业务原像补充（**NOT RUN**）：同一全表 owner／计数 0 的原始 global unit、十四表 nonce、History 与适用 NV 下保存整个家族 manifest、全部原始发现／占用／精确行（含 NOOP）。单回应 2 MiB，去重后的独立 envelope 16 MiB，wire／manifest 仍 1 MiB；不保存认证 header、静默分批或截断。八个 file／dir 屏障后才写 marker；真实 C5/C6 receipt 与双表 NV 联动后，UNKNOWN／冷进程只重解码原件；末段原件改写、同字节新 inode、链接／权限／额外文件、nonce／History／NV 漂移均 HOLD。仅必要观察，不是 COMPLETE／新鲜准入／行结算／受审发送。证据继续按下列 stat/inode、SHA、完整日志、原屏障物理顺序留存；清理仅自有 fixture，真实原件与 UNKNOWN 永不删除；真实断电及 Stage O 未运行。

- Case ID：`TC-REAL-REQ7-HISTORY-PREREAD-JOURNAL-001`；类型：durable / integration / real-environment；对应 C-6/C-19/C-26。状态：**NOT RUN / REAL_ENV REQUIRED**。涉及 `monitor/issue_tracker_history_preread_journal.py`、`monitor/issue_tracker_global_attempt_journal.py`、`monitor/issue_tracker_spreadsheet_owner.py`、`monitor/issue_tracker_sheets_read_plan.py`、`monitor/issue_tracker_sheets_read_decode.py`、`monitor/issue_tracker_tls_inputs.py`。本地合成 root 元数据、真实文件屏障和私有 TLS 不代表整个 REQ7 或部署身份。
- 风险与目标：保留首个意图前完整 History 原始响应及 `history_last_row_before_send`，不能以 caller 行号或后来的尾替换。实际全局 journal 与 owner 必须成立，已有 ATTEMPT-1 时不能补建；六个图像屏障后才能写 INITIALIZED，缺 marker 与部分落盘永不采纳。
- 前置条件与输入：另获 owner 精确 Stage O 副本只读授权、固定 root 目录预置与实际 Python/SSL/CA 身份；绑定不可变 unit/action/wire、目标 sheetId、策略与白名单、一次固定完整全尾 GET。容量超过 5002 或无法安全满足时保持 NOT RUN；本卡不授权凭据、部署或在线写入。
- 步骤与独立预期：于实际全表 owner 内核全局计数 0 → 固定原生 TLS GET → typed 全尾解码 → 持久原始响应和 header → 图像屏障 → marker。真实冷进程必须重新解码同一原像并保持边界；原目标、unit、链或 header 漂移拒绝，重哈希的外来目标不能 retarget。该必要观察不是 COMPLETE，不清除 UNKNOWN 或预留。
- 证据：精确 HEAD/tree/dirty、命令及退出码、Python/平台、完整日志及 END、前后 stat/inode/大小/SHA256、marker 的物理屏障顺序、原像摘要和尾边界。History/raw/token 私密，不公开；实际断电与部署身份仅由授权真机证据确认。
- 故障注入与清理：缺失/截断 raw、链接/权限/位移、额外命名空间、六个屏障逐项失败、重哈希外来目标与 UNKNOWN 后补建均 HOLD；只回收确证自有临时目录和进程，不删除真实 journal、fence、nonce 或解锁重发。

本卡新增本地联测：原始 rowCount／typed 最后占用行与冻结 wire 的全部实际业务＋
ALL 审计行确定唯一 append 窗口（NOOP 无虚构行），精确耗尽可接受、溢出 HOLD。
冷进程和 UNKNOWN 不重分配；metadata 预留创建前必须校验 History 预算，并保存
原 History 摘要／窗口绑定。真实编辑后的鲜度、CAS、认证来源仍 NOT RUN，不是 COMPLETE。
完整 2 MiB 原始回应须逐字节保留；不能受 wire／manifest 的 1 MiB 上限误截断，
也不得扩大那些上限。短写、超限、NOREPLACE 与 file-dir 屏障保留原合同和证据。

## TC-REAL-REQ7-BOUNDED-HISTORY-READ-001 — 原始类型的有限 History 回读

- Case ID：`TC-REAL-REQ7-BOUNDED-HISTORY-READ-001`；类型：real-environment / integration；对应 C-8/C-19/C-26。状态：**NOT RUN / REAL_ENV REQUIRED**。涉及 `monitor/issue_tracker_sheets_read_plan.py`、`monitor/issue_tracker_tls_inputs.py`、`monitor/issue_tracker_sheets_read_decode.py`；本地 direct 与原生私有 loopback TLS workflow 已覆盖类型、矩形和一次读取，不证明部署环境或整个 REQ7。
- 新增全尾自动化：固定 `A3:E5002` 与 `sheetType=GRID`、`gridProperties.rowCount/columnCount` 在同一个完整 GET 返回；拒绝超过 5002 行容量、缺/非整数容量、非 GRID、错位/缺 grid、超过实际容量的 rowData 和部分响应。全部 5000 个数据行上界内原始 A:E 占用决定 `last_data_row_index`（零基）；显式空 grid 为表头边界 1，False/0/公式/显式空 string 也算占用。不能把 caller-supplied row number、有限窗口或静默分页提升为完整尾；该观察不是事务快照或 COMPLETE。
- 风险与目标：只读 `Update_History` A:E 明确起止行，最多 5000 行及 2 MiB 响应；缺 grid、错位、额外列、非 200 或不完整回应拒绝；保留 `userEnteredValue` 的原始类型与字面值，不将数字、公式、格式化文字或规范化空白冒充五列 stringValue。该矩形观察不是 COMPLETE，不证明整个尾部完整或 unit 的缺行／重复行不存在。
- 前置条件与输入：另获 owner 精确 Stage O 一次性副本只读权限；先绑定部署 Python/SSL/CA、固定 public SDK、目标 sheet ID、两个 enrollment nonce 与受管不可变 journal 的 before 行、完整当前尾边界。大于有限读取界限 HOLD，不截断，不现场放宽上界；本卡不授权实际凭据或出站。
- 步骤与独立预期：由固定 launcher 和总预算监督读取已证边界，保存 typed 原像、单元所有实际业务行与全部审计行；比对 journal、完整 outcome mapping、action digest、nonce 和永久 fence 四要件。只因一个矩形一致、200 或 fence 存在不得推进 APPLIED。非 200 与第二次回调都不得额外联网。
- 证据：保存精确 HEAD/tree/dirty、命令/退出码、完整物理顺序日志及 END、前后 stat/inode/大小/SHA256、矩形与完整尾边界来源、对应 sheetId 和响应 framing/总预算。私有行、token 和 nonce 不公开；无法安全取得前提保持 NOT RUN。
- 故障注入与清理：仅在获准隔离副本注入 missing/duplicate grid、错 sheetId、数值／公式替换 string、部分响应及超界尾；只回收确证自有临时进程和副本，不删除真实 journal／History／fence 或解锁重发。真实编辑竞态、断线与部署监督仍须另证。

## TC-REAL-REQ7-COMPILED-SEND-INTENT-001 — 非递归 action 与 wire 的持久化先后

- Case ID：`TC-REAL-REQ7-COMPILED-SEND-INTENT-001`；类型：real-environment / durable transaction；对应 C-6/C-14/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。`monitor/issue_tracker_send_intent.py` 是未安装库；本地 direct 与真实 composer → C-6 owner → action/wire journal → 六个冷启动进程 workflow 不证明实际断电、在线发送或 COMPLETE。
- 风险与目标：非递归 ACTION-PREIMAGE、action_digest 与 wire_sha256 必须先于任何 counted intent 完整落盘；不接受摘要一致作为来源权威，不把旧 opaque wire journal 补成新的 action 权威；部分／陌生记录、文件或目录位移、链接、权限或 fsync 不确定保持 HOLD。六次意图不证明真实尝试上界。
- 前置条件、权限与输入：另获 owner 精确 Stage O 一次性副本及断电故障注入授权；在固定部署 Python/平台、已证 spreadsheet-wide OS owner、新鲜准入、固定单次消费 launcher 与不可变受管单元完成后执行。当前库使用项目 C-6 owner，不提供跨项目锁、凭据、发送能力或清理入口，本卡不授权在线操作。
- 步骤与独立预期：先核真实受管单元，将 ACTION-PREIMAGE 和 explicit header 以 single-link 0600、目录 0700、held no-follow FD、atomic NOREPLACE、file/directory fsync 持久保存，再保存精确 wire，再记录每次 UNKNOWN；故障重启后计数和原像不重置。观察器不得制造、修复、回收记录；第七次、变字节、旧 store 或 unresolved 单元拒绝。必须由固定 launcher 另证一份新意图只消费一次，响应另经完整同连接关联和 COMPLETE 对账，不从本地文件存在推导发送许可。
- 证据：保存精确 HEAD/tree/dirty/manifest/Python/平台、完整日志物理顺序及 END、前后 stat/inode/大小/SHA256、action/wire 摘要、每份 intent 与 barrier 顺序、真实调用次数和冷启动见证；私有 wire、nonce、表内容及凭据不公开。局部 PASS 不代表整个 REQ7 或普通发布证明。
- 故障注入、清理与风险：仅获准副本或私有卷内注入 action/header/wire/count 各 barrier 失败、断电、命名空间位移和父进程退出；保留部分证据和 UNKNOWN，不补建 action、不删除真实 journal／fence／预留或解锁重发。只回收本卡确证拥有的测试进程和临时副本，实际断电／卷回滚及线上故障仍 NOT RUN。

## TC-REAL-REQ7-ORIGINAL-APPLIED-001 — 原 C6 与完整远端证明的持久结算证据

- Case ID：`TC-REAL-REQ7-ORIGINAL-APPLIED-001`；类型：transaction / recovery / real-environment；对应 C-6/C-19/C-26。自动化：`test_req7_remote_history_match` 的 direct 与真实多脚本 native/TLS/cold-process workflow。状态：**NOT RUN / REAL_ENV REQUIRED**；本地组件不是 REQ7 整体或发布证明。
- 逐单元 key 高水位补充（**NOT RUN**）：在本卡同一精确环境授权下，保留正常实际发送 key/原 sequence 的持久配对、NOOP 排除、COMPLETE-only 拒绝、代表性 marker 前中断保留 pending、同字节 APPLIED 原件替换拒绝和独立冷进程重读。两份 key 记录须互绑首写 inode 并持续核原 C6/COMPLETE/APPLIED 与屏障；部分证据不补建、不覆盖、不删除，原 count/WIRE/UNKNOWN/预留与本地 C6 字节/inode 不变。返回逐单元 key/sequence 不等于所有历史单元的最大高水位，不授予 FIFO/NEW 或发送权。保存原件与 key 配对的 before/after stat/inode/SHA、完整 END/物理顺序、提交屏障及零重发/清栅/清理见证；仅清理确证自有 fixture。没有省略或合并原场景，无新风险接受确认；本地独立 direct/真实 native/TLS/cold-process 替代证据不能冒充断电/设备/Cloud，相关现场、全局消费者及在线 worker 未验证范围继续 NOT RUN，原研发确认、现场授权与发布门禁有效。
- 风险与目标：不得把 caller 标志、摘要形状、NOOP、被替换原件或 partial 当成已结算，不能丢原计数、回滚 UNKNOWN 或重发。边界是原 C6 全套文件/已发布 XLSX→原 COMPLETE 全 RAW/nonce/fence/History→独立历史 APPLIED 配对；尚不释放 FIFO/quota/预留/高水位。
- 前置条件与权限：另获精确 Stage O 一次性副本、部署 Python/平台、实际 project→spreadsheet 双锁、真实固定读取及断电/设备故障注入授权；本卡不授权真实 SSH、root 管理、线上 mutation、清栅或生产发布。自动化仅使用自有私有 native 文件与本地加密 socket。
- 步骤与独立预期：验证正常完整原 C6/COMPLETE，仅实际发送业务子集结算，NOOP 原映射不变；准备两份 single-link 0600 记录并互绑原 inode，持有首写 FD，STARTED 后 marker 的 NOREPLACE/file/parent 屏障完成才确认。冷进程重核全部原件/语义/屏障，无父对象、新身份或重新编译来源参与。
- 故障与恢复：保留两份 file fsync、两次安装 parent fsync、代表性 marker 前中断、暖/冷同字节 inode 替换、提交时原 C6 收据丢失及恢复后安全状态。partial/pending 原件保持 HOLD，不补建、不覆盖、不删除、不自动释放重发；最终安装后 parent fsync 失败不 ACK，完整原配对仅可在重新建立全部必要屏障后读回，不得填补缺项。SIGKILL/native fsync 注入/冷解释器不能冒充断电或真实设备。
- 证据与清理：留精确 HEAD/tree/dirty/manifest/Python/平台、命令/退出码、原始完整日志 END/物理顺序、前后 stat/inode/SHA、每个 barrier 与锁生命周期、原 count/WIRE/UNKNOWN 不变及零新增发送/清栅/清理见证；不公开凭据、nonce 或业务原文。清理只限确证自有 fixture，不改真实原件。
- 范围与残余风险：没有删减、跳过、弱化或合并原自动化/现场场景，无新风险接受确认人；本卡登记依据为 owner 2026-10-08 验证指令。替代证据仅为独立本地 direct/真实 workflow，不替代设备/Cloud/断电持久性、在线 worker 消费闭环或当前树 full/check；这些未验证范围全部 NOT RUN，原现场授权、研发确认及发布门禁保持有效。

## TC-REAL-REQ7-IMMUTABLE-SEND-UNIT-001 — 单表不可变 batch / History / 永久 fence

- K current 无覆盖提交补充（**NOT RUN / REAL_ENV REQUIRED**）：保留全部原八个 event/outbox/current 屏障场景，另加旧指针移动后的源目录与 quarantine 屏障（合计十个安装屏障）、移动前原名被替换、移动后陌生 current 插入，以及暖／冷拒绝收养 partial 场景。正常提交将持有的原指针 NOREPLACE 归档，逐字节保留且两目录同步，再 NOREPLACE 安装新 current；不得覆盖陌生对象、回滚事件、补建交付投影或 ACK 失败。证据含各原件与归档 before/after stat/inode/SHA、完整屏障物理顺序和新进程 HOLD，清理只限确证自有夹具。未省略或合并原场景；确认人为本轮 owner 指令，替代证据为独立 direct 与真实成对 native/TLS/cold workflow。真实断电、设备／卷持久性及在线 worker 仍未验证，不标通过，不扩大既有现场授权、研发确认或发布范围。

- K guard 收尾补充（**NOT RUN / REAL_ENV REQUIRED**）：保留原 guard 替换件、既有归档目的名碰撞、原子 NOREPLACE 移动后 settings／quarantine 两个目录屏障失败、最终证明丢失和冷恢复场景。成功后仅归档原 guard，不删除名称替换件；任一异常不 ACK，保留 partial／归档与持久 STOP，原事件、已冻结单元及 UNKNOWN 不回滚或释放。前后 stat/inode/SHA、屏障物理顺序和新进程证据沿用本卡要求。没有删减或合并原场景；确认人为本轮 owner 指令，替代证据为本地独立预期和 native 双 owner／TLS／冷进程故障流程；真实断电、实际卷持久性及线上 worker 仍未验证，不标通过，不扩展原现场授权、研发确认或发布范围。

- 完成配对 K 写入补充（**NOT RUN / REAL_ENV REQUIRED**）：沿用本卡原精确副本与环境授权，保留正常原 COMPLETE/DELIVERED 后 K 更新、精确请求重放／冲突、八个 event/outbox/current 提交屏障、未决 guard 的 file/parent 与清理屏障、代表性中断、冷恢复、证明丢失和同字节指针替换场景。immutable event／投影使用原子 NOREPLACE，保留 temporary-file／installed-parent／held-file 三屏障；安装后临时名称被替换时必须保留替换件并 HOLD，不按不再可信的临时名称删除。新 K 只在全部必需屏障及原件最终复核后确认；失败保留 partial 与 guard，暖／冷 owner 不采用 coherent-looking tail、不回退旧 K、不补建已交付投影、不改变旧 ACTION/WIRE 或 UNKNOWN。保存精确树／命令／退出码／Python／平台、完整 END／物理顺序、前后 stat/inode/大小/SHA、锁生命周期和每个 barrier 的原证据，只清理确证自有夹具。未缩减或合并原场景，确认人为本轮 owner 指令；本地 native/fsync 故障与新进程不能冒充断电、真实 Cloud 或设备验收。残余风险含真实持久性、默认 root worker／可信 relay 接入、后续 outbox 清理与全表结算，均未验证；原现场授权、必要研发确认及发布门禁保持有效，不新增真实环境权限。

- 完成配对 writer scope 补充（**NOT RUN / REAL_ENV REQUIRED**）：在本卡已有精确现场授权内验证项目锁→固定 spreadsheet 锁的获取顺序、暖／冷重新核原 ACTION/WIRE/COMPLETE/DELIVERED 和启动见证、每次 K 读取及正常 scope 收尾再核、异常保留与关闭前撤销、部分／伪造上下文和收尾证明丢失拒绝。保留完整前后 stat/inode/SHA 与锁生命周期、零补建／重发／清理证据，只清理确证自有 fixture。本地独立原预期、真实 TLS/native/cold workflow 不代表真机、断电或在线默认 worker；不增加 K 写入或发布权限，不删减／合并原场景，未验证范围及风险含实际设备持久性、真实 Cloud、默认 worker 与后续清理／K 写入闭环，原现场授权、必要研发确认及生产门禁保持有效。

- 统一 K 读取原配对补充（**NOT RUN / REAL_ENV REQUIRED**）：在本卡原精确环境授权下，核完整 COMPLETE／DELIVERED、固定启动见证及原 settings 仍由双 owner 持有。保留已交付投影缺失后的最高已提交 K、后续事件投影仍必需、冷进程重新获取实际锁／ACTION／WIRE、部分／假／失效上下文和缺交付证明拒绝，以及返回前同字节 current 替换拒绝的现场场景；保存前后原件 inode/stat/SHA、完整原始日志与物理顺序、零补建／重发／清理见证。只清理确证自有 fixture，不变更真实原件或计数。独立本地固定 TLS、native 文件和冷进程证据不代表真实 Cloud、设备或断电；本补充不删减／合并任何原场景、不标通过，残余风险含真实持久屏障、默认 worker／清理／K 写入闭环和生产发布未验证，原研发确认、现场授权及发布门禁保持有效。

- C25 实际 COMPLETE→DELIVERED 补充（**NOT RUN / REAL_ENV REQUIRED**）：双 owner 下核 ALL 初次待审计原事件分配，并持续持有 settings、allocation、全局计数／enrollment／preread 和完整完成证明 FD／stat／字节／命名边；先核实际完整 History、fence、nonce 与屏障，先独占写目录外 `.tracker/SETTINGS-AUDIT-DELIVERY-STARTED` 固定见证，再写独占交付目录 HEADER 和后置 DELIVERED。见证首写身份持有至最终返回，HEADER 绑定该身份；四个见证屏障／首字节故障与目录位移均保留 STOP，冷读不补建、不采用替换原件。HEADER 首写身份须穿过 marker 提交；六个提交屏障失败留存 partial／原 outbox／UNKNOWN，不补建、不回收。冷进程重新核完整配对与屏障；缺失、别名、同字节替换、损坏原 COMPLETE 均 HOLD。有效配对只排除本单元原审计，后续 K 仍待处理；残留投影 cleanup-only、不作重发来源，仅该重新核验配对的精确原 event IDs 可全部或部分缺失投影，暖／冷读不补建、不重发；缺 marker／启动见证／有效原 COMPLETE 或后续未交付 K 的投影缺失均 HOLD，普通 pending／分配／计数仍严格要求所有投影，本实现不执行 outbox 清理，不释放 UNKNOWN／FIFO／高水位或新单元。现场正常完成、关键提交边界、中断、冷恢复和故障后安全状态仍须另获精确副本与环境授权，留全部原件、物理顺序、barrier 与零新增发送／删除见证；只清理确证自有 fixture。独立 RED、本地真实固定 TLS／native 文件／冷进程不代表断电或真实 Cloud；没有删减、合并或标通过原现场场景，残余风险为真实设备、断电、在线 root worker／旧 R2／清理闭环未验证，原研发及发布门禁保持有效。

- Cabling 来源组批补充（**NOT RUN**）：真实每家族两个键的 producer／资格／原始 admitted C6 workbook receipt 与双 owner、十四表 enrollment、两表原始 NV reservation 联动；活动更新不写 A，missing／Closed 以实际原始最高 ID 之后的持久预留追加，所有 A..AC 操作者占用参与尾边界和整组容量；共用原始读像，拒绝 caller ID／坐标／nonce，原像中途变化、篡改 NV、容量不足或未决全局 journal 均 HOLD，保留证据不发 mutation。本地 synthetic root 元数据仅作用于 ownership 测试边界；durable 业务原像／行预留、每次远端模板／enrollment／新鲜准入、固定 launcher 与 COMPLETE 尚未闭合，不是真机或发布证明。

- 完成配对 outbox 归档补充（**NOT RUN / REAL_ENV REQUIRED**）：沿用上述 C25 卡原精确授权；保留正常双 owner／原 COMPLETE+DELIVERED 后归档、部分旧投影缺失、后续 pending 保持、精确重放、源／quarantine 两目录屏障、代表性中断、原名替换、既有归档碰撞、EXDEV 明确拒绝、证明丢失和冷恢复／故障安全状态。仅同设备原子 NOREPLACE 移动精确已交付投影至既有私有隔离区，保留 inode／0600／字节；不删除真实原件、不 copy/delete、不重发、不补件或释放 UNKNOWN／FIFO／高水位。任一失败不 ACK，已移动证据保留；已有实际持久交付时合法 ABSENT-VALID 不等于失败清理通过，交付证明丢失暖／冷必须 HOLD。证据留原件与归档前后 stat/inode/大小/SHA、精确树／命令／平台／退出码、完整 END／物理顺序及锁和屏障。只清理确证自有夹具。没有省略／合并场景；确认人为本轮 owner 指令，替代证据为独立 direct、真实 C19/TLS/native/cold 多脚本自动化。真实断电、设备／卷、Cloud、默认在线 worker 仍未验证，不标通过；残余风险和原现场授权、必要研发确认及发布门禁保持有效，不扩权。

- Case ID：`TC-REAL-REQ7-IMMUTABLE-SEND-UNIT-001`；类型：real-environment / transaction / C-19+C-25+C-26。状态：**NOT RUN / REAL_ENV REQUIRED**。`monitor/issue_tracker_send_unit.py` 是未安装的纯组合库；caller-supplied manifest、坐标、nonce 和 occupied IDs 只被绑定，不是发送许可或完整准入。
- 默认 prod 只读状态原件恢复补充（**NOT RUN / REAL_ENV REQUIRED**）：沿用本卡已有精确副本／环境授权；保留正常交付投影归档后的最高 K、后续 pending／原 WIRE 保持、真实 worker 状态写入、缺失 tracker 不初始化、错误 scope 不访问来源、缺交付证明 HOLD、per-key 来源读取后同字节 HEADER 替换、代表性中断、冷恢复和故障后安全状态。只读状态仍无在线发送权限，C6 提交与 AIR／完整手动 preview 原 owner 不变；不补件、不重发、不释放 UNKNOWN／FIFO／高水位。证据含原件前后 stat/inode/大小/SHA、锁、状态文件与零 tracker 写入见证、精确树／命令／Python／平台／退出码及完整 END／物理顺序；仅清理确证自有本地夹具。没有省略或合并场景；确认人为本轮 owner 指令，替代证据是独立 direct、真实 C19/TLS/native/cold 与实际 worker 状态流程。真实设备／卷、断电、Cloud、旧周期 R2 和线上 lifecycle 仍未验证，不标 PASS；原现场授权、必要研发确认及发布门禁保持有效，不扩权。
- C25 设置工厂原件发现补充（**NOT RUN / REAL_ENV REQUIRED**）：仅沿用本卡原精确现场授权；保留正常认证设置读／改／精确重放、LK-P 后 spreadsheet 锁顺序、无交付声明时普通 pending／UNKNOWN 不变、缺失 tracker 不初始化、错误候选 binding、分配 HEADER 同字节替换、原 WIRE 缺失、K 提交中原件丢失及持久 STOP、作用域撤销、代表性中断与冷恢复／故障安全状态。候选 HEADER 只定位，必须用持续持有原件和实际双 owner 验证原 COMPLETE+DELIVERED+启动见证／分配；不从 caller 标志、缓存或重编译回填，不重发、不释放 UNKNOWN／FIFO／高水位、不启用默认在线 worker。证据留原件前后 stat/inode/大小/SHA、锁／屏障／命名空间、精确树／命令／Python／平台／退出码及完整 END／物理顺序；仅清理确证自有本地夹具，不删真实原件。保留和省略范围：上述场景全部保留，无合并或低概率豁免；替代证据为独立 direct、真实工厂/C19/TLS/native/cold 自动化，确认人为本轮 owner 指令。真实 Cloud、断电、真实设备／卷及完整线上 lifecycle 仍未验证，残余风险明确不标 PASS；原现场授权、必要研发确认和发布门禁不变、不扩权。
- C25 原始审计分配补充（**NOT RUN**）：`monitor/issue_tracker_settings_audit_allocation.py` 仅在实际项目 ACTIVE 与 spreadsheet owner 下读取原始 events/current/INITIALIZED/outbox，派生 revision/hash/时间/内容并固定到 `.tracker/settings-audit-allocation` 的 HEADER、ASSIGNMENTS、后置 INITIALIZED。首次尝试前分配，六次 UNKNOWN 及后续 K 变更均保留原行／wire／outbox，真实受保护 C5/C6/业务原像 workflow 的每次计数前后必须重核分配，后失败不回滚 UNKNOWN。本地使用 native 私有文件／flock／fsync 和 ownership 模块的 scoped root 元数据；不读真实凭据、不发远端 mutation。现场前置须精确双锁、私有路径／祖先、原始 event hash 与 History 归属见证；证据留完整故障日志、各 barrier、分配与计数前后身份／摘要；清理必须保持 UNKNOWN、分配和 outbox，不授予删除权限。该原始分配切片不包含 COMPLETE/DELIVERED；后续桥接见上述独立补充，原始分配接口本身不清理 outbox；完成配对后的独立归档见上述补充，风险是遗漏／重分配同一审计，真实验收及 REQ7 整项仍未完成。
- 原 C25 身份保持补充（**NOT RUN**）：pending 读取和 allocation 的整个调用须保持原 settings/events/outbox/current/INITIALIZED 目录／文件 FD，并在读核后、完成 marker 前及最终返回前核原完整 stat/inode、字节和命名空间；同字节替换也拒绝，不重新采用当前路径。现场仅在另行精确授权的一次性副本故障注入中替换原件，保留各原件与完整物理顺序；无 marker 的 partial 原样保留、不可补建，不删除真实 outbox、UNKNOWN 或分配。此补充不证明 COMPLETE/DELIVERED 或发送准入，权限、清理与风险沿用本卡。
- 原 C25 分配／计数窗口身份补充（**NOT RUN**）：已完成分配的 HEADER、ASSIGNMENTS、INITIALIZED 和外部见证须保持原只读 FD 至同步和最终复核结束；受保护普通计数及共享重试从前置原件读取至最终后核持续持有原 settings 和分配文件。分别在计数前、持久计数后同字节替换原件，预期前者零计数、后者保留 UNKNOWN 和原计数；共享重试后拒绝还保留未配对 admission INTENT，各 lane 后续 HOLD，不回填配对记录。另行精确授权的隔离副本须留存原件与替换件 inode/stat/SHA、原始 workflow 日志、分配/outbox/C6/admission/计数前后身份；只回收确证自有夹具，真实原件不修补、不删除。此补充仅证明调用／计数窗口内身份，不声称永久 inode 登记、断电、真实设备、COMPLETE/DELIVERED 或发送准入；权限、清理和风险沿用本卡，未缩减或标通过任何现场场景。
- 本地受保护来源联动：`freeze_prod_source_unit` 在实际 C-6 owner 下前后重核三个 family 的 C-5 源，真实 SourceRow 决定业务文字与原记录时间；调用方不能覆盖 manifest／业务／时间。真实多脚本 workflow 覆盖三类业务、原文字 NOOP、来源中途漂移与伪造 candidate 拒绝，模板和发布目录不改变。该证据不是坐标／preread 权威、C-6 receipt、新鲜准入、原始预留、真实发送或 COMPLETE；本卡仍 NOT RUN。
- generation 字节衔接：批次、意图和 NV 预留允许原样绑定 C-6 正序号的 native `gen-…` 名；实际本地 generation／INTENT／commit 到 batch／durable intent／冷进程计数已用私有 fixture 验证。候选摘要身份不是真实 generation，任意合法 native 名亦不证明存在对应 receipt；完整受保护工作簿 receipt、恢复、准入与在线资格仍须独立核验，本卡仍 NOT RUN。
- Switch 混合组批补充（NOT RUN）：真实 C5／原始 admitted C6 receipt 与实际双 owner 联动，原始十四表 enrollment 决定 target／History numeric ID 和 nonce；任意同一 spreadsheet 的未决 journal／预留／原像命名空间阻止新组批，不允许 UNKNOWN 重建。完整键／占用原像共用，逐项派生 L-only 更新或不同预置空闲行新增，SourceRow 决定全部文字与原记录时间，组批前后核来源／receipt／nonce／typed 行／History 容量。本机仅在 ownership 模块 OS 边界合成 root 元数据，其他 C6 模块保持 native 路径和 UID，flock／FD／fsync 是真实私有文件；不是真机或线上授权。durable 业务原像／行预留、Cabling 插入、每次远端模板／enrollment／准入、发送和 COMPLETE 尚待闭合，不发 mutation。
- 原始 receipt 联动：`freeze_receipted_prod_source_unit` 在 owner 和恢复屏障下核原始当前周期工作簿／RECEIPT／共享准入及受保护 C-5 manifest，generation 和发布摘要由原始证据决定，不接受 caller 替换。真实多脚本 workflow 覆盖三表、伪造序号类型、缺失准入和组批后出版文件被替换，拒绝后不修复证据、不创建 remote intent。此为原始本地绑定，不是行身份／nonce／preread／预留、新鲜发送准入、固定 launcher 或在线资格；本卡仍 NOT RUN。
- 物理连续性：组批前后原 generation 目录及 STATE／MANIFEST／INTENT／RECEIPT 的 dev/inode/大小均须保持；同字节 receipt 新 inode 的独立故障注入必须 HOLD，不能以摘要相同接受替代对象。只在私有本地 fixture 换名保存原对象并恢复，真实原始证据不做自动修复。
- 风险与目标：禁止跨表原子性假象、遗漏 NOOP outcome／附带审计、递归 action_digest、拆批绕过预算、fence 碰撞后换 ID 或单独 fence 冒充 COMPLETE。业务 run、全部对应 Update_History 五列字面行和一个 SHEET 锚定 DOCUMENT fence 必须同 batch；全 NOOP 审计 pending，不产生发送单元。
- 前置条件与输入：owner 对精确源码／测试／manifest／Python／平台树签发 Stage L、固定 launcher、真实尝试上界、新鲜准入、spreadsheet-wide owner、enrollment 与容量预留证明；另有一次性表副本的精确 Stage O 授权和人工编辑契约。未满足时 HOLD，不启动凭据或 mutation；本卡不授予部署或在线写权限。
- 步骤与预期：经受管入口冻结一个合格单表单元，核对最多 1000 请求对象（含 History/fence）、wire 与非递归 action preimage 各最多 1 MiB；同字节 journal 后只通过被批准 launcher 发送。读取原生连接相关响应与目标、History、两份 nonce、永久 fence，按不可变 journal 完整对账；缺项、重复、碰撞、不同单元或摘要不一致均 UNKNOWN／CONFLICT，不换 ID、不清除预留。全 NOOP 不形成 audit-only 单元。
- 证据：保存精确 HEAD/tree/dirty、stat/inode/大小/SHA256 与完整前缀／END 的日志，manifest/outcome/action/wire 摘要、实际发送业务子集、全部审计 ID、真实 attempt 计数、History 完整行数与类型化摘要；不公开凭据、token、nonce 原文或目标表内容。本地真实 cell encoder → composer → C-6 owner/journal workflow 只证明不可变组合及六次意图，**不证明真实发送上界或 COMPLETE**。
- 故障注入与清理：owner 批准副本内验证掉线、部分响应、重复 ID、位移和重启，原断言不弱化；未知时保留锁、journal 和预留，不回收永久栅，不擅自删除远端 History／marker；仅退役一次性副本需 owner 另行指令。库本身无网络、重试、安装、清理或解锁入口。

- C25 分配留存的外部见证补充（**NOT RUN**）：实际项目 `.tracker/SETTINGS-AUDIT-ALLOCATED` 的 file/parent barriers 必须先于分配目录创建。分配目录整体丢失、见证被移走／篡改／链接或根目录出现未解释 pending 均 HOLD；不能把它们解释为首用、清理或重建许可。保留外部见证、原目录及所有 partial 原像，不恢复／覆盖真实原件。本地独立删除和逐 barrier 故障注入不代表现场抗删除或发布证明。

## TC-REAL-REQ7-METADATA-CAPACITY-001 — 永久栅与可见容量的保守核算


- Case ID：`TC-REAL-REQ7-METADATA-CAPACITY-001`；类型：real-environment / read-only API / G1；对应 C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。`monitor/issue_tracker_metadata_capacity.py` 是未安装库；本地 direct 和实际 TLS → 固定 read-only search → 十四表身份 → 容量核算 workflow 只使用私有 fake 服务，不是发送许可。
- 前置条件与权限：另获 owner 精确 Stage O 副本及只读调用授权；完整固定 launcher、30 秒整体 read budget、依赖/CA、每次目标与准入复核及 spreadsheet-wide owner 已证后才可接入。固定 search 返回的 PROJECT 元数据只覆盖发起调用的 Cloud 项目；他项目元数据可不可见，HTTP 完整不等于全球完整库存，未闭合时保持 VISIBLE_ONLY_UNPROVED，不以空查询或缺少记录允许写入。
- 步骤与独立预期：保留永久栅，无自动回收；按 metadataKey/metadataValue 实际表示、enrollment、其他可见元数据和全部未决预留分别核每 sheet 30000 与 spreadsheet 30000 字符池。UTF-8 字节保守计量并明确单位；row/column 归属各自 sheet，不混作全表总池。原生 id 冲突、未知位置、重复或畸形内容 HOLD，溢出 STOP_CAPACITY；相同 id 和字节仅避免双重容量计费，不证明 COMPLETE、不清除预留。
- 证据与风险：记录精确 HEAD/tree/manifest/Python/平台、完整有界 read 与旧前缀、前后 stat/inode/大小/SHA、物理顺序和 END、逐池 usage/reservation/remaining、不可见 PROJECT 风险及库存完整性证明缺口；无秘密正文、nonce 或 token。不可见使用量、外部编辑与读写间竞态不由本地观察闭合。
- 故障注入与清理：在精确授权副本测试 enrollment/他方 metadata/未知预留、Unicode、各池临界与超限、部分响应/redirect/non200，不触碰真实业务数据。只清理本卡创建的私有 fixture；不删除未知永久栅、真实 journal 或预留，不以重试/改目标/释放 owner 消除不确定性。无法安全执行仍 NOT RUN。

## TC-REAL-REQ7-NATIVE-READ-WHITELIST-001 — 精确字面列与每单元同规则读核

- Case ID：`TC-REAL-REQ7-NATIVE-READ-WHITELIST-001`；类型：real-environment / read-only API / whitelist；对应 C-7/C-8/C-24。状态：**NOT RUN / REAL_ENV REQUIRED**。本地先决为 `test_req7_sheets_read_plan`、`test_req7_sheets_read_decode`、`test_req7_online_whitelist_read` direct 和真实 TLS/read-plan/grid-decoder/本地 held-workbook workflow 全绿。对应 `monitor/issue_tracker_sheets_read_plan.py`、`monitor/issue_tracker_sheets_read_decode.py`、`monitor/issue_tracker_online_whitelist_read.py` 均为未安装库，不是在线发送入口、APPLIED 回执或新鲜准入许可。
- 前置条件、平台与权限：只有另获 owner 的 Stage O 一次性副本授权，固定启动器和完整每次准入、实际依赖/SDK/TLS/总预算/锁证明闭合后，才执行真实只读 GET；本地开发不联网。先冻结本地设备 Whitelist 快照及合格判定，核精确目标枚举、模板、来源连续性、History/fence/journal/UNKNOWN；这些合同不因本卡单独通过而解除。
- 步骤与独立预期：业务发现只读取 Switch A/F/L 或 Cabling A/F/G/K/L/Q/R 的明确有界 userEnteredValue；行读取只采用精确已绑定矩形，零基坐标/工作簿/sheetId/title/格子联合类型必须逐项匹配。缺失/重复/越界 grid、foreign target、formatted/effective 字段、冲突联合值或非完整响应均拒绝，不把缺失 grid 当空数据、不重新编号源行。
- 模板必要读核：先以没有 ranges/grid 的固定 metadata GET 核十四表身份（精确名称、唯一 native numeric sheetId），再单独读取 Switch A2:U2、两张 Cabling A2:AC2、Update_History A2:E2；按真实本地格式合同逐格比较原始 stringValue，保留多行文字及空白，不接受公式、格式化值、行坐标替换或不同 sheetId。两个 GET 是非原子观察，不证明完整本地格式快照、两侧 enrollment、新鲜连续性或每次发送准入；不是发送许可，不能把引用表的第二行数据当作 header。
- Whitelist 预期：每一 governed unit 之前重新完整读取固定 `'Whitelist'!A1:F10000` 六列并核真实 gridProperties；rowCount 大于 10000 明确 HOLD，不把截断窗口当完整表。只接受精确字符串表头与规则单元格，以真实规范化器比较冻结本地 rules/canonical bytes/SHA，公式/数字/bool/规则变更/读不到均拒绝在线写；不改变本地合格判定、不重筛本地 manifest。此读核是必要条件，不取代完整十四表模板/表头/键发现/预留/History/fence/send-authority。
- 证据、故障与清理：保留脱敏精确命令/退出码、当前树/manifest/Python/平台、完整有界响应摘要和范围/坐标、冻结本地快照的前后 stat/inode/大小/SHA、旧前缀与完整 END、原像/外部哨兵不变、每单元 fresh-read 见证。只恢复获准隔离副本，无 API 写入、真实表重排或外部数据泄漏；真实容量/模板/来源或完整性未证仍 NOT RUN。

## TC-REAL-REQ7-MUTATION-ERROR-CORRELATION-001 — 原生完整错误、全尝试 UNKNOWN 与持久计数

- Case ID：`TC-REAL-REQ7-MUTATION-ERROR-CORRELATION-001`；类型：real-environment / transaction / native connection；对应 C-14/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。`monitor/issue_tracker_mutation_rejection.py` 仅是未安装纯观察器；direct 和真实 literal-cell encoder → 拒绝观察器 workflow 不证明真实发送、同连接关联、持久 M=6 计数、History/fence 或完整 REQ7。
- 前置条件：另获 owner 精确 Stage O 副本授权；先完成 SDK、固定 launcher、总预算／锁、每次新鲜准入、不可变 SEND_INTENT、请求字节绑定与自动重试禁止。原始响应必须由承载该次固定 mutation 的原生完整连接取得，不接受调用方标志代替见证；本卡当前不发真实请求。
- 步骤与独立预期：完整 HTTP/REST JSON 同时匹配 INVALID_ARGUMENT/FAILED_PRECONDITION=400、PERMISSION_DENIED=403、NOT_FOUND=404 才作为明确拒绝；REST JSON code 是 HTTP 数字，不是 grpc code。断流、超时、401、429、5xx、非有限值、重复字段或不一致结果均 UNKNOWN。先前任何 UNKNOWN 必须跨全六次 durable 尝试保留，后续拒绝或成功 ACK 不自行解除；只有完整 journal、双 enrollment、History 与 fence 的相关证明才能解决。
- 证据与清理：保留脱敏命令／退出码、当前 HEAD/tree/manifest/Python/SSL/CA、前后 stat/inode/大小/SHA、完整 END 与物理顺序、不可变发送字节摘要、原生同连接与 framing/截止期见证，以及跨重启的全尝试计数。清理只恢复授权隔离副本；不更改真实表、不移除未知 fence/预留、不向外部 PID 发信号、不打印错误正文或 token。缺实际相关证明保持 NOT RUN，不授予发布许可。

## TC-REAL-REQ7-NV-RESERVATION-001 — 两张 Cabling 的共享持久编号

- Case ID：`TC-REAL-REQ7-NV-RESERVATION-001`；类型：real-environment / durable transaction；对应 C-17/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。`monitor/issue_tracker_nv_reservation.py` 未安装；本地 direct、真实私有 TLS 双读取和冷进程重读只验证保守 pending 单元预留，不是 COMPLETE、来源鉴别、新鲜准入或发送权限。
- 前置条件、权限：另获 owner 精确 Stage O 隔离副本与预置私有 root state 授权；完整模板、原始 enrollment、固定读取器、真实 spreadsheet owner、受审 launcher 和跨单元结算须先闭合；当前不会创建真实目录、凭据或远端数据。两份响应必须绑定原始表 ID、同一 spreadsheet、完整容量及原始 A 列，含 Closed 和无关活动行。
- 步骤与独立预期：保留两份完整原始响应和 immutable generation/publish/目标表/活动键；下一 NV 严格高于两表原始最大值，模板下一号为 NV30017；原有 ID 不改写。十个图像持久屏障全部完成后才能写 INITIALIZED；模拟每个屏障失败、UNKNOWN、冷启动、改变绑定、跨表重复、空种子与 NV99999 耗尽，分别要求 HOLD／保留原号，不回填、重分配或清除。既有 global journal（包括 unattempted/partial）保守阻止新预留；未实现的跨单元结算不冒称通过。
- 证据：精确 HEAD/tree/dirty/diff/manifest/Python/平台、执行命令与退出码、前后 stat/inode/大小/SHA256、完整 END 与物理顺序、两份 RAW 摘要、实际 owner/nonce 原绑定、每个屏障、冷进程和 UNKNOWN 原编号见证；不输出凭据或私有业务正文。
- 清理与风险：只恢复另行授权的隔离副本，保留所有 UNKNOWN 原像／预留／fence；不删除真实 state、不向外部 PID 发信号、不安装或发布。真实断电、卷回滚、在线并发编辑与认证来源保持 NOT RUN。

本卡的新增本地联测还须证明：实际冻结 batch 的每个新增 key/NV 与原始预留集合一致，
两份 nonce 原绑定保持；混合 update 不触碰 A。缺项、换号、外来键／nonce、不同
generation/publish 及 UNKNOWN 下改 action/wire 均 HOLD，不计作 COMPLETE 或线上通过。

## TC-REAL-REQ7-METADATA-RESERVATION-001 — 原 batch 的永久 fence 持久预算

- 共享 retry 原配额补充（**NOT RUN / REAL_ENV REQUIRED**）：保留正常 retry 及持久次数增加后原配额 HEADER 同字节替换的场景；后置身份丢失须在配对 COUNT 前 HOLD，保留未配对 INTENT、已计 UNKNOWN、C6／业务／C25／outbox 原像，后续所有 lane 保持阻断，不补建或回滚。本地 direct 只隔离原 quota/count 边界，实际 C5/C6→原读取→共享事务 workflow 才见证跨脚本行为；均不证明断电、真实 Cloud、旧周期 R2 或发送准入。没有删减或合并既有场景，本卡原授权、证据、清理和未验证风险保持不变。

- 原配额计数连续性补充（**NOT RUN / REAL_ENV REQUIRED**）：现场须保留正常计数、计数前原件缺失及持久计数后同字节替换目录／HEADER 的独立预期；后置替换必须 HOLD，并保留已计 UNKNOWN、原配额和替换前后证据，不回退或重建。本地 direct、六个冷进程及真实受保护 C5/C6 workflow 只验证自有隔离夹具中的原 FD 身份连续性，不冒充断电、真实设备、历史排他或完整 G1 库存验收。未省略或合并原场景；保留本卡原授权、证据及清理边界，未验证范围和残余风险仍为原卡所列。

- 原项目认证与读取接线补充（**NOT RUN / REAL_ENV REQUIRED**）：本地 direct 及真实固定 FD→SDK/OAuth→监督 template/metadata 读取→原 global/enrollment/History→quota 工作流只证明来源支配原 reservation。保留原卡前置、精确授权及现场范围，另留存脱敏认证与原读取关联、落盘前拒绝和落盘后过期仍保留原 quota 的安全状态；不记录 token／JWT／私钥。quota 冷回读不是历史排他／完整库存或 COMPLETE；G1 与 worker 准入未验证。未省略或合并原场景、不授予真实 root／Cloud／项目操作，清理仍限确证自有隔离夹具。

- Case ID：`TC-REAL-REQ7-METADATA-RESERVATION-001`；类型：real-environment / durable transaction；对应 G-1/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。`monitor/issue_tracker_metadata_reservation.py` 未安装；本地 direct、真实私有 TLS 固定读取及冷进程只是原始可见字符池预算见证，不是 COMPLETE、在线准入或发送许可。
- 前置条件：另获 owner 精确 Stage O 隔离副本授权；预置全表私有 state、原始全部模板 ID／双 enrollment、真实 owner 和 global action/wire，首个 intent 前完成固定完整 metadata 读取。源鉴别、新鲜准入、隐藏 PROJECT 使用量、行容量、受审 launcher 和跨单元结算须单独闭合；不创建真实目录、凭据或在线修改。
- 步骤与独立预期：实际 immutable batch 的 fence ID/key/value/目标表确定唯一预留；两份 nonce 可见预算各为 86，z=1 为 2，sheet 与 spreadsheet 各自 30000 池。容量溢出、已存在同 ID（包括相同图像）、部分响应、原 nonce 错误、foreign target 必须在创建 state 前 HOLD；八个图像屏障全部完成后才写 INITIALIZED。部分屏障不采用，冷进程及 UNKNOWN 不换 fence、不回填／清理／释放配额。链接、marker 缺失、重哈希替换 reservation HOLD。
- 证据：精确 HEAD/tree/dirty/diff/manifest/Python/平台、命令／退出码、前后 stat/inode/大小/SHA256、完整 END／物理顺序、固定 TLS 请求见证、原 RAW 摘要、原 action/wire／nonce、所有 fsync 屏障和冷进程 UNKNOWN；不输出 bearer 或业务正文。
- 清理与风险：只恢复另获授权的隔离副本；保留 UNKNOWN 原像与预留／永久 fence，不删除未知 state、不向外部 PID 发信号、不安装／发布。真实断电、卷回滚、隐藏 PROJECT、在线并发修改仍 NOT RUN。

## TC-REAL-REQ7-DURABLE-ATTEMPT-JOURNAL-001 — 意图先落盘与跨重启总计数

- Case ID：`TC-REAL-REQ7-DURABLE-ATTEMPT-JOURNAL-001`；类型：real-environment / durable transaction；对应 C-6/C-14/C-19。状态：**NOT RUN / REAL_ENV REQUIRED**。`monitor/issue_tracker_attempt_journal.py` 是未安装的保守本地证据库；direct 与实际 C-6 owner → literal encoder → 意图 journal → 后续拒绝观察，以及真实私有子进程退出／重启 workflow，不证明实际断电或六次真实网络尝试上界。
- 前置条件、权限：另获 owner 精确 Stage O 隔离副本授权；固定 root worker、跨项目同 spreadsheet 的唯一 OS 锁、继承锁的固定 launcher、每次新鲜准入、不可变完整 batch、双 enrollment 与 COMPLETE 对账闭合后才可接入。当前 API 只使用现有项目 C-6 owner，保守阻止所有新单元；不接受它作为完整 spreadsheet-wide ownership 或发送能力。
- 步骤与独立预期：WIRE、HEADER 与每次 ATTEMPT 必须以 single-link 0600、目录 0700、no-follow held FD、atomic NOREPLACE 和文件／目录 fsync 保存；返回前后重核 ACTIVE token 和命名目录身份。第七次记录、wire 改变、部分／陌生记录、gap、链接及 barrier 失败必须 HOLD 且保留原像；意图落盘后进程死亡不能重置计数／UNKNOWN。必须独立证明固定发送器一次且仅一次消费每份新意图；六次记录本身不等于六次真实尝试。
- 证据、清理与风险：记录精确命令／退出码、HEAD/tree/manifest/Python/平台、完整物理顺序日志、前后 stat/inode/大小/SHA 与 END、跨重启链、故障前后字节和计数。部分记录不自动修复或采用，新单元不夺取 UNKNOWN；无清理／重置入口。真实断电、卷回滚、跨项目锁和 orphan 存活保持 NOT RUN；只恢复获准私有隔离副本，禁止删除真实 journal、预留或 fence、禁止向外部 PID 发信号或输出私有 wire。

## TC-REAL-REQ7-SHARED-RETRY-ADMISSION-001 — 原单元重试与 C23 同一准入域

- Case ID：`TC-REAL-REQ7-SHARED-RETRY-ADMISSION-001`；类型：transaction / integration / real-environment；对应 C-19/C-23。状态：**NOT RUN / REAL_ENV REQUIRED**。本地 `test_req7_shared_retry_admission` direct/实际 C6 与双 owner workflow，以及 `test_issue_tracker_stage_l_consumer_workflow` 的真实 protected 源／原生只读／原计数 scenario 不代表现场发送或完整 REQ7。
- 前置条件与权限：另获 owner 的 Stage O 一次性副本及原私有 state 精确授权。验证 collector alias、实际 clock/boot 身份、唯一项目和 spreadsheet owner、当前 C5/C6、原 ACTION/WIRE、fresh config/W1/template/nonces/ALL business/History 后，才验证必要 shared retry 屏障。固定 launcher 整链、hidden G1、older-cycle R2、FIFO 和 COMPLETE 尚须单独闭合；本卡不授权生产/在线修改。
- 步骤与独立预期：automatic/manual/retry 只有一个 collector-floor limiter；retry 不受独立 N limiter，但推进共同时间及周期锚点。INTENT 在原 counted attempt 前持久化；COUNT 精确关联原 ATTEMPT SHA。每机会只增加一次，M=6 不重置；断电或异常造成 orphan 时所有 lane HOLD，不回填／采用／修复。重试不得生成 C6、伪造新周期发布或修改原件。实际准入时刻而非早期探测时间入记录；boot 不可核验、目录位移（含相同字节复制）、文件漂移均拒绝。
- 证据：精确 HEAD/tree/dirty/diff、manifest、ledger、命令／退出码、Python/平台、完整物理顺序及 END、前后 stat/inode/大小/SHA256 与历史前缀；两把锁、实际 collector completion、clock/boot、前后原 C6 四件、原计数及 INTENT/COUNT 屏障逐项见证。保留 FAIL，不输出秘密正文或 token。
- 故障注入与清理：只在精确批准的隔离副本做 fsync/异常退出、目录位移、计数间源／策略漂移、重启与 exhaustion。保留 UNKNOWN、orphan、原件和预留；不删除真实 state、不安装／发布、不触碰未知 PID、不以冷启动或人工重发清除不确定性。仅清理本卡拥有的临时 fixture；真机断电、boot、并发编辑与卷回滚仍 NOT RUN。
- 历史周期原件边界补充：先实际记录首次 UNKNOWN，再产生真实新 collection completion；只回放原 admitted C6/native K 来源，不能重新编译原 WIRE 或生成新 C6。保留正常第二次重试、计数前输入身份丢失、计数后 C6/策略/W1 同字节替换、同步窗口内换回、INTENT/COUNT 中断及冷恢复的安全状态验证；计数后漂移须留下原计数与未配对 INTENT。记录两份原件 inode/stat/字节及物理日志顺序，不把仅本地 fixture 的 SIGKILL/恢复冒充真实断电。此补充没有省略现场场景或接受新剩余风险；现场、Cloud、设备与断电仍 NOT RUN，依本卡精确授权后再执行。
- 原 worker records 目录换出再换回也须拒绝：完整原 stat/ctime 与 FD 持续核验，不能只凭最终 inode/字节恢复采用中途替换。保留普通 current-cycle 计数拒绝历史单元及 shared retry 正向的独立预期与完整日志。本地自动化不替代现场，未省略原场景或改变授权，状态仍 NOT RUN。
- 共享原计数至固定发送边界补充：保留正常同字节第二次发送、原收据换出、issued ALL-business/History 过期、COUNT 配对前中断、配对后至 consume/pre-Popen/post-send/退出的原件漂移和冷恢复。记录真实原次数、两把锁、唯一子进程、原 WIRE digest、共享时间锚点及完整日志；拒绝不得回滚计数、UNKNOWN 或配额，不得以刷新读取期限通过。已有本地原生 TLS fixture 不代表 Cloud/设备/真实断电；没有省略原现场场景、接受新风险或扩大授权，现场仍 **NOT RUN / REAL_ENV REQUIRED**。

## TC-REAL-REQ7-RETAINED-INVENTORY-001 — 原始 namespace 覆盖与读取证据持有

- Case ID：`TC-REAL-REQ7-RETAINED-INVENTORY-001`；名称：共享 spreadsheet 的既有单元原始 inventory 读取；类型：transaction / integration / real-environment；对应 C-19；状态：**NOT RUN / REAL_ENV REQUIRED**。
- 自动化：`test_cases/test_req7_retained_global_inventory.py` 的独立 shape/direct 和真实 enrollment → GLOBAL journal → History workflow。涉及原始 `issue_tracker_retained_inventory.py`、spreadsheet owner、global/attempt journal、local commit、enrollment、History preread 与 remote History match。
- 适用平台：本地开发 fixture；现场 Linux 管理服务器 / AIR / 容器须另获精确授权。本卡不授权 root、设备、真实 Cloud、SSH、系统 cron、服务切换、发布或未知进程操作。
- 风险与目标：拒绝遗漏或接管 same-spreadsheet 的未知/partial namespace；在解释和恢复屏障前持有每一原始文件与目录。固定 legacy namespace 目前只有一个单元；观察不证明多单元/project/C6/APPLIED 全集、global max、FIFO 释放、G1 或 NEW/发送权。
- 前置条件：精确授权的独立现场副本、原始 root 0700 / private regular single-link 0600、共享 owner 锁和完整原始化记录；当前精确 HEAD/tree/dirty、Python/平台/依赖身份、命令与完整日志；清理范围提前限定为该副本和确证自有资源。缺一保持 HOLD。
- 正常流程：在正常 count 0..6 原始单元中保留所有固定 family，逐项核 namespace、目录与文件 original FD / name / full stat / ctime / SHA；enrollment NONCES 和 History RAW 核原 HEADER/INITIALIZED 摘要，并重放实际 nonce/id、History decode/capacity 与原 GLOBAL 单元绑定。dispatch count 1..6 的 HEADER/CLAIM 链必须绑定实际持有 WIRE/ACTION 身份与原 UNKNOWN-intent；消费不证明 SENT、COMPLETE、FIFO 释放或新请求权限。其他 family 的 witness 不替代其专用语义校验。
- 关键提交边界与中断：保留 unknown suffix、缺 STARTED、partial family、gap/extra entry、special file、同字节名字替换、原 inode 改写、目录位移；持有、语义解释、各 file/dir/parent fsync 与消费者边界注入代表性中断。失败只 HOLD，原文件和 UNKNOWN/count 原样保留，零新增请求、零许可，不修补、重编译、回退、删除、重置或释放 FIFO。
- 冷恢复：独立冷进程重开同一原始 namespace，核原 count/WIRE/STARTED 和 enrollment/History 原件；缺失、被替换、失败后未提交状态不得变成 first-use、NEW 或发送证明。真实断电与恢复、设备及线上 worker 仍 NOT RUN，SIGKILL/正常重启/本地模拟不能冒充断电。
- Business 必要链接：核原 GLOBAL/header/manifest/raw 摘要、全部 operation ID、sent 与 NOOP 覆盖计数和有界原 envelope；自洽 marker 不得绑定 foreign-unit/manifest、遗漏 NOOP 或改变 operation ID。此预滤不替代完整 cell/source 语义，不从 enrollment ids 虚构远端 identity 来取得 typed API 权限，完整 business 验收仍未完成。
- COMPLETE 原件：存在 completion 时必须保留 enrollment、History 和原 completion-started/header/identity/metadata/headers/History 图像，调用现有原件读者重放固定读几何、nonce、fence 与全部 History 绑定；文件形状、自洽摘要、empty-match 或 APPLIED 标签不能代替语义证明。真实本地 owned TLS 正常流程在主树 22 方法 direct/workflow 模块中通过；保留初始旧 owner 注册表造成的夹具 ERROR 与加载顺序修正证据，不改写 UNKNOWN/count，不证明 APPLIED、FIFO 释放、NEW 或真实 Cloud/设备验收。
- 证据：精确树、完整执行命令/退出码/物理日志顺序与 END，读取前后 stat/inode/已知旧前缀 SHA256，全原件 before/after 和屏障顺序；确证实际零 mutation/permit、已持有 FD 的清理以及异常后的安全状态。原日志和诊断失败保留。
- 清理：仅关闭本次仍拥有的 FD 与已授权 fixture；若数字 FD 已被复用并命名其他 dev/inode，保持 HOLD 且不得误关外方 FD；不冒称同 inode 的 open-file-description 身份可移植证明。保留故障原件，不碰真实锁、历史 journal、预留、outbox、count 或未知进程。现场副本移除须独立精确授权，不因自动化 PASS 擅自清理。
- completion-start 清理回归：原读者无条件 finally-close 的真实 FD 误关已由独立 H 见证和 root 两脚本叶测试复现；主树只关闭原 dev/inode，原字节/ctime 变化仍关闭自有对象，复用到其他对象的 FD 不误关。主树 22 方法模块和 H 原见证对集成后主树的独占 native 重跑通过；初始失败保留，主树关联/full 和现场仍须后续验证，不将局部结果标为现场通过，也不宣称同 inode 的 open-description 身份。
- GLOBAL 清理回归：实际 GLOBAL 原件作用域中的 WIRE 与 journal-directory 数字 FD 复用均有独立初始 FAIL，修改后两方法 PASS；保留失败原件、原 UNKNOWN/count 与原校验，原 inode 字节变化后仍关闭自有 FD，外来 dev/inode 不误关。合成 root metadata 仅本地测试夹具，不是现场权限证明；主树实际 workflow/full/check 与现场仍 NOT RUN，局部通过不代替验收。
- 验证范围：本次没有合并、省略或暂缓原现场场景，无新增剩余风险接受确认人。替代证据仅为独立测试与真实本地文件/fsync/多脚本流程；未验证范围为现场 root/Cloud、Linux/容器原件、真实断电、设备和线上完整恢复，均 NOT RUN。原现场授权、研发确认和普通发布门禁保持有效，候选及局部 PASS 不替代当前精确主树 full/check。
- 原顺序联测夹具修复：GLOBAL → remote History → retained inventory 初次 196 方法产生 11 ERROR；实际原 GLOBAL 前置顺序与首个失败 workflow 有界复现确认 enrollment/preread 持有旧 owner 注册表，当前令牌在生产流程前被拒绝。新增独立注册表预期先 RED，再仅修正 owned fixture 的发行前依赖捕获；原行为断言和预算不变，原顺序含新回归 197 PASS / 471.715 秒 / exit 0。完整初败、诊断、RED/GREEN 和旧前缀身份保留；这是精确 dirty 主树局部证据，不是正式 full、现场通过或新风险豁免。
