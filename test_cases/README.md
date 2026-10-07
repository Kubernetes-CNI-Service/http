# Test Case 案例库

`test_cases/` 是仓库唯一的测试案例目录。这里集中保存全部自动化回归、案例模板和必须在
真实环境执行的验收案例；测试文件不得散落到其他源码目录，也不提供旧 `tests/` 别名，避免
同一个案例被 discovery 重复加载。

本目录中的自动化测试不连接设备、不修改项目运行数据，重点检查跨目录接口，而不是替代
真实交换机、Docker 或端到端部署测试。

`test_image_context_safety.py` 约束 H1–H4：三份 Docker ignore 的最终、任意深度凭据规则与
DAY0 最小重包含；镜像专用入口扫描物理目录，不能用 manifest 的选择结果证明不存在项目或
凭据文件。AM-1–AM-6 将 gate 的 generated 路径/前缀与最终 ignore 排除绑定，四个构建支持
文件的 path_rules 必须实际选中本模块；DAY0 重包含精确限定三个规则。共享凭据词表覆盖
ASCII 大小写变体、备份、私钥容器及 SSH 私钥名字；模板 output/lock/history 不能被重包含。
普通 live manifest 校验仍允许 DAY0 项目，并在生成时排除运行时与凭据名字。
AM-7–AM-9 从 setup/activation 共用的 producer 表生成全部固定运行时绑定 fixture，并对实际
producer 的名称/目标消费做覆盖断言；允许 controls 仍为独立清单。共享 image-only host-state
词表生成三份 ignore 最终拒绝块并驱动物理 gate，拒绝 named 子树入口及后代、动态 sample、
generated monitor HTML 和 reference-only 内容。测试覆盖普通文件、合成项目 resolving 与
dangling symlink 三种形态，不把历史 17 路径清单视作完整性证明；
不再用 Python glob 模拟 Docker。显式设置 `HTTP_TEST_SYNTHETIC_DOCKER=1` 时，仅把新建
临时目录中的无害 marker、一份 ignore 文本与其 package/activate 生成的 manifest 送入
本机 BuildKit 的 `FROM scratch / COPY`；三入口 × 三形态的 terminal 集合扣除唯一 manifest
载体，须同时等于 package-generated 路径集和独立允许集合；named 子树空入口也必须消失。再执行
physical + manifest gate。绝不把仓库、项目数据或凭据作为构建上下文。默认不执行 Docker，此项
skip 是 `TC-REAL-IMAGE-CONTEXT-001` 的未执行证据，不是通过；legacy builder 另行验收。

Cumulus QoS、MLAG、snippet 与跨平台 workflow 共用 `module_loader.py`：只按对象身份移除
loader 自己插入的 sys.path 项，保留模块自己声明的路径，保证真实 lazy AIR import 仍可达。
手册参数清单无数量截断；独立测试同时固定 load 的 `--type` 兼容别名不会因增加参数而消失。

四类交付制品的自动化与真实环境分工见
[《四类交付制品与 2026-12 部署流程》](../docs/deployment/BUNDLE_WORKFLOWS.md)。

## 变更感知测试治理

完整机制和退出码见 [CHANGE_AWARE_TESTING.md](CHANGE_AWARE_TESTING.md)。
`test_runner_preflight.py` 覆盖 PF1–4：复用 public authority 的同一干净提交判定，保留固定
历史模块的原合同，并按有效选测做本机 loopback bind/close 能力检查。独立 direct 与真实
临时 Git 仓库的 runner CLI workflow 验证失败先于子进程和 ledger 写入；只读模式不增加
网络要求。内容相同但 Git stat 信息陈旧时须显式运行 `git status` 后重跑；linked worktree
须回到 main checkout。watch 不重试同一失败字节状态，权限或 Git 状态修复后必须重启。
`--preflight` 不是测试证明或验收；H 及发布门禁保留。真实 OS 完整矩阵是 macOS/Linux 各自
允许/拒绝 loopback，未执行的行保持 REAL_ENV OPEN。
受管脚本、canonical 目标和软链接 alias 的数量由当前 manifest 与工作树动态推导；使用
`run_related_tests.py --list` 查看当前值，不在文档中维护容易过期的快照。
runner 每次运行都会重新发现生产脚本，并实时校验每个路径都有 direct 测试
映射、至少一个覆盖多个真实脚本的 workflow/scenario，以及正确的 canonical target。新增脚本
没有完整映射时会 fail closed。

manifest 还把 Cumulus `03-templates-j2/*.yaml.j2` 与 Cumulus/NVOS 配置根的
`default*.yaml` 标为 complete tracked support authorities。runner 只接受正向、仓库相对的
POSIX 直接子项 glob，并通过 held descriptors 校验非链接目录和 single-link regular members；
磁盘新增但未 pinned、pinned 后缺失、特殊文件、symlink/hardlink 或 root/member rebinding
都会阻断证明。生成的 `99-output*` 不会因宽泛递归匹配误入 authority。模板闭包另由不可跳过的
Jinja 测试锁定静态 include/import/from-import/extends 引用及 cycle 拒绝，默认文件则由完整
literal semantic oracle 锁定。上述任一 authority byte 变化会使旧 full-suite attestation
过期；related 测试不会被提升为 eager full，也不能铸造或沿用 stale full proof。

开发期间建议持续观察；普通单次运行会根据已批准 SHA-256 自动选择受影响的 direct 与
workflow/scenario 测试，并且只有全部通过才更新批准哈希：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --watch --interval 2 -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py -v
```

全部 `test_*.py` 还在同一份 manifest 中归入 7 个互斥主测试域。先查看完整目录，再按域执行；
`--suite` 可重复，用于一次合并多个域：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --list-suites
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --suite deployment-runtime -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --suite packaging-sync --suite repository-governance -v
```

分类运行不会更新批准哈希，也不会替代发布前的全量门禁。新增测试模块若没有主分类、属于多个
主分类，或分类引用了不存在的模块，manifest 校验都会 fail closed。

正式发布需要一份绑定当前源码、测试、manifest 和 Python/平台身份的全量回归证明。本机
macOS 正式 `DAY0-Prepare/11-load.py` 先解析并拒绝互相冲突的纯命令行参数，再在生成项目文件前
执行 `--check --require-full`。检查成功会直接复用证明；仅退出 4/5 会触发一次全量回归并复核，
治理/安全错误不会被当成 cache miss。普通 DAY0 项目输入和运行输出不进入治理 snapshot，
所以同一执行环境的 fresh clone 携带有效 ledger 后，仅修改项目 global/devices/subnet/P2P 等输入
不会重跑 full suite；项目自身合法性、生成和发布检查仍每次执行。load 成功后继续做只读逐字节
复核。也可以单独执行以下治理命令生成及检查证明：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --all -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --check --require-full
```

发布前合同是：生产行为变更必须先或同时更新独立测试预期；确认
`script_test_manifest.json` 的 direct 与 workflow 映射；执行 `--all` 并全部通过；随后执行
`--check --require-full`，确认源码、测试、manifest、执行环境和批准状态仍是同一组精确身份。
AIR/prod 验证阶段有且只有 ISSUE-0016 的三个同 UID 非协作 crontab 并发反例，经 owner
2026-09-28 明确授权登记为已知 FAIL。三个测试仍实际运行且断言不变；全量结果必须
明示 `failures=3`、`errors=0`，原有四项真实环境 skip 的身份不可增加或替换，不能把三项写成 PASS。
使用 `--all --validation-only` 运行全量，并用 `--check --require-full --validation-only`
复核；正式 AIR/prod 验证 load/sync/package 必须各自显式传 `--validation-only`。
普通 `--all` 和不带验证意图的正式检查继续失败，验证证明不能作为最终发布证明。
该例外以其他同 UID crontab 写者在安装、自动移除及 unsetup 的完整读—改—写窗口保持静默
为前提，见 `REAL_ENVIRONMENT.md` 的 REQ10C 卡片；不证明任意并发安全，不授予最终生产发布。
`sync-code.py` 与 `tar-for-upload.py` 只复核并复用这份证明，不会运行全量测试；证明缺失、过期
或执行环境不匹配时必须要求重新完成本机正式 load，并在任何打包或远端连接前停止。Linux
管理服务器 load 与 macOS `--dry-run` 不运行开发测试。任一步失败都必须阻断
`sync-code`、`tar-for-upload --deploy` 和正式部署。runner 只负责选测、执行及成功后的批准哈希
更新，绝不会根据实现自动重写断言；禁止通过弱化、跳过或删除测试来接受失败。

正式 macOS load 会把 `core.hooksPath` 固定为仓库跟踪的 `.githooks`，并记录签发证明时使用的
精确 Python。pre-push gate 只接受当前 checkout HEAD；approval ledger 必须已跟踪且其工作树
字节与该 HEAD 中的版本完全相同，再由同一解释器通过 `--check --require-full`。源代码、测试、
manifest、依赖锁或环境身份变化会阻断 push；仅 DAY0 项目输入变化不会使代码 proof 失效。
默认 push 只接受 release proof，validation-only proof 仍与最终发布严格隔离。仅执行经 owner
授权的 AIR/prod 验证时，可显式使用 `HTTP_VALIDATION_ONLY=1 git push ...`；它只匹配已提交的
validation-only proof，不能接受 release proof，也不会容许三项登记反例之外的任何失败。

manifest 校验还会直接加载并合并三份真实部署选择器：`sync-code.py` 的根目录同步选择、
`infra/docker/activate.py` 的镜像源码选择，以及 `_package_common.py` 的归档源码选择。任一选择器
缺失、无法加载或返回非法路径属于配置错误；成功选择出的路径若不在 `scripts` 与
`tracked_support` 的并集中，则属于未受管部署权威。两类错误都在读取或更新批准 ledger 之前
fail closed，`--check --require-full`、`--list` 与 `--list-suites` 也不能绕过。

## 新功能、流程和场景的补充规则

1. 功能或缺陷修复必须先在 `test_<area>.py` 中增加可稳定复现的案例，再修改实现。
2. 单函数行为写 unit/contract case；跨文件提交与回滚写 transaction case；跨 DHCP、Apache、
   monitor、worker 或设备身份边界的行为写 integration/scenario case。
3. 无法在本机安全执行的步骤不能省略，必须按 [CASE_TEMPLATE.md](CASE_TEMPLATE.md) 写入
   [REAL_ENVIRONMENT.md](REAL_ENVIRONMENT.md)，记录前置条件、证据、清理和是否具有破坏性。
4. 每个自动化文件必须有模块 docstring，并能被下面的统一 discovery 命令发现。
5. 测试数据只放本目录或运行时临时目录；案例库永远不进入 upload/sync 部署包。
6. 行为、流程、场景或文档合同变化时，要同时更新相应案例和本 README。
7. 每个受管脚本还必须在 `script_test_manifest.json` 中同时拥有 direct 和 workflow/scenario
   映射；新增脚本在映射和测试齐全前必须保持 fail closed。

## 在整体架构中的位置

`test_docker_management_ssh_key.py` 同时覆盖固定管理密钥的 direct 与多脚本 lifecycle workflow。
进程清理的 group-observer 案例将 ESRCH 与 EPERM/EIO/EACCES 分开：只有 ESRCH 是完成，EPERM
只允许在原有单一 2 秒期限内继续确认，其它错误立即 fail closed。持续未确认的实际 reconcile
失败路径必须在同一案例中证明 selector/pipes 关闭且未发布 canonical key pair。原有真实
endless/oversize/held-pipe 断言不放宽；单项通过不代表 fixed100、全量或 Linux/root 门禁已完成。
M2 另外固定 kill#1→非回收退出观察→保留锚点的 kill#2→wait→最终 ESRCH 顺序，并使用真实
same-session 晚加入子进程证明第二次信号不可省略。Linux waitid 必须同时携带 WNOWAIT/WNOHANG；
Darwin 验证 kevent 身份、EV_ERROR 和晚注册 ESRCH 的正向 PID0 锚点，不能只认回显 NOTE_EXIT。
所有观察/等待共用单一期限；不支持的平台与非默认 SIGCHLD 在 Popen 前拒绝，helper 必须是 sole
reaper。成功启动窗口同样断言不调用 signal.signal；kqueue 的 timeout 参数不得超过共享期限剩余量，
首个 SIGKILL 返回 EPERM 仍须经过退出观察与第二个 SIGKILL，首个 ESRCH 则以调用次数断言禁止
后续组信号。reap 超时保留此前 cleanup 失败的异常 cause。helper 自身轮询上限 10ms，
Popen.wait 的内部退避不是同一轮询承诺，但仍受同一期限约束。
异常路径在真实 reconcile 的 pre-publication 链证明资源关闭与无 key publication；post-link
验证失败可留下 canonical leaves，保留现场而不自动删除。回收后禁止再次组信号。

本目录验证公共模块之间的静态合同和安全边界，适合每次代码同步前快速执行；它不替代
管理服务器 load、Docker infra、AIR simulation 或真实设备闭环。用户流程以
根目录 `USER_MANUAL.md` 为准，失败时再回到对应模块 README 定位接口。

`test_project_contracts.py` 是跨目录契约主入口，按功能契约分组加载各目录模块。
`test_dhcp_optional_contract.py`、`test_dhcp_optional_workflow.py` 与
`test_ztp_service_runtime.py` 还锁定空 DHCP subnet 占位文件的唯一例外：
`dhcp-server.status` 和 `ztp.status` 都显式为 `disabled` 时，仅有规范表头、没有
语义数据行的 `02-dhcp-subnet_config.csv` 可继续参与来源哈希及 IB 配置流程；
中间或尾部纯空行（含仅空格/Tab）允许，只有分隔符等伪装成空行的 CSV 记录拒绝，
并按原始物理记录跨度报告行号。缺失、零字节、纯空白、非法表头或符号链接输入仍拒绝。
双 disabled 时 DHCP listener 和生成/安装/启动保持关闭；仅表头但 DHCP/ZTP 任一启用、
非空畸形 CSV、无网络却指定 relay ingress 均拒绝。Docker 实际服务切换需另按
`REAL_ENVIRONMENT.md` 留存证据。
Supervisor 的 Apache 判断还须独立使用已启用的 HTTP 服务和显式本机地址：
DHCP/ZTP 双 disabled、无 ZTP endpoint 时仍可启动 HTTP-only Apache，启动前要通过
本机地址门禁；HTTP disabled 即使留有 address 也不能启 Apache，DHCP-only/relay
不能被空的 ZTP endpoint 误判为需要 Apache。
`test_load_release_transaction.py` 在隔离临时目录中验证 load 的统一 release：只有 DHCP 与
Cumulus/NVOS 子 manifest 的设备身份、真实 YAML hash、完整 MAC 链接集合、effective default
及 DHCP 输出都匹配当前输入时才发布 parent release；旧 `latest_yaml`、篡改 YAML/链接或
生成后被修改的 DHCP 文件必须被拒绝。测试还要求 infra 延迟服务激活，
`current-release.json` 只在 `/etc/dhcp` staging/事务安装成功之后原子提交；失败时恢复旧 DHCP
文件、旧 YAML latest 和进入启动阶段前的服务状态，不能把已验证但尚未安装的 parent 当作
current。由于 child manifest 尚无输入来源证明，非 dry-run `--skip-generate` 必须在任何状态
修改前失败。

R22 setup WAL 冷恢复还必须持有原凭据文件的 descriptor，并在恢复写入及收尾前复核文件、
父目录身份和完整原字节；同字节换 inode 或同 inode/尺寸/mtime 改写都不得继续授权。
direct 和真实 LOAD→SETUP 强杀→新 LOAD workflow 覆盖凭据读入后及 P 后核验后的换绑，
后者即使 P 已恢复也必须 HOLD 并保留替换凭据，不能按旧路径删除新的所有者文件。
这不构成对任意同 UID 非合作写者的原子 compare-and-unlink 承诺，仍须排他写者静默和
REAL_ENV 见证，也不关闭完整共享写集、父 B 收口或旧 A 显式激活。

SETUP 登记新链接、实体 latest 或 infra/logs 写集时，也必须在替换 WAL 前复核原凭据
的 uid/gid、ctime 和有界读回字节/模式；同 inode 写后还原原长度、字节与 mtime 不得
继续登记。direct 与真实 LOAD→SETUP 写前流程覆盖此 ABA，拒绝保留原 WAL inode、
P manifest/链接及实体目录；候选临时 WAL 只清理自己的名字。该守卫不是原子
compare-and-replace，仍要求排他锁及其它写者静默，不提供新写集、恢复或激活授权。

P manifest 恢复与 WAL 内 Q manifest 发布的暂存文件也必须持有原 FD，在最终 mode/字节
flush 后、fsync 前冻结身份，并在 replace 前复核暂存名称、持有 inode、父目录及独立预期
字节。同步边界的换 inode或同 inode改写须 HOLD，不能将外来暂存发布到 manifest；失败
清理只删除仍能证明自有的暂存，未知/未完成身份的对象保留为事件证据。direct 与真实
LOAD→SETUP workflow 覆盖这两类注入，既有同步失败与正常冷恢复仍须执行。这不是非合作
写者免疫或完整 R22 验收；现场前提、未闭项及正式诊断闸门继续适用。

未绑定的 manifest `.rollback.*` 残留（含悬空链接）还必须阻断无 WAL 的新 LOAD、
恢复入口与 WAL 退休；不能忽略暂存证据后改回 P 并假报收口。检查只枚举持有的真实父目录，
不跟随或删除条目；目录身份变化、不可读或超过 4096 个条目均 HOLD。自有 manifest 暂存
在发布回调期间由原 FD/字节复核，不被当作外来残留。direct 与真实 LOAD→SETUP 强杀→
全新 LOAD 覆盖首写前零恢复写入及 WAL/未知对象保留；不提供自动清除残留的权限。

旧 link-only `restore_active_setup_state` 也不得旁路 pending WAL：入口拒绝所有占用
WAL 名称的对象，链接暂存/replace、Q-only 删除、manifest 暂存/replace 和成功出口
复核 WAL 缺席、持锁/明确停服及 manifest 父身份。回调不将自有 manifest stage 误判
为孤儿；既有无 WAL 正例仍须通过。direct 覆盖既存及链接暂存期间晚到 WAL，真实
LOAD→SETUP→parent primitive→旧 API 负例保留 Q 与原凭据。该 workflow 使用私有
合成 P2P 依赖和最小 schema1 parent，不证明完整 B 生成/健康收口或 root 入口。
复核不是原子 compare-and-write；晚到证据前已发生的自有写入不得称零写入或完整恢复。
不能删除 WAL 后放行，也不授予旧 A 激活权。

链接恢复的 `.setup-rollback.*` 名称不能自行证明所有权。发布及失败清理前须复核
捕获的 symlink inode/元数据、准确 raw target 和物理父目录；捕获不完整或对象换绑
必须 HOLD、保留未知暂存，不把外来对象发布到受管名称。direct 和真实 SETUP 强杀→
新 LOAD 冷恢复分别覆盖外来链接发布及 WAL 换绑后误删外来普通文件；原正常恢复和
自有暂存清理仍须执行。这是有写者静默前提的名称复核，不是持有 symlink FD 或原子
compare-and-replace/unlink，不证明任意 ABA/非合作写者免疫、孤儿暂存自动收口或完整 R22。

已留存的未知链接暂存还须阻断后续恢复：link helper 创建新暂存前，以及非 verify-only
WAL 冷恢复首写前和退休前，对已验证 WAL 的链接行及 Q-local latest 名称进行有界只读盘点。
普通文件、目录或悬空链接均不得因前缀而被删除或忽略；父身份变化、不可读或超过 4096
条目保持 HOLD。退休前重新验证已登记 Q-only 目录的确切缺席，不能把正常移除自有目录
误报为扫描错误；已恢复 P 也不能授权消费晚到的未知暂存。direct 和真实 SETUP 强杀→
新 LOAD 分别覆盖首写前及 P 后核验后残留，原正常冷恢复仍须执行。此围栏仅覆盖验证过
的 WAL 链接名称和 helper 的目标，不是无 WAL 新 LOAD 全树孤儿盘点、未知对象自动收口、
完整 runtime 写集或成功 B finalizer；root/Linux/断电、旧 A 显式激活与正式超时闸门仍未闭。

Q 已有的 ETH/NVOS `latest` 软链接须在首次共享写入前单独记录原始链接文字、
旧/新真实完成目录和父目录身份，不混入 P manifest，也不当作原本缺席的 Q-only 名称。
SETUP 通过 Q 的物理父目录写入，稳定共享入口仍保留原有相对链接合同；替换后同步父目录。
direct 与真实 LOAD→SETUP→新 LOAD workflow 覆盖临时链接、指针替换和 Q manifest 提交后
恢复两类旧指针；未知指针、目标换绑及外部发布目录软链接保持 HOLD。局部恢复仅证明
链接前像，不证明完整旧 A 制品安全激活或断电持久性。

R22 的 P 恢复还须证明 Q 父提交仍为写前状态：WAL 冻结 Q 的 `current-release.json`
缺席或完整身份/摘要，并在恢复写入、后核验和收尾前重核。Q 父提交出现、同字节换 inode
或同 inode 写后复原均阻断恢复，保留 WAL；缺前像的旧凭据不自动升级。
这只是禁止提交后误回 P 的围栏，不是成功 B 的备份/receipt 收尾或旧 A 激活协议。

R22 停服恢复门禁必须使用服务后端的明确状态合同。Systemd 查询不能把缺少 `systemctl`、
未知 unit/manager 错误或任意非零退出一概解释为“服务已停止”；这些情况在首个恢复写入前
拒绝并保留 WAL。direct 覆盖查询错误、命令缺失及既有 active/inactive 正例，真实
LOAD→SETUP 强杀→新 LOAD workflow 覆盖未知状态下 P/Q 链接、manifest 和 WAL 零恢复写入。
本机注入的是查询边界，不是 Linux 实际停服或完整旧 A 安全激活见证。

R22 旧 A runtime receipt 发布前须用独占创建的私有文件 FD 写入 payload 和 receipt.json，
最终模式、完整内容逐文件 fsync 后，再同步 stage 目录并发布；新 receipt 根名须先同步
其父目录。任一文件同步失败不得发布最终 receipt 或变更 A selector。
direct 与真实 SETUP manifest→LOAD active receipt API workflow 覆盖同步次序、payload/
metadata 同步错误及私有 staging 清理；生成制品采用独立夹具，不证明完整 A 激活或断电。

R22 receipt 必须兼容 SETUP 正常发布的项目公钥相对软链接，并恢复原链接而非摊平成
普通文件。schema2 的 link 记录只允许当前项目同名 `.pub` 的单链接普通源文件，冻结
源 dev/ino/mode/nlink/size/mtime/ctime、摘要和发布父目录身份；旧普通文件 receipt 仍为
schema1，不把旧凭据自动升级为链接授权。源别名、外部目标、源 ABA 或父目录换绑须拒绝；
恢复前先核全部 link 源，异常时不开始 flat runtime 写入、不改 receipt、不启动服务。
准备时 key 名称缺席后重现须先拒绝，不能发布缺少 payload 的不完整 receipt。
direct 与真实 SETUP 公钥发布/manifest→LOAD receipt/restore API workflow 覆盖原链接保持；
workflow 的制品是独立私有夹具，IB 发布保持原状，不证明完整跨项目 A 恢复或激活。

R22 infra/logs 冷恢复不能只按预检时读取的 receipt 内容推定之后的删除权。
预检须冻结 receipt 的物理父目录、dev/ino/mode/nlink/size/mtime/ctime 与完整字节，
包括原本缺席的状态；每次恢复写入及退休 receipt 之前重新核验。相同字节新 inode、
同 inode 改写后还原、恢复中途替换均须 HOLD，保留未知 receipt 与 WAL，不启动服务。
漂移发生在源目录恢复之后时，已恢复的源和尚未清理的 Q 副本保持现场，不报完成。
direct 与真实 LOAD→SETUP 强杀→新 LOAD workflow 覆盖该窗口；名称复核与 unlink
不是原子 compare-and-unlink，正常窗口仍要求其它写者静默，不证明完整写集或断电。

R22 infra/logs 的 Q 清理同样须保留预检时的副本所有权，不能按文件名删除后来的对象。
首写前核全部 P 原文件/Q 副本，逐项 unlink/rmdir 前重核文件身份、独立 receipt 摘要、
原目录/Q 根及嵌套父目录身份；自己的删除只将该项的预期转为缺席，退休 receipt 前再核。
同内容不同 inode 的副本及预检期间目录换绑必须 HOLD，保留替换对象和 WAL，不启动服务。
reader 在打开前拒绝非 regular leaf，以非阻塞/no-follow 打开，并在同一次读取前/FD/名称
后核验 nlink/ctime；读内 ABA 拒绝。自己的硬链接 unlink 会改变存活 P inode 的 nlink/ctime，
因此跨清理步骤绑定 dev/ino/mode/size/mtime 和完整摘要，不冒称整个恢复窗口的 ABA 免疫。
嵌套重复硬链接正例必须仍完整恢复原 P inode；本地 workflow 不替代 Linux/断电或完整 R22。

R22 实体 latest 迁移的 `.latest.tmp.<PID>` 也是独立 WAL 写集名称：必须在原目录
rename 前登记原缺席及精确相对 Q 目标，已有名称一律保留并拒绝，不得先删除后登记。
迁移中异常由外层完整 WAL preflight 决定恢复，不做绕过未知状态的局部 eager cleanup。
临时链接创建后死亡须在新 LOAD 恢复原目录 inode 时消费自己的临时链接；换成无关对象
必须在任何恢复写入前 HOLD、保留 WAL/备份/未知对象。当前实现只按登记的 P/Q 值及
父身份核验，不宣称同值新 symlink owner 的原子比较/删除免疫。父 B 成功收口、完整
写集与旧 A 显式激活仍需独立完成，局部诊断不是正式 full/check。

R22 父 B 的“已可见”和“目录持久化已确认”是两个状态。`current-release.json`
replace 后，父目录 open/fsync 失败必须传播 HOLD，保留可见 B，不能假报成功、
继续提交报告/代次选择器/启动服务，或把共享链接和 DHCP 自动回退到 A。
同一未确认候选重试仍拒绝；仅父目录同步成功后才可返回成功和幂等返回。
direct、受控 main 清理测试及真实 SETUP→父 LOAD 提交 API→新 LOAD 冷恢复
workflow 覆盖两个同步故障边界；workflow 使用独立最小 B marker，main 的服务
边界使用替身，不冒称完整根入口、真实服务或完整 B schema 验收。冷恢复须保留
Q manifest/链接/WAL 与 B，拒绝旧 P 回退。本机故障注入不证明断电持久性或父 B
成功收口，显式旧 A 激活、完整写集和正式 full/check 仍须独立完成。

同一未确认 B 状态下，DHCP 事务的 finally 不得删除原 A backup 和 B staged 文件，
也不得提示“手工删除”。必须保留原 0700 backup 目录及事务路径、报告 HOLD，等待
人工核验实际 A/B；不能自动恢复 A。目录同步已确认且无未结清 SETUP WAL 的普通成功，以及父 replace
之前拒绝并完整还原 A 的原路径，仍执行既有清理。direct 和真实 SETUP→LOAD
安装算法 workflow 使用固定独立 A/B 字节，仅将 sudo/文件命令/dhcpd 替换为私有
文件系统端口，不触碰 `/etc/dhcp`，不证明真实语法、root 权限或备份断电持久性。
保留的事务不是完整恢复凭据/WAL 自动登记，不能冒称完整旧 A 激活或 B 成功收口。
非 dry-run main 的成功出口还须重新检查 SETUP WAL 缺席：若切换期间留下未结清
WAL，即使父 B replace/目录同步和后续步骤返回，也不得返回 0 或打印 load 完成。
服务门禁也须在 preflight/启动之前检查：不能先启动未结清 WAL 的 B，再等末尾停服。
无 WAL 的明确启动请求仍执行既有路径；不以此守卫替代完整 B 健康验收。
按既有提交后失败路径保持 B、WAL 与恢复凭据并停止受管服务，不自动回 A。
direct 与真实 SETUP 成功→受控 main workflow 覆盖此守卫；main 的输入、生成及
服务端口使用替身，父提交使用私有真实 primitive，不是 root 入口/真实服务验收。
WAL 缺席只是必要条件，不是完整 B 健康或成功退休的证明；finalizer 仍未完成。
父 B 尚未 replace 时，安装失败后的 A 恢复若有命令非零或抛异常，同样不得从
finally 删除 A backup/staged/事务。恢复开始即进入“未完成”状态，仅所有原恢复
命令正常结束才走原清理路径；异常仍传播、报告 HOLD 与事务路径，禁止提示手工
删除。新 LOAD 的残留事务闸门继续拒绝该部分 A/B 状态。direct 与真实 SETUP→LOAD
私有文件端口 workflow 覆盖复制非零/异常和正常清理；这不证明完整恢复后校验、
恢复目录 fsync、真实 root/服务或健康旧 A 激活。
后续 A leaf 后验证候选进一步要求：首次备份之前独立冻结原缺席、regular 的
字节 SHA/size/mode/uid/gid/mtime 或 symlink 的原始目标文字及叶元数据；regular
读取持有 NOFOLLOW FD，读前后核名称/FD 完整身份（含 ctime）。全部恢复命令
exit0 后逐项复核这些预像字段，读取失败、错误字节/权限/叶类型或原缺席未恢复
仍 HOLD，保留 0700 A backup/staged/事务并阻断新 LOAD；只有该字段集全部相等
才恢复原预提交失败清理。旧链接和缺席正例仍保留。此字段集不是 ACL/xattr、
硬链接拓扑、目录祖先并发免疫、持久 receipt/WAL、恢复 fsync/断电或健康激活证明；
排他锁与其它写者静默仍为前提，整体 R22 和正式 related/full 批准仍未闭。
后续同步候选在该预像后验证完成后，持有 NOFOLLOW runtime 目录 FD，并通过
该目录 FD 打开每个恢复 regular 文件；文件同步前后名称/FD 身份须一致。
逐文件 fsync 后再 fsync 同一目录，复核目录身份与全部恢复预像，全部正常结束
才解除“恢复未完成”并清理备份。文件 fsync、目录 open/fsync 或后验证失败均
保留 A backup/staged/事务并 HOLD，不以命令 exit0 或一次读回代替这些步骤。
原链接和缺席通过父目录同步保留。这里仍没有完整持久 grouped receipt/WAL、
备份持久性/断电见证、B 成功退休或旧 A 显式健康激活，不能称完整 R22 已完成。
DHCP 首个 B install 前还必须核每个 A backup 与首次冻结预像的 leaf 类型、
字节/size/mode/uid/gid/mtime 或原始链接文字/缺席。cp exit0 后的错误字节、
权限、链接替换或无法读回均在任何 B 安装/parent 提交前 HOLD，原 A 不变，
0700 backup/staged/事务作为未验证证据保留，磁盘前置闸门阻断新 LOAD。
读回通过只验证当前字段集，不证明 backup 已持久化、完整 WAL/receipt、
备份之后的非协作篡改免疫或服务可健康激活；其它写者静默仍是必要前提。
后续写前同步候选要求通过上述读回之后，持有 NOFOLLOW runtime→transaction→
backup 目录 FD，先同步所有原 regular backup 和 backup 目录，再同步 transaction
及 runtime 目录。每步重核持有/名称身份、原 A 和 backup 字段集；任何失败在零 B
install、零 parent 提交状态 HOLD，并保留未确认的事务。正例必须见证全部文件→
backup→transaction→runtime 完成后才能首次安装 B。这里仍没有完整持久分组
receipt/WAL、祖先原子比较、Linux 断电见证、B 成功退休或旧 A 显式健康激活。
DHCP 安装另在第一次 B 覆盖前创建事务内独占、0600 的 `a-preimage.json`。
其 schema1/prepared-a body 独立绑定四个原 A 的类型、内容摘要及元数据/原始链接/
缺席、四个拟安装 B 摘要、runtime/transaction/backup 目录身份和父提交前像及
候选摘要；body 校验和与完整 record 文件同步后，还必须完成上述备份/目录链同步。
凭据创建、同步或后核验失败仍零 B 写入并保留原证据；清理前必须核原凭据身份、
字节及目录 ancestry，不消费换绑对象。无跨项目 SETUP WAL 的正常成功、或已完整
恢复 A 的前提交拒绝才按既有合同清理。parent 提交/目录同步成功不等于整个 LOAD
的 B 健康确认：只要 SETUP WAL 名称仍被占据，DHCP API 保留 A backup、staged 和
`a-preimage.json`；无法核 WAL 名称是否缺席须 HOLD，不清理，也不自动回 A。
这只是防止提前删除，不提供完整 B 健康 finalizer；WAL 缺席本身也不证明 B 健康。
这是持久四文件写前证据，不是新进程恢复/激活权限：普通新 LOAD 仍 HOLD，
完整 R22 分组恢复、B 健康成功收口、旧 A 显式激活和断电见证仍未完成。
`inspect_dhcp_a_preimage` 是显式只读 API：调用方给定原 runtime/transaction/parent
名称，先核 NOFOLLOW 持有目录链、0600 同 owner 单链接有界凭据、唯一 JSON 字段及
checksum，再核固定四文件清单、backup 子项和前像、当前 runtime/parent 与记录的
A 或 B 是否相符，并重复核组内文件、持有 FD/名称身份。未知名称、内容、权限、
schema 或变化均 HOLD。返回的 `a-visible`/`b-visible` 只是本次读取观察，B hash
相符不证明目录已持久化、完整 release 健康、P/Q 恢复授权或可启动服务。
API 不恢复、清理或执行服务命令；它返回后 FD 已关闭，调用者不得把返回字典当成
后续写入的授权。普通 LOAD 的残留事务闸门不因只读核验成功而解除。
只读核验也须持有 owner 指定 parent 发布目录的 NOFOLLOW FD，将 record 的目录
身份绑定该 FD，并在返回前同时复核持有 FD 与名称的完整身份（含 ctime）。预检后
把同一 parent 文件 inode 移入新目录也不能转移原目录授权：须 HOLD，所有凭据保留，
零恢复/清理/服务命令。此读取窗口检查不是原子快照或新进程冷恢复/旧 A 激活权限。
SETUP WAL 的 checksum 也不是“写集完整”证明：恢复、只读核验和新增写集登记均拒绝
未知 envelope/body/row 字段及任何重复 JSON 键。只有当前 schema2 reader 已实现的
闭合字段集可进入既有身份/前像/持有凭据核验；未来写集不能被忽略后还原 P 或退休 WAL。
缺失 Q parent 前像仍须明确 HOLD；该 reader 闸门不提供 B 成功收口或旧 A 激活权限。
Q comparison 新建目录也属于持久写集。`q_created_directories` 只记录规范 Q 下
`99-output-ztp/optimize` 的原缺席状态、同父暂存名及准确目录/父身份；必须先登记，
再 no-replace 安装，普通 mkdir 的 umask 模式不能被暂存机制改为固定0700。
暂存 mkdir 后、行登记前的死亡可能留下未知 `.optimize.setup-*`：该命名前缀只能
阻断恢复/核验/登记，不能用作删除或采用权限。既有实体 comparison 的数据迁移
仍保持原 HOLD；此 typed 行不是任意 Q 目录创建或迁移权限。自有目录 rmdir 后
恢复再次中断，下一次恢复也必须同步已核父目录的缺席状态，再退休 WAL。
安装前、安装后须核登记时捕获的原目录 dev/ino/mode，不能重新读取暂存名后把
晚换绑 inode 当成已登记所有权。检查后与 rename 间的任意非合作写者原子隔离
不在此保证内；其他同 UID 写者静默仍是前提。
direct 及真实 LOAD→SETUP 强杀→新 LOAD/恢复再次强杀→第三 LOAD 的 workflow
保留原断言；manifest 明确包含实际 helper `ztp/optimize/sample_links.py`。
本地服务端口替身不证明真机停服/启动、Linux 断电、完整 B 收口或旧 A 激活。
实体 latest 冷恢复不能只在预检时核源/备份 inode：持有原目录、匹配 release 和父目录
的 NOFOLLOW FD，捕获的原目录/release 必须重新绑定 WAL 中的 dev/ino；在删除 Q 指针、
备份 rename、恢复后和 WAL 退休前复核名称/持有 FD 的身份与元数据（含 ctime），并核
原始链接文字。自己的 unlink/rename 后只更新自己的已核状态。换绑须 HOLD，不能
删除同目标但新 inode 的链接，也不能把未知备份搬入 latest。若换绑发生在自己的
unlink 之后，latest 可暂时缺席；保留未知对象、原目录和 WAL，不假称完整恢复。
这些检查不是原子 compare-and-unlink/rename，不证明全目录内容、任意非合作写者
免疫、断电持久性、完整共享写集、B 成功收口或旧 A 健康激活。
同一进程内再次用可见但未确认的父候选调用 DHCP 安装 API，必须在读入安装映射、
创建事务、备份或安装之前 HOLD。原输入后来改变也不能许可第二次覆盖 B；第一次
的 B/A 备份、原事务及 backup inode 保持不变。此内存候选入口闸门不是跨重启凭据，
不声称所有新进程/孤儿事务识别或冷激活已完成。

另有磁盘前置闸门：普通 management-server LOAD 在排他锁内、项目解析/模板/生成
之前，以及非 dry-run DHCP 安装 API 在读源/创建事务之前，检查运行目录内任何
`.load-dhcp-transaction-` 名称。目录、文件、悬空链接、FIFO 都是未结清证据，
须 HOLD，不能因新进程的候选 flags 默认为 false 而继续覆盖 B 或备份 A。
扫描持有 NOFOLLOW 目录 FD，并核读前后完整目录身份（含 ctime），至多 4096 项；
目录错误、换绑、同 inode 名称集 ABA 或无法完成扫描均拒绝，不删除未知对象。
真实 SETUP→未确认 B→新 Python LOAD 安装 API workflow 覆盖已保留事务的冷拒绝；
服务/文件命令仍是私有端口，main 为受控 direct，不声称完整 root 入口、所有孤儿
类型、WAL 成功退休、自动冷恢复或健康旧 A 激活；其它写者静默及排他锁仍是前提。

R22 Q parent 预像必须在首次内容读取前冻结完整文件身份或缺席状态，持有原 inode
并在读取后同时验证名称、FD 和物理父目录。读取后插入的新文件、同字节换 inode
不能成为稳定预像，也不能据此启动 SETUP 或发布 WAL。此门禁不意味着父 B 成功
收口、旧 A 激活或整树正式 full 已完成。

R22 infra/logs 源名称恢复不能只依赖最初的副本预检。预检冻结源名称的完整 inode/
ctime/链接文字或缺席状态，每次 unlink 和 backup→source rename 前同时重核源名称、
原备份和 Q 根身份；同目标文字新 inode 也不能继承删除权。自己的 unlink 将源预期
更新为缺席，rename 后只接受已登记原目录 inode，再绑定实际恢复后的名称身份。
旧指针删除后才换绑的未知备份须留在 Q，P 源保持缺席、WAL/receipt 保留并 HOLD，
不得先搬进 P 再报错；同步失败后从缺席源重入仍须恢复原 inode，不启动服务。
这些检查仍不是原子 compare-and-rename，也不证明断电、完整写集或旧 A 激活。

R22 P manifest 恢复同样须在持有的新文件 FD 上设置最终模式、写入完整字节并 fsync，
之后才 replace 和同步父目录；不能先 fsync 后 chmod。文件同步失败须保留 Q manifest
和原 WAL。真实 LOAD→SETUP 在 Q manifest 发布后死亡→新 LOAD 恢复同步失败→第三 LOAD
重入 workflow 覆盖该窗口，不启动服务。Q 临时链接的目标若为另一条已登记共享链接，
恢复重入应沿 WAL 的精确 Q alias 行核验最终 Q 权限边界，不能把已恢复 P 的当前解析值
当作原 Q 目标。循环、未登记外部目标、未知名称/父身份仍拒绝；不放宽原停服/锁/父提交
或磁盘 P/Q 检查，不以此声称完整写集、旧 A 激活或断电验收。

R22 runtime 普通文件恢复须在最终模式及文件内容 fsync 后 replace，再 fsync 父目录；
暂存文件还须持有创建时 FD，在最终 mode/完整字节 flush 后、fsync 前捕获完整元数据，
发布前复核父目录、名称、持有 inode 和准确 payload/mode。换 inode、同 inode 改写或
捕获不完整均 HOLD；失败清理只删除仍能证明自有的暂存，外来/未知对象包括悬空链接
保留为事件证据。direct 与真实 SETUP 登记 Q 链接→强杀→新 LOAD 的 A runtime 冷恢复
覆盖上述两种漂移和 WAL 换绑后错误清理，原同步失败及正常恢复继续执行。这不提供
未知 runtime 孤儿暂存的后续冷收口、原子 compare-and-replace/unlink 或非合作写者免疫。
R22 普通文件恢复的未知孤儿另有 fail-closed 入口/退休围栏：仅从已验证 A receipt 的
frozen files 与普通文件 publickeys 枚举恢复名称，用持有物理父目录 FD 的有界扫描检查
`.name.rollback-`，不跟随对象、不按前缀清理。普通文件 helper 自身、runtime receipt
入口/后核验以及现代 WAL 在 P 首次写入前/退休前均拒绝未知暂存，悬空链接同样 HOLD。
direct 与真实 SETUP 登记 Q 链接→强杀→新 LOAD 覆盖原有普通/悬空暂存及 runtime
后核验后晚到暂存，保留原 WAL；晚到故障如实记录已发生的 P/A 恢复，不承诺零写入。
这不是无 WAL 的全树扫描、未知对象归属判定/删除、完整 root/B 健康退休或旧 A 激活。
同一围栏也须纳入 receipt 中的 managed publickey 链接，按链接恢复 writer 的
`.name.setup-rollback.` 名称检查；不能等恢复 key 时才发现未知暂存，因为 P 和其它
flat runtime 已可能先被改写。direct 与真实 SETUP 强杀→新 LOAD 覆盖原有普通/悬空
key 暂存的零 P/flat 写入，以及 runtime 后核验后晚到 key 暂存阻止 WAL 退休；正常
managed key 恢复仍保持链接、原源文件和既存权力换绑断言。这只扩大已验证 receipt 的
暂存名围栏，不完成 YAML/prefix 全写集、B finalizer、旧 A 健康激活或 root 入口验收。
受 WAL authority 保护的 prefix 恢复另须拒绝旧 `.name.rollback.` 链接暂存，
新链接复用已验证自有的随机暂存 writer；marker 保持 `.name.rollback.` 名称合同，
复用持有 FD、fsync 前 mode/字节冻结及发布/清理前身份检查，外来暂存不发布、不删除。
链接 replace/unlink、marker replace/unlink 与已缺席重入均须同步父目录，失败保留 WAL。
direct 和真实 SETUP 强杀→新 LOAD 覆盖 marker 换绑及同步失败→第三 LOAD 重入。
此分支不创建未绑定父目录；未带 authority 的旧入口未改变。尚未完成 prefix 在 P
首写前/退休前的全部孤儿围栏、任意非合作写者免疫、完整 B finalizer 或旧 A 激活。
missing 前像的 unlink 和已经缺席的重入也须同步父目录。同步失败不得报成功或退休 WAL。
direct 覆盖实际模式/同步顺序和写入/删除同步异常；真实 LOAD→SETUP 强杀→新 LOAD
workflow 使用实际 runtime 文件 writer 注入父目录同步错误，保留 WAL 后在新进程重入。
其 runtime 仍是独立边界见证，不是完整 A receipt 恢复或服务激活；断电见证保持 OPEN。

R22 跨项目恢复不能在 P 链接和 manifest 恢复后、旧 A runtime 恢复之前删除 WAL。
原 WAL 的 descriptor、身份和完整字节须持有到 runtime 恢复返回，再复核停服/锁、
P/Q 盘面及 Q 父提交前像，只有全部通过才退休凭据；异常或进程死亡保留 WAL。
direct 覆盖真实 receipt 缺失、runtime 失败、同字节换 inode 和后核验 P 漂移；真实
LOAD→SETUP→新 LOAD workflow 覆盖 runtime 边界再强杀及第二次新进程重入。
该正例 runtime 使用边界见证替身，不证明完整 A 制品恢复或显式服务激活；服务保持停止。

读取 R22 manifest、receipt 和回滚普通文件时，打开前、持有 FD 和读取后名称的身份须
包括 ctime；同 inode 写入再复原字节/大小/mtime，仍不是稳定授权。direct 使用真实
A receipt 加载与恢复 API，真实 LOAD→SETUP 强杀→新 LOAD workflow 在 manifest 读取
期间注入 ABA，要求首个恢复写入前拒绝并保留 WAL/混合盘面。该校验仅覆盖读取窗口，
不承诺任意非合作同 UID 写者免疫，也不代替完整旧 A 显式安全激活或 REAL_ENV 验收。

同一模块还覆盖端到端 deployment scope：默认 `all` 同时生成 Production/AIR；`prod` 只发布
Production Cumulus/IB/NVL；`air` 只发布 AIR DHCP/YAML/release，并只临时渲染 AIR full profile
实际引用的 Production 来源；单独指定 `mini` 会自动选择 AIR scope 和 `eth`，显式 `prod+mini`
必须在本机全量测试启动前失败。scope 必须逐段写入 child/parent
manifest，monitor `auto` 仅继承明确的 `air`/`prod`，冲突组合在锁和任何项目写入前 fail closed。

`test_mlag_evpn_generation.py` 覆盖 Cumulus MLAG 与 EVPN-MH 的互斥边界：MLAG 设备只保留
EVPN 控制平面，非 MLAG 设备继续启用 EVPN multihoming；同设备混合两种冗余模式会在 CSV、
legacy/nested bond 预处理及跨 `set` 的最终 YAML 门禁中失败。跨模块案例通过真实 Border 父模板
和 `generate_all()` 验证 MLAG 输出，再经过发布规范化并与 `nv config show` 比较；MLAG 输入若
选到不能生成 MLAG 配置的模板也会在发布前失败。测试还确认 MLAG `peerlink` 只生成
成员和 `type: peerlink`，不显式配置 `bridge`/`vlan`；它依靠 VLAN-aware bridge 的默认行为
继承 `br_default` 的全部业务 VLAN，`peerlink.4094` 仍作为独立控制子接口生成。

`test_terminal_l2_stp_generation.py` 覆盖 schema v2 终端二层端口的 STP 防环策略：生成器自动为带
`bridge` 配置的独立二层 `swp` 或逻辑二层 `bond` 生成版本匹配的枚举；Cumulus 5.14 及以前为
`admin-edge: on`/`bpdu-guard: on`，5.15 及以后为
`admin-edge: enabled`/`bpdu-guard: enabled`，CSV 不增加策略字段。版本缺失或无法识别、跨 `set`
片段的 `stp` 非 mapping 覆盖均 fail closed。routed BGP 接口、peerlink 和 bond member 保持无
Edge/Guard；`oobofoob-leaf` 的 `bond49b51`、`oobofoob-spine` 的 `bond1` 到 `bond11`
作为普通 STP 交换机互联固定排除。冲突值、排除接口上的 Edge/Guard 和合格目标缺失配置
都会安全拒绝。workflow 覆盖真实 CSV→91-devices→配置生成、发布规范化、
`nv config show` 比较以及 Feedback 不向 CSV 回写派生策略字段。

`test_qos_evpn_uplink_generation.py` 覆盖 Border/TAN RoCE QoS 与 EVPN-MH BGP uplink：
Border 只选择普通父物理口，TAN（排除 `tan-cp-1gleaf`）只选择 breakout 子接口，逻辑
bond 不得配置 PFC watchdog；任何启用 EVPN-MH 的模板都必须为每个接口型 BGP neighbor
配置 uplink，并排除 `peerlink.4094`。该模块同时运行真实 Border generator → publisher →
manual runtime/latest 比较；`test_v2_generation_flow.py` 还覆盖真实 v2 TAN breakout 流程。

`test_v2_project_schema.py` 是 schema v2 的单模块合同：版本选择、零到多个普通/EVPN
重复字段组、严格行宽、全局 VRR 按 VRF+VLAN 推导与四位十进制 VLAN-to-MAC 编码、
locally-administered/低 16 bit 基址门禁、standalone SVI、
两种 SVI/VRR + DHCP relay 模式、
Border-only `/29` 高低三地址分区与 VRR±3 next-hop、`/native` 语义、local/MLAG/EVPN
bond 分组以及引用完整性都必须 fail closed；非 Border 模板不受 `/29` 半区策略约束。
`test_v2_generation_flow.py` 在临时项目中串联真实 setup、load、DHCP、Cumulus/NVOS 解析器、
全部具体 Jinja 模板与发布规范化，验证重复 VLAN 不被模板丢弃、单 native VLAN 仍为 trunk、
设备可以没有任何 VLAN 组，并要求等价 v1/v2 管理清单生成逐字节相同的 DHCP 运行文件。
该流程还锁定管理 Docker API 的版本化语法：只有 Cumulus 5.17.x 和 5.18.x 生成的
`system.docker` 只保留 `vrf: mgmt`，不得再生成 `state: enabled`；包括 5.16.x 在内的
其他版本继续保留原语法。
该流程还把真实生成 YAML 再送入 Feedback，验证重复组、native、bond 与派生 VRR 运行态证据
能够回环；Border 只把唯一 `/29` SVI 用于自动默认路由，非 `/29` SVI 不触发规则，
错误半区、多个 `/29` 候选或无效默认下一跳必须在发布目录创建前阻断，
maximum/minimum 两种方向必须分别渲染 N+3/N+4。setup 的 direct case 同时
覆盖未声明 bond 引用、`|` 对齐/MAC 规则和未使用声明 warning；若 `bond_ports` 为空，
遗留的 `bond_type`/`bond_mac` 只产生 warning 且生成器忽略它们，但 VLAN 对未声明 bond
的引用仍必须阻断。
同一 VRF/VLAN 混用共享 gateway 与其他 SVI 地址时，生成器必须在写入任何派生 VRR 字段前
按网段和策略指出共享 gateway、异常 hostname、CSV 行号、字段组及实际地址；该主错误不得被
后续“缺少 vrr_mac”的派生校验掩盖，失败时也不得留下部分 VLAN 已推导、部分未推导的模型。

版本化网页 User Manual 的合同由 `test_project_contracts.py`、upload 与 sync workflow 共同覆盖：
首页必须提供离线入口；V1、V2、V3-dev 均以 Release Notes 开篇，并按目录/文件、逐脚本使用说明、
总体流程、受支持场景、测试验收和故障恢复组织；每个操作入口必须独立写明用途、运行位置、
使用场景、典型用法和是否允许直接执行。场景名称和后端边界使用独立预期，不从页面实现反向
生成。`tools/update-user-manual.py` 的完整目录必须精确覆盖当前 Git tracked 与 untracked/nonignored
文件；每个文件独立说明类别、作用和维护/生成责任，被忽略的大型项目数据、镜像、缓存和运行态
按受控路径模式说明。全部 `.py`、`.sh`、`.cgi`（包括 operator、worker、CGI、内部库和测试）
必须逐项说明是否可直接运行、环境、场景、前置条件、语法、参数、输入输出、成功判据、失败恢复
和示例。V2 Native 主路径必须给出可复制的项目创建、本机 load/full proof、直连/relay 发布、
服务器 load、验收、sync、收集/backup、download/import 和 unload runbook；尚未取得成功真机证据的
Docker 必须标成未准入，不能出现可复制的生产部署命令。生成器 `--check`、真实 upload archive
与增量 sync 还必须证明发布的是同一份当前 `user-manual.html`。

覆盖内容：DAY0 模板输出骨架和 DHCP 唯一性、setup 管理的 monitor global 链接、项目时区、
ibdiagnet 报告发现、首页本地链接、upload/sync 人工备份过滤，以及 Ubuntu 24.04 双架构离线
仓库布局。

Docker operator 合同还覆盖参数化 init：它必须从显式 project/scope 生成 root 私有、single-link、
不可覆盖的 `infra-runtime.conf`，AIR mini 自动固定 Ethernet。`image-export`（兼容别名
`build-export`）必须在同架构联网构建端冻结 source manifest，两次验证 immutable generic image
identity，原子输出 image tar、`image-metadata.json` 与两项 `SHA256SUMS`，且不得读取项目/runtime、
启动、停止、load 或激活服务容器。项目 upload release 必须由 `tar-for-upload.py --relay-bundle`
独立生成，并与 matching installer、upload metadata 和摘要一起发布；shared artifact 与可选
bootstrap-only project image 也各自独立。目标端逐目录校验、由 installer 应用 release、一次
`docker load` 并使用完整 image ID 执行 `deploy-preloaded`。测试必须证明 upload/live release 可在
runtime contract 与 image-coupled 记录匹配时比 generic image 新，也必须证明 coupled drift、非法
compatibility JSON、Mac UID/GID 泄漏和私有 staging 残留都 fail closed。

部署场景测试按位置、后端和操作类型三条轴组合：Mac 只生成/测试；adapter 直通 Ubuntu VM 后与
远端 Ubuntu 共享 Native/Docker 合同；可直连目标区分 Native、Docker 在线 build 和 Docker
预构建；可信中转分别验证这三种后端入口。每一组合还要覆盖首次部署、source update、同一
Service IP 换接口、Service IP 地址值改变、重启和事务中断。中转不把 `sync-code.py` 当作离线
增量包，Native 离线 apps 与 Docker image bundle 也不能互相替代。自动化锁定命令和 fail-closed
边界，真实 adapter、DORA、重启、架构与物理设备证据登记在对应 `TC-REAL-*` 案例。

还覆盖 AIR 行在统一设备清单末尾的原子重建与幂等性、旧 AIR 清单退役，以及 ZTP 状态默认
同时处理 Production/AIR、显式 scope 才筛选单一环境，以及共享 IP 必须按实际 DHCP MAC
唯一归属环境的契约。

新身份/DHCP 契约覆盖：AIR JSON 的 hostname/eth0 MAC 为权威，AIR-only Cumulus 必须生成
“effective default + hostname”的 baseline YAML 与完整 12 位 MAC 链接；Production 未绑定
Cumulus/NVOS 依据 option 60/61/77 仍取得对应 bootstrap，真正 unknown 不取得 ZTP 指令；
ISC DHCP 输出必须直接使用受支持的 option 条件并明确禁止 Kea 风格 `member()`；生命周期日志
中的非零填充 MAC（例如 `2:b:...`）也必须归一化后关联 commit/release/expiry；
`identity_pending` 不生成 host declaration，`transit_dynamic` 不写 `fixed-address`，计划静态
IP 落入动态 range 必须失败。IB/NVL 的 eth0/eth1 MAC 都参与 lease 转正、发布和远端身份匹配。
`dhcp_runtime_inventory.py` 的日志/lease 合并保持只读，临时别名必须包含完整 12 位 MAC；正式
MAC 出现后，当前 hostname 覆盖旧别名并过滤旧 archive 成员。lease 文件先按地址取最后一个
状态块再按 MAC 合并，地址 release/free 或重分配后不会让旧 MAC 继续保留同一 live IP；
`test_dhcp_runtime_reassignment.py` 独立覆盖重分配、无 MAC free 块和 lease 过期。

`test_splitter_profile_breakout.py` 与 `test_splitter_profile_breakout_workflow.py` 约束 REQ-14：
splitter profile 决定 2x/4x/8x 硬件模式，不能按已连接 lane 数缩小。direct 覆盖 BGP、direct VLAN、
bond 及混合角色父口；workflow 使用从 0915 工作簿人工转录、主机名匿名化的 literal 语料，
保留原 sheet/行号与 23 列双行表头位置。源码注释中的 SHA-256 标识转录来源；自动化不读取或
重新校验私有原工作簿。测试串联真实 P2P 推断、物理链路解析、Jinja 渲染和空对端 description
patch，要求保留 8x、最小未用 lane 与零虚假 empty-missing，已接线/空 lane 预期均为独立常量。
案例先建立修复前 RED，再覆盖真实 P2P 入口写入、精确文件名选择、四份输入的 SHA256 绑定、
唯一 JSON/profile key、设备归属歧义、链接文件拒绝、stale map 清空和失败前零生成 staging。
load 默认严格表头检查，只有显式 `--p2p-legacy-columns` 才向真实 producer 传入一次
`--legacy-columns`；携带 AIR policy 不隐含放宽表头。独立测试显式提供 literal profile 输入，
不从 maxsub 反推模式，bond 与非 bond 分支均约束未使用父口不能生成配置。
真实工作簿的 main() 发布证据和 436 父端口的 generate_all() 对账属于树外、单独绑定摘要的私有
证据：前后使用同一当前 consumer，前态仅恢复四处历史模式，后态使用真实 main() sidecar；
它不是历史版本 executable 的重跑，也不是正式 load/实机 PASS。不得用内存 workflow、历史
文件总数或 render() 层对账替代 generate_all() 证据。设备侧风险登记于
`TC-REAL-SPLITTER-PROFILE-001`，owner 接受规则不等于真机 PASS。

`test_air_link_endpoint_contract.py` 同时覆盖 REQ-2 与 REQ-14 的 AIR 依赖合同：
真实 P2P producer 的 `unconnected` / `outbound` 单端链路必须进入真实 YAML consumer，
保留真实 Cumulus `swp` 的接口启动策略，不给 sentinel 或 ZTP server 合成配置。共享 token
仅在 `tools/project_contract.py` 定义，源码扫描和 AST 检查防止两端重复定义；direct 的
literal oracle 独立于该实现。未知字符串、大小写/空白变体、错误类型、两个 sentinel 和不完整
真实 endpoint 必须失败。真实 AIR JSON 的离线验证在私有证据中固定 size/SHA256，并非公开
测试运行时会读取、校验该私有 JSON；历史发布与当前同模型
前后比较分开记录，REQ-2 防火墙端口策略差异不能算作 REQ-14 拆分模式变化。
此后变更涉及 producer artifact 的 consumer 时，第一轮须离线运行至少一次最新适用的真实
artifact 并绑定其摘要；无法安全执行的真机步骤仍登记 REAL_ENVIRONMENT，不能用构造数据冒充。

P2P/AIR 契约还覆盖项目级 `03-air-topology-policy.json`：源 P2P 自连接默认失败关闭，只有
AIR policy 中唯一精确命中的 rewrite 可以替换 AIR edge；LLDPQ 仍保留原始设计链路，节点
allowlist、replacement 和端口集合都必须通过冲突检查。load 把 global 的 Cumulus 版本传入
AIR 生成器，并把 policy hash 纳入 parent release；manual-ZTP 会拒绝发布后新增、修改或删除
该 policy。inventory 中 PDU 的显式分类必须优先于交换机名称启发式，不能生成假 AIR 交换机。
P2P 历史空对端写法必须按完整“设备+端口”端点分类：双端真实才进入物理 LLDPQ DOT；一端
真实、一端为空只进入绑定该 DOT SHA-256 的 description-intent sidecar，并给存在于 YAML 的
接口写入固定 `P2P:----UNUSED-----NO-PEER` 描述；完全未出现在 P2P 的 breakout 补齐端口保持
无 description 的 INFO。部分填写、空意图与真实链路冲突、sidecar 漂移或 sidecar/YAML 不一致
必须独立失败或告警，不能伪造物理 edge。
`test_xlsx_zero_row_fail_closed.py` 与真实 `11-load.py` 配置生成 workflow 还约束 XLSX 提取门禁：
TAN/OOB sheet 的两行表头默认必须成功自动定位，只有显式且仅出现一次的 `--legacy-columns`
才允许使用历史固定列；未识别表头或所有已扫描 sheet 合计提取零行都返回 1，后者必须列出
扫描过的 sheet。开始提取前只删除当前解析后 workbook stem 对应的旧 `*-lldpq.dot` 与
`*-description-intent.json`，因此失败运行不会留下看似可用的旧拓扑，同时不影响其他 workbook
或 AIR 输出；workflow 必须证明 DHCP、交换机配置生成和发布均未继续执行。
AIR DOT 与最终 JSON 的普通、继承及 OOB 节点都必须至少分配 4096 MB 内存，原有更高值不得降低；
`ztp-server` 在两种模板和完整 load workflow 中都必须固定为 8 CPU、8192 MB 内存和 80 GB 存储，
且不能把该专用规格误用到普通交换机。
AIR JSON `positioning` 还必须复用 Ethernet Diagram 的角色、TAN/OOB/OOBofOOB 分区和上游端口排序
语义，在 275 像素网格上稳定生成无重叠的多行坐标；节点或链路输入顺序不得改变结果。

`11-load.py --switch eth|ib|nvl` 的 direct 与 release workflow 必须证明选择器贯穿 devices CSV
平台字段校验、镜像、DHCP、Cumulus/NVOS 生成发布及 parent/child `switch_scope`。默认值为全部
平台；AIR 未显式指定时默认选择 `eth`，AIR+IB/NVL 必须在加锁前失败。单平台成功会退役未选
平台旧 `latest`，后续事务失败必须从快照恢复；不得用未选平台的旧 child release 补齐本轮 parent。
`test_dhcp_switch_scope_preservation.py` 与对应 workflow 进一步约束 DHCP 子事务：显式单平台或
AIR 隐式 Ethernet 只重写所属 `dhcpd_*.hosts`，其余平台文件的字节、inode、mode 和 mtime
保持不变；release manifest 同时记录三族实际声明数与四个输出 SHA-256。候选生成或 manifest
发布失败时，`dhcpd.conf`、所属 host、保留 host 和旧 manifest 必须全部回滚，不能留下跨族半成品。
`tar-for-upload.py` 的首选上传接口为 `PROJECT HOST`，并保留互斥的 `--host` 兼容路径；两种写法
必须生成同一套固定 SSH argv、身份检查、SHA 和远端锁行为。

今日监控回归还覆盖：ZTP 多轮次与 30 秒持续间隔、同网段静态 SVI fallback 的轻量身份探测
（主采集地址绿色，hostname+管理 MAC 双重匹配的备用地址淡绿色，身份错配红色，且完整日志
只采集一次）、
独立 ZTP/Switch 按钮和 worker、Switch Status Auto-Refresh 默认关闭，以及信息收集、配置备份、
持续收集、持续备份四个控制；收集与备份使用独立执行 lane、周期和状态，可以同时运行，跨类型
不会互相阻塞。同类型手工/持续任务共用 10 分钟冷却；启用持续模式时只禁用同类型手工按钮，
两个手工按钮均按“单次执行；开始后不可中断”保持运行中且禁用至终态；两个持续按钮均按
“周期执行；停止只取消后续轮次”排空当前轮。
停止后也不得绕过该类型冷却。停止持续模式只取消后续调度；若当前轮已开始，状态必须保持
“停止中，等待当前任务完成”、不得设置该 lane 的取消事件，同类型手工按钮继续禁用，任务自然
收口后才发布 stopped；worker/Supervisor 整体关闭的有界终止路径除外。持续备份密码只经匿名 FD 和短生命 `SSH_ASKPASS` 子进程环境传递；
单设备不可达或步骤失败必须保留成功设备发布并返回“完成但有警告”及失败设备汇总；全部设备
失败或全局事务错误才返回整体失败。
其他页签保持独立 Auto-Refresh，AIR scope 保留 Ethernet
Diagram、VX/CPU/Disk 解析，以及 optimize 的 AIR/Production 边界和实际 hostname 漂移。
统一页面排序合同还覆盖 ZTP 首个显示 IPv4、完整状态等级、自然名称与缺失值，SPX/IB/NVLink
设备组和端口、十进制/科学计数/温度，以及各表独立 ARIA/刷新持久化状态；真实浏览器验收见
`TC-REAL-MONITOR-SORT-001`。
`test_ztp_group_handoff.py` 独立覆盖 ZTP→Switch 的四组交接：部分类型先完成即先采集、同组
设备全部完成门禁、AIR `pending_eth` 的环境归类、unknown/`pending_nvos` 隔离、单组命令边界、
schema 2 分组签名持久去重与 schema 1 安全重采、单组失败不阻塞兄弟组，以及自动单键和手工
AIR/Production/All 多键冷却语义；所有组仍通过共享锁串行执行。
`test_ztp_group_handoff_display.py` 补充覆盖 `scope=all` 下未归类设备不会被误标为 Production、
自动新完成签名不受页面 30 分钟冷却吞并、各组 `collected_at` 审计时间保持独立，以及刷新
`monitor.html` 时仍保留原始 AIR/Production/All 展示范围。

setup/upload 的监控清单合同还要求部署包继续排除运行态 CSV 链接，而管理服务器正式 load
必须在 fresh HTTP root 中重建三条固定别名：`ethernet/monitor/eth.csv -> ../eth.csv`、
`infiniband/monitor/ib.csv -> ../ib.csv` 和 `nvlink/monitor/nvsw.csv -> ../nvsw.csv`。
三条别名必须纳入 setup 的冲突检查、整批回滚和 manifest，并最终解析到当前项目唯一的
`02-devices_config.csv`；采集器由该 canonical 链定位项目 `mgmt-server.pub`，不得在 monitor
目录复制公钥或用环境变量绕过活动项目身份。三个发布入口必须按自身 lexical area 精确绑定：
Ethernet 只读 `eth.csv`、InfiniBand 只读 `ib.csv`、NVLink 只读 `nvsw.csv`；即使同目录存在
指向其他项目且完全有效的异类 inventory，也不得用“第一个存在文件”替代。`MGMT_PUBKEY_FILE`
环境值不受信，公钥只能从该精确 inventory 的项目目录推导。

手工 ZTP 契约覆盖具体 hostname/多个通配符的展开与去重、类型和环境边界、任一未匹配即
整次拒绝、GUI `preview → diff → confirm` 两阶段协议、精确 `operation_id`/`trigger_id`、
服务端发布/配置指纹复检、CGI 固定请求、worker 固定 argv、逐设备按钮准确携带 hostname，
以及 Cumulus 零参数固定 URL helper 与最小 sudoers 权限。还覆盖触发前轮次基线、旧轮 100%
不得完成、新轮执行中、仅新轮 100%/complete success 才结束、每设备独立状态、不同设备并发
排队和同设备去重；同时验证自动/Web/CLI 共用单调 `ztp_round`、独立 `trigger_source`、CLI
operation 发现、DHCP 预期下一轮、Bootstrap 后逐栏重置、失败不增轮次且完成时间不复用、
跨刷新待执行状态、上一轮 success index 不得显示为本轮成功，以及客户端时区转换入口。
`preview_ready` 与 future 完成之间到达的 confirm 必须留在 durable queue，不能静默丢弃；
Production host-key mismatch 默认 fail closed，只有单台完整 hostname 的交互 CLI 显式
`--refresh-host-key` 才允许替换，AIR 公钥模式兼容 rebuild，GUI/密码隐式刷新均禁止。
`trigger`、Cumulus factory reset、NVOS ZTP force 与 `renew` recovery intent 分别验证；测试必须
确认 renew 不会写 ISC lease，服务端 lease release 也不会被当成客户端已重新 DHCP 的证据。
配置同步另以 `--replace-config` 与原 ZTP 操作互斥：只读 preview 后才允许完整
`nv config replace`/apply/save；eth0、ssh-server、全部 AAA 用户使用当前运行态与 latest 比较，
不可观测 password hash 则必须使用 trusted full-replace prior。patch receipt、缺失 AAA、prior 解析
失败、运行态/确认后指纹漂移均按独立原因 fail closed；ACL 明确不受该门禁保护。CGI、worker、页面
按钮/状态列与 JS 状态名由同一 workflow 对账，未绑定身份按钮可见但 disabled，并发上限仍为 8。
测试不会连接或触发真实交换机。
配置同步在 apply/save 返回成功后还须向同一固定 host 新建两次独立 SSH 调用，分别核对
eth0 MAC 与本次配置的 hostname、回读 `nv config show` 与冻结输入的可观测投影比较；
它们不是原保存连接，也不是同一会话或原子快照。只有带本次 operation/trigger 绑定证据的
结果才可由 Web/CLI 显示同步成功；旧 `triggered` 不足以证明成功。保存后核验失败标记
`applied-but-unverified`，提交超时或非零退出标记 `outcome-unknown`，都不自动重试。
此检查不读取 startup，也不验证不可观测密码散列，更不刷新设备 root-owned prior receipt；
提示必须保留“可信回执未刷新，连续同步闭环未完成”，不能把单次运行态一致当作连续同步已修复。

`test_ztp_applied_receipt.py` 覆盖 bootstrap 的 root-owned `/run` 独立工作区、原子
`latest-log` 指针，以及在该指针成功发布后非致命创建的 `ztp-last-run.log` 固定名硬链接；测试验证
同 device/inode、0644、实时追加、下次运行原子替换、旧时间戳日志保留、不安全目标原样保留和失败
只清理私有暂存目录。真实 `11-load.py` 渲染 workflow 另证明 `_oob`/`_oobofoob` 只继承唯一模板源，
不会生成第二套固定名逻辑。该套件还覆盖未来 mtime 旧日志反例、apply/save receipt、原始 YAML
字节/hash、失败后默认回退和固定只读 helper。`test_manual_applied_config.py` 覆盖手工操作始终把 selector-normalized
的当前 `nv config show` 与 current latest 比较，包括 breakout `swp1s0-3`/组合 selector；receipt
只用于审计和 preview/confirm TOCTOU 指纹，可信 receipt 也不能掩盖后续运行态漂移。该套件还
覆盖 `system.aaa.user.<用户名>.hashed-password` 在 show 中缺失/显示 `*` 时不产生假 diff，
同时验证其他同名路径、其他配置漂移及完整发布哈希仍严格生效。
`test_bootstrap_config_fetch_contract.py` 与真实 `11-load.py` 渲染 workflow 约束两份 Cumulus
bootstrap 的专属 MAC YAML 获取：固定为 5 次重试、3 秒间隔、5 秒连接超时、120 秒单次总时限，
只重试连接失败和 5xx。明确 404 才允许使用 default 并标记 degraded/source_kind=default；
401/403、空 200、连接或 5xx 耗尽必须终止，且不能产生 NV 配置写入、成功回执、last-success
或 authorized_keys。
该 direct 的超时事件诊断通过持有 FD 的前后 dev/ino/mode/nlink/size/mtime/ctime 和
当前名称身份检验有界尾部；同 inode ABA 也须标为不稳定、拒绝输出尾部。诊断增强不改变
原 15 秒夹具时限或认证断言；小范围前序未重现不能当作历史 full/related 失败原因已收口。
`test_ztp_http_identity_binding.py` 覆盖 OOB Leaf 通过前面板 transit
端口取得 DHCP、再用 eth0 MAC 下载专属 YAML 时的 canonical 身份归属；404、歧义 MAC 和匿名
别名不能冒充受管设备；已有 eth0 IP 时禁止 transit 回退，eth0 IP 为空时只有 canonical eth0
MAC 与实际 DHCP holder 接口 MAC 都唯一匹配，才允许用黄色 transit IP 临时采集。主契约测试
还验证 reset 日志中途改变时区时以 log mtime/boot ID 和实际
marker 晋级阶段、macOS 空管理-key 占位仍保留固定下载 URL，以及重启窗口的瞬态 SSH failure
不会提前终止同一操作。

`test_diagnostic_bundle.py` 覆盖只读支持包的独立安全边界：结构化配置必须递归脱敏，坏
YAML/JSON 只能写 omission metadata；命令使用固定 argv、净化环境、超时和输出上限；输出不能
位于 DocumentRoot、软链接或不安全目录；tar 只能含单一安全顶层和普通文件。测试还验证历史
项目不得执行 live SSH但仍生成 partial 包、运行态项目只能从固定 inventory link 识别、远端
hostname/MAC 任一不符时不保存设备状态/配置，以及诊断脚本确实进入 tools upload/sync 部署合同。
新版诊断还必须按严格 `latest-log` pointer 选择设备日志；pointer 非法只记录错误，不回退 mtime。

`test_deployment_writer_lock.py` 覆盖 sync 与 `tar-for-upload --deploy` 从第一次远端写入到最终
marker promotion 全程共用 `.deployment.lock`，失败保留 marker，dry-run/普通上传不取锁；
只上传后的 `--deploy-uploaded <ARCHIVE>` 必须复用同一份本地/远端 SHA-256 已验证归档，不能
重新打包或传输，并继续使用归档内 source manifest 绑定的 guard；
同步结束必须按 runtime 提示恢复入口：Native 重新 load；Docker 写入先 stop 并标记
rebuild-required，随后重新 deploy，避免 resident worker 继续执行旧代码或旧镜像。

`test_deploy_upload_archive.py` 覆盖可信中转后的服务器本地安装入口：installer/archive 的
root owner、single-link、NOFOLLOW 与稳定读取，安全 tar member、唯一项目、source manifest 和
embedded guard 哈希绑定，`--verify-only` 零 live 写入，以及 Native/Docker 后续提示。归档内
相对软链接只允许规范解析到同一归档中已验证的普通文件或目录（包括 P2P 的
`lldp-analyze-tool` 目录入口），逃逸、缺失、循环和特殊文件仍拒绝；source manifest 可精确绑定
设计上的 0 字节普通占位，但 installer、guard 和 manifest 权威文件本身必须非空。真实临时
workflow 会执行归档内 guard，但不接触 SSH、Docker、NIC 或宿主服务。成员校验不得把 8 GiB
全局安全上限当成单次内存申请：小型权威文件只按声明大小读取，manifest payload 使用有界分块
SHA-256，因此包含多 GiB switch image 的合法归档也不会要求把整个成员载入内存；内存分配异常
必须转成明确的 installer fail-closed 错误，不能泄漏裸 `MemoryError` traceback。

`test_apache_publication_boundary.py` 覆盖 infra 托管的 Apache 静态发布边界：项目输入、
DHCP/manifest、运行状态、日志和源码必须拒绝静态读取，bootstrap、公钥、
`latest_yaml`、镜像和 APT 仓库仍可访问；自定义 `ztp_url_prefix` 不得绕过规则，
load 在启动 Apache 前还必须核对 infra 签发策略的精确 SHA-256。根 README 汇编测试
同时自动发现非项目输出目录中的源 README，防止新模块文档未被嵌入。

`test_all_script_entrypoints.py` 对源树中的每一个 Python、CGI 和 Shell 脚本做分类及语法检查，
并执行所有 argparse 入口、明确列出的手写 Python 入口和操作员 Shell 入口的只读 `--help`；
两份运行时 bootstrap 还必须与唯一模板逐字一致（仅允许声明的运行参数不同）。
`test_ztp_release_core_review.py` 对 ZTP/release 核心逐模块检查模板渲染、authorized_keys 原子去重、
过期动态 AIR lease、CSV/hostname/path 注入、manual deployment lock、归档/latest 路径逃逸和
P2P 资源上限。`test_monitor_stack_review.py` 覆盖 monitor/collector/CGI/worker/IB-NVL 工具的
身份、队列、并发、原子发布、时间同步独立性与高延迟不确定度门禁、密码来源和危险升级确认门禁。
`test_ops_deployment_review.py` 覆盖 setup/load/unsetup/unload、upload/sync/download/import 和
infra 的共享 deployment lock 安全继承、归档边界、私有权限、事务回滚及输入一致性。

`test_docker_destructive_confirmation.py` 与
`test_docker_destructive_confirmation_workflow.py` 约束 Docker `unload/down` 的破坏性确认边界：
项目、scope、immutable container ID 以及精确删除/保留范围必须在提示或 `--yes` 触发的首个写入前
完整打印；交互只接受逐字节小写 `yes`，EOF、大小写或空格变体均零写入取消。`down` 把提示时捕获的
container ID 传入 hostlock，并在同一 deployment lock 内再次核对；确认期间 A 被替换为 B 或消失时，
不得 stop/rm 新容器，也不得清除 activation。Native `13-unload.py` 使用同一 literal-confirmation 语义，
而容器内部 `hostctl unload` 仍只在外层确认完成后精确传递一次 `--yes`。

`test_monitor_writer_quiesce.py` 与 `test_monitor_writer_quiesce_workflow.py` 从 Monitor 每轮实际
读取的四项 authority（`current-release.json`、项目 `01-global.yaml`、项目
`02-devices_config.csv`、active `p2p-air.json`）反向发现受支持 writer。Native setup、unsetup、
load、unload、DHCP/P2P generator、密码更新、feedback writeback 和 deployment prewrite guard
必须在共享 deployment lock 内、首次相关写入前停止并确认同项目 detached Monitor 已退出；load
子流程复用继承 lock/quiesce，不得重复停止。`import-from-download.py` 只允许 merge-new 且不得覆盖
任一既有 authority，因此是精确豁免而非通用写入豁免。测试以真实多脚本 workflow、失败零写入、
反向 sink/caller 闭包和写入顺序 hostile mutation 共同约束该集合。

`test_ztp_monitor_watch_resilience.py` 与 `test_ztp_monitor_watch_runtime_workflow.py` 约束持续
Monitor 的故障恢复合同。只有明确命名的 runtime transport 与报告发布边界属于可重试故障；每次
失败必须先原子刷新 unhealthy sidecar，再用最后一次成功报告重建带告警的 `monitor.html`，不得
改写 `latest` 或报告。第五次连续失败、输入身份漂移和边界外异常均永久退出；成功轮次重置预算。
同一进程固定 project/scope、setup manifest、active inventory、current release，以及 Monitor
实际读取的四项 authority 字节身份，任何同路径替换都在下一轮工作前拒绝。重复日志抑制与摘要
周期 `max(300, 10 * max(watch, 5))` 仅存在于当前进程内，重启不会继承抑制状态。Native load、
Docker activation 与 Monitor cleanup 还必须通过持久 sibling `.ztp-monitor.pid.lock` 串行化 PID
发布/清理；该锁只保护参与协议的受支持 writer/remover，不声称阻止可绕过锁的并发 root。

`test_full_flow_integration.py` 使用真实 ISC structured event、普通 DORA 和 Apache access-log 格式
串起跨模块状态机：OOB Leaf 的前面板 transit lease 只有在当前 lease epoch 内出现精确
`GET 200` 专属 eth0-MAC YAML 时才归属 canonical 身份，transit IP 永不成为 SSH 地址；真正
未知平台即使取得 lease、甚至伪造相同 HTTP 请求，也不能获得受管身份或触发 SSH 采集。

`test_upload_package_contract.py` 覆盖 upload 的项目消费清单和 P2P XLSX 清理：包中只允许三份
固定配置、当前选中 P2P、公钥和镜像；其他规划工作簿、项目说明及 setup 管理的 `p2p.xlsx`
链接必须排除。选中 P2P 只在临时副本中删除 `xl/media`、图片 relationship 和对应 drawing
anchor，非图片 drawing 保留；测试同时验证源 XLSX SHA-256 不变、归档内工作簿仍是有效 ZIP。

`test_ztp_service_runtime.py` 覆盖 Ubuntu host-network 容器的动态 DHCP 监听边界：监听逻辑接口
由 subnet CSV 和同一份 `ip -j` 快照按精确地址、前缀和 ifindex 推导，数量为 0..N，relay
网段不会平白增加 NIC，allowlist 只收窄候选而不能扩大监听；同一 ifindex 的任一 secondary IP
命中多个 `shared_network` 时必须在服务变更前失败。DHCPD 始终使用显式 argv，空接口列表和
option-like 名称均被拒绝。容器明确选择 Supervisor 后端，不能调用 systemd/journald；load、
monitor、unload 与容器入口必须共用同一 runtime 模块。真实 DORA、host-network 抓包和容器重建
验收登记在 `TC-REAL-DOCKER-ZTP-001`。

`test_ztp_container_runtime.py` 把 Docker 发布选择贯穿到真实 load parser：
`HTTP_ZTP_SCOPE`、`HTTP_ZTP_SWITCH_SCOPE`、`HTTP_ZTP_MINI` 先由 wrapper/Compose 规范化，再由
`hostctl.py` 转成 `11-load.py --deployment-scope/--switch/--mini`。AIR 默认 Ethernet，mini 只允许
AIR + Ethernet；Production 默认全部平台，也可显式只选 eth/ib/nvl。parent release、runtime
plan、activation marker 和 health-check 必须精确绑定同一选择，旧范围的 release 或运行中容器
不能被复用。workflow 使用真实 `container.env.example`、Settings、hostctl argv 与真实
`11-load.py` parser 串联验证，而不是复制参数解释逻辑。

`test_ztp_release_core_review.py` 与 `test_load_release_transaction.py` 共同锁定 AIR mini 的项目策略
authority：`03-air-topology-policy.json` 必须提供严格 `mini_sampling`，未知角色动作只能显式为
`keep|exclude|error`；`anchors` 只在需要 anchor 选择时显式声明，也可省略或为空列表。角色/anchor
歧义、非法 regex、重复键、symlink、越界和超限输入均失败关闭。
direct 测试验证异构角色抽样、04 显式选择优先级及逐设备原因；真实 11-load→拓扑生成 workflow
验证旧 canonical 可由已校验客户源刷新，而策略/客户源漂移不会留下部分输出，也不会在 policy
缺失时先计算 release basis。parent release 必须同时绑定 policy 与最终 04 的 SHA-256。

同一 Docker 合同把“宿主发行版”与“容器发行版”分开验证：宿主只接受 Ubuntu 22.04 或
24.04 的 `amd64`/`arm64` 本机 rootful Docker，其他发行版或版本在任何 Docker mutation 前
fail closed；Dockerfile、image label、preloaded verifier 和容器内 `/etc/os-release` 始终固定
Ubuntu 24.04。测试不得为了支持 22.04 宿主而把容器 base image、镜像身份或容器运行态降级。

同一模块还覆盖管理服务器的动态网络恢复：没有 source write 时，Service IP 从一个合格接口移动
到另一个合格接口后，真实 runtime planner 必须选择新的接口名、ifindex 和 fingerprint；
`hostctl.transactional_reload_network()` 必须在共享锁内先核对既有 image/source、release、DHCP、
runtime plan 与 committed activation，只允许 listener identity 和观察摘要变化，再撤销 authority、
停止旧服务、发布新 plan/precommit、由 Supervisor 收敛并完成两阶段 health，最后提交 activation。
该事务不得运行 `11-load.py`、重置 worker control、清除 rebuild/quarantine 或改写项目生成制品；
NOOP 不得停止服务，失败则撤销 authority 并让五个业务服务保持停止。宿主 systemd 或直接
`supervisorctl restart dhcpd` 不能替代该事务。

`test_ztp_container_runtime.py` 还独立验证 activation 的双快照稳定性 projection：只允许 Linux
bridge 精确路径 `linkinfo.info_data.gc_timer` 的有限非负数值变化，以及 DHCP 地址
`valid_life_time`/`preferred_life_time` 在 Linux uint32 有限范围 `1..4294967294` 内保持或自然
递减。`0`、字符串 `forever` 与数值 forever sentinel `4294967295` 均不归一化，跨类别变化、
增长和超界值必须 fail closed。第一次原始完整 link/address 快照继续交给 planner 并保留诊断
hash；projection 不得原地修改输入。ifindex/name、MAC、flags、operstate、link type/kind/parent、
VLAN ID、地址/prefix/scope、tentative/dadfailed/deprecated 仍严格比较；全表 IPv4 route 也必须
连续采集两次并逐字段保持不变，非规范 timer/lifetime 及非对象 route 记录必须 fail closed。Ubuntu 24.04
风格的跨脚本场景还证明两个 listener 的 fingerprint 不因上述倒计时漂移，真实拓扑或路由变化则
在发布 runtime plan、Apache listener、activation/precommit 或启动服务前失败。真机复现与证据要求登记在
`TC-REAL-NETWORK-SNAPSHOT-001`。

`run_vm_validation.py` 是 upload/load 完成后的 Ubuntu 24.04 管理 VM 只读验收器。它核对
parent/child release 与输入/制品 hash、DHCP shared-network 到 vNIC 的唯一映射、服务、worker、
AIR scope 和 mini 清单绑定，但不会运行 load、更新密码、重启服务或修改项目。`test_cases/`
不进入生产 upload/sync 包，须按 `TC-REAL-VM-ZTP-001` 单独复制到 VM，并把 JSON 报告带回审核。

原生 systemd 的完整验收使用 `--full-systemd --worker-scope prod|air`。完整模式在上述检查之外，
还会只读编译部署树中的 Python/CGI、对 Shell 执行 `bash -n`，核对 systemd enable/MainPID、
DHCP `INTERFACESv4` 策略（空值代表自动发现；显式值须与实际 cmdline 一致）、Apache 发布边界、
已安装控制 CGI、worker 状态与最新报告，
并主动 GET bootstrap、ztp.json、SSH 公钥、monitor.html 和 parent-bound MAC YAML，HEAD 已发布镜像，
同时证明内部路径返回 403、三个控制 CGI 返回存活 JSON。它不会修改项目、NIC、Netplan、服务或
配置，但主动 HTTP 请求会正常写入 Apache access log。`--expect-mini` 只用于确实生成 mini AIR
清单的项目，不能为了“全量”盲目添加。

直接 unittest discovery 只用于开发定位，不更新批准哈希，也不替代上面的发布门禁：

`test_collection_cycle_contract.py`、`test_collection_cycle_worker_contract.py`、
`test_collection_cycle_persistence.py` 与 `test_collection_cycle_handoff_workflow.py`
共同约束 Switch collection cycle：纯层固定 scope/slot/identity/result；worker 对每个 slot 只产生一个
终态 wrapper；只有持有 allowed collection gate 的 store 才能分配 sequence，并用私有 0700/0600、
write-ahead witness 与不可覆盖 start/launch/completion 记录持久化。真实 collector 由专用 coordinator
子进程运行，identity 只经匿名 context FD 进入，result 经匿名 FD 返回；父进程在放行子进程前先发布
精确 PID/boot/start launch，验证完整 result 后先发布 completion，再允许 cooldown/UI success。
busy/cooldown/取消和直接 internal-mode 调用不分配 sequence；SIGKILL 工作流必须先对 live binding HOLD，
随后只在确认 dead 后写入 `cycle_crashed` 并分配下一 sequence。现有 v1 collector 可以操作成功，但其
cycle 始终 nonqualifying；v2 artifact authority 属后续独立 emitter 批次，不能由本组测试伪造。
真机/AIR/Production 边界登记于 `TC-REAL-COLLECTION-CYCLE-001`。

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -m unittest discover -s test_cases -t . -p 'test_*.py' -v
```

该测试套件只做快速契约检查。发布前还应执行 Python/Bash 语法检查、setup/load dry-run、
临时目录生成/发布流程，以及 `ubuntu:24.04` 容器中的 infra setup/teardown。

### P 阶段正式证明的 Python 依赖 capsule

P 阶段在绑定的 macOS CPython 3.9 环境中，把独立审定的依赖文件构造成确定性 USTAR archive。父进程在关闭唯一写 descriptor 后，以 `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` 重新打开并立即 unlink；正式流程只复用这个 anonymous read-only inode。每个顶层需要第三方依赖的 Python child 都从它重新安全解包到独立 `0700` snapshot，逐项核对固定清单、SHA-256、模式、Mach-O/ABI 和包版本，再经固定 `/usr/bin/sandbox-exec` profile 启动 `-I -S` Python。该顶层 child 创建的普通 Python 后代仍在同一 sandbox 中运行，并使用经逐级验证的 exact-layout `PYTHONHOME` 与 exact-empty `site-packages`；它们的 `PYTHONPATH` 精确包含 snapshot、绑定的标准库和 `lib-dynload` 三项，从而阻断 ambient、user 或 system site-packages 的意外回退。该 profile 禁止 child 及其后代写入、重命名或建立 snapshot alias；任何 sandbox 不可用、依赖漂移、非法 archive、FD/identity 漂移或清理失败都阻断证明，不能回退到 user/system site-packages。只负责启动正式 FQN 的 orchestration harness 使用绝对路径 CPython `-I -S` 和受信任标准库，不导入第三方依赖、也不套外层 sandbox；它只把同一个 anonymous archive FD 交给正式 full runner。该 runner 作为顶层依赖 child 建立并持有经过认证的 snapshot、exact-layout `PYTHONHOME` 和 archive identity。只有精确批准的 test-runner argv 才能进入 reentrant 模式；每次 reentry 都重新认证这些 held authority，证明嵌套 `sandbox-exec` 精确返回 71 且 snapshot 写入被内核拒绝，然后在既有 sandbox 中用有界 direct child 运行，绝不嵌套 sandbox、重建 archive、回退或清理继承状态。

只有 `-B test_cases/run_related_tests.py --all -v`、`-B test_cases/run_related_tests.py --suite repository-governance -v` 与 `-B test_cases/run_related_tests.py --all --no-approve -v` 三组精确审定的 runner argv 会在进入顶层 child sandbox 前，由父进程在同一个私有 state root 内预启动受管 loopback OpenSSH fixture。父进程使用固定的 `/usr/sbin/sshd`、`/usr/bin/ssh-keygen` 与 `/usr/bin/ssh-keyscan`，以临时 host key 在 `127.0.0.1` ephemeral port 完成真实 KEX，并用持久 held read-only descriptor 绑定 key、config、manifest 与 daemon log identity；每轮另通过 held root dirfd 对 PID file 做短持有 `NOFOLLOW` open、双 `pread`/`fstat` 与精确 `pid\n` 验证。near-miss、hidden probe 与普通 child 均不得触发或继承该 fixture。父进程只向精确三类 child 传递 routing marker，不传 fixture 路径或 descriptor；child 先认证既有的 exact-nine environment protocol 与 archive、snapshot、`PYTHONHOME` exact-seven dependency descriptor，再从 authenticated `snapshot.parent` 派生固定 sibling 路径并以 `NOFOLLOW` held reads 自行验证 fixture，因此不会增加任何传入 FD。顶层 sandbox profile 另以 literal/subpath 规则禁止 child 及其后代写入、重命名或建立指向 fixture subtree 的可写别名。child 返回或抛出任何异常后，父进程都重新核对 held identity 与 payload，并以有界 TERM→KILL process-group 流程回收 daemon、关闭全部 descriptor、删除 fixture；创建、KEX、认证、内核写保护、回收或清理任一步失败都会阻断正式证明。

这项自动化保证覆盖当前证明进程、child/grandchild 以及其可执行的 snapshot 篡改；它明确不承诺抵御另一个已在运行且拥有同一 UID 的独立恶意进程在 archive 建立窗口内抢占 writable FD。正式证明必须在无不受信任同 UID 进程的专用会话中执行；该剩余边界与人工证据登记在 `REAL_ENVIRONMENT.md`。
