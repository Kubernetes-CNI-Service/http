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
macOS 正式 `DAY0-Prepare/11-load.py` 先解析并拒绝互相冲突的纯命令行参数，再在生成项目文件前执行全量回归，并在成功后做只读逐字节
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

manifest 校验还会直接加载并合并三份真实部署选择器：`sync-code.py` 的根目录同步选择、
`infra/docker/activate.py` 的镜像源码选择，以及 `_package_common.py` 的归档源码选择。任一选择器
缺失、无法加载或返回非法路径属于配置错误；成功选择出的路径若不在 `scripts` 与
`tracked_support` 的并集中，则属于未受管部署权威。两类错误都在读取或更新批准 ledger 之前
fail closed，`--check --require-full`、`--list` 与 `--list-suites` 也不能绕过。

## 新功能、流程和场景的补充规则

`test_issue_tracker_credential_shape.py` 与 `test_issue_tracker_credential_fd.py`
约束 REQ7 的固定私有输入：held-FD 单次有限读取、目录与文件身份前后复核、严格凭据形状及
真实目标策略消费。root 元数据仅由私有临时夹具注入，不读取真实凭据，不证明原生 root/RO-bind
或 Google SDK 身份。`test_issue_tracker_online_cells.py`、`test_issue_tracker_online_nv_ids.py`
与 `test_issue_tracker_online_rows.py` 将真实本地来源和工作簿接入独立的 literal-cell、共享
NV 序列及有限 Switch 行候选检查；所有工具/人工占用列、预写入位移和后像冲突均保留断言。
这些纯候选不发送请求、不持久分配 ID、不授予 permit，也不提供 CAS 或回滚保证；
它们不代表 REQ7 整体完成。真实 SDK、远端完整模板、journal/fence/History 与传输闭环仍须
独立落地。相应真实环境卡保持 NOT RUN，单项或局部 PASS 不替代同树正式 full proof。

`test_req7_dependency_contract.py` 与 `test_req7_dependency_workflow.py` 约束独立于
TOPLEVEL-5 的 REQ7 C-14 无 extras 依赖闭包、两个 Linux wheel 架构的精确 artifact/hash、
固定公开策略/锁的有界无链接读取、读取期间替换拒绝，以及真实 activation/runner 的元数据
与源码快照绑定。镜像声明使用 `--only-binary=:all: --no-deps --require-hashes`；本地测试
不构建镜像、不安装依赖、不导入 SDK、不打开网络，不证明 Linux wheel 在 macOS 执行过。
Python 3.9 开发身份另绑定条件依赖 typing_extensions；正式镜像限定 Linux CPython 3.12。
这些基础合同不授予令牌或发送许可，不代表 REQ7 整体完成；真实两架构卡保持 NOT RUN。

`test_req19_infra_log_contract.py` 和 `test_req19_infra_log_workflow.py` 覆盖第八个
`99-output-infra` 骨架、四状态日志根、规范项目归属、无覆盖迁移与中断恢复，以及真实
setup → deploy/probe/collector 和项目重指后的写者归属。2026-10-07 owner 限定真实目录
迁移仅支持同文件系统；源根/父目录、目标根和两侧嵌套对象跨设备时，必须在凭据发布与
首次转移前明确 `EXDEV`，空源也拒绝，已有恢复凭据和已复制对象保留。设备身份注入不等于
真实挂载卷、断电或冷启动验收，`TC-REAL-REQ19-INFRA-LOG-RECOVERY-001` 仍 NOT RUN。

shell 采集的便携 timeout 测试替身以同一监督者持有命令、计时和 finally 回收责任；
就绪屏障失败或监督者自身出错时也必须终止并回收私有命令，不能留下无截止时间的命令。
`test_monitor_authority_semantic_workflow.py` 以独立的缺失就绪及监督者故障负例约束该清理路径；
另以固定参数、标准输入/输出/错误和非零状态约束 shell 函数替身的兼容执行。
原采集时间上界、输出/token 拒绝和 holder 存活断言
保持不变，不以单项 PASS 推断全量超时的根因已闭合。

K 设置与本地提交的两进程 workflow 由父夹具持有全部私有子进程，第二次启动失败、
就绪屏障失败或断言失败时，先终止并回收自己创建的子进程，再清理私有目录并保留
子进程 stderr 阶段证据。子进程只能等待父夹具明确释放，不能以自己的五秒计时先释放
锁或退出；父夹具原有五秒就绪、十秒/八秒 communicate 和 0.15 秒互斥断言不变。
本地锁的第二进程还必须实际到达尝试锁的屏障，才开始互斥观察，避免未启动的进程
制造空洞 PASS。两个现有 workflow 模块中的独立故障测试覆盖启动故障、就绪超时、
延迟兄弟启动和锁尝试屏障。此夹具修复不证明原全量的就绪超时根因已闭合；
必须继续按失败阶段诊断，不能用单项通过或未变化的重复 full 代替根因证据。

`test_config_sync_authority.py` 的方法 V2 后端与手工 replace-config V1 分开：
本地代次、固定私有 receipt、writer witness 和失败 veto 不依赖 reporter 墙钟。
V2 最大合法 canonical 成功/失败夹具分别是独立推导的 2270/14134 B，有限 wire
上界为 16 KiB；缩小到正例以下必须使 ACCEPTED 断言失败。真实 writer/reader →
monitor JSON/HTML 负向流程确认该后端不能借旧九阶段或手工应用收据取得完成资格。
ZTP monitor 的实际周期在 SSH 提交前铸造本地 pending 方法代次，采集后重新核验
当前 parent → child manifest/marker → 本设备 YAML 与 global/CSV 输入绑定。
同一 BatchMode 会话的身份、live digest 和闭合来源收据仍须逐项比较 DNS、NTP、
timezone、key 等请求配置；配置或绑定漂移只发布 failed/veto，不能借旧成功日志晋升。
读取器以 held descriptors 检查项目根/目录链与叶文件的 owner/mode/no-follow、
single-link、有限读取及前后重绑定；Cumulus 与 NVOS 分别使用现有 eth/ib_nvl 输出。
`test_manual_applied_config.py` direct 和 `test_config_sync_authority_workflow.py`
真实 load → collect → method journal → report/HTML 流程覆盖这些正负例。
initial-setup 另有标准库独立只读观察：同一 public-key-only BatchMode 会话读取
hostname/eth0 MAC、当前 Day-0/services 和 authorized_keys，与调用前冻结的逐设备
预期比较。管理私钥采用 owned 0600 single-link/no-follow held FD，观察后核验身份；
stdout/stderr 共享 8 MiB 上限并受单一 deadline 约束，不在捕获结束后才限制大小。
direct 覆盖漂移、冲突、期望中途修改、密钥替换和不安全文件；真实脚本 workflow
执行 cache → batch shell → V2 generation/veto，下一轮缺失密钥必须撤销旧成功。
现有 key-possession 的 `ssh true` 保持原合同，不作为配置证明。
管理入口 `python3 ztp/config_sync_authority.py --project <project> -- <initial-setup arguments>`
通过可选周期对象接入原 initial-setup main；显式 `--apply` 和逐 IB 的 `config_method=initial-setup`
在 report/cache/authority 写入前验证，eth_jump 仅为 transport。项目输入必须位于显式项目内，
代码从仓库加载，global/publickey 从该项目的 `infiniband/bringup/xdr-initial-setup` 读取，
不能靠脚本 `__file__` 指向项目来隐式取得输入。管理 CLI 可用 `--tool-inputs <project-dir>`
显式选择项目内的其他 global/publickey 布局（包括 `99-output-ib_nvl/bringup/xdr-initial-setup`）；
该目录必须已存在且受当前 UID 所有、不可组/全局写入，外部目录或外链在 leaf 输出前拒绝。
此选项只选择数据，不加载其中的代码。真实管理 CLI 的五轮流程覆盖缺省及显式布局。
受管 CLI 在进入 leaf 前取得仓库的共享部署锁，并持有到方法撤销与报告清理结束；
load/setup/unsetup 的排他锁期间拒绝入口，不在拆除窗口重新授予成功。
direct 覆盖实际 flock 的共享兼容、排他拒绝、异常释放；真实 unsetup → 撤销 →
受管 CLI → 链接拆除 workflow 验证同一部署锁，不接触本地主树的运行锁或真实设备。
受管 leaf 在建立 report/cache/snapshot 或方法代次前，验证 CSV/P2P 的项目内有限输入像，
并检查全部输出路径和现有父目录仍属于该显式项目；外部 CSV/P2P、cache/report 或 snapshot
不得先落下输出再报错。该准入只用于显式方法周期，不改变单文件离线 leaf 的路径合同。
由 owned/single-link/no-follow 有限读取绑定，重新验证 cache/parser 后再次核验输入与项目根。
受管 writer 和只读 initial monitor 的 cache/parser 只消费同一次 held 读取捕获的
有限 bytes、mtime 与 canonical 名称，不重新打开项目路径；缺失或坏快照不回退文件系统。
缓存、CSV、P2P、global、公钥在捕获后被换绑到外部文件或 FIFO 的真实解析负例必须拒绝，
保留外部字节且不发布方法权威。默认离线 leaf 仍使用原路径解析合同。
操作前 pending，完成后同会话观察及发布后重读；失败撤销自己的当前代次，不触碰新写者。
默认单文件离线入口不依赖后端、不产生方法权威；REQ10B 密钥探针和 REQ10C 的 cron 条件不变。
initial-setup 消费端原语 `apply_current_initial_method_authority` 只消费操作前捕获的已完成本地代次，
核验本轮闭合身份/配置观察、显式当前输入摘要，并在 held 收据读取后再次核验代次与字节。
缺失、漂移和晚期失败只撤销该原代次；pending 或较新写者不被撤销。它不创建 generation，
不借 bootstrap 来源、不补造九阶段，未尝试设备仍 pending。direct 与 backend → monitor → HTML
流程覆盖正向、漂移、晚期读取错误、较新写者和完成拒绝。
`monitor_once` 接入此原语：显式 `--initial-target-cache`、`--initial-device-csv`、
`--initial-p2p`、`--initial-tool-inputs` 四项绑定项目内当前 cache/CSV/P2P/global/publickey，
并绑定监控设备 CSV；缺输入不回退。实际 observer 前后及收据读取后复核输入，
操作前捕获原本地代次，不创建新代次。坏 JSON、observer 错误、清单或配置中途变化均拒绝。
真实本地 BatchMode shell → readonly 输入 → backend/monitor 流程另验证配置和密钥漂移，
不把保存的报告作为观察传入；管理监控 main workflow 只替代设备 I/O 与 runtime/release 前提。
项目 `02-unsetup.py` 在删除托管链接/清单前撤销现有 manual V1 和方法 V2 当前权威；
先核验所有历史，不创建缺失目录/锁，不删除旧回执、不新建代次。历史不安全、HOLD、
并发新写者或设备集合变化均拒绝；失败保留链接/清单，已撤销状态不恢复为旧成功。
dry-run 不撤销。direct 与真实 backend → unsetup 流程采用本地临时项目，
runtime/cron 清理前提被显式替代，未操作真实服务或 crontab。
这不补造其他九阶段，也不代表 F02 整体验收；完整方法
生命周期仍需继续实现、测试，真机保持 `REAL_ENVIRONMENT.md` 的 NOT RUN。

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
`test_load_release_transaction.py` 在隔离临时目录中验证 load 的统一 release：只有 DHCP 与
Cumulus/NVOS 子 manifest 的设备身份、真实 YAML hash、完整 MAC 链接集合、effective default
及 DHCP 输出都匹配当前输入时才发布 parent release；旧 `latest_yaml`、篡改 YAML/链接或
生成后被修改的 DHCP 文件必须被拒绝。测试还要求 infra 延迟服务激活，
`current-release.json` 只在 `/etc/dhcp` staging/事务安装成功之后原子提交；失败时恢复旧 DHCP
文件、旧 YAML latest 和进入启动阶段前的服务状态，不能把已验证但尚未安装的 parent 当作
current。由于 child manifest 尚无输入来源证明，非 dry-run `--skip-generate` 必须在任何状态
修改前失败。

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

`test_config_sync_authority.py` 的独立 v1 正例/边界覆盖本地严格递增整数代次、
闭合 schema、owner/mode/no-follow、受控暂存、file/directory fsync、部分回放与持久 HOLD。
配置同步 result v1 另有闭合的 23 个成功字段或 16 个失败字段；失败不携带成功证明。
受管 writer 在 finish 前验证版本、类型、执行窗口、身份和诊断上界，worker 读取时同样校验。
其独立最大 canonical 正例为 14331 B（1024 个最长 JSON 转义的诊断码点及最大合法身份），
固定读取预算 16384 B；退化到正例长度减一须拒绝。超过原始文件预算的空白填充也拒绝并
保留原字节，不以解析后的小对象掩盖超限；未知成员或无版本旧配置回执不能晋升。
这条 schema 不改变 ZTP/reset 旧收据的读取合同，也不关闭 F02 其他消费端工作。
manual writer 的 result/summary 发布同样校验暂存 FD 与命名对象的完整身份；同步期间的
链接、文件和权限置换不能被 rename 为本写者成功，外来最终像不能被回退覆盖。
目录同步失败恢复仍属于本写者的旧像及原权限，新增父目录的目录项也逐级 fsync。
manual/worker 在发布前拒绝非当前 EUID 或 group/other 可写的旧像及最终父目录，
不能靠 chown/chmod 把不安全旧证据修补为成功；暂存同步后重验父目录权限。
worker 的调用参数也不得请求 group/other 可写的新状态，拒绝时旧字节、inode 和权限保留。
真实 writer 的 result stage 被置换时，本地 journal 保持 pending/veto，不铸造成功。
`test_config_sync_authority_workflow.py` 执行真实 manual writer → journal/receipt：
同会话身份和 live digest 只绑定自身代次；下一轮失败先撤销旧成功，preview 不改代次，
最终目录同步期间的 journal/witness rebind 拒绝并保留外来对象。真实 worker 读取本代回执
还须拒绝重复 JSON 成员、非当前 EUID、group/other 可写和 held read 后的路径/元数据替换，
不得截断或清除拒绝证据。三份见证共享恢复域，
消费回执之前还要完整校验 summary 全部 targets/results：未知主机、缺少或重复主机、
casefold 冲突、非对象成员和完成结果集合不闭合均拒绝，不能只检查所选主机然后忽略其余错误。
worker 的身份观察必须位于同一命令的开始与完成时间闭区间内，三者均须有时区；
配置同步完成后的 hostname、所选 endpoint 的 MAC 与 live NVUE 文本由同一次 BatchMode
SSH 读取；独立的旧身份探针不能给后一次仅含 YAML 的连接授权。真实 writer → journal
拒绝缺失同连接身份或 MAC 已变化的 live-state，并撤销上一代成功；私有 shell 夹具验证
身份读取和 `nv config show` 的物理顺序及非零退出，未连接真实交换机。
结束时间缺失、倒序、无时区或身份观察晚于结束均不能晋升。真实 CLI 结果到后台导入
保留原 `finished_at`，不能用后台更新时间伪造该执行窗口的结束边界。
worker 的配置同步接纳还须绑定当前本地 success/veto、严格整数 generation、来源命名空间及
自身回执摘要；summary 和目标 generation 必须一致。读取所有回执和 summary 后再次核对
当前代次，读取期间发生撤销或下一代 pending 时不能返回旧成功。缺失本地历史不由读者补造，
拒绝时原始回执字节保留；真实 manual writer → worker workflow 覆盖这些边界。
CLI 配置同步导入同样使用 held/no-follow summary 和本地代次，不用 reporter 墙钟在旧成功与
新 pending/成功之间择优。缺失、摘要不符或多份冲突观察不能绕过回执接纳；导入结束再复核
本地代次。配置同步的 generation/命名空间必须有严格类型及有限整数边界，不能混入旧 ZTP
操作。旧 ZTP/reset 的时间排序不因这条配置同步合同改变。
成功 worker 状态保存其自身回执的同会话证明、摘要与代次；每轮重新检查当前回执。
丢失、撤销或已变更的证明使旧成功持久转为 failed/authority_revoked，同一代旧文件恢复不能
撤销该否决。只有真正更高且同命名空间的代次才能覆盖该操作的否决；新代次不被旧状态的
未来墙钟挡住。配置同步失败不能借旧九阶段 ZTP 报告被修正为成功。真实轮询 workflow
覆盖这些边界。worker 状态通过 held inode 校验、file fsync、原子替换和目录 fsync 发布；
文件同步后的 symlink/hardlink/普通文件/权限替换，以及最终目录同步期间的外来状态替换
均拒绝并保留外来对象。目录同步失败只能回退自身仍未变更的发布像，恢复原字节和权限，
首次创建则撤掉自身新像；真实 writer → worker 轮询故障注入不能留下成功状态。
这些本地 I/O 注入不证明真实断电耐久性，现场卡仍 NOT RUN。
当旧状态仍绑定当前精确代次时，worker 的撤销还更新本地 generation journal；随后恢复旧
worker 状态和旧回执不能复活成功。观察者使用持锁 compare-and-revoke，完整版本化预期
须与锁内当前像一致，不能把读取之后并发启动的新 pending/成功代次一起撤销。
不宣称抵御全部镜像或整卷回滚。worker/九阶段监控消费端尚未完成接入，F02 整体仍 OPEN；
真机持久化卡 `TC-REAL-F02-LOCAL-GENERATION-001` 仍 NOT RUN。

九阶段 collector 现在在原 BatchMode SSH 中读取 live NVUE，独立的版本 1 frame 保留
原始文本（含尾部换行）和摘要；缺失、重复、截断、NVUE 非零退出或另一失败连接的
输出不能提供正向摘要。固定合法正例为 8 MiB，退化预算及超限均拒绝且不截断。
私有 fake SSH 运行完整真实 remote script，未连接设备；与真实 manual observer 的
shell workflow 核对同一 live 文本。此字段只是传输观察，不是持久配置成功收据，
也不是 generation 权威；九阶段晋升与当前本地代次的接入仍须完成，不能据此关闭 F02。

同一次实际 BatchMode remote script 还调用固定 `sudo -n --
/usr/local/sbin/http-manual-ztp-applied-config`，用唯一闭合状态 frame 收集 bootstrap
来源凭据。与 manual reader 共用无 I/O 的 V1 decoder：校验闭合字段、来源/模式、
设备 eth0 身份与原始 YAML 摘要；缺失、HOLD、拒绝、歧义、截断和前一次失败连接均不能
提供来源 YAML。完整协议响应独立固定 8 MiB 正例可接受，退化界和超限拒绝且不截断。
清单及来源 MAC 只接受 12 位十六进制或六组冒号格式；额外字符、重复分隔符、空白
不能通过删字符“修复”为本设备身份，manual 与 monitor reader 均按同一合同拒绝。
私有真实 helper → 完整 collector remote shell → 共同 decoder workflow 验证两次单连接
及 HOLD 原像保留，未连接真机或执行 sudo。这只是来源诊断，不铸造/复用本地代次，不将
旧 applied_at 或 YAML 等同当前 live state，也不授权九阶段完成；bootstrap generation
与本地代次的因果消费接入仍未完成，F02 整体 OPEN。

analyzer 现在以本次连接的 BatchMode、live 摘要和 inventory 主接口身份重新验证
bootstrap 来源响应，向报告写入闭合的紧凑来源观察，不写原始 YAML 或 generation。
显式来源缺失、畸形、摘要漂移或后续连接失败均否决旧 config_apply/complete 成功；
JSON、HTML 和机器判据保持一致，不降低既有 failed，不阻断独立健康采集。
来源变化属于独立快照状态，保存后不随输入对象变化；此必要条件不等于当前本地代次
或本轮配置应用成功，bootstrap/initial-setup 的代次接入与 F02 整体仍 OPEN。

来源否决不覆盖独立核验的当前 manual-config-sync：只有闭合且严格类型的本地代次
成功投影，与本次自身 BatchMode 身份/live 摘要匹配时，保留 config_apply 成功；
bootstrap 来源缺失仍否决九阶段 complete、HTML 与机器 handoff。缺失、畸形、旧代
或漂移的手工来源不能借此豁免，既有 failed 也不降级。实际 writer → collector →
monitor_once → JSON/HTML 场景在私有项目覆盖该边界，未连接设备，真机仍 NOT RUN。

monitor inventory 逐设备物化并验证 `config_method`，与真实 load 的同一输入结果一致。
重复方法列、显式空值、未知或设备不兼容执行者在监控/范围过滤前拒绝，错误带行号与
主机；合法 server 声明验证后仍不进入 Switch Status，动态 AIR 使用受管默认值。
方法变化属于 snapshot 状态变化，但声明方法本身不证明任何配置已执行或完成。

monitor 的 `configuration_observation` 用严格布尔 BatchMode 标志、唯一身份 frame、
完整 hostname 与选定管理接口 MAC 绑定本次 live 文本重新计算的摘要。采集允许的过渡
hostname 不自动成为配置证明；缺失或失败的新观察清空旧正向观察。真实远端脚本没有
eth1 时的零行空字段仍允许 eth0 证明，重复/多行身份拒绝。此字段只用于诊断，**不是**
持久收据或 generation 权威，不授权九阶段晋升；当前代次接入仍须独立完成。

本地 generation 的只读回执 API 持同一 authority 锁核验 run/hostname/result.json，
不按 report 时间选择代次。读取包含 owner/0600/no-follow、闭合 schema、当前 journal
摘要和读取后文件/父目录复核；旧代返回不可用，矛盾或不安全原像报错并保留，读取不会
建立新 history。独立 16384 B 合法原始 wire 正例、16383 B 退化界及超限保留均有测试。

monitor 在 SSH 采集之前读取本地 manual-config-sync 当前代次；采集后以自己的同会话
身份/live 摘要核对唯一安全当前收据，并再次复核代次。当前匹配只能证明配置同步，
不能借旧九阶段日志恢复本轮 complete/overall/handoff。live 漂移、缺失或不安全/歧义
收据以持锁 compare-and-revoke 撤销精确旧代；并发新代、pending 写者和关闭采集不能
被旧观察改写，既有 failed 阶段也不能降级成 warning。真实 `monitor_once → report.json`
workflow 覆盖匹配、漂移与采集中换代，另外覆盖读取后换代与撤销边界的并发写者。
此接入仅覆盖 manual-config-sync；bootstrap/initial-setup 当前轮权威及非 ZTP 健康
分类仍须单独完成，F02 整体仍 OPEN，真实环境卡仍 NOT RUN。

monitor 的 DHCP 模式来自已核验的当前 parent release/global 绑定（legacy v1 仅 enabled），
不能按旧 DHCP manifest 或租约存在推断。disabled 周期不读/哈希租约、不采集 DHCP 日志、
不创建本地 DHCP 归属或查询该服务状态；静态 SSH 与独立 Apache 证据继续，report 明示
disabled。真实 load 发布 → monitor_once workflow 保留 enabled 正向 DHCPACK，并证明
disabled 在旧日志/租约存在及完全缺失时均无需读取，也不改写原始来源文件。
离线入口只在当前 parent release/global 通过同一完整身份校验后免除 disabled 的
DHCP log/lease 参数和文件检查；enabled 或没有 mode 权威的旧诊断入口仍要求显式文件。
损坏/悬空 release 不得回退，入口后 release 改变须在 inventory/DHCP 读取前拒绝。
Apache/AIR、single-link 文件、独立输出及 no-SSH/no-watch/no-HTML/no-handoff 限制不放宽。

健康分类另有真实 `sw-info.sh → generate-monitor-html.py` workflow：在私有目录运行
完整采集脚本，仅设备/系统命令为独立夹具。ETH/IB/NVL 各覆盖 OK、Not OK 和缺证据，
一轮即得到对应健康/异常/未知页面分类；没有 ZTP 或配置收据仍可分类，但当前九阶段
保持 pending，不产生配置历史，也不放行 HTML/机器 handoff。临时文件和锁须完全清理。

九阶段历史不能把已有但不可读、非对象、非列表或重复大小写主机成员的快照当作空历史。
`test_ztp_group_handoff.py` 独立验证负向历史权威跨轮保持及 JSON/CSV/Markdown 诊断；
`test_ztp_group_handoff_display.py` 串联真实监控快照写入、下一轮读取与真实 HTML 判据，
证明历史损坏不能恢复“完成”。四个身份/晋升/轮次否决字段存在时必须是严格 boolean false；
0、空字符串、null、数组和对象均不等价于没有否决，页面与机器交接遵守相同合同。
`finalize_device` 的 overall success 同样受当前九阶段交接判据限制：第二轮缺失、无效、
无时区或过期阶段时间不能仅凭复制的 success_index 宣称成功。真实快照/CSV/Markdown
须保留 CURRENT_NINE_STAGE_PROOF_INCOMPLETE 诊断；新鲜可比证据可以消除此派生诊断，
但不得改写旧快照。配置、代际权威本身没有因此新建或放宽。
机器/HTML 完成资格只接受当前受支持的 ETH/ETH_SPX/SPX/AIR/IB/NVL 类型；server/UFM、
未知或空类型即使持有声称九阶段全部成功的旧快照，也不得取得 Switch/host 完成。
真实报告写入 → HTML/机器判据正反例不改变 server/UFM 的独立部署合同。
当前轮 no-SSH/未获采集资格的设备也须在历史阶段复制前写入明确的未采集观察，
不能因没有 analyzer 调用而借缺字段的旧快照恢复总体或 HTML/机器完成。
真实 load → disabled 离线监控 → 持久 JSON → HTML workflow 覆盖有/无旧九阶段成功历史；
旧快照仍原样保留，未采集不新建配置收据或本地 generation，也不撤销另一个写者。
当前 analyzer 显式给出的 configuration_observation 必须通过共同的只读否决检查：
闭合 v1 schema、严格 True 的 BatchMode 身份、当前 inventory 主机与所选接口/IP/MAC、
合法同会话 live digest 及空否决原因。显式缺失成员、畸形或失败观察不能被旧九阶段
成功记录掩盖；真实 analyzer → report → HTML/机器 workflow 保留此负向证据。
显式 candidate_identity 必须为映射；false、null、0、空字符串或数组不是缺省主接口身份。
独立 direct 与实际 analyzer → report → HTML/机器 workflow 保留这些负例和合法空映射正例。
旧快照不含该字段仍保留原九阶段合同；不因此获得新观察、应用收据或 generation，
bootstrap/initial-setup 本地来源代次接入仍 OPEN。
这些本地证据不证明真实采集器已执行，也不关闭 F02 的配置同步消费端剩余工作。

SSH 身份负例夹具执行真实生成的 askpass Python body 时绑定当前测试解释器，
并以污染 PATH 的独立负例核验，不依赖 `/usr/bin/env` 选择其他 Python；原 2 秒限制与
FIFO rebind 的原断言保持。其他 askpass 用例继续覆盖直接 executable/shebang 路径。
这不是生产 SSH 超时合同的变更，也不证明其他启动/banner/清理超时的根因已闭合。
进程 I/O/deadline 的受控 fake SSH 夹具显式使用指定的 shell/Python；仍运行真实子进程，
保留原 SSH 参数、new session、FD 白名单、输出上限、子孙清理断言及 0.1/1/2/5 秒期限。
真实 stock OpenSSH 的参数与路径不被该夹具适配器改写；loopback 失败保留 daemon trace，
不把 banner 超时当作 host-key 拒绝或隐式重试通过。

`test_ztp_applied_receipt.py` 覆盖 bootstrap 的 root-owned `/run` 独立工作区、原子
applied-receipt publication HOLD：受控负向 guard 须在数据/收据 rename 前刷盘，且真实
Cumulus/IB/NVL 配置以及 SN/VX 镜像升级分支须在首次 NVUE/安装/重启前撤销旧成功。
只读 helper 拒绝任何 guard 占位并在输出前复核；末次目录 fsync 或 guard 清理失败保留 HOLD。
实际 bootstrap→helper→manual/monitor workflow 证明早期 staging 或晚期持久化失败不能借同字节
旧成功晋升，外来 HOLD 不得自动采用或删除。monitor 按物理日志顺序保留未清除 HOLD 的
负向否决，旧 saved 日志、未知状态或不安全来源不能清除后来的 HOLD。无诊断否决不是
同会话 BatchMode/live digest 或设备 generation 的正向证明，F02 整体仍 OPEN；真实升级未执行。
该模块也覆盖 `latest-log` 指针，以及在该指针成功发布后非致命创建的 `ztp-last-run.log` 固定名硬链接；测试验证
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
其中 Native load→generation report 与 feedback→runtime stop 的源码绑定检查仅证明各自列出的
单一路径：外层精确 AST 摘要遇源码变化即撤销证明，独立结构层的改写负控另行验证导入、停机次序
与目标。它们不构成 H 的完整固定点盘点或真实服务停机证明；H 验收仍按 D-59 的现行合同及
`TC-REAL-MONITOR-WRITER-QUIESCE-001` 的 NOT RUN 状态分别判断。
补入的 `test_imported_mapping_argparse_real_writers_still_require_governed_literals`
独立检查生产 setup 的导入映射到软链接、feedback 的真实 argparse 构造绑定，以及受管目标传入
未知/改绑导入函数时的拒绝；正反例均由测试固定。这是缺失验收方法的有界替代检查，**不是**
历史私有 304-test H oracle 的逐字节恢复，也不将该方法或当前模块的绿色结果升格为 H 完成。
未解析导入门禁只覆盖实际传入受管目标的调用；对完整导入/返回形状/运行时输入不作全面证明。

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

采集交接 workflow 的私有 bash 夹具用匿名可定位 FD 保留完整 context 字节，再启动真实 cron，
不在读者启动前同步填充有容量上限的管道。独立 direct 校验 2 MiB 合法 JSON 的完整字节数与
SHA-256，真实跨脚本案例校验同样大但字段不变的 context 仍保持原 cycle/slot 身份并取得
qualifying；原 10 秒 slot、30 秒 workflow 和所有篡改拒绝断言保持不变。该夹具缺陷由新案例
独立复现；不能据此宣称此前小 context 的全量超时已定位，也不能用局部 PASS 代替 full proof。

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -m unittest discover -s test_cases -t . -p 'test_*.py' -v
```

该测试套件只做快速契约检查。发布前还应执行 Python/Bash 语法检查、setup/load dry-run、
临时目录生成/发布流程，以及 `ubuntu:24.04` 容器中的 infra setup/teardown。

### P 阶段正式证明的 Python 依赖 capsule

P 阶段在绑定的 macOS CPython 3.9 环境中，把独立审定的依赖文件构造成确定性 USTAR archive。父进程在关闭唯一写 descriptor 后，以 `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` 重新打开并立即 unlink；正式流程只复用这个 anonymous read-only inode。每个顶层需要第三方依赖的 Python child 都从它重新安全解包到独立 `0700` snapshot，逐项核对固定清单、SHA-256、模式、Mach-O/ABI 和包版本，再经固定 `/usr/bin/sandbox-exec` profile 启动 `-I -S` Python。该顶层 child 创建的普通 Python 后代仍在同一 sandbox 中运行，并使用经逐级验证的 exact-layout `PYTHONHOME` 与 exact-empty `site-packages`；它们的 `PYTHONPATH` 精确包含 snapshot、绑定的标准库和 `lib-dynload` 三项，从而阻断 ambient、user 或 system site-packages 的意外回退。该 profile 禁止 child 及其后代写入、重命名或建立 snapshot alias；任何 sandbox 不可用、依赖漂移、非法 archive、FD/identity 漂移或清理失败都阻断证明，不能回退到 user/system site-packages。只负责启动正式 FQN 的 orchestration harness 使用绝对路径 CPython `-I -S` 和受信任标准库，不导入第三方依赖、也不套外层 sandbox；它只把同一个 anonymous archive FD 交给正式 full runner。该 runner 作为顶层依赖 child 建立并持有经过认证的 snapshot、exact-layout `PYTHONHOME` 和 archive identity。只有精确批准的 test-runner argv 才能进入 reentrant 模式；每次 reentry 都重新认证这些 held authority，证明嵌套 `sandbox-exec` 精确返回 71 且 snapshot 写入被内核拒绝，然后在既有 sandbox 中用有界 direct child 运行，绝不嵌套 sandbox、重建 archive、回退或清理继承状态。

只有 `-B test_cases/run_related_tests.py --all -v`、`-B test_cases/run_related_tests.py --suite repository-governance -v` 与 `-B test_cases/run_related_tests.py --all --no-approve -v` 三组精确审定的 runner argv 会在进入顶层 child sandbox 前，由父进程在同一个私有 state root 内预启动受管 loopback OpenSSH fixture。父进程使用固定的 `/usr/sbin/sshd`、`/usr/bin/ssh-keygen` 与 `/usr/bin/ssh-keyscan`，以临时 host key 在 `127.0.0.1` ephemeral port 完成真实 KEX，并用持久 held read-only descriptor 绑定 key、config、manifest 与 daemon log identity；每轮另通过 held root dirfd 对 PID file 做短持有 `NOFOLLOW` open、双 `pread`/`fstat` 与精确 `pid\n` 验证。near-miss、hidden probe 与普通 child 均不得触发或继承该 fixture。父进程只向精确三类 child 传递 routing marker，不传 fixture 路径或 descriptor；child 先认证既有的 exact-nine environment protocol 与 archive、snapshot、`PYTHONHOME` exact-seven dependency descriptor，再从 authenticated `snapshot.parent` 派生固定 sibling 路径并以 `NOFOLLOW` held reads 自行验证 fixture，因此不会增加任何传入 FD。顶层 sandbox profile 另以 literal/subpath 规则禁止 child 及其后代写入、重命名或建立指向 fixture subtree 的可写别名。child 返回或抛出任何异常后，父进程都重新核对 held identity 与 payload，并以有界 TERM→KILL process-group 流程回收 daemon、关闭全部 descriptor、删除 fixture；创建、KEX、认证、内核写保护、回收或清理任一步失败都会阻断正式证明。

这项自动化保证覆盖当前证明进程、child/grandchild 以及其可执行的 snapshot 篡改；它明确不承诺抵御另一个已在运行且拥有同一 UID 的独立恶意进程在 archive 建立窗口内抢占 writable FD。正式证明必须在无不受信任同 UID 进程的专用会话中执行；该剩余边界与人工证据登记在 `REAL_ENVIRONMENT.md`。

`test_req7_sdk_authentication`、`test_req7_tls_inputs`、`test_req7_native_tls_wire` 和
`test_req7_attempt_supervision` / `test_req7_native_supervised_workflow` 约束公有 SDK、
固定 CA 与受控原生 TLS、单次回调以及包含启动／DNS／慢读的完整预算。其组件均为未安装库，
本地仅使用合成密钥及私有 loopback，不读取真实凭据、不安装依赖或开放在线入口。
监督器的可选私有 stdin 限定原生 bytes 1–32768 字节，以非阻塞分段写入和 EOF
纳入启动前开始的同一总预算；管道背压不能阻塞父进程或刷新截止期。错误、提前
关闭和未完整输入均 HOLD，无重发、无私有诊断泄露、不释放 borrowed 锁。
实际输入 → 单次原生 TLS → 完整响应 → 已结束 session 工作流仍使用合成数据，
此通道不是 mutation WIRE、固定读取入口或在线准入证明。
`test_req7_history_read_launcher` 将固定 History-tail GET 接入实际双 owner：
启动前和完整响应后重新读取当前项目策略及固定白名单，私有输入仅经 stdin，
固定隔离 child 继承两把实际锁并在同一 30 秒总预算内返回 nonce/path/body 摘要
关联响应。整个私有输出（报头加原始正文）沿用 2 MiB 上限；接近上限时拒绝，
不截断或扩大限额。401/重定向/失效 token/输入或响应破坏均不重发。
此入口未安装，只给完整 HTTP 观察；不验证 typed History、nonce 连续性、
fence 匹配或 COMPLETE/APPLIED，不授予 mutation/R2/在线激活权限。
同一固定只读 child 也承载八种枚举形态：History tail、完整 Whitelist、十四表
identity、四表 headers、活动列、插入占用列、精确单行和固定 metadata search。
参数仅允许规定的表与 typed 行号，不接受任意范围或 URL；metadata POST 仅是
固定只读 search，不是 batchUpdate。真实双锁 → 私有输入 → 原生 TLS → W1 规则
比较、模板解析和可见 metadata 计量工作流仍不授予准入；后者始终
VISIBLE_ONLY_UNPROVED，不能把不可见的其他 PROJECT 使用量说成零。
后续读核只接受固定入口实际签发的原始 completion 对象，重新核原双 owner、
精确读取形态及 native 参数类型、未改变的原始响应、当前策略和原 30 秒截止期。
相等的 dataclass 副本、独立协议解码结果或 caller 摘要不能建立读取来源；
该进程内来源登记不是持久证据、远端原子快照、发送许可或 COMPLETE。
`test_req7_token_launcher` 约束未安装的固定 auth-only 子进程入口：不接收调用方
argv/URL/凭据路径/预算，固定 `-I -B`、清空继承环境、DEVNULL stdin、新 session、
仅 pass_fds 借用原 spreadsheet 锁。启动前开始 30 秒总预算，单次消费及 nonce
关联的严格有界私有输出；凭据/JWT/token 不进入 argv、环境或公开诊断。公有 SDK
和实际 stdlib HTTPS/TLS 到拥有的 loopback 正向及 401/503 负向均不重发。已知
Python 3.9/3.10 EOL 警告以固定 tag 保留并由父进程重新发出，不转发任意私有警告。
本地子进程的 SDK user-site 路径仅在测试启动边界显式注入，不是生产隔离解释器或
部署依赖身份的证据。无法确认结束时仍 HOLD，子进程继承的实际 flock 在 owner
退出后继续阻挡候选。此入口只刷新 token，不授予 mutation、发送尝试计数、
新鲜 W1/连续性、COMPLETE 或重试许可，REQ7 整体仍未完成，REAL_ENV 仍 NOT RUN。
G1 的固定项目认证补充仍为未安装的必要来源层：独立 v2 私有协议只从固定
`cre.json` 的原字节、严格 project_id、公有 SDK 和固定原生 OAuth 返回项目身份，
不接收 caller unit。实际监督 child 成功后才登记原 completion 对象／owner／PID；
复制、独立解码、owner 撤销、过期和固定凭据项目／字节漂移均 HOLD。原 v1 合同
及 30 秒预算不变。owner 已确认专用表／单一 Cloud 项目写 metadata 的限制；
本层不证明历史隐藏 metadata 不存在，也未接入完整库存、准入或发送边界。
可见容量计量仍 `VISIBLE_ONLY_UNPROVED`，G1 与 REQ7 整项仍未关闭。
项目认证来源另与实际固定只读 launcher 接通：`OwnedProjectSheetsReadUnit`
只消费实际签发的原认证对象，启动前及完整回包后复核固定凭据、原双 owner、
当前目标策略和原 30 秒截止期；后续消费只接受该次认证与该次原读取对象。
同值 token 的另一次成功认证、复制／解码对象或使用相同 token 的 legacy 真实读取
不能取得这份来源登记。公有 SDK→原生 OAuth→双锁→私有 stdin→原生 Sheets
metadata search 的本地真实流程及读取前／中凭据漂移拒绝均保留原预算、不重试。
来源接通仍不证明专用表／历史项目排他、不构成原子库存或配额保留、发送许可；
完整 G1 容量与最终 worker 准入尚未接入，现场卡仍 NOT RUN。
`prepare_owned_project_metadata_reservation` 把该原认证／原实际 template 与 metadata
读取接入既有 durable quota：模板身份从原读取解码，永久栅及保留量只从原 global
unit、enrollment 与 History journal 导出，不接收 caller identity、plan、项目声明或
reservation 列表。复制、过期及来源不一致在落盘前 HOLD；落盘后原读取过期仍
保留全部原 reservation，不撤销、重建或返回发送许可。冷回读保留原可见计量合同，
不能把持久化 quota 当作认证来源、历史排他或完整库存证明；整项仍 OPEN。
quota 原目录及四个原文件 FD 保持到最终校验／内部来源复核结束；同字节目录或
HEADER／RESERVATION／METADATA-RAW／INITIALIZED 替换不能通过重新读取而被采用。
晚失败不删除原始或替换后的证据，也不增加发送次数。
`test_req7_settings_audit_allocation` 从持有实际项目 ACTIVE 锁的 C25 原始事件链、
最高 current、INITIALIZED 和逐事件 outbox 投影导出审计行；调用方不能伪造队列、
revision、时间或内容。双 owner 下把真实非空单元的原始审计固定到项目
`.tracker/settings-audit-allocation`，全部 image barriers 后才创建 INITIALIZED，
根目录的外部 `SETTINGS-AUDIT-ALLOCATED` 见证先于分配目录创建并持久化；
目录整体丢失、见证缺失／损坏／链接或未解释 pending 文件均 HOLD，不当作首用重建。
拒绝迟于第一次尝试的分配或 partial journal 回填。真实 C5/C6/原始业务 workflow
在每次计数前后复核实际分配，后失败保留 UNKNOWN 和计数；新 K 事件不改旧 wire，
全 NOOP/audit-only 不分配也不消费 outbox。当前为保守单单元留存；原分配本身
不证明 COMPLETE/DELIVERED，不提供 outbox 清理或后续单元回收，不能冒称 REQ7 整体完成。
原分配／UNKNOWN 的实际冷进程回读保留 `-I -B`；本机隔离 fixture 仅在测试启动
边界注入实测 PyYAML distribution root，不注入整个 user-site，不提供生产依赖
fallback，也不把该本地回读当作容器解释器、SDK 或真机资格证明。
pending 读取及分配的整个调用另保持原 settings/events/outbox/current/INITIALIZED
目录和文件 FD；核对原完整 stat/inode、字节与命名空间，同字节替换也 HOLD。
分配前后及 INITIALIZED 之前必须核同一原像，不得通过重新打开当前路径来采用
替换件。根目录允许本调用新增自己的分配见证，但不允许替换原 settings 子树。
原 allocation/outbox/journal 不回填、不清除；这只补原件稳定性，不授予
COMPLETE/DELIVERED、outbox 消费、发送或在线 worker 激活。
已完成分配的 HEADER、ASSIGNMENTS、INITIALIZED 和外部见证也保持原只读 FD，
穿过同步和最终复核；同字节替换不能被重开路径采用。受保护普通计数及共享重试
另在原 C5/C6、业务、预留和审计的前后复核之间持续持有 settings 与分配原件，
计数前身份漂移不计数，持久计数后的漂移保留 UNKNOWN，不回滚或修补。
共享重试的后计数拒绝保留未配对 admission INTENT，所有后续 lane HOLD；
这不是清理或重试许可。独立 direct 覆盖八类原件及计数前后两种状态，真实
Stage-L/C5/C6 workflow 覆盖普通计数和共享重试后的同字节替换，保留原字节故障测试。
此身份快照仅绑定本次观察／计数窗口，不是跨冷进程的永久 inode 登记或现场证明。
实际 COMPLETE→C25 桥另在双 owner 下持有原分配、settings、全局 journal、
enrollment、History preread 与全部完成 proof 原件，重放完整语义并完成屏障后，
先独占写目录外 `.tracker/SETTINGS-AUDIT-DELIVERY-STARTED` 固定见证，
再向独占 `.tracker/settings-audit-delivery` 写原 HEADER 与后置 DELIVERED。
见证的首写原身份持续到 marker 和返回；冷读从 HEADER 重新核见证身份。
目录位移、首字节或四个见证屏障失败均保留 STOP，不能再次按首次交付补建。
HEADER 的首写原身份持续到提交及返回；missing／partial／链接／同字节替换或
原 COMPLETE 不成立均 HOLD，不回填、不采用。六个提交屏障故障保留 partial、
原 outbox 和 UNKNOWN 计数。真实固定 TLS→原事件分配→全证明→DELIVERED→
冷进程读取覆盖本地跨脚本闭环，不代表 Cloud 或断电验证。
首次分配必须包含 ALL 已提交待审计事件，不能漏行；后续 K 不改旧分配。
`pending_settings_audits_after_completed_unit` 仅在上述原 COMPLETE/DELIVERED 对
重新核验并持续持有原件时，排除该单元原 event IDs；残留 outbox 投影为 cleanup-only，
只有该已重新核验配对的精确原 event IDs 可以缺失投影；全部或部分缺失分别返回
ABSENT-VALID 或 PARTIAL-VALID，暖／冷读均不补建或重发。缺失交付 marker、启动
见证、有效原 COMPLETE，或缺失后续未交付 K 的投影均 HOLD；普通 pending、分配
和计数读取仍严格要求所有投影。后续 K 仍 pending。不执行清理，不释放全表 UNKNOWN、FIFO、
高水位或新单元资格；普通未带完成证明的 pending 读取仍不是发送权威。
统一 `current_k` 的显式双 owner／binding／原 unit 只读入口在同一 held 原 COMPLETE、
DELIVERED、启动见证与 settings 范围中返回最高已提交 K。缺失旧交付投影不能造成
旧 K 回退；后续待交付事件仍须保留其投影。部分／伪造／已失效上下文、缺交付证明
或返回前同字节 current 替换均拒绝；普通无上下文入口仍严格要求全部投影。
真实冷进程获取双 owner 并重读原 ACTION/WIRE，不采用父进程缓存。此显式只读入口
不等于默认 worker 接入，不授权 K 写入、outbox 清理、发送或全局状态释放。
显式 `tracker_writer(completed_binding=..., completed_unit=...)` 先获取原项目 owner，
再获取固定根目录下的原 spreadsheet owner；初始、每次 `current_k`／
`require_current_k` 及正常 scope 收尾都重新核完整原配对，不缓存 K 或 consumed IDs。
上下文只属于实际 token，在任一 owner 关闭前撤销；调用方异常原样保留，正常收尾
证明丢失则 HOLD。冷进程重读原 ACTION/WIRE 并重新获锁；部分／伪造上下文拒绝。
该 scope 本身不修复投影或执行写入／清理，也不等于默认在线 worker 接入。
`set_k` 另在此实际配对 scope 内重新持有原 COMPLETE、DELIVERED、启动见证与分配，
验证最高原链、请求 payload／重放及 expected revision，按独立预期提交新 immutable event、
必需投影和最高 current；原已冻结 ACTION/WIRE 不变，后续新事件仍 pending。
immutable event／投影以已有原子 NOREPLACE 原语安装，保留 temporary-file／
installed-parent／held-file 三屏障，不按可被替换的临时名称 unlink。安装后重新出现
的 pending 名称必须保留并 HOLD，不能删除替换件；全部既有故障断言仍执行。
current 同样不使用覆盖替换：将持有的原指针原子 NOREPLACE 移入既有私有 quarantine，
重核原 FD／字节并同步源和归档目录，再 NOREPLACE 安装新指针及同步 settings。
中途替换原指针或在移动后插入陌生 current 均保留实际对象，HOLD 而不 ACK。
变更前持久化未决 guard，所有十个 event/outbox/current 屏障完成前不清除；任一屏障、
原件身份／证明或收尾失败均 HOLD 并保留未决证据，暖读取和新 native 进程不采用
coherent-looking tail、不回退旧 K、不恢复已交付投影。清理 guard 的故障保守保留 STOP，
成功收尾把原 guard 原子 NOREPLACE 移至既有私有 quarantine 并完成两目录屏障，不按
临时名称 unlink；替换件保留且 HOLD，归档／证明收尾失败保留新的未决 STOP。
不修补事件或对外发送。原无上下文的 K store 仍严格；actor 信任仍由调用方 relay 另行
证明，本地接口不授权 root／CGI 激活、outbox 清理、UNKNOWN／FIFO／高水位释放。
`test_req7_settings_audit_allocation` direct 与 `test_req7_remote_history_match` 的实际
双 owner／固定 TLS／冷进程 workflow 保留独立事件字节、幂等重放、全部原八个与新增
两个指针归档提交屏障，以及原指针／guard 替换证据不丢失和
guard 屏障／收尾故障预期；不替代正式 full/check、现场断电或 REQ7 整项验收。
独立的 ETH/IB cabling 夹具分别获取其合成 token 和读取计划，不沿用前一夹具已过期
的 token；TTL 和生产过期拒绝不变。新增受控墙钟跨窗口测试不冒充休眠或断电见证。
计划失败仅追加阶段、类型一致性及剩余有效秒数，不输出 token、header、ID 或业务内容。
`cleanup_completed_settings_outbox` 是独立的显式双 owner 接口，不是上述读取／K 写入
接口的隐含副作用。持续持有原 COMPLETE／DELIVERED／启动见证／分配及最高 settings
原件，仅将该单元精确 event IDs 的残留投影原子 NOREPLACE 移至既有私有同设备
quarantine，保留 inode／0600／字节并同步源与归档目录后才确认；后续 pending 不动。
不存在的旧投影只允许原交付证明解释；重放仅重新同步既有目录，不补件、不重发。
归档碰撞、EXDEV、源替换、任一目录屏障或证明收尾失败不 ACK；实际移动的对象保留，
不 copy/delete、不回滚、不释放 UNKNOWN／FIFO／高水位。已持久交付且原投影已移动后，
K／pending 观察可合法返回 ABSENT-VALID；这不把失败清理计为成功。证明丢失则暖／冷 HOLD。
direct 与真实双 owner／TLS／原 C19／native 冷进程 workflow 保留正常、部分缺失、后续
pending、精确重放、两个屏障、替换／碰撞／EXDEV 和故障安全状态的独立预期。
本地接口不等于默认 worker 接入、真实 Cloud／断电或 REQ7 整项完成；现场卡仍 NOT RUN。

`tracker_settings_writer` 在真实设置工厂及默认 prod 只读状态入口接入原件发现：先取得实际 LK-P；无交付声明
仍走严格普通 K 链，不初始化缺失状态。已有交付声明时，持续持有分配 HEADER 和原始
ACTION-PREIMAGE／WIRE 的 FD、命名、完整 stat 与字节；HEADER 仅定位候选 binding，
随后必须取得真实 spreadsheet owner 并证明原 COMPLETE／DELIVERED／启动见证及分配。
不能从 caller flag、旧缓存、同字节替换或重编译获得缺失投影的权威。每次读写及内部
K 提交边界前后重新验证该原件作用域；写入中丢失原件须保留 STOP／已提交尾部，不 ACK。
作用域结束前撤销上下文；认证 principal／UTC 仍由既有可信 relay 产生，精确请求重放
不重复事件。独立 direct 与真实工厂／双 owner／C19／TLS／native 冷进程 workflow 固定
正常、无交付／UNKNOWN、缺件、错误 binding、同字节替换、提交中断、冷恢复与故障安全
状态。此接入不替换发布／来源 owner、不安装在线服务、不释放 UNKNOWN 或授权发送；
全量证明及真实设备／Cloud／断电验收仍未完成，不以本地 PASS 标为通过。

默认 prod `inspect_stage_l` 与真实 worker 状态入口在合法交付投影归档后读取最高 K，
仍保持 pending／来源资格／本地 receipt 的原合同和 `disabled_no_send_authority`。
独立 direct 验证缺失 tracker 不初始化、错误 scope 不读来源；实际多脚本流程验证正常
暖／冷读取、后续 pending 与原 WIRE 保持、缺失交付证明 HOLD，以及真实 per-key 来源
读取后同字节替换分配 HEADER 时不能返回成功。真实 worker 写出的只是状态文件；
AIR、完整手动 preview 与 C6 提交仍使用原 owner，不借此放宽来源、发布或发送准入。
这组本地自动化不覆盖旧周期 R2、APPLIED／FIFO／高水位或默认在线发送闭环。

`test_req7_sheets_read_plan` / `test_req7_sheets_read_decode` 与
`test_req7_online_whitelist_read` 固定精确列／坐标、十四表身份、四张 row-2 多行字面表头
和完整有限 Whitelist；非原子 GET 不构成 enrollment、发送许可或完整格式快照。
`test_req7_activity_discovery` 验证发现列必须包括 Switch N / Cabling U 原始 Status，
按完整规范化活动键分类，仅精确字面 `Closed` 排除活动项；重复活动键 CONFLICT，
不改线上已有 NV ID，不把公式／格式化值当字面。原生 TLS GET → 真实 planner / decoder
流程仅产出有限窗口观察，空匹配不证明全表不存在、可新增、COMPLETE 或发送许可。
`test_req7_enrollment_journal` 在实际全表 owner 内生成一次四张表的独立原始 nonce，
在 folder／NONCES／HEADER 六个屏障完成后写真正 INITIALIZED；冷重开保留，不从远端
采纳／重生／修复 nonce。真实 composer 与 C-6 action journal 必须绑定同一 target/History
pair；完整 metadata 只读匹配要求 SHEET 锚定、DOCUMENT 可见、两 nonce 一致且无重复。
匹配不是新鲜准入、metadata 容量、COMPLETE 或发送能力；库未安装，真机仍 NOT RUN。
`test_req7_mutation_rejection` 保留四类一致错误之外的 UNKNOWN，后续拒绝不能消除旧 UNKNOWN。
`test_req7_attempt_journal` 在实际 C-6 owner 内测试不可覆盖字节、file/directory fsync、
六次意图计数、真实子进程退出／重启、部分记录与外来对象拒绝。六次意图不证明真实尝试
上界：固定 launcher 的单次消费、spreadsheet-wide 锁、新鲜准入、History/fence 与 COMPLETE
仍须完成；组件无重置／清理／在线发送权限，不代表 REQ7 整体完成。对应真机卡保持 NOT RUN。

`test_cases.test_req7_metadata_capacity` 另验证固定只读 metadata search 与真实 TLS、
十四表身份解码、每 sheet 和独立 spreadsheet 池的永久栅／enrollment／其他元数据／
未决预留核算。UTF-8 字节计数是保守计量；溢出 STOP_CAPACITY，未溢出仍
VISIBLE_ONLY_UNPROVED，因为别的 Cloud 项目的 PROJECT 元数据可能不可见。
可见空池、响应完整、相同 fence id 或未溢出都不是完整库存、COMPLETE 或发送许可；
预留不清除，栅不回收，容量不承诺剩余天数。库未安装，真机部分仍 NOT RUN。

`test_cases.test_req7_send_unit` 以独立字面预期验证 C-19 单个有限 batch 的业务 run、
全部对应五列 Update_History 与一个 SHEET 锚定 DOCUMENT fence；action_digest 非递归，
完整 outcome、NOOP intended digest 和全部附带 settings 审计均绑定到 manifest。
全 NOOP 不制造 History/fence/意图，审计保持 pending；请求对象含 History/fence 不超过
1000，冻结 wire 和 action preimage 各不超过 1 MiB，不静默拆批。
真实 cell encoder → composer → C-6 owner / immutable journal workflow 验证同字节六次意图
和改变字节拒绝，不证明真实发送上界、nonce 权威、全表锁、新鲜准入或 COMPLETE。
31-bit fence 投影可能碰撞，占用时 HOLD 不换 ID；库未安装，真机卡 NOT RUN。
`freeze_prod_source_unit` 另在实际 C-6 owner 内前后重核三类受保护 C-5 来源，
由真实 SourceRow 生成业务字面值和原记录时间；不接受 caller manifest、业务文字或时间覆盖。
真实采集／资格核验 → manifest → 字面 encoder → 冻结 batch workflow 验证三个 family、
原文字 NOOP、组批期间来源漂移及伪造 candidate 的拒绝，保持模板／发布目录不变。
坐标、观察、generation/publication、nonce 和 preread 仍只绑定；不冒充原始预留、
行身份、C-6 receipt、每次新鲜准入、固定 launcher、真实发送上界或 COMPLETE。
批次、意图和原始 NV 预留保留实际 C-6 的 `gen-20位序号-32位小写hex` 身份，
序号必须大于零；不把它改写为任意 64 位摘要。独立候选的摘要身份仍只用于纯组合测试。
实际 local begin/INTENT/commit → composer → durable intent → 冷进程计数 workflow
核原 generation／发布摘要与不变 wire；形状正确或 local receipt 均不是在线资格。
`freeze_receipted_prod_source_unit` 进一步读取原始当前周期 C-6 工作簿 RECEIPT、
共享准入链及全部原始 XLSX；在 owner 和恢复屏障下，manifest 必须与重新核验的
受保护来源逐字节摘要一致，generation／发布摘要不接受 caller 替换。组批前后再次
读取，receipt 序号类型、准入缺失、原文件替换均 HOLD 且不修复原证据。
原始 generation 目录及 STATE／MANIFEST／INTENT／RECEIPT 的 dev/inode/大小前后
必须一致；仅把 RECEIPT 改为同字节的新 inode 也拒绝，不能用重算摘要替代原始物理对象。
真实 producer／资格／工作簿投影／C-6 commit／准入 → 原始 receipt → 三表冻结批次
workflow 不新建 generation、remote intent 或网络调用；仍不是行身份、原始 nonce／
preread／预留、新鲜发送准入、全表 owner、固定 launcher、COMPLETE 或 REQ7 整体通过。

`test_cases.test_req7_send_intent` 将真实 composer → C-6 owner → 非递归
ACTION-PREIMAGE/action_digest → immutable wire journal → 六个冷启动进程的意图计数
串联验证。action 文件和摘要 header 必须先于 wire、wire 必须先于计数持久化；
旧 opaque wire store 不能补建 action 权威，部分 barrier、链接、外来命名空间和位移
拒绝且保留 UNKNOWN。库未安装，无重置、解锁、修复或发送能力；六次意图仍不证明
真实尝试上界、spreadsheet-wide owner、新鲜准入或 COMPLETE，不代表 REQ7 整体完成。
真实断电和在线关联部分见 `TC-REAL-REQ7-COMPILED-SEND-INTENT-001`，状态 NOT RUN。

`test_cases.test_req7_remote_history_match` 串联实际 global intent、持久发送前原像、
原始 target/History nonce、精确 ID/锚点/DOCUMENT 永久 fence，以及全部实际业务和
附带审计 History 行；原始 typed 前缀、容量、行顺序、完整尾和摘要同时匹配才返回
MATCHED_OBSERVATION。整个 matcher 和最终 issued-read 门禁期间持续持有原 global
count/WIRE、History preread、enrollment 目录，并前后核全部原文件的 stat/inode/字节
及命名边。读后加次数、同字节替换文件／目录均 HOLD，保留实际 UNKNOWN，不采用
替代原像。纯 matcher 仍不写 durable COMPLETE，也不是释放 FIFO 的依据。
缺 fence 为 UNKNOWN，外来栅或缺/多/重复/错序/伪造 NOOP
History 为 CONFLICT；缺原像、异常/部分响应、外来目标或重复 metadata HOLD。
25000 个 typed cells 只扫描一次，不按行重复扫描。真实私有 TLS 三个只读请求
验证 planner/transport/decoder → 实际持久 journal → matcher；没有发送、结算、
COMPLETE、APPLIED、新鲜准入或 UNKNOWN 清除。未安装；真机卡 NOT RUN。
固定双 owner 入口另要求原始签发的模板 identity/headers、metadata search 和
History 全尾四份响应；不接收 caller plan/identity/freshness 标志。原形态、
原 30 秒 deadline、双锁与当前固定策略在解析前后均重新核验。真实受监督
私有 TLS → 严格模板解析 → 原 journal 对账覆盖副本伪造、表头漂移、缺审计、
解析后超期和策略撤销；四次只读仍非原子快照，隐藏 metadata 库存仍未证明，
匹配不结算、不清除 UNKNOWN，不授予发送权限。

`record_owned_completion_evidence` 另从实际双 owner 签发的四份原始读取重新匹配，
将 identity/headers/metadata/完整 History RAW 与全部原 journal/nonce/History 原像
stat/inode/SHA 绑定到独立只增不改的 `.completion`。四份 RAW、HEADER、目录与父目录
屏障全部成功，原计数/策略/读取期限仍成立后才写 COMPLETE 标记。十四个前置屏障
逐项中断均保留 partial/HOLD；不补建、不覆盖、不收走 UNKNOWN。冷进程在原 OS owner
下同步并核原文件、HEADER inode、marker/header 摘要与完整 History extent，仅返回
`COMPLETE-PRESENT-NOT-APPLIED` 历史证据观察。它没有消费者可释放全表屏障、预留、
FIFO、高水位或 settings outbox，也不作为真实源准入、在线激活或正式 full proof；
这些 REQ7 集成仍待完成。新增真实 TLS→双锁→文件屏障→冷进程回读联测覆盖缺审计、
复制回应、同字节 HEADER 替换、尾行摘要漂移、计数后变和最终期限失效。
冷读入口持续持有六份 completion 原文件 FD，从解析前至 RAW 语义重放、fsync 与
返回之后核原 stat/inode/字节和命名边；HEADER 的同 inode／同字节改写加上同步
更新的 COMPLETE 也不能被收编为原证据。独立 direct 与实际受监督 TLS→完成落盘→
冷读 workflow 先复现拒绝断言 RED，修复后仍保留 UNKNOWN，不授予 APPLIED 或重发。
原始 WIRE handoff 的入口和每次 live CLAIM 核验还拒绝任何已开始的 completion
目录（含 partial），在创建 dispatch 或启动子进程前停住。存在 COMPLETE 标记时，
原始诊断计数也拒绝新增 ATTEMPT；无效标记只导致 HOLD，不被解释为 APPLIED。
真实固定读→完整落盘→原计数／WIRE claim 联测保留原次数、UNKNOWN 与全部原件。
这些 no-resend 边界不释放全表屏障、FIFO、永久 fence、预留或 outbox。
完成写者还在创建 proof 目录前持久化独立的 spreadsheet `completion-started`
见证（原单元、binding 与原 journal 集合摘要）；file／parent 屏障失败不创建 proof，
固定见证名在首字节写入前以 NOFOLLOW／CLOEXEC／EXCL 建立；short write 或首个
file fsync 失败留下 partial 固定名，不能只留下不被 no-resend 检查识别的临时名。
首写后的原 stat 贯穿 file／parent 屏障及 writer→reader FD 交接；同 inode／同字节
改写或关闭重开前的同字节替换均不能被收编为原启动见证。
见证残留不得采用或重建。目录移走后仍拒绝新计数、WIRE claim、新 journal 和新 proof，
冷进程保留原次数与 UNKNOWN。writer／cold reader 从入口到返回 pin 住见证 FD、
stat、字节与命名边，并核 HEADER 的原见证身份；缺失、改写、别名或替换一律 HOLD。
原 partial-proof 的诊断计数漂移测试仍执行并阻止 COMPLETE；这不是发送权限。
已有无独立见证的历史 proof 不自动迁移或背书。独立 RED、真实固定 TLS→落盘→
目录移位→冷进程，以及原十四个 proof 屏障测试均保留；不代表断电或在线设备验证。
冷读还须从四份原 RAW 重放模板 identity/headers、nonce、永久 fence 和全部
History 语义，并逐项核固定读取路径的原摘要；不能只接受重新自洽的 HEADER/
MATCHED 描述。与 live matcher 共用原 journal/WIRE/前缀对账，但仅构造无凭据的
历史 decoder 输入，不签发新 HTTP 回应、读取期限或远端新鲜性。六个独立篡改
子项在原始 fixture 内同步改 RAW/摘要/stat/marker，仍须 HOLD 且不改变原文件。
真实读取夹具 ERROR 保留原异常与原时限，另只输出读取种类、服务端接收次数/
错误类型和自有子进程退出码；不记录 token、请求头或响应正文，单独复跑通过
不得据此关闭原始联测失败的根因。

`test_cases.test_req7_activity_discovery` 另区分 caller 有限窗口和固定完整容量读：
显式身份/Status 列与 GRID rowCount/columnCount 在同一个 GET 返回；仅容量 3..5002
接受并完整覆盖到实际末行，溢出、缺 grid、错位和部分响应 HOLD，不分页、不截断。
全部原始 A 列 NV ID（含 Closed 和无关活动键）参与最大值观察；两张 Cabling 取各自
完整读的最大值和原始 ID 集合，但本读取器没有分配或持久预留。真实 TLS 全键读 → 精确行矩形 → 字面 L-only
encoder 验证既有线上 ID 不重写；仍不是新鲜准入、CAS、模板权威或发送许可。

`observe_active_row` 从完整容量活动键发现派生唯一活动行，再对精确行矩形逐项
复核全部发现列，包括原始 ID、Status、描述和 Cabling 对侧；位移、Closed、重复键、
部分发现或任一原始 typed 值漂移拒绝，不回退另找行。保留完整 A:U／A:AC 单行
typed 原像，不能把公式、数字、布尔或操作员字段强制转换为业务字面值。
`freeze_observed_receipted_source_updates` 将真实 C5 来源、原始 admitted C6 receipt、
全部业务发现／精确行以及完整 History 原像串联；全部活动更新的坐标和 tool-cell
before-image 直接派生，combined preread 摘要绑定原始读路径与原始响应摘要。
调用方不得覆盖 placements、业务文字或 preread；原像组批前后漂移、History 容量
不足或目标不符 HOLD。三个 family 的真实 producer／资格／工作簿提交／receipt／
行复核／literal encoder／批次 workflow 不创建 remote journal 或发送。
这是未安装的全活动更新编译路径，不是插入／空闲 Switch 行或 Cabling 尾预留、
durable 业务原像 journal、nonce／模板权威、新鲜准入、固定 launcher、COMPLETE，
也不代表 REQ7 整体完成；真机卡保持 NOT RUN。

`prepare_insertion_sheet_read` 与 `observe_insertion_position` 补充插入位置的必要
观察：完整发现无活动键，原始容量及全部共有列在两次读之间一致；Switch 固定读
A/B/C/F/J..U，选择首个 F/B/C/J..U 真正无 userEnteredValue 且不在已知预留集合的
行，然后读取该精确 A:U 行，核原预置 NV10001..NV15000、D/E/G/H 公式及 I 第三行
公式／以后空白。Cabling 固定逐列读取 A..AC，操作员列也参与最后占用行；公式、
显式空字符串、数字 0、布尔 False 均占用，间隙不复用，全部追加行须在原始容量内。
原生只读 TLS → 完整键／占用列／Switch 精确行 → literal updateCells 或 Cabling
appendCells 的多脚本 workflow 不发 mutation，不改 lookup／参考／操作员列。
已知预留集合不是原始 journal 权威，观察的容量／坐标不是 CAS 或新鲜发送许可；
仍缺持久原像／预留与真实来源组批、发送和 COMPLETE 集成，不代表 REQ7 整体完成。

`freeze_observed_receipted_switch_unit` 将真实 C5 来源、原始 admitted C6 receipt、
实际 C6 owner 和 spreadsheet owner、原始十四表 enrollment 联到 Switch 单元。
target／History sheetId 与 nonce 来自原始 journal，不接受 caller 覆盖；存在任何
同一 spreadsheet 的未决 journal／预留／原像命名空间时拒绝新组批，不能借新代重建
UNKNOWN。所有操作必须共用原始完整发现／占用像，逐项派生更新或新增，新增在单元内
选择不同预置空闲行；全部值和原记录时间来自真实 SourceRow，编译后再核来源、
receipt、nonce、原读像及 History 容量。真实 producer → 资格 → workbook commit →
双 owner／原 nonce → 混合 L-only 更新和 literal 新增 workflow 不写远端。
局部 root 元数据仅在 ownership 模块的测试 OS 边界合成，其他 C6／来源模块保持
实际路径和 UID；native flock／FD／fsync 不替换，真机仍 NOT RUN。
单元内候选行分配尚不是 durable 原始预留；组合原像 journal、
每次远端模板／enrollment 连续性、新鲜准入、受审发送与 COMPLETE 仍未闭合。

`freeze_observed_receipted_cabling_unit` 将实际 C5／admitted C6 receipt、双 owner、
原始十四表 enrollment 与 C17 两表 NV journal 串联，完整家族不得拆选。
共享原始键／全部 A..AC 占用像决定 active 更新或 missing／Closed 新增；
全部新增键恰好匹配当前原始 generation／publication 的持久 NV 预留，
目标发现像 SHA 必须等于 NV journal 保留的 ETH／IB 原始列像 SHA。
既有 ID 不写，新行以 literal appendCells 追加在所有操作者／工具占用后，
全部新增行一起核原始容量，禁止复用中间空隙或 caller ID／坐标／nonce。
真实两家族来源每家族两个独立活动键 → 原始工作簿 receipt → 双 owner／
两表最高 NV39999 → 单元内更新＋NV40000 新增 workflow，不创建网络发送或
新 NV journal。既有原始 reservation 和任何 UNKNOWN 全局 journal 均保留；
后者拒绝 NEW 组批。组批中途原像漂移、原 NV 被篡改、容量不足均 HOLD。
本入口不证明业务 preread durable journal／行预留、每次新鲜准入、CAS、
受审 launcher 或 COMPLETE，不代表整个 REQ7 完成；真机仍 NOT RUN。

`test_cases.test_req7_nv_reservation` 将两张 Cabling 固定完整容量读取、原始 enrollment、
实际 spreadsheet owner 和 C17 共享分配器串联，Closed／无关行 ID 参与最高值，
下一 ID 严格高于两表；没有种子、跨表重复或编号耗尽时拒绝且不创建图像。
ETH/IB RAW、原绑定和预留记录的十个图像屏障完成后才写 INITIALIZED；冷进程
重新解码原像并保持同一编号，UNKNOWN 后不换号，既有全局 journal 阻止新预留。
这是未安装的单个 pending 单元保守预留，不是完整跨单元结算、行容量／metadata
预留、新鲜准入、来源鉴别、COMPLETE 或发送许可；真机卡 NOT RUN。
实际冻结 batch 的每个新增 Cabling 行须与原始 key/NV 集合逐项一致，并重新经
literal encoder 校验；混合 update 不触碰既有 A。缺项、换号、别的 generation／publish、
外来业务键或 nonce HOLD；global journal 存在后还须匹配原 action/wire，不能用相同
编号重建不同 UNKNOWN 请求。三者同时匹配仍不是发送能力或 COMPLETE。

原始 enrollment journal 的 sheet ID 必须保持 native int；即使 NONCES／HEADER／
INITIALIZED 被一致重哈希，bool 或浮点数的 Python 相等别名仍 HOLD，不自动修复。
`test_cases.test_req7_enrollment_journal` 保留原始数字 ID 合同及篡改证据。
global／enrollment／History 夹具的 canonical sys.modules 与父包别名同步，
避免改变执行顺序后从旧包别名取得已撤销 owner 的 token registry；生产检查不放宽。

`test_cases.test_req7_metadata_reservation` 串联固定真实私有 TLS metadata 读取、
原始双 enrollment、实际全表 owner 与真实冻结 global action/wire，首个意图前
持久预留该 batch 的永久 fence（不是调用方配额）。METADATA-RAW／HEADER／
RESERVATION 的八个图像屏障完成后才能 INITIALIZED；冷进程及 UNKNOWN 保留
原预算、原 fence，不重分配／采用已有 fence／回填部分图像。容量溢出、链接、
重哈希替换 fence 或原绑定漂移 HOLD；token 不落盘。独立 spreadsheet／sheet
字符池保留全部可见使用量，但其他 Cloud PROJECT 不可见，仍是
VISIBLE_ONLY_UNPROVED，不是新鲜准入、COMPLETE、结算或发送许可；真机 NOT RUN。

`test_cases.test_req7_history_preread_journal` 在实际 spreadsheet owner 与已初始化
且计数为 0 的全局 action/wire journal 内保存原始全尾响应、容量与
`history_last_row_before_send`。RAW/HEADER 的六个图像屏障后才能写 marker；
部分创建不可补建，首次意图后不能创建或替换。实际冷进程重新读取并解码原像，
原始目标、策略、白名单、unit/action/wire 必须保持绑定；连带重哈希的外来目标
也拒绝。这不是远端来源鉴别、新鲜准入、网络许可或 COMPLETE；完整业务、审计、
nonce/fence 对账和受审 launcher 仍需集成，未安装且真机卡 NOT RUN。
原始 History 容量与冻结 wire 共同确定全部实际业务及 ALL 审计的行预留；
NOOP 不产生虚构行。typed 空字符串／false 和 gap 的最后占用行均参与尾边界，
精确余量为 0 可接受，溢出 HOLD。metadata fence 预留前必须先校验这一原始
行预算并把原 History 摘要／预留窗口绑定入 header；UNKNOWN 和冷进程保持
同一窗口，无 caller 计数器／新尾替换／额外分配，仍不是当前鲜度、CAS 或许可。

`prepare_business_preread` 在同一实际全表 owner、计数 0 的 global journal、
原始 enrollment 与 History 原像内，保存完整家族 manifest 和全部业务读像，
包括 NOOP 操作的完整键／占用／精确行。共享原件按路径和完整字节去重，
不保存认证 headers；逐回应保持 2 MiB，整个独立 envelope 上限 16 MiB，
不扩大 wire／manifest 的 1 MiB 界限、不截断或分批。
八个原件 file／dir 屏障之后才写 marker，partial 永不采用／回填。
冷进程重解码原件，核实际原始 nonce／NV、坐标、C8 literal 重编码、
NOOP typed 意图、组合 preread SHA 与冻结 action／wire；UNKNOWN 不重读当前
源来重组旧批次。最终 marker 屏障内的原件改写或同字节新 inode 替换亦 HOLD。
真实 C5／C6 receipt → 双 owner／双表 NV → 混合 Cabling 组批 → 原件 journal →
UNKNOWN 联测保持原始预留，不发送网络；只有必要原件观察，不证明 fresh
admission、per-key FIFO settlement、受审 launcher、COMPLETE 或整个 REQ7。
真机仍 NOT RUN。

`record_owned_receipted_attempt_intent` 在原始 C5/C6 计数前后核对实际固定读取器
签发的模板 identity、四表 headers、W1 六列与 metadata；W1 sheet ID 必须等于
十四表 identity 中的 Whitelist，规则须等于冻结本地快照，不重新筛选业务。
双 enrollment 必须保持原 nonce，已有 fence 或可见容量溢出拒绝新计数。
原始 metadata 预留绑定原始 identity 响应字节摘要，不能用重新序列化的图像替代。
复制的 completion 不具来源权威；计数后原 30 秒期限到期仍保留 UNKNOWN 和原计数，
不能回滚。真实双 owner／固定私有 TLS → 原始 receipt／来源／预留 → C6 流程
检验此边界；可见库存仍 VISIBLE_ONLY_UNPROVED，不是隐藏 PROJECT 配额、新鲜业务／
History 连续性、共享节流、真实 mutation、COMPLETE 或整个 REQ7 验收。

`observe_owned_business_continuity` 用当前双 owner 签发的固定 identity、全 History、
完整发现／占用／精确行读取逐项比较持久化原件，包含全部 NOOP 和操作者列。
只忽略 JSON 序列化差异，保留类型、全响应、容量和尾边界；漏项、重排、复制回应、
编辑或原文件同字节新 inode 均 HOLD。坐标从原件固定请求派生，不接受 caller plan／row。
前后重核原文件身份、全局计数、策略和原 30 秒期限，不重组 UNKNOWN 或缩小 batch。
`record_continuous_owned_attempt_intent` 将此门放在真实 W1/template/nonces 和原 C5/C6
计数前后；后置失败保留已落盘的 UNKNOWN／计数。真实双家族原始来源和原生固定 TLS
workflow 验证边界，仍不是共享 cadence、隐藏 PROJECT 库存或一次性发送／COMPLETE 权威。

`prepare_mutation_request` 只从完整且自洽的原 C19 单元派生固定 batchUpdate POST，
不接受 URL／body／预算覆盖；原 1 MiB／1000 requests（含 History/fence）限额保持。
未安装 `NativeSheetsMutationUnit` 原型在创建连接前重核形态和 token 期限，每对象
最多单次原生请求；完整同连接响应仅供 rejection 语法观察，200／redirect／401／
quota／server error 都不证明 APPLIED，framing 缺失或冲突拒绝。读取和鉴权的原
HTTP 200 合同不变。`test_req7_native_tls_wire` 对拥有的隔离 TLS 服务验证这些边界，
不是受监督总 60 秒、持久单次消费、共享 cadence／隐藏配额或在线 GO 的证明。
轻量 mutation 类型位于纯 stdlib read planner；原 token/read 的固定隔离子进程
不得因此导入 composer 的 YAML/workbook 图。独立 `-I` 负例和原 native 读取／监督
workflow 覆盖此依赖隔离合同，不添加 ambient fallback 或放宽原超时。
拥有的 loopback TLS 夹具先用连接 readiness／独立 scope-cancel socket 同步，再执行
原 3 秒 accept／握手／正文时限；子进程启动／导入／本地检查仍属于原生产 TOTAL，
不能提前耗尽 fake server 的 transport 时限。独立延迟启动、空闲取消、已连接但不握手
负例及实际固定读取子进程覆盖此夹具边界；原 30／60 秒监督器和所有断言未放宽。
这修正已复现的夹具时序缺陷，不证明过去没有启动阶段原证据的超时根因已经闭合。
G1 认证联测的合成 root facade 只补丁当前 canonical SDK 模块，不采用重载后残留
的包属性；独立 stale-parent 负例和原顺序认证→项目读取 workflow 验证这一隔离边界。
SDK 的 canonical 测试重载同时保持 `sys.modules` 与父包属性指向同一新模块；独立
重复重载测试核两种合法 import 形式逐次一致，不能让旧 root facade／类型残留。
生产 root-only／原凭据／原 token 来源校验及相关拒绝断言保持不变。

History、两张 Cabling 与 metadata 的原始 RAW 持久化统一使用固定名称的
2 MiB 有界图像写入器，原字节全部保留、不截断；超限在创建 store 前拒绝。
短写继续完整落盘，无进度／file-dir barrier 失败保留 partial HOLD；NOREPLACE
不覆盖旧图像。此独立读取界限不扩大 1 MiB wire／manifest 合同，未知文件名拒绝。

`test_cases.test_req7_history_read` 验证固定 `Update_History` A:E 有界矩形
（最多 5000 行、2 MiB 响应）的 planner → 实际自有 loopback TLS → typed decoder；
仅在明确返回的同一 grid 内补空单元格，保留 formula/number/bool/string 的区别和
原字面值。拒绝错位、缺 grid、重复、额外列、非 200 和部分响应，不重发、不静默
截断或分页。新增固定 `A3:E5002` 全尾形态在同一个 GET 获取 `GRID` 类型、
`rowCount` 容量和所有 A:E 原始单元格；超过 5002 行容量拒绝，不能接受截断尾。
`last_data_row_index` 为零基实际最后占用行，完整显式空 grid 为表头边界 1；
False、0、公式与显式空字符串也算占用。它不是事务快照、新鲜准入、缺行/重复行
单元对账或 COMPLETE，不授予发送能力；nonce、fence、不可变 journal 与完整
业务及审计集合仍须另证。真实 TLS 部分响应/溢出不重发，真机卡 NOT RUN。

`test_cases.test_req7_spreadsheet_owner` 验证未安装的跨项目 spreadsheet-wide
非阻塞 OS owner：固定 root-only `/var/lib/http-ztp-container/issue-tracker`
目录必须另行授权预置，目录与锁使用 held-FD/name identity，无 UID／路径／过期覆盖。
按完整 spreadsheet ID 摘要取持久空锁，同 ID 的不同项目／policy 竞争；不同 ID 隔离。
退出先撤销 token，仅关闭 FD，不 `LOCK_UN`／不删除，原生独立进程和继承子进程
实证剩余持有者继续互斥，实际 C-6／action journal 流程不改变 UNKNOWN。
它不授予发送许可，不证明跨主机、真实 root/container、全局 UNKNOWN/FIFO、durable
reservation 或受审 launcher 的实际尝试边界，也不代表 REQ7 整体完成。真机卡 NOT RUN。

`test_cases.test_req7_global_attempt_journal` 在实际 spreadsheet-wide owner
内验证共享持久 action/wire/原绑定、八个初始化 fsync 屏障及六次链式 UNKNOWN
意图。只有全部八个原像屏障完成后才写 INITIALIZED 及其两个持久屏障；计数前
持有 FD 重核并同步原 marker，缺失不补建，不能从完整外观的 HEADER 推断完成。
已有 journal 保守阻断同 spreadsheet 的所有新 generation/publish/sheet；
原像、计数、链接／名字位移或原策略白名单变化均 HOLD，不补建或重置。六个真实
冷启动进程共用计数，实际 C-6/action journal 流程保留 UNKNOWN。冷启动夹具继承
runner 的依赖环境，不冒称 `-I` 隔离传输；六次意图不是六次真实尝试，两个本地
记录也不是跨 store 原子发送。`record_reserved_attempt_intent` 在计数前及计数后
重开并核对同一原 enrollment、History 行预算、实际永久 fence quota，Cabling 新增还
必须匹配 BOTH 原始列的 NV 预留；缺失／漂移／链接或屏障错误 HOLD。前置失败不计数，
后置失败保留已计 UNKNOWN，不回退或补建。原计数 primitive 仅记录证据，不授予发送。
六个真实冷启动进程及实际 TLS 原读取链验证同一预留不会被重分配；这仍不是新鲜
准入、隐藏 PROJECT 全配额、行连续性、FIFO 或真实 M=6 发送证明。未安装库无
COMPLETE／清理／联网能力，受保护准入、单次 capability 和固定 launcher 仍须接入；
REQ7 整体未完成，真机 NOT RUN。

原持久 WIRE 的私有 `_hold_counted_original_wire` 交接在实际项目／spreadsheet
双 owner 内，先同步原初始化证据，再写独立 NOREPLACE/fsync 的链式 CLAIM，
然后才借出原只读 CLOEXEC FD。重复领取、冷进程复用、缺失旧 CLAIM 前缀和
部分初始化均 HOLD，不重建原像或回退次数。领取失败及后置漂移保留消费后的
UNKNOWN；元数据漂移拒绝但关闭仍属原 inode 的 FD，被违反借用后重用的外来
FD 不关闭。真实冷进程、失败注入及原像逐字节不变覆盖实际多脚本流程。
隔离子进程只核 ACTION/WIRE 一致性，不导入父侧 YAML/workbook 编译依赖。
这些仍是必要交接证据，不是新鲜准入、共享 cadence、隐藏 quota 或 M=6 发送证明。

连续首次计数至固定启动的私有边界持续持有原 worker/config/W1、C6、审计和配额，
签发读取期限在计数、实际消费、最终 pre-Popen、发送后和退出时仍按原规则核验。
仅在实际 worker gate 与完整 records/witness 原 FD、名字、stat（含 ctime）和字节
全部保持不变的作用域内复用一次周期语义解析；每次读取仍复核所有原件，退出即撤销。
其余来源、归档与准入语义仍由原校验器执行，不接受调用者快照／verifier／GO 标志。
资格判定对自己刚完成读取的 HOLD 来源使用内部候选投影，避免同一边界嵌套第三次
完整来源读取；公开预览仍重读调用者来源，资格返回前仍完整重读三域来源、IB 与
周期链。内部投影仅产生 HOLD 诊断值，不是缓存的来源证明或写入许可；Switch W1
matched-rule 输入仍重开比较。独立 literal direct、首尾两次真实来源读取 workflow
和末端 W1 漂移拒绝保留原期限，正常固定发送及收据／读取漂移负例仍须执行。
首次计数执行一次原 `_observe`，前后完整来源核验不变；计数后的来源换 inode 或
原读取过期必须零 child／请求并保留 count=1、UNKNOWN 和已消费 CLAIM。
独立 direct 与真实 worker→C6→原读取→计数→固定 TLS child workflow 不代表整项
REQ7、默认在线 worker、共享重试、隐藏配额、FIFO 或 COMPLETE 已完成。

交接同时借出原 ACTION-PREIMAGE FD。`NativeOriginalSheetsMutationUnit` 对两个
原只读、私有、单链接、受限 regular FD 各 pread 一次，检查前后精确身份，
从原 ACTION/WIRE 恢复一致性投影，不重编译源文件、不重开路径；失败和元数据
变化消费一次对象，不重发。真实 `-I` 子进程多脚本 fixture 继承双锁和这两个 FD，
以固定 TLS 发出 >64 KiB 的完整批次，不扩大 32 KiB 私有控制输入；401 不刷新，
真实慢 body 在原 60 秒 TOTAL 边界终止，原次数保持 UNKNOWN、父侧双锁保持。
程序/DNS/CA 重定向仅存在 test-owned fixture，尚不能冒充生产固定 launcher、
shared cadence 或新鲜发送准入闭合；REQ7 整体仍未完成，现场 NOT RUN。

`test_cases.test_req7_mutation_launcher` 验证未安装的私有固定启动器：只有实际
双 owner 下原 CLAIM context 发出的当前对象可消费，dataclass 复制、context
失效、重复调用及启动失败不能再 Popen。固定 `-I -B` 子进程／cwd／剥离环境，
凭据只用 ≤32 KiB 私有 stdin；原 ACTION/WIRE 与两把锁按 FD 继承，不允许
URL／程序／CA／body／PID／budget 覆盖。完整响应须精确关联 nonce、原次数和
wire digest；未知、超时或 401/503 不刷新、不重发、不清 UNKNOWN。
原 60 秒 TOTAL 包含启动、输入、DNS/TLS/body 和终止；未确证终止显式 HOLD。
真实自有 TLS 流程覆盖单次领取、六个原次数最多六个同字节请求及慢 body 终止。
这个库仍未接在线 worker，新鲜 protected source/continuity、shared cadence、
G1 隐藏 quota、older-cycle R2、FIFO 和 COMPLETE 仍须整链集成；不是功能 GO。

`test_req7_shared_retry_admission` 验证 C23 的必要共享重试屏障：实际原 C6、
项目／spreadsheet 双 owner、原单元持久次数与 automatic/manual/retry 共用
collector interval-floor alias。INTENT 先落盘，原次数只增加一次后配对 COUNT；
任一中断保留 orphan 并阻断所有 lane，不重置次数、不回填。记录实际准入时刻，
不同 boot 或不可核验 interval HOLD；读取固定原目录及文件 stat/inode/字节，
相同内容的替换目录不采用。重试推进共享时间／周期锚点但不创建新的 C6，
不把旧收据算作当前周期新发布，也不绕过 automatic 的 N 个新周期要求。
新增真实 protected Stage-L 流程在前后核当前 C5/C6 原件与 issued ALL business /
History、W1/template/nonces，只在屏障内增加一个原次数。该接口仍限定 current-C6；
固定 launcher 整链、G1 隐藏配额、older-cycle R2、FIFO、COMPLETE 未由此闭合。
真机卡 `TC-REAL-REQ7-SHARED-RETRY-ADMISSION-001` 为 NOT RUN，不是在线 GO。

私有 `_hold_shared_retry_owned_attempt_wire` 现在把实际共享准入与原计数贯穿
固定 mutation launcher：计数前持有 worker 周期／config／W1／audit／quota 原件；
原 retry INTENT/COUNT 配对完成后持有其新完整原 namespace，不能把合法新增
误判为普通只读 admission 漂移，也不能采用替换件。consume、pre-Popen、
post-send 与退出范围保留实际 issued ALL-business/History 的原 30 秒期限，
不延长或刷新权限。真实 C5/C6→只读→双 owner→两次同字节 TLS 请求场景，
原收据同字节换出及读取过期均在第二次 Popen 前拒绝，保留 count=2、UNKNOWN、
原 WIRE、配额和共享 retry 配对证据；对象不可重复消费。这仍是未安装的必要
发送边界，不是 default online worker、hidden G1、COMPLETE/FIFO 或整体 REQ7
闭合，也不将本地 TLS fixture 冒称真机验收或正式 full proof。

`record_original_business_reserved_attempt_intent` 进一步在每次计数前后重开整个
原始业务 journal（完整家族 manifest、全部发现／占用／精确行，含 NOOP），
与原 enrollment、History 行预算、metadata 及适用 BOTH Cabling NV 一同核对。
原件缺失／漂移在前置 HOLD 时不新增计数；后置失败保留计数及 UNKNOWN，
不回退、不补建或重新编译。六个独立冷进程保持同一原件，第七次不能计数；
真实 C5/C6 Cabling 混合组批联测贯穿完整原链。
这仍仅是必要的持久意图，不是 fresh admission、隐藏 PROJECT 配额证明、
FIFO settlement、实际 M=6 发送上限、发送许可或 COMPLETE；真机 NOT RUN。

`record_receipted_original_attempt_intent` 在双 owner 下，进一步于每次计数前后
通过实际 recovery／共享 admission／受保护 C5 重放重开原始 C6 四件，并把
generation／published SHA／manifest ID 与原 ACTION 精确绑定。伪造 receipt、
未持有 LK-P、源／模板漂移、任一原件损坏前置不计数；后置失败保留 UNKNOWN。
原件不补建，不重新编译 wire。真实 ETH／IB 混合组批执行六次计数与第七次拒绝，
含计数后 receipt 漂移。本接口保守限定 current-cycle，不证明旧周期 R2、fresh
config／W1／cadence、固定 launcher、真实发送、FIFO 或 COMPLETE；REQ7 整体
仍未完成，真机 NOT RUN。
普通受保护计数还持续持有 admission、generation 四件、原发布 XLSX 和
settings/events/outbox/current 的原目录／文件 FD 至最后复核；同字节替换
原 admission 不能因前后内容相同被采用。前置原件缺失零计数，计数后替换
仍保留已计 UNKNOWN、两份证据和原配额，不修复或回滚。此只读 namespace
guard 不用于会新增 INTENT/COUNT 的共享 retry，后者仍走既有专用事务；
这里没有授予历史 R2、settlement 或发送能力。

原配额计数（普通、原业务以及受保护 C6）还在整个持久计数范围内持有
quota 原目录和四件原文件 FD，并在计数前后及退出范围时复核身份。
同字节替换目录或 HEADER 也必须 HOLD；计数后发现替换保留原次数、UNKNOWN
及两份原像，不采用替换件、不回退或重建。这是原 reservation 的必要连续性，
不证明历史排他、完整 G1 库存、发送许可或 COMPLETE。

共享 retry 同样持有原配额目录／四件 FD，但继续使用其专用 INTENT/COUNT
事务，不套用会拒绝新增 retry 记录的普通 admission guard。持久次数增加后
原配额身份丢失必须在配对 retry COUNT 前 HOLD；保留未配对 INTENT、次数、
UNKNOWN、C6、业务、C25 和 outbox 原像，不以补建配对或回滚来清除故障。

配额冷进程联测保留原 argv、5 秒预算和六次 UNKNOWN／第七次拒绝断言。
原生子进程记录 fixture import/setup、source load、owner、count 和 cleanup
阶段，父进程超时保留原 TimeoutExpired 与完整 partial stdout/stderr；
测试夹具在异常路径也执行 finally 清理。这些仅为本地诊断与隔离证据，
不延长预算、不自动重试，也不把诊断复跑 PASS 作为原超时根因闭合。

`inspect_business_source_projection` 把完整原件中每一项 wire 和 NOOP 的 C8 工具列
与重放源行派生的值比较，并核发送项的原 UTC 时间。调用方 typed 行本身不提供
来源权威；上述双 owner 计数接口只能从实际 `qualify_prod_stage_l` 重放结果派生行，
不得以哈希自洽的业务原件替代真实 C5 值。源行必须逐键覆盖原 manifest 全部操作，
缺失、重复、NOOP 值／发送值／发送时间漂移均 HOLD，不修改原件或重新组批。
独立 Switch 正向／篡改测试及真实 ETH／IB 原始 C5/C6 多脚本流程覆盖这一边界；
本接口仍仅返回必要观察，无发送许可、COMPLETE 或整项验收能力。

`inspect_project_online_target` 在实际 ACTIVE 项目 owner 下，通过 held 项目 FD
单次有界读取当前 `01-global.yaml`，调用严格 YAML／策略校验，再消费固定
root-only allowlist FD 读取器。非 root、伪造或已撤销 owner、缺少旧精确 binding、
不安全文件、短读、读中替换／改写、disabled／撤销／目标或 N 变化都 HOLD，
不读取凭据、不接受路径或 caller document 覆盖。C6 计数接口在原链核验前后使用
此观察，撤销前置不计数，后置错误保留已计 UNKNOWN。真实 ETH／IB 原链与
独立项目 owner／固定读取器 workflow 核这些边界；native root/RO-bind 仍 NOT RUN。
这不替代实时远端 W1／template／nonce 连续性、cadence、固定单次 launcher
或真实发送证明，REQ7 整体仍未完成。

`read_local_receipt_history` 在实际 ACTIVE 项目 owner 下读取完整已准入 C6
历史，包括最新周期之后仍保留的旧周期原 RECEIPT；不把旧回执累计到当前
周期 published。全程持有 admission、generations 四件、原发布 XLSX 与 K
events/outbox/current 的目录／文件 FD，复核完整 stat、身份及字节；调用真实
共享链、受保护周期窗口与原 generation recovery。相同内容的文件／目录替换、
未持锁、未终结回执、当前周期缺 C5 重放均 HOLD；不补写、修复或重新生成原件。
返回 `RECEIPT-HISTORY-PRESENT-NOT-ELIGIBILITY`，只是历史原件观察，不是
旧周期 R2 的来源重新资格化、fresh admission、实际发送、FIFO 或 COMPLETE。
原 current-cycle reader 合同不变；真实 worker/emitter→C5/C6 多脚本联测
覆盖旧回执仍可观察、当前计数为零及所有原件／名字替换。REQ7 整体仍未完成，
现场卡 `TC-REAL-REQ7-PER-KEY-STATUS-001` 保持 NOT RUN。

`replay_original_receipted_prod_source` 只对真实已准入旧 C6 重新资格化其原
连续 K 窗口：截止周期来自实际 admission/MANIFEST，K/W1 必须仍与当前合同
相符；调用方不能提供 cutoff、历史快照或重建原件。全程持有所有 C6/准入/K
原件及当前完整 worker 链、策略/W1 的 FD、stat、字节和名字；记录目录必须
先持有原 FD 再首次读取名字，同字节文件或目录替换也 HOLD。私有只读视图只在
native 三面板 C5 回放期间有效，返回前撤销，当前
receipt 计数和共享链始终用完整真实 store，不把旧回执计入最新周期。
当实际完整 worker 原件 scope 已持有时，这个私有窗口只做一次完整语义解析，
并逐项对照真实当前链中由原 C6 定位的前缀。native 内部每次查读仍核完整当前
链的原 FD、名字、stat/ctime、字节、owner 和 gate；不是仅核历史前缀或缓存 IB
归档／资格结果。原完整 scope 不在时仍逐次原生解析，调用者不能提供视图、
cutoff 或 verifier；native 调用退出后立即恢复完整当前链，再核 history/recovery。
独立 workflow 要求每个实际旧 C6 私有窗口恰好一次语义解析，并保留新周期后
第二次实际原 WIRE 请求、原读取期限以及所有漂移拒绝预期。
返回仅为 intent，不创建 generation/RECEIPT、不计 retry、不发 mutation，不证明
R2 新鲜准入、M=6、FIFO/APPLIED/COMPLETE、默认线上 worker 或 REQ7 整体完成。

原 UNKNOWN 的 shared retry 现在回放实际已准入 C6 的原窗口，而不是把它当作
当前周期的新编译资格；新单元编译仍限定当前周期。原 ACTION/WIRE、计数和 C6
不重建。worker 全链／高水位、策略和 W1 输入先以原 FD/stat/字节固定，覆盖
计数及 COUNT 配对；INTENT 已落盘后才固定 C6/准入原件命名空间，计数后漂移
必须在 COUNT 前拒绝并保留 UNKNOWN、计数及 orphan，不回滚或回填。
历史 native 回放的完整输入／K 校验保留在同步回放的前后边界，内部每次 record
访问仍核 ACTIVE owner、实际 collection gate 和原窗口边界。原件 FD 始终持有，
ACTIVE owner 的项目祖先只在实际活跃原目录 scope 内借用持续持有的 FD，
每次仍重核原祖先名字／身份、项目、publication、私有 tracker root 和 LOCK
的权限与身份；借用 FD 独立关闭。不得缓存 owner 校验结果，也不放宽读取期限。
独立 direct 覆盖重复访问、原父目录替换后保留同项目 inode 仍拒绝，以及 LOCK
权限变更仍拒绝；真实 freeze→INTENT→commit→冷读取覆盖原发布字节与非 GO 状态。
三域组成检查在 ETH 观察前后各重新读取一个真实 Switch/IB 分支，不再在每个
分支内部递归执行另一套完整的双分支检查；独立 Switch/IB 检查入口仍重新读取
两次。每个分支均重新验证原 worker、IB 报告、K/W1、owner 与 gate，资格判断
仍保留完整开始／最终三域复核，不缓存来源或资格结果。独立 direct 固定实际
观察顺序与各域漂移 HOLD；真实受保护 IB＋worker/emitter 三域 workflow 验证
前后读取及 ETH 首次读取后 W1 变动拒绝。局部通过不替代原 native 重试、全量或
REQ7 整体验收，原读取期限不变。
同字节替换或换回由原 stat/ctime 校验拒绝；不放宽实际签发读取的原 30 秒期限。
独立新周期后的原单元重试、计数后同字节 C6 替换、窗口内策略换回测试覆盖这些
本地边界；仍不代表隐藏 PROJECT G1、真实发送上界、FIFO/COMPLETE、正式 full
证明或整个 REQ7 完成。真机／断电范围见对应 REAL_ENV 卡并保持 NOT RUN。
独立 direct 与真实 K=2 C5/C6→新周期→原来源回放 workflow 保留这些边界，
真机、断电和真实 Cloud 仍 NOT RUN；不得以本地 PASS 替代当前精确树 full/check。
普通原 C6 计数入口继续限定 current-cycle，旧周期原件只由 shared retry 的
专用路径重放，不扩大普通计数合同。完整 worker records 目录还固定原始完整
stat（含 ctime）；目录换出再换回，即使原 inode、文件及字节全部恢复也 HOLD。
独立 direct 和实际 native 窗口流程覆盖该恢复式替换；不修改计数、期限或断言。

手动单面板旧 C6 的 native 重放保留完整三面板来源摘要与资格集合；只有原
MANIFEST 的 W1 决策和评估标签按原选定面板比较，未选面板必须精确为未评估，
不能伪报无跳过。来源摘要漂移、遗漏、错面板、额外字段、布尔 K 或标签冲突均
HOLD。独立 direct 覆盖三面板投影和拒绝预期；真实 worker/emitter→手动 Switch
C6→新周期→原窗口重放验证 full 来源集合不被裁剪、原周期 published=1 而
新周期 published=0、原件及状态不改写。此比较不创建收据、计数、准入或许可，
不证明 M=6/真实发送/FIFO/COMPLETE、历史全量失败根因闭合或整个 REQ7 完成。

原次数启动交接还须持有 HEADER、INITIALIZED 和完整 ATTEMPT 前缀的只读
原 FD，并固定 journal 与已持久化 dispatch 目录的完整 stat（含 ctime），持续到启动前及发送后检查。
固定动作、WIRE 和前缀必须先固定原 FD/身份，再首次解释计数；解释完成至
固定之间的同字节换 inode 或原 inode 写后恢复也不能被收养为有效启动像。
每次语义计数/CLAIM 重放的前后都须重核已持有的完整原件身份；最后一次
启动前重放返回时发生的原 inode 字节/mtime 恢复也必须在 Popen 前拒绝，
不能等实际请求发出后才以退出检查发现漂移。
同字节替换、原 inode 写后恢复字节/mtime、目录换出再换回均 HOLD；启动前
必须零 Popen/零请求，发送后发现漂移保留 UNKNOWN、原计数和 consumed CLAIM，
并准确保留已确证的子进程终止结果，不创建第二次或修复原件。独立 direct 和
真实原生 TLS/固定子进程 workflow 保留原 60 秒预算及 M=6 测试；这只是
原件交接安全切片，不是完整准入、G1、FIFO/APPLIED/COMPLETE 或 REQ7 完成证明。

首次连续原件计数的私有交接须把真实 worker/config/W1、C6 收据、审计和配额
原 FD 持有到固定启动器的 pre-Popen、发送后和 context 退出；实际发行读取的
原期限也在这些边界重核。计数后同字节收据替换或读取过期必须零子进程/请求，
保留 count=1、UNKNOWN 和 consumed CLAIM。已有 UNKNOWN 不得借首次入口
绕过共享重试节奏；该入口不接收调用者 verifier 或 GO 标志，也不启用默认
在线 worker，不证明隐藏 PROJECT 库存/G1、FIFO/APPLIED/COMPLETE。
