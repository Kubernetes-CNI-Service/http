# Test Case 案例库

`test_cases/` 是仓库唯一的测试案例目录。这里集中保存全部自动化回归、案例模板和必须在
真实环境执行的验收案例；测试文件不得散落到其他源码目录，也不提供旧 `tests/` 别名，避免
同一个案例被 discovery 重复加载。

本目录中的自动化测试不连接设备、不修改项目运行数据，重点检查跨目录接口，而不是替代
真实交换机、Docker 或端到端部署测试。

`test_project_image_owned_guard.py` 独立约束项目镜像测试夹具的固定解释器、两个借用原始 FD
及真实 snapshot context 来源。原项目镜像正常/重试 workflow 使用真实 shared/upload installer，
但其 guard 子进程仅消费本次私有目录中的 state/proc；不读取宿主服务状态、不扫描真实 PID，
也不调用 Docker。成功要求原 guard 的真实返回、一次原始 waitpid 见证及无救援的收尾；
目录0755前提显式设置，不依赖启动者的 umask。此夹具不是文件系统沙箱，也不把本机流程
通过当作 Docker/设备验收；现场仍见 `TC-REAL-BUNDLE-PROJECT-001`。

备份命令的固定辅助脚本由 `test_backup_bounded_process.py` 的独立 direct、
`test_backup_bounded_protocol.py` 的原状态/期限/中断合同，以及
`test_backup_bounded_process_workflow.py` 的真实三脚本私有 FD alias census 共同覆盖。
`test_backup_bounded_delivery.py` 固定两辅助脚本的逐字节复制，原 auth workflow 另验证真实
worker 到 collector 路径；文件复制或 isolated 候选通过不等于该业务流程或 full/check 通过。
外层测试调用可使用正式 runner 的 `-B`，内层 launcher 与 Python 测试命令仍保留固定 `-I -B`、私有 FD、
原环境与返回码断言。现场限制及未验证范围见 `TC-REAL-BACKUP-BOUNDED-ANCHOR-001`，仍 NOT RUN。

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

REQ7 联测的夹具必须保留当前原生 context 的完整可 seek 字节，阶段 trace 只能追加见证，
不能重建过期的 pipe 图像。quota/count 边界夹具显式持有并复核 cycle 原始来源，
真实跨脚本 workflow 继续验证原始收据、计数和 UNKNOWN，不以夹具替代生产恢复能力。
W-1 的跨库 mutation summary 按导入来源区分原生 `os.close` 与同名写入函数；
namespace 重绑定、嵌套 import/global、属性写入和未知回调逃逸仍拒绝，不能按 basename
豁免真实写者。私有 FD 生命周期、真实两脚本 replace、失败安全与冷读取有独立见证。
合成 token/无效 PEM 的测试输入和预期字节不变，仅采用明确的合成构造；公开审计
同时检查工作树及实际 Git index，不增加凭据例外。四个固定 launcher/audit 内部库在
生成手册中仍为未安装、未启用、无独立 CLI、不授予执行权威。
这些修复只闭合相应联测机制，不代表 REQ7、H 或同树正式 full 整体通过。

REQ7 catalog 的项目来源 STARTED／ORIGIN／WITNESS 由真实 C6 writer 首写并绑定原始
project／tracker／publication／LOCK；跨项目冷读取在 flock 前核原 dev/ino，一次性非阻塞
取得原 owner，任一缺失、替换或锁忙都拒绝全部前缀。实际多脚本测试持续持有全部 C6 与
已计数 COMPLETE／APPLIED／key 配对，不跨项目比较本地 sequence，也不由只读观察释放
UNKNOWN、FIFO 或 NEW。counted WIRE 的所有来源原件穿过 CLAIM 消费与结束复验；缺失或
替换不能被重新采用。锁竞争夹具的固定就绪期限、EOF/部分读取、消费异常和退出等待失败
有独立预期，整个作用域只清理确证自有 session，原互斥和时间上界不放宽。这些测试与
手册不声称 G1、qualified NEW、默认在线 worker、真机或正式 full/check 已闭合；对应
REAL_ENV 补充仍为 NOT RUN，既有场景、权限与发布门禁不变。

REQ7 的 `reconcile_pending_project_units` 从真实 ALL catalog/C6 原件选择当前项目的
已计数单元，不接受 caller unit/generation/path。全部共享旧 family 在语义读取前持有；
实际 COMPLETE 创建者与接收者重叠复核原 FD、字节和 full stat，仅放行该创建者的两个
精确派生名。另一项目 pending C6 也持续持有但不选择，count zero 不触发读请求。
独立 direct 与真实 C6/OAuth/四次加密 socket workflow 覆盖缺 fence、额外共享名、原
ORIGIN/另一项目 RECEIPT/创建后 COMPLETE 同字节换 inode；原 count/UNKNOWN 不重置，
失败不写 APPLIED/key。此片段不证明默认 worker 编排、NEW/G1/FIFO 或整体 full/check。

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
`_hold_owned_project_catalog_metadata_capacity` 把实际原项目认证及该次 template／metadata
双读取接入 ALL catalog quota 消费；复制对象在库存访问前拒绝，消费与最终校验中
仍复核原读取截止期、双 owner、固定凭据／目标及全部原 quota FD。计量来自全部
永久 fence，不接受 caller reservations；两个原单元的 86 可见字节与 4 预留字节
独立见证剩余 29910。原读取过期或后继 quota 同字节换 inode 都 HOLD，不改原
count／UNKNOWN、不释放预留。这里仍为 `VISIBLE_ONLY_UNPROVED`，不是隐藏 PROJECT
完整性、真实 C6/FIRST/R2 或默认在线发送；本地 workflow 使用真实 OAuth／TLS
读取及原 catalog/global/enrollment/History/quota，测试 frozen unit 本身不冒充 C6。
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
首次 allocation 写者另将四个真实 creator FD 与写者最终完整 stat 交接给读者，
持续持有到读者 finalizer 结束；不能在写者返回后重新登记改过的 stat。
首写后、reader 捕获前同字节换 inode 或同 inode 原样重写均 HOLD，marker 前
故障不能提交 INITIALIZED；marker 后故障保留 evidence，不确认成功或计数。
FD 槽复用为 foreign inode 时只拒绝、不误关；creator 清理中断仍收尾目录。
首次 pathname stat 失败而身份未建立时，不重新采纳 FD 槽身份、不盲关未知 FD；
保留原失败／中断对象，并将清理未确认作为明确 cause，保留失败证据。
原两次文件/父目录屏障、八次 pre-marker 与十三次总屏障合同保持不变，默认
`_write_new` 调用仍保留原行为；私有 `(FD, fullstat)` 只供本地原件交接，
不是 cold 首用、多单元 catalog 外锚、COMPLETE、DELIVERED 或发送许可。
真实 native C6 创建链另在原 origin seal 后、唯一 catalog ENTRY 前，从实际 LIVE
项目 settings 原件分配本次 ALL 尚未分配的审计；目的地由实际 spreadsheet owner
与 unit 派生，不接受调用方路径、队列或 newness 声明。四个实际 creator FD/fullstat
连续进入同一 preparation 原图与共享 image budget；catalog HEADER→INITIALIZED→ENTRY
绑定外部 allocation 目录、启动见证和三个原文件的完整身份/SHA。冷读必须核实际
全部原件与冻结 revision/event/hash/时间/内容，lost-all 或同字节新 inode 不回退首用。
无 audits 的旧 native 分支不创建 settings 文件或 scope。settings scope 收尾只关闭
仍属原 dev/inode 的 FD，foreign 槽保留并拒绝成功；首文件检查失败关闭已确证自有
槽，原操作者中断保留同一异常对象。一个 finalizer 拒绝不能跳过 preparation/budget
撤销及其他自有图像清理。
同一原件图内任一关闭抛出中断时，仍逐槽尝试其余原文件与目录的条件关闭，
随后原样抛出中断；foreign 槽不误关，普通清理错误不能覆盖操作者中断。
本地 direct 与真实 C6→NV→allocation→catalog→冷读覆盖这些边界；这是创建/发现接线，
不是 GLOBAL/count/retained 接收、第二单元 DELIVERED、
投影归档、默认 worker hook 或 REQ7 整体/full/check 证明，这些仍须分别实证闭合。
native catalog 的 GLOBAL/retained 原图接收另只允许两个精确派生 family：
`settings-audit` 的固定 HEADER/ASSIGNMENTS/INITIALIZED 和单文件
`settings-audit-started`。实际 ALL catalog 外锚仍必须验证全部原件，不能按后缀
前缀放宽未知名字、接受未锚定目录或丢弃不认识的项目。仅 ASSIGNMENTS 的读取限额
为 1 MiB，其他小文件 16 KiB、总量 48 MiB 以及 legacy namespace 合同不变。
真实 C6→native allocation→catalog→GLOBAL count-zero→retained 消费者保持原 NV
六文件与全部 allocation 原件；实际 holder 内同字节新 inode 拒绝整个读取，保留
旧 journal/count/WIRE，无修复或有效前缀。未知审计 suffix 在消费者前拒绝。
这是原图覆盖，不是 protected COUNT/CLAIM 原 allocation 接收、DELIVERED、发送
许可、默认 hook 或当前精确树正式 full/check 证明。
native 事件分配按已持有、外锚与 ALL C6 核验的原 ORIGIN 项目 dev/inode 分组，
不是全表 event_id 集合；不同项目同一个 literal settings 事件可分别分配。
缺失、多份、未读原 ORIGIN 或 unit/project 身份不符均 HOLD，不通过重新开路径、
当前 ACTIVE 或调用方项目标签补算。冷 ALL catalog 在原 allocation/ORIGIN/ENTRY
全部核验后拒绝同一项目同一事件出现在两个单元，不返回有效前缀。
独立 direct 与真实两项目 C6/NV/allocation/catalog 正向流程，以及仅在真实 creator
分类边界注入一个重复事件的冷读反向流程覆盖此合同；旧原件、count/WIRE 保留，
无 ATTEMPT/CLAIM/修复。这不关闭 DELIVERED/归档/default hook 或正式 full/check。
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

已完成单元的设置原件冷发现也支持真实 `.unit-<id>.journal` catalog：分配 HEADER
中的 unit_id 仅作定位，先保持全部原 catalog/count 及真实项目 C6，再唯一选中并核
选中 C6 的 project dev/inode、原 ACTION/WIRE 和完整 COMPLETE/DELIVERED 对；
同表另一项目的真实 C6 不授权当前项目，即使旧接口留存相符分配/交付；有 catalog
不回退旧 `.journal`。其他 pending 单元的同字节换 inode 在 ALL-C6 holder
已钉住原件后及最后 K 读取时均整体 HOLD，
不能只证明已交付单元便忽略它。真实双 C6／TLS 完成／DELIVERED／同设备归档后，
独立冷进程读取最高 revision=1、K=7，原 count/WIRE、后续 outbox 和全部上下文撤权
不变。首次 K 读取的中断/退出/未列异常也先撤销两份 registry 再关闭所有原件；
调用者原异常保留，收尾拒绝单独发生时为 typed HOLD，无 ACK。
这里仍仅支持原第一分配的交付恢复；不是多单元事件分配、默认 delivery hook、
FIRST/R2 发送或 REQ7 整体完成，不能替代当前 full/check 或现场验收。

`pending_settings_audits` 在同一 LIVE 设置工厂作用域内复用其实际原
COMPLETE/DELIVERED 对，只剔除该原单元明确交付的事件。后续未交付事件仍须有
原 outbox 并保持 pending；无 matching held guard 的普通 writer 保留旧严格合同。
委托读取前后核同一 ACTIVE owner 与同一 registry 对象，撤销／替换后不能返回缓存
结果或降级采用旧投影。独立 literal 后续事件、真实双 C6／TLS／交付／归档及冷进程
覆盖这条只读接线；不产生多单元分配、清理、COUNT／CLAIM 或发送权限。

默认 prod `inspect_stage_l` 与真实 worker 状态入口在合法交付投影归档后读取最高 K，
仍保持 pending／来源资格／本地 receipt 的原合同和 `disabled_no_send_authority`。
独立 direct 验证缺失 tracker 不初始化、错误 scope 不读来源；实际多脚本流程验证正常
暖／冷读取、后续 pending 与原 WIRE 保持、缺失交付证明 HOLD，以及真实 per-key 来源
读取后同字节替换分配 HEADER 时不能返回成功。真实 worker 写出的只是状态文件；
AIR 与 C6 提交仍使用原 owner，不借此放宽来源、发布或发送准入。
这组本地自动化不覆盖旧周期 R2、APPLIED／FIFO／高水位或默认在线发送闭环。

完整手动 preview 的再次资格核对使用同一原件发现设置 owner，解决真实完成、
DELIVERED 及两个审计投影归档后普通 writer 无法读取最高 K 的边界；C6 确认写入
owner 不变。独立 direct 与真实 producer/worker/C6/native COUNT/固定本地 TLS 请求/
四个完成读取/交付归档/fresh owner broker 流程保留原审计预期、K/W1 和逐源摘要。
预览只读全部原件，不补 outbox、生成代次、再次 COUNT/CLAIM 或发送；同字节新 inode
RECEIPT 必须拒绝且不修复。本地 TLS/进程及证书夹具不是真实设备或 Cloud 验收。

旧原 COMPLETE/APPLIED/key/DELIVERED 与投影归档后，固定的 native 当前编译输入
接收器只在实际 writer/spreadsheet owner 与 ACTIVE preparation 内重放当前周期、
原 K/W1、C5 资格及 admitted C6 receipt，不采用 caller 快照、旧周期来源或返回许可。
实际 observed Switch compiler 的 manifest 须与默认本地 C6 的 manifest 严格相等，
真实注册仍由 catalog 独立执行。当前 cycle/C6/source 原件持有者先进入、K 最后进入，
使 K 撤权和最后 settings FD 清理先完成，再由仍 LIVE 的 raw 原件收尾验证；不能
在撤 K 后重新 qualify 或调用关闭的 verifier。真实多脚本正例须完成单次注册，
负例须独立证明接收器本身拒绝清理后的 receipt 同字节新 inode，而非用未注册
preparation 的外层 HOLD 冒充。此接线不新增 COUNT/CLAIM/send，不证明默认 NEW
整体闭合、当前 full/check 或真实 Cloud/设备/断电；现场卡仍 NOT RUN。

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

`record_owned_applied_evidence` 是另一个尚未接入在线 worker 的历史结算证据边界。
它要求实际项目 writer 与 spreadsheet 双锁、原生完整 C6 generation/MANIFEST/INTENT/
RECEIPT/已发布 XLSX，以及逐项重放四份 RAW 的完整原 COMPLETE。全部原件的 held FD、
stat/inode/字节/命名边和必要屏障持续至返回；不接受 caller COMPLETE 或 generation 标志。
只有原单元实际发送的业务 operation IDs 记录 APPLIED，完整 outcomes 中的 NOOP 仍保留，
不成为 APPLIED。独立 `.tracker/REMOTE-APPLIED-STARTED-<unit>` 与
`REMOTE-APPLIED-<unit>` 在准备时互绑两个原 inode；持有两份首写 FD，STARTED 先提交，
marker 后提交，均原子 NOREPLACE 并同步父目录。同字节替换、原 C6 收据漂移与 partial
配对 HOLD，保留 pending/原件，不补建、不回滚。完整配对的冷进程只重新核原件及屏障，
不依赖父进程对象；最终 parent fsync 失败不 ACK，若两份原文件均完整，后续冷读可以重新
建立必要屏障，不能补齐部分配对。这些测试包括独立初始 RED、实际加密固定读取、原生
文件、关键提交故障与独立冷解释器。原 global count/WIRE/UNKNOWN、C6 原文件与 NOOP
均不修改；该观察不释放 FIFO、预留、quota 或高水位，不授予发送、清栅、在线激活或正式
证明。REQ7 的消费者整体接入与当前精确树 full/check 仍待完成；现场卡
`TC-REAL-REQ7-ORIGINAL-APPLIED-001` 如实 NOT RUN，不能冒充断电或真实 Cloud 验收。

`record_owned_applied_key_watermarks` / `inspect_owned_applied_key_watermarks`
另持续持有原 C6、完整 COMPLETE 与互绑原 inode 的 APPLIED 配对，只从实际发送的
业务 activity key 和原生 generation sequence 保存不可变的逐单元高水位证据。
NOOP 不推进；原 UNKNOWN/count/WIRE、预留与 C6 文件不修改。两份独立
`REMOTE-KEY-HIGH-WATER-STARTED-<unit>` / `REMOTE-KEY-HIGH-WATER-<unit>`
同样经首写 FD、NOREPLACE 与 file/parent 屏障，partial/pending 不补齐或删除。
原件替换、COMPLETE-only 与中断必须 HOLD；完整配对的冷进程和重复观察只重新
核原件/屏障，不改记录。这个返回值不是所有历史单元的最大高水位，也不释放全表
UNKNOWN/FIFO、授权 NEW/catch-up 或接入在线 worker；全局消费者及精确树 full/check
仍须完成，现场新增范围沿用同一 NOT RUN 卡，不以局部通过替代正式证明。

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

NV 原像重读期间，目录及 ETH-RAW／IB-RAW／HEADER／RESERVATIONS／INITIALIZED
全部持续持有并核对 named/stat/字节；同字节换 inode 仍须 HOLD，保留原像和替代物，
不更新 UNKNOWN 次数或原 wire。借用 catalog 的原件持有与 conditional-owned close
只约束原对象，不赋予跨单元分配、结算或发送能力；marker FD 被复用于外国对象时
不得由本轮清理关闭。既有编号、十个图像屏障与冷恢复预期不变。

prepare／inspect 的外层目录也须在取得 FD 后立即记录原对象身份，重读结束后再核对
原 dev/inode 与 named 目录；若 FD 被复用于外国对象，返回 HOLD 且不得误关该 FD。
新增 direct 和真实 enrollment→NV→冻结 batch→GLOBAL UNKNOWN→原编号校验 workflow
同时要求原图像、原 wire 与 UNKNOWN 次数不变；不证明同 inode 的 open-file-description
一致性，也不替代跨单元分配或正式 full。

原生 catalog NV 诊断入口用真实 spreadsheet owner 派生 `.unit-<unit-id>.nv`，
固定保存两份 RAW、HEADER、RESERVATIONS、INITIALIZED 和完整原 PRIOR 链，
目录前写不可变 `nv-started`。固定原件读者重放全部旧单元，下一编号同时高于
两表所有原 ID 与全部旧预留；同 key 的不同 generation 不复用旧编号。
旧 GLOBAL 任一 UNKNOWN、部分或整个 journal 丢失，均在新 witness 写入前 HOLD。
default catalog 的 LOST 门禁不变；只有当前真实 owner 的未过期 opaque preparation
可以交接自己的精确新增名字和实际 FrozenUnit literal key/ID。
creator 原目录 FD 从创建至冷读交接和 append 始终持有；完成六份文件后封存其最终
目录身份与名字，不依赖关闭后再次打开恰好复用同一整数。INITIALIZED 完成后的
真实 full stat/SHA 经 opaque preparation 写入实际 catalog HEADER，沿既有
catalog marker→ENTRY 原身份链外锚；冷读同 inode 原样改写 marker 或原位重编码
其他文件的新身份仍 HOLD，不能从当前 marker 重新认领首写身份。默认无 NV 的
catalog header 合同不变；已有 native NV 但缺外锚不得按 legacy 路径采用。
这是未安装的原件准备、append 和冷重读，不证明真实 C5/C6 来源准入、FIFO 释放、
跨项目结算、当前 freshness、NEW 或发送许可；这些整体接线仍未完成。

真实 Cabling compiler 的私有 native preparation 分支另须保持实际 C5 来源与
current admitted C6 receipt 的前后复核，不用 reservation 替代来源。完整 missing-key
集合、receipt-derived generation/publish、原 nonce 和真实 literal key/ID 逐项相同；
仅 key 分配集合排序，ACTION 保留 manifest 原操作顺序，active update 不写 A。
最后真实 receipt 回读后、compiler 返回前再核一次原件；同字节换 inode 或同 inode
原样重写均要求 compiler 本身 HOLD，不以外层 scope 退出 HOLD 冒充。真实 protected
workflow 编译后单次 catalog append，再由既有 ALL C6 reader 核原 ACTION/WIRE、真实
generation 四件和已发布 XLSX。这不是 project-origin writer，也不授予 freshness、FIFO、
APPLIED、NEW 或发送许可；唯一 C6 registration 的 origin 交接仍需后续整体接线。

原生 C6 registration 的显式 `_nv_preparation` 分支现先完成实际
project-origin WITNESS/STARTED/ORIGIN，再唯一 append，不在已注册后补写 origin。
真实 writer/C6、NV 与全部旧 catalog 原件贯穿其间；pair finalizer 先于 append，
全部实际 C6/ALL-project reader 的 finalizer 成功后才确认本次注册完成。
完成的 origin 三份文件 full-stat/SHA 与目录原身份沿 catalog HEADER→marker→ENTRY
绑定；冷读全部 origin 名字丢失或原样换 inode 仍 HOLD，不降级成不要求 origin 的
旧 catalog。部分 origin、失败 append 即使被调用方捕获，准备作用域仍保持 HOLD，
不修复或自动采用。exclusive creator 同时交接实际原身份与 FD，首次 stat 失败只
关闭自有原对象，外来复用 FD 不关闭；默认旧 creator 返回合同不变。
独立 direct 与实际 protected C5→admitted C6→native NV→origin→单次 append→ALL C6
workflow 覆盖本地交接；不是 FIFO 释放、freshness、NEW/send 或整个 REQ7 证明。

catalog-retained inventory 的 native NV 分支只从持续持有的真实 catalog
HEADER 原链识别，不接受 caller boolean/name-list 或合成 TemplateIdentity。
共享 enrollment/原 ACTION nonce 逐项核验后，从已持有的实际 FD 重放两份 RAW、
PRIOR、预留及完整 INITIALIZED/started 原件语义；跨 unit 的预留链顺序不重置。
native 六文件与 `nv-started` 全部覆盖，只有该分支的 HEADER/PRIOR/marker 使用
原 native 1MiB 边界；legacy 五文件形状和原界限不变。原件 named/full-stat/bytes、
catalog/count 与精确 parent namespace 持续贯穿 consumer 和退出，原样换 inode
仍 HOLD。独立 direct、旧 retained 回归和真实 protected C5→C6→NV→origin→
catalog→GLOBAL→retained workflow 是只读原件接线证据，不是容量释放、APPLIED、
freshness、NEW/send 或整个 REQ7/full 证明。

native NV 目录自身也接收 exclusive creator 的原身份与 FD，接收方首次
`fstat` 在 conditional-close 范围内；失败只关本次原 dev/inode，外来复用
对象保持打开。失败保留 `nv-started` 与空/部分目录，冷重试不得采用或修复。
独立 direct 的 owned/recycled 两类与 actual protected C5→C6→NV 工作流
均在异常作用域外核真实注入及清理；不是断电、设备或发送许可证明。

native 原件固定发送边界增加实际 protected ETH/IB C5/C6→native NV/catalog→
History/business/quota 原件→逐次签发的真实隔离 TLS 读取→原计数→原 CLAIM→
固定隔离 child 单次请求流程；原 wire 请求收到 401 后仍 UNKNOWN，同一 CLAIM
再次消费必须在 child 前拒绝。计数后原 RECEIPT 原字节换 inode、已签发读过期
均须无 child/无请求并保留原 count/UNKNOWN。使用原 30 秒读取与 60 秒 mutation
合同，不改时间阈值；只替换私有测试根/CA/DNS边界，实际 child 解析、FD与 TLS
发送不替换。正常路径先在现实现上通过，不宣称实现 RED/修复。新增映射测试
先 RED 再登记真实 fixed read/sender/supervisor/TLS/rejection 模块。此流程仍不
建立 G1/隐藏 PROJECT 容量、共享准入/FIFO release 或生产发送许可；相关回归、
当前精确树 full/check 和 REAL_ENV NOT RUN 如实分别记录。

native 原始计数链新增实际 protected C5/C6→NV→唯一 origin/catalog→GLOBAL→
History/business preread→永久 quota→原 C6 第一次计数流程，ETH/IB 两类均核原
编号、原 wire、原文件不变与 count=1/UNKNOWN。NV RAW 在真实计数期间脱离名字
再恢复的独立反例在原实现上已经拒绝，因此不宣称实现 RED 或新增持有修复；
已写计数不可回滚。新增流程夹具只在 preparation 完结时关闭该 scope，目标/
白名单隔离根仍持有至 source replay/计数退出，旧用例预期不变。映射独立 RED
补登真实 History/quota/target 模块和相关测试。这是实际原件计数边界证据，
不产生 freshness、G1、FIFO release、发送许可、COMPLETE 或整项 REQ7 证明；
REAL_ENV 仍 NOT RUN，当前精确树 related/full/check 仍须如实验证。

origin-backed native NV 后继准备从实际 catalog HEADER 原链选择全部旧 origin，
并持有其真正项目 writer/LOCK、C6 四件和已发布 XLSX；这些原件贯穿 witness、
全部 native 文件写入、compiler、origin 和唯一 append，不能只核共享 origin
摘要或在写前检查一次。旧 receipt 原样换 inode 在写前要求零新 NV 写入，
在实际 witness 后要求零下一 NV 文件写入，并保留失败原件、禁止冷采用。
原 ALL-project C6 reader 仍核真正 origin，获取/原件校验逻辑不变；旧 namespace
仍逐项精确校验，仅实际 native writer 自有的新名字和唯一 append 允许增长。
独立失败用例、两代真实 C6→NV→origin→GLOBAL→ALL/FIFO 和实际 protected
C5/C6 workflow 核原件、零 APPLIED 及重叠 pending 屏障；不释放 UNKNOWN、
不授予 freshness、qualified NEW 或发送许可。REAL_ENV 仍 NOT RUN。

old/current/indexed 以及 catalog 内部重读共用固定 16MiB 原始图像预算，按持续
持有的 dev/inode 去重，并在实际 pread 前核单文件 size 与整组预算；同字节不同
inode 分别计费，同一原件仍逐次真实读取并核 full-stat/named/bytes，不能缓存许可。
这是 retained originals 的容量约束，不宣称 Python 解码/临时数据的进程峰值上限。
新目录每次真实 RAW/后续 sibling 写入前后核原 FD/name 和精确已写名字；目录
fsync 期间或 ETH 写入后 FD 外来复用均 HOLD，零下一 sibling 写入且不误关外来 FD。
七个已提交文件边界覆盖 witness、两份 RAW 和四份其余图像；负例在异常 context
外核注入命中、无 yield/ack，避免 assertion 被转换成 HOLD 造成假绿。
原生固定名 creator 保持 exclusive O_RDWR 的首次文件 FD，不在写完后重新打开
名字来认领原件。INITIALIZED 核前五份实际 writer FD 的完整身份/摘要与自身预开
FD 的 dev/inode，冷读取同字节换 inode 仍 HOLD。witness 自 exclusive open 成功
即为可见 STOP 名字，零字节/partial/file-fsync/parent-fsync 失败也不能 fresh-first-use。
旧 legacy pending/rename 阶段不冒称为这条原生 direct-create 路径；全部残片保留，
不采用/删除/宣称恢复。未做现场缩减、豁免或断电验收，REAL_ENV 仍 NOT RUN。

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

多单元 catalog 的 metadata 预留沿实际 global journal 的原单元命名空间
`<spreadsheet>.unit-<unit-id>.metadata` 保存，不能在 catalog 旁创建旧的
`<spreadsheet>.metadata` 共享槽。真实 catalog/global/enrollment/History/quota
流程验证两个未尝试单元分别落盘与只读回放、后来单元部分图像不采用／回填、
首个原配额计数后 UNKNOWN 继续阻断后来计数。旧无 catalog 流程仍使用原共享槽，
现有断言及预算不变。这只修正原配额的单元归属；不证明跨单元容量汇总、隐藏
PROJECT 库存、FIFO/NEW、COMPLETE 或发送许可；现场仍 NOT RUN。

catalog 容量只读 handoff 还须持续持有 ALL 原 catalog/global/retained family 和
各单元四份 metadata 原件，按全部永久 fence 汇总各自的可见字符池；不能接受 caller
列表或只返回有效前缀。UNKNOWN 与已可见的同一 fence 仍算 outstanding，后者只避免
重复字符收费，不释放原预留。后来 quota 缺失、部分图像或 consumer 期间同字节换 inode
均使整体 HOLD，保留所有原像，不回填／收养／清理。新增真实多脚本 workflow 的固定
预期同时覆盖双单元、UNKNOWN、容量溢出和消费后置替换；夹具每轮加载同一真实
inventory 源码与当前 owner/global，生产身份检查不放宽。这只汇总本地原配额与所给
固定可见响应，不能证明响应鲜度、隐藏 PROJECT 全集、历史排他或 NEW／发送许可。

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

首次初始化在创建 journal 目录前，以独占固定 `.journal-started` 名保留
GLOBAL-UNIT-STARTED STOP，先完成原文件／parent 两个 fsync 屏障，并持续持有
原 FD／命名边／完整 stat 到初始化返回；空、partial、改写或被替换见证均 HOLD，
不补建、覆盖、删除或视为正向许可。原八个图像及两个 INITIALIZED 屏障仍全部执行。
UNKNOWN journal 位移后，同一单元不能回到零次；M=6 journal 位移后，新 generation
也不能绕过。独立 direct 故障注入与实际 local intent→global intent→独立冷 owner
流程保留原次数、UNKNOWN、WIRE 及所有原件。该 STOP 只关闭首次防重建边界，
不证明完整历史 inventory、APPLIED/FIFO/high-water 最大值或 successor/NEW 准入；
已有保守屏障不能当作 REQ7 整体完成。现场与断电/设备验收仍 NOT RUN。

原件读取的 `inspect_original_global_unit` 不接收当前或缓存 unit：在解释前持续持有
原 STARTED、ACTION、WIRE、HEADER、INITIALIZED、完整 ATTEMPT 前缀及原目录，
从实际 ACTION/WIRE 恢复历史单元；旧 `inspect_global_unit` 也必须经同一持有作用域，
再比较调用方 unit，不能绕过 STARTED 或接受解释期间的同字节换绑。原 FD／命名边／
完整 stat／字节在解释、恢复 fsync 和消费者退出两侧重核，全部自有 FD 关闭后才公开
返回。缺失、partial、缺链、FIFO 等特殊文件及漂移仅 HOLD，不补造、重编译或重置；
真实 local intent→global intent→独立冷 owner/read 流程保留 UNKNOWN 与所有原像。
该接口仅观察既有单一单元，不证明完整历史 inventory、successor、APPLIED/FIFO／
高水位最大值、G1 或 NEW 资格，不能当作发送许可或 REQ7 完成。HISTORY 六屏障
故障夹具仅将注入限定到实际 HISTORY 建立阶段，六个边界及原断言全部保留，
新增 exact-boundary 断言；上游 GLOBAL 恢复屏障不能替代 HISTORY 故障证明。

settings-audit allocation 的屏障夹具也只选择本轮私有 allocation 图像的实际
dev/inode：原 witness／pending、目录、HEADER、ASSIGNMENTS、INITIALIZED 及其
恢复同步。八个故障注入点、marker 之前的原物理顺序和总计 13 个 allocation
屏障预期不变；上游 GLOBAL 原件读取的恢复 fsync 必须照常执行，但不计入这些
allocation 故障点。额外负例验证 GLOBAL 同步失败在 allocation witness 之前
停止，原 GLOBAL／settings 图像不变、无 pending／marker、无修复或尝试计数。
该修正是夹具隔离，不减少生产屏障，也不替代相关、完整 full 或现场证明。

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

## REQ7 retained-original inventory — bounded main receiving

`issue_tracker_retained_inventory.py` covers every current same-spreadsheet
legacy namespace entry, holding its original directory/file descriptors, names,
full stat/ctime and raw bytes before semantic replay and through recovery fsync
and the consumer. Missing/partial/foreign or unsupported namespaces stay HOLD.
The fixed legacy namespace represents one unit only. Unknown future or archive
namespaces are not silently dropped or treated as empty/first use.

The observation contains no send/NEW/APPLIED permit. Original enrollment and
History initialization markers and raw digest links are checked using the
already held originals, then actual enrollment nonce/id and History decoder,
unit/capacity contracts are replayed against the original GLOBAL unit.
Dispatch HEADER/CLAIM chains must bind that original unit, its actual held
WIRE/ACTION full identities and original UNKNOWN-intent digests. A consumed
UNKNOWN is not SENT, completion, FIFO release or retry/send authority.
Business prefilter also binds the original GLOBAL/header/manifest/raw digests,
all original operation IDs and both sent/NOOP coverage counts. It replays the
existing bounded original envelope grammar, not the full cell/source classifier.
It explicitly does not fabricate a remote identity observation from enrollment
ids just to satisfy a typed semantic API; full business replay remains required.
Other retained families are coverage witnesses requiring their specialized
semantic validators. This is not whole multi-unit/project/C6/APPLIED inventory,
global high-water/FIFO/G1/default worker closure.

When a retained completion family is present, its file shape alone is not
accepted: the existing remote-history reader replays the original start,
header, identity, metadata, headers and History proof against the original
GLOBAL unit. Enrollment and History originals are mandatory. Coherent foreign
unit, empty-match, fabricated raw and APPLIED-label images remain intact HOLD.
This replay is a historical COMPLETE observation only; it does not change the
original UNKNOWN/count, create APPLIED, release FIFO or authorize a NEW unit.
The actual owned local TLS completion workflow passes in the main 22-method
direct/workflow module after the fixture rebinds enrollment and preread aliases
before issuing owner tokens. Its first ERROR and bounded registry diagnosis are
retained: enrollment's old owner registry rejected a newer issued token. The
same assertions then pass; no permission or implementation validation is
relaxed. This is not full proof or real Cloud/device acceptance.

The completion-start cleanup also has an independent actual-FD RED: after a
consumer closes the original reader FD and assigns its number to another
dev/inode, the old unconditional finally-close destroyed that consumer FD.
Cleanup now closes only the original dev/inode, including an original whose
bytes or ctime changed. The two leaf tests retain the original HOLD and verify
both foreign-FD survival and changed-original closure. They use actual shared
owner/GLOBAL/start-reader scripts and native files, not sockets or a full
completion proof. They do not prove same-inode open-description identity,
portable FD ownership beyond this contract or global settlement. The original
independently failed H witness passes against the integrated main guards in its
own bounded native-file run; its initial ERROR remains retained. This closes
that local cleanup defect, not whole H inventory/oracle or full acceptance.

The original GLOBAL reader had the same unconditional-cleanup defect for both
its WIRE FD and journal directory FD. Independent native-file tests reproduced
two rejection-survival FAILs (one method with two subtests), while the changed
original byte test still required the owned FD to close. Candidate cleanup now
captures the original dev/inode immediately after acquisition and closes only
that object. Both methods pass with the same assertions; files/count/UNKNOWN
and original validation remain unchanged. The first setup-error log is retained
separately: owner-only synthetic metadata was insufficient for the local
directory validator, so the existing synthetic-root fixture is required. No
root access or same-inode open-description guarantee is implied. The exact main
22-method direct/workflow module passes; runner-related/full and onsite evidence
remain required, and no approval hash is manually changed.

Independent missing-API RED and four real corrupted-original REDs are retained.
A diagnostic negative-test harness initially raised its own AssertionError
inside a fail-closed context; that false-positive run is not rejection evidence.
The negative body was corrected without changing any expected HOLD, followed by
four actual rejection FAILs and implementation repair. Later independent REDs
cover coherent foreign unit/nonce links, recycled file/directory FD numbers and
four coherent foreign dispatch images. All old logs remain. Cleanup closes only
an FD still naming the owned dev/inode, never a recycled number naming a foreign
object; it does not claim portable same-inode open-file-description identity.
Five coherent foreign business-preimage/coverage REDs are retained too; no such
prefilter PASS is full business semantic, source, admission or APPLIED proof.

The first dispatch fixture run produced five setup ERRORs because the old
global root-redirection fixture also redirected local project ancestor opens.
Using the existing owner-module-only scoped fixture keeps real local OS paths
and identities intact, without changing assertions. The resulting four actual
rejection FAILs are the dispatch RED; the setup-error log is not production RED.

The manifest adds one script, one direct rule and one true multi-script workflow,
retaining all existing mappings and suites. Tests were installed first on main:
the independently bound initial RED retained two GLOBAL FD subtest failures,
one completion-reader FD failure and the absent inventory API failure. Reviewed
production and semantic manifest additions followed. Main direct/workflow PASS
does not replace runner-related approval or frozen full/check under the existing
failure and narrow validation-only rules. The partial diagnostic candidate was
not a standalone production/full-proof tree.
`TC-REAL-REQ7-RETAINED-INVENTORY-001` is NOT RUN; no onsite risk waiver is implied.

The original upstream sequence (GLOBAL, remote History, retained inventory)
initially ended with 11 ERROR entries in 196 methods. Bounded replay of the
actual GLOBAL prefix and first failing owned remote workflow established the
fixture cause: enrollment/preread retained an obsolete owner module registry,
so the current issued owner token failed before the production flow began.
An independent direct regression failed first (three registry assertions),
then the owned fixture was changed to capture the current enrollment/preread
registries before issuing any token. Production owner checks, all old behavior
assertions and time budgets are unchanged. The same original three-module
sequence, including the new regression, ends with 197 PASS in 471.715 seconds,
exit 0, on HEAD 7335587 plus the exact reviewed receiving diff. Its complete
append-only log preserves the old prefix and physical BEGIN/END identities.
The failed 196-method log and both bounded RED logs remain diagnostic evidence;
neither this local sequence nor single-case PASS is a current full proof.

The retained APPLIED-key reader reconstructs the historical generation identity
only from the held original unit, then joins the actual original C6
STATE/MANIFEST/INTENT/RECEIPT/published XLSX, COMPLETE proof, APPLIED pair and
key-watermark pair. A reconstructed reading handle is not registered as an
issued mutation handle. The caller cannot supply a generation, unit or keys;
an unissued writer is refused before inventory reading. No original is repaired,
removed or changed. Only actually sent business keys are returned; NOOP is not
APPLIED, and the original count=1/UNKNOWN stays unchanged. The main tests first
failed on the missing API (four independent methods), then the actual owned
native workflow and the existing inventory module passed together (26 methods).
The final five-method direct/workflow module additionally rejects same-byte
replacement of a held key marker or C6 receipt before consumer acceptance.
All held originals are verified across the consumer and final scope exit.
This one-unit historical reading is not a global maximum, per-key FIFO,
multi-unit recovery, G1, NEW permission or default worker activation. Those
integrated transitions and current exact-tree full/check remain open.

### Multiple pending originals and original counted-wire/APPLIED reading

2026-10-11 bounded C25 receiving: the default local settings factory now joins
the complete claimed native delivery set under actual project/spreadsheet,
ALL catalog/count/C6 and immutable COMPLETE/DELIVERED originals. A private
live opaque context permits only those proved missing projections while
reading the full K chain; it cannot be forged, copied, rebound, revoked or
used across threads/contexts to obtain a fallback. The public delivery
observation and physical archive still select exactly one original unit,
not the private union. A new K event remains independently paired with its
new outbox. Raw original holders survive ALL semantic finalizers and refuse
same-byte C6 replacement at the final exit boundary. The new direct and
actual two-unit TLS/C6/delivery/archive/cold-process workflows passed together
(21 tests, 166.200s); this is diagnostic evidence, not runner approval or full.
The old cold selected-unit expectation remains unchanged; only its interim
default-ALL refusal is replaced by the independently specified C25 read.
No existing timeout, negative proof boundary, skip or ledger is relaxed.
Default online sending/G1, whole REQ7 closure and current exact-tree
full/check remain open; the corresponding onsite scenarios remain NOT RUN.

The shared FIFO reader joins ALL original project C6/APPLIED inputs and each
project's immutable UNSENT records in one held scope. Overlapping pending keys
follow catalog order across projects; generation numbers and later APPLIED
witnesses are compared only within the original project. A genuine foreign
project's APPLIED sequence 1 cannot supersede local sequence 1. Computed
supersession without its original write-ahead witness and paired records stays
HOLD; any UNKNOWN, missing receipt, changed original or interrupted/new
disposition namespace refuses the whole view through consumer exit. The reader
does not record dispositions, reset attempts, clear UNKNOWN, issue NEW or bypass
the original GLOBAL guard. Independent missing-API RED, direct file/cold-process
and actual local TLS COMPLETE/APPLIED workflows remain distinct from runner
approval, exact-tree full/check, G1/default-worker and whole REQ7 completion.
Existing single-project readers, all assertions and time budgets remain.

`test_req7_unit_catalog.py` covers the immutable append-only pending catalog
under the genuine spreadsheet owner, per-unit GLOBAL/History/dispatch original
names and the one shared enrollment nonce. All old original rules remain.
Missing catalog with surviving per-unit UNKNOWN cannot become legacy first use;
partial/tail loss, changed scalar types, later-unit substitution or fsync failure
refuse the whole handoff. All catalog/count originals dominate actual consumption,
the last semantic replay and exit. Newly created dispatch HEADER/INITIALIZED
are held BEFORE the first claim read; only its exact one-CLAIM append may extend
the namespace. Genuine six-count same-unit retry preserves old CLAIM full stat/raw
and refuses consumed-count reuse or a seventh intent. These necessary primitives
do not issue admission or a send permit and never clear UNKNOWN.

Historical C6 reading derives generations only from held actions and never
reissues mutation handles. The APPLIED join requires genuine writer ownership
before inventory access and every counted unit's original COMPLETE/APPLIED/key
pair. Unattempted originals contribute no applied keys; unresolved or foreign
project originals refuse ALL, not a valid prefix. Independent initial RED logs
precede each implementation/fault repair. In the owned candidate,38 file-only
methods,17 unchanged consumers and12 unchanged legacy methods pass. Three actual
owned TLS workflows also pass: COMPLETE/APPLIED plus a pending native C6 unit,
held key/pending RECEIPT replacement, and missing APPLIED/key pairs. Main receiving
has its own initial RED (45 methods, 48 failure entries including subtests), then
45 PASS including the three actual TLS workflows and four manual-profile tests.
On the same frozen receiving source/test tree, the original GLOBAL → History →
retained inventory → APPLIED → catalog → manual/documentation → actual upload
archive sequence passed all 347 methods (579.553 seconds, exit 0). Real manual
regeneration and generator --check exit 0 corrected the stale inventory gate.
Evidence logs are req7-catalog-main-receiving-green-20261010.log and
req7-catalog-main-original-sequence-and-manual-green-20261010.log in the ignored
local evidence directory; these diagnostic passes do not update the ledger or
replace current exact-tree related/full/check or the public child workflows.

The manual-profile tests require uninstalled/no CLI boundaries; changing source
inventory requires real manual regeneration and original documentation/public
packaging workflows, not just profile PASS. Current full5281/27FAIL/4SKIP on
485e7f9 is preserved:24 additional failures trace to stale generated manual;
the remaining REQ10C3 stay raw FAIL. No assertion/timeout/skip/ledger is weakened.
This local slice is NOT cross-project/global maximum/FIFO release/current NEW,
G1/default worker or whole REQ7 closure. Current related/full/check and field
TC-REAL-REQ7-PENDING-ORIGINAL-CATALOG-001 remain required; onsite NOT RUN.

The next one-project key-order slice retains every original input while folding
the actual APPLIED key watermarks and listing unattempted native C6 generation/key
comparisons. Project-local sequences are never compared across projects. Pending
and NOOP keys do not advance APPLIED; unresolved counted units refuse the entire
fold. No UNKNOWN clearing, UNSENT disposition, FIFO release, G1 or NEW permission
is introduced. Its pure arithmetic helper is not original proof; only the held
reader can observe actual inputs. Existing methods and expectations are retained.
Main receiving first ran the seven new methods against the old implementation:
7 methods / 8 failure entries including subtests, missing APIs only. After the
implementation, catalog → retained inventory → APPLIED → manual profile passed
all 79 methods (57.295 seconds, exit 0), including five actual owned TLS workflows.
The reverse overlapping-key catalog case preserves the actual original FIFO
rejection; it is not a fabricated successful first send. These diagnostics do
not replace current exact-tree full/check, cross-project inventory or whole REQ7.

The next one-project UNSENT slice requires count=0 and strictly later original
APPLIED coverage for every actual candidate key. Pending/SENT/equal sequence,
partial coverage and caller settlement/maxima cannot issue a disposition.
Its immutable record binds fixed original witness units and key-pair identities;
new maxima cannot rewrite history. A fixed write-ahead STOP witness plus an
original dual-inode pair keeps missing/partial/rebound records HOLD without
repair, first-use recreation or UNKNOWN/count mutation. Independent tests
exposed whole-pair-loss recreation before the witness fix; the raw failure is
retained. Main receiving ran11 new methods against the old implementation
first (11 missing-API FAIL), then catalog → retained inventory → APPLIED →
manual profile passed93 methods/103.033s/exit0 including11 actual owned TLS and
cold-process workflows. All old assertions/timing contracts remain. This is
not FIFO release, global high-water, current NEW/G1/default worker integration,
wholeREQ7 closure, field acceptance or current exact-tree full/check.
REAL_ENV stays NOT RUN; no field risk waiver was added.

The prior full24 stale-manual failure entries were diagnosed from original
tracebacks. After actual manual regeneration, the original documentation/
upload sequence347 and clean-tree public packaging/capsule/S failure-chain14
all passed (the latter1424.368s). These are cause-specific workflow evidence,
not a current full success. REQ10C3 still execute and remain raw known FAIL.

The settled-successor GLOBAL preparation slice joins actual catalog origins,
all original project C6 images, counted GLOBAL/History/COMPLETE, and original
APPLIED/key-high-water pairs before the fixed creator writes. All old shared
images remain held through the new write-ahead witness and journal commit;
only that creator's two exact derived names may extend the namespace. Missing
APPLIED/key evidence or same-byte old-original replacement must HOLD. Count=1
and UNKNOWN of the settled original remain unchanged. This permits diagnostic
GLOBAL preparation only: successor counting, CLAIM, native NV allocation,
G1/current qualification, default online worker and formal full/check remain
separate obligations. The original positive workflow initially failed at the
old permanent-count guard; the missing-APPLIED rejection already passed.
The positive, rejection and actual-witness/old-APPLIED-inode drift workflows
then passed against the corrected implementation. The extra direct cases
reject unissued owner and any public caller settlement/verifier override.
All earlier tests remain unchanged; no manual ledger or field waiver.

The native NV settled-successor slice uses two actual owned Cabling reads and
all previous catalog/C6/GLOBAL/COMPLETE/APPLIED/key originals. Counted units
without these original pairs remain a barrier; a legacy count cannot use a
caller settlement label. The project scopes remain held through NV STARTED,
each image, compiler/catalog append and exit. Rebinding old APPLIED immediately
after the actual STARTED return must stop before creating the successor NV
directory, retaining STARTED and the original count/UNKNOWN. Source Closed and
unrelated A-column identifiers still determine the next literal reserved IDs;
no history reset, expiry, reclamation or ID reuse is introduced. Direct cases
reject unissued owners and caller settlement/verifier overrides, and real
multi-script workflows retain the positive, missing-pair and commit-boundary
negative expectations. This is necessary diagnostic allocation, not current
source/freshness/G1, successor counting/CLAIM, default worker or whole REQ7
closure. Formal current-tree full/check and REAL_ENV remain separate.
Both actual C6 registration paths are verified: an original independent origin
pair and a native NV HEADER anchor must reach the same genuine all-origin/C6
reader. A name or label never substitutes for that proof. The new fixed private
settlement scope holds matched GLOBAL/History/nonces, COMPLETE, C6, APPLIED and
key pairs before its one full entry replay; subsequent checks verify the same
held originals through each creator boundary, without broadening the public
cold reader's namespace. An interrupted unindexed NV STARTED keeps that public
reader HOLD while original count/inodes/bytes remain unchanged. Original key
writer/readers and prior test methods retain their existing contracts.

The settled-successor diagnostic counter continuously holds ALL original
catalog/origin/C6/GLOBAL/History/nonces/COMPLETE/APPLIED/key evidence through
one exclusive derived ATTEMPT-n, including the actual creator FD and captured
reader original. Its bounded current scope requires the final catalog unit
and genuine settlement of every OTHER counted unit; another pending or UNSENT
unit stays HOLD, never omitted. First count checks the real shared FIFO before
writing; identical subsequent counts retain selected UNKNOWN and the total
six-count bound. Actual local sequence/key maxima are compared only within
their original project. Every older count image/inode remains unchanged;
missing prior APPLIED, a same-byte old APPLIED replacement after the actual
count write, or replacement of that creator's ATTEMPT original refuses return
without deleting, repairing, clearing UNKNOWN or issuing another opportunity.
Independent direct and true C6/catalog/four-owned-read/settlement/count workflows
cover these boundaries. The fixture installs its current canonical inventory
before original owners are issued; a stale previous-test module is not proof.
Public owner failures keep the original sanitized GlobalAttemptHold contract.
CLAIM/launch, multiple pending/superseded frontier integration, current source,
G1/shared cadence/default worker, current full/check and whole REQ7 remain OPEN.
These diagnostic counts are not evidence of actual mutation wire sends.

Settled-final-successor counted-wire handoff now holds every original catalog,
origin, C6 and shared family before interpretation, plus genuine OTHER
COMPLETE/APPLIED/key pairs through exclusive dispatch HEADER/INITIALIZED and
one derived CLAIM creator, consume, final semantic checks and exit. The actual
selected writer/project must match; only the final unit with all OTHER units
genuinely settled is accepted. Missing APPLIED, an unrelated writer or another
pending/UNSENT unit remains HOLD. Legacy and unresolved UNKNOWN contracts are
unchanged. Old count/CLAIM images remain original, each count is consumed once,
copied images and cold-process reuse are rejected, and the six-count limit is
not reset. Selected C6 or old APPLIED same-byte/new-inode replacement at entry
or last consumer refuses return while keeping partial/UNKNOWN evidence.
Independent direct tests and the actual C6/catalog/four-read/APPLIED/successor
workflow include a fixed isolated child making one owned loopback TLS request
with the original wire. It receives 401/UNKNOWN, not COMPLETE, and is reaped.
Negative consumer/cold assertions are checked outside production exception
normalization; a swallowed assertion is not refusal evidence. This bounded
handoff is not current-source qualification, freshness/G1, shared cadence,
multi-pending/superseded FIFO, default online worker, whole REQ7 or current
formal full/check proof. No real device, Cloud or power-loss verification is
claimed; existing automated cases and production release gates remain intact.

The final-successor join additionally accepts an OTHER unit only when its
original count is zero and its immutable UNSENT WITNESS/STARTED/final originals
bind every key to a strictly later genuine same-project APPLIED/key witness.
This is original-derived classification, not a caller label or computed maximum.
Every old shared image is held before semantic replay; the three disposition
FDs overlap the real FIFO reader before its read-only scope ends and remain
held through the writer's exact ATTEMPT append, CLAIM/consumer and finalizers.
Selected UNKNOWN contributes no APPLIED witness. Missing/partial/foreign names,
uncovered pending or counted UNKNOWN still HOLD; local sequences never compare
between projects. The final catalog unit and six identical-count limit remain
unchanged. Direct closed-owner tests and real C6/four-read/APPLIED/UNSENT/count/
CLAIM workflows preserve older counts, wire and disposition images, including
replacement at the actual write boundary. This diagnostic count/claim join
does not install default NEW/R2, create UNSENT records for a mixed-project
catalog, qualify current source/freshness/G1, or prove whole REQ7/full/check.

The mixed-project UNSENT writer derives every project and pending unit from
the genuine shared original catalog, holding ALL C6/count/COMPLETE/APPLIED/key
inputs before any append. Strictly later APPLIED sequences are compared only
within the original project. Only the selected original unit's fixed
WITNESS/STARTED/final names may be created; every project's disposition namespace
is rechecked across write callbacks. A foreign new entry, changed original,
partial pair or pending write refuses the whole result, retaining all evidence.
Each creator callback captures only earlier retained readers that outlive it;
its own prepared originals remain held and verified through the later reader
handoff and final creator exit. It must not call a later reader after that
reader has closed its FDs. Independent missing-API and namespace RED tests,
actual encrypted C6/APPLIED workflows, a second-commit interruption and separate
cold-process replay preserve old counts/wire/UNKNOWN and never repair partials.
No caller project/root/maximum/settlement is accepted. This library append is
not default worker NEW/R2 admission, freshness/G1, T6, whole REQ7 or current
formal full/check. Existing tests and budgets remain unchanged; onsite device,
Cloud and power-loss verification remain NOT RUN.

The mixed-project disposition-to-count/CLAIM composition now uses a genuine
second project's original C6 and selected wire, never a caller foreign writer.
The older first-project count=0 disposition releases only the original-derived
FIFO classification; local sequence=1 in another project does not inherit that
project's sequence=2 watermark. The actual ATTEMPT append and final CLAIM
consumer retain all three disposition originals. Same-byte/new-inode witness
or selected C6 replacement refuses return and retains UNKNOWN/consumed state.
A separate cold process observes original counts (1,0,1) and cannot reconsume
the used claim. Initial composition errors were fixture registry import-order
errors, not implementation RED; only the new fixture's canonical import timing
was corrected, with old test definitions unchanged. The fixed four scenarios
passed, followed by all 109 retained-applied/GLOBAL module tests. Existing
manifest direct and real six-script workflow mappings cover this composition.
These are local development results, not default worker dispatch, NEW/R2,
freshness/G1/T6, whole REQ7, runner approval or current formal full/check.

Every original terminal prod cycle's default read-only worker lane now calls
the ALL-project UNSENT writer after original reconciliation, while the same
sheet owner and current target/cycle scopes remain held. The append acquires
and verifies its own ALL catalog/C6 scopes; no closed reconciliation verifier
is reused. RetainedInventoryHold stops only disposition: it neither discards
the original UNKNOWN/CONFLICT observations nor claims an append succeeded.
Historical APPLIED with stopped disposition gets a fixed mutation-disabled
notice, not GO; ordinary stalled diagnostics stay byte-identical. Cycle drift,
config/allowlist/owner finalizers and BaseException still refuse successful
return. The observation cache keeps its existing five non-authority fields.
Five independently observed direct cases and two actual OAuth/four-read/C6
workflows first failed before implementation, then passed unchanged after the
16-line worker seam. The positive registers selected generation2 before old
generation1 and proves only automatic historical UNSENT submission, not a
final-unit count/CLAIM handoff. UNKNOWN/count/wire and cycle originals remain.
This adds no NEW/R2 mutation, current-source qualification, freshness/G1/T6,
whole REQ7, real device/Cloud/power-loss or current formal full/check claim.

The non-authoritative online observation display distinguishes UNKNOWN with
an original durable total count of six as `retry_exhausted`: read-only
reconciliation and escalation, with mutation still disabled. Counts one through
five remain stalled, and CONFLICT takes precedence. Invalid typed counts are
rejected before any diagnostic prefix or snapshot is emitted. The fixed five
cache fields do not carry identities, credentials or send authority. Independent
direct tests and an actual six-intent GLOBAL journal → worker cache → authenticated
CGI GET → generated JavaScript workflow retain all original count evidence and
reject a seventh intent. Durable intent count is not proof of six physical wire
attempts, T6 cadence, current-source freshness, G1 or whole REQ7/full/check.

Protected reserved, original-business, receipted, continuous and shared-retry
count boundaries now call the same catalog-aware public counter. Their original
quota, History, receipt, audit and current-source gates remain in place. Real
settled-C6/APPLIED successor reservation cases retain old bytes/inodes; missing
APPLIED refuses without count. Actual protected ETH/IB receipt and fixed TLS
launch flows, and identical original-unit retry, independently assert exact
count/outcome and shared-route identity outside sanitized production contexts.
401 remains UNKNOWN, never COMPLETE or a reset opportunity.

A bounded native launch diagnosis established an issued template-identity read
expiring during final source replay, not a missing registry entry: its original
30-second deadline had elapsed by 0.596632375s (fine timing reproduced 0.212110125s).
The native qualification now projects its own just-observed protected IB/W1
window instead of rereading that same intermediate window. Public IB readers,
final independent IB/projection/full-cycle checks, producer timestamps and all
original deadlines remain unchanged. Tests-first structural RED was retained;
five actual normal/receipt-rebind/read-expiry checks passed, 303.205s, with exact
source/test identity frozen. The structural test is supplemental, not a field
provenance oracle. Existing drift/source-leg workflows remain required.
This narrow correction and local PASS are not the diagnosis of the historical
formal full's three other timing failures, current full/check, G1 proof, default
online-worker integration or whole REQ7 closure. REAL_ENV remains NOT RUN.

The fixed original-project reconciliation driver now obtains the four actual
project-authenticated read results itself (template identity/headers, metadata,
History), keeping original C6/count/wire/nonces/History and current auth/policy
held. Missing fence remains UNKNOWN; missing audit remains CONFLICT. Only a
complete match creates COMPLETE, APPLIED and the original sent-key watermarks;
it never adds a wire/count, resets UNKNOWN, releases G1 or cleans an outbox.
Created COMPLETE identities remain held by the creator through the next proof
capture and are checked BEFORE APPLIED. A same-byte replacement at that handoff
or at the final key/auth boundary refuses while preserving both originals and
failure evidence. Existing/partial proof stores use strict readers, never a
repair/recreate fallback. Direct refusal and real native C6/OAuth/owned TLS
four-read workflows retain independent request/child/cleanup observations
outside all exception normalization. Live original replay makes no new read;
this is not a cold-process, default coordinator, whole REQ7 or current full/check
proof. Existing automated cases and their original budgets remain required.

Initial target binding is a separate fixed-input API under the actual live
project owner. It reuses the same no-follow, bounded current config and root-only
enumeration reader, including named/held stat checks after both reads. It takes
no caller target/document/path, and a typed binding is never a permit. The old
inspect API still rejects missing/invalid previous bindings BEFORE any input;
it never silently initializes or retargets one. Independent direct and real
owner/config/fixed-enumeration workflows cover disabled policy, empty listing
and same-byte config replacement. Root/RO-bind field provenance remains NOT RUN.

The actual collection coordinator dispatches its existing status and local
tracker lanes independently only after durable completion. An ordinary failure
in either cannot skip the other or relabel collection success; diagnostics do
not echo exception contents, and KeyboardInterrupt/SystemExit still propagate.
Independent direct cases and real worker/gate/emitter plus three cron workflows
observe original start/launch/completion bytes before both dispatches. This
dispatch-edge proof is not actual online reconciliation, a new send permit,
whole REQ7 closure, field verification or current full/check. Existing local
business, admission and publication tests retain their original expectations.

The default terminal prod-cycle entry now independently reconciles old counted
UNKNOWN units, even when the actual terminal cycle is nonqualifying or local
publication is not due. AIR never enters this online lane. Its actual gate and
store binding and ALL lifecycle originals stay held; initial config/allowlist
originals are continuously FD/name/full-stat checked through actual OAuth,
four reads, creator, APPLIED/key and both shared/project-owner finalizers.
Read-only original checks after project-token revocation never extend ACTIVE
authority. OAuth is lazy: count zero makes neither token nor Sheets request.
Only this project's actual catalog/C6 counted rows are selected, but all other
originals remain held. The actual exclusive creator checks cycle/target/old
catalog/C6 sources before COMPLETE; its only two derived new names do not
authorize a third name or adoption of replacement images. Late finalizer drift
returns HOLD while preserving already genuine COMPLETE/APPLIED, not rollback.
Independent initial RED cases cover same-byte cycle/config/allowlist replacement,
gate drift, HEADER-to-COMPLETE and actual project-owner revoke/close boundaries.
Actual owned OAuth/TLS four-read workflows and real worker/gate/emitter/three
cron dispatch workflows are separate evidence; dispatch observers alone are
not online proof. Existing raw UNKNOWN/count never reset. No business mutation,
NEW/FIFO/G1 release, whole REQ7 or current full/check is established here.
REAL_ENV remains NOT RUN; no existing automated or core field case is omitted.

Unresolved default-lane observations now emit fixed UNKNOWN-stalled or
CONFLICT-stopped diagnostics only after the original owners' final checks.
The reporter validates the entire typed tuple before emitting anything and
never echoes evidence, credentials or target details. Historical APPLIED is
not labelled current online GO. An independently missing permanent fence in
the actual OAuth/four-TLS-read workflow must preserve every original file and
the initial UNKNOWN/count, with no completion, dispatch CLAIM or mutation.
This is log visibility only, not durable operator status, retry scheduling,
T6 escalation closure, default NEW/R2 permission or whole REQ7/full proof.

Protected FIRST and original R2 may compose inside the terminal worker's
identical actual held cycle store. Only the original live holder issues reuse;
copied stores, caller callbacks/tuples, revoked holders and ContextVar changes
are refused. The borrower checks original FD/name/full-stat/gate bindings at
entry and exit without resetting or closing its owner; the standalone holder
still rejects nesting. Independent negative facts are asserted outside sanitized
HOLD scopes and locate borrower rejection before the outer finalizer. Existing
real source/compiler/C6/CLAIM/encrypted-request workflows exercise both entries
under that outer scope. This necessary composition does not prove default NEW,
G1, FIFO release, overall REQ7, field verification or current full/check. No
original behavioral expectation or field case is removed or weakened.

The public cycle reader uses the same live-owner registry before consulting a
held result and after each original verification. Caller tuples/malformed scopes
and an actual copied context retained after owner exit are typed HOLD, before
any caller callback or stale result is used. A live scope for another actual
store still performs the original fresh replay. Independent direct negatives
and real worker publication of a second cycle prove revocation without repair;
this is not persisted cache authority or online send permission.

An older admitted C6's private native window is issued only by the real
receipted-source replay after the original cutoff, complete parent chain and
expected prefix have been verified. Its live registry entry lasts only for
that synchronous native qualification and checks the original parent's live
identity before and after verification. The private window is revoked before
restoring the full parent; a copied private context cannot survive even while
the original parent remains live. There is no caller callback registration API
or exemption from the public reader's live-owner check.

The default read-only reconciliation also publishes a separate best-effort
`issue-tracker-online.status.json` observation cache only after all original
finalizers succeed. Its five fixed fields contain no evidence, credentials,
project identity or permission; `updated_at` means last observation, not current
admission. The authenticated collection CGI's GET-only `issue_tracker_online`
view and default HTML label display UNKNOWN/CONFLICT escalation, historical
APPLIED, or the unscoped empty observation, always without send permission.
Missing/untrusted/malformed/future input is unproved. The existing local status
and disabled manual UI contracts remain unchanged. This cache is not a durable
journal, T6 scheduler, G1 proof or power-loss recovery authority.

Independent direct and actual worker→protected CGI→generated JavaScript tests
cover fixed fields, secret rejection, real completion-path publication and
unchanged originals/count/CLAIM. Real first-fstat fault tests require closing an
unchanged owned parent/image and preserving a numeric FD rebound to a foreign
inode. Named-before-open identity is cleanup-only fallback, never read authority;
concurrent name drift plus failed first stat may leave cleanup unconfirmed and
cannot prove an open-file-description. Original automated/field cases are not
removed or weakened; whole REQ7, field verification and full/check remain open.

The owned FIRST/R2 native fixture prepares its actual encrypted endpoint
before issuing the original bounded reads. Nested read children use a separate
owned TLS root, preserving the mutation CA's bytes/inode and outer DNS endpoint;
both children still run the fixed production CA reader and verified TLS. The
independent readiness test and actual old-cycle retry workflow retain exact
wire/count/UNKNOWN/one-claim expectations. Original read, transport and startup
deadlines and post-count expiry/rebinding negatives are unchanged. This fixes
fixture preparation/isolation, not proof that earlier startup failures or the
whole REQ7/full/check have been resolved; REAL_ENV remains NOT RUN.

Fixed catalog reconciliation has an internal lazy-authentication handback for
the next default stage. It returns only the actual issuer-bound project OAuth
object after every ALL-catalog/C6/completion finalizer succeeds; the ordinary
read-only API still returns its diagnostic tuple. No caller authentication or
factory is accepted. No current counted unit still means no OAuth and an empty
result. New direct and real OAuth/TLS/catalog/four-read workflows cover live
handback, owner close revocation, count-zero, and foreign C6 original rebinding.
This is neither a retained read snapshot nor G1/send permission: subsequent
stages must acquire fresh source and actual reads under the original owners.
No existing assertion or deadline is relaxed. Field verification is NOT RUN;
default FIRST/R2, whole REQ7 and exact-tree full/check remain open.

The next default worker stage reuses only actual issued project authentication,
after reconciliation and local ALL-UNSENT finalizers. It reacquires ALL actual
catalog/C6/family originals, current K, fixed workbook W1 and protected native
source before four new issued project gate reads. Fresh gates and ALL visible
quota originals surround actual receipted-source/business/reservation replay
and another current source qualification. Original read deadlines are checked
again after holder cleanup. Ordinary preparation HOLD preserves the old
diagnostic tuple; cycle/owner finalizers and operator interruption still apply.
It never counts, claims, mutates, invents NEW, or excludes a unit merely because
an APPLIED filename exists. Visible accounting is VISIBLE_ONLY_UNPROVED, not
historical hidden-PROJECT completeness. Settled-unit exclusion, fresh History
and per-operation business continuity, shared opportunity/default FIRST/R2,
whole REQ7 and exact-tree full/check remain open. Existing automated tests and
deadlines are not weakened; the new direct and actual native/TLS workflows are
registered in the manifest. Field verification remains NOT RUN.
The post-finalizer native negative advances only the original issuer's clock
after the actual last catalog holder has exited: all four real reads succeed
first, but expired observations must HOLD without changing count/CLAIM/images.
Removing the new final read checks makes both independent direct and native
expectations fail. At the time of this evidence, the fixed30s observation
budget was unchanged. This is historical evidence; the owner-approved current
observation contract is documented under2026-10-15 below.

REQ7 mixed settlement is an original-held read, not admission: the private
fixed-owner reader joins ALL actual project C6/catalog/family/count originals.
Only a counted COMPLETE with the complete original APPLIED/key pair is settled;
counted UNKNOWN and unattempted units remain pending without count mutation.
Each project APPLIED/key namespace must exactly match the completed units,
including both STARTED/final pairs. Bare, missing, partial or extra markers
refuse the whole observation. Actual proof and C6 originals remain held through
the consumer, and namespace checks run again after proof-reader finalizers while
project owners are still held. Existing strict APPLIED readers are unchanged.
Independent direct and actual native/TLS multi-script tests cover original
classification, count retention and inode/namespace faults. This prerequisite
does not reclaim permanent quota fences, issue NEW/count/CLAIM, close REQ7, or
replace exact-tree full/check. Field validation remains NOT RUN.

REQ7 mixed original quota accounting keeps ALL permanent wire fences charged,
including a historical full C6/COMPLETE/APPLIED/key settlement with no quota
family. Pending or UNKNOWN units require the entire original quota family;
present partial families, missing settlement proofs and same-byte original
replacement refuse the whole budget. Matching visible fences avoid arithmetic
double charging but never release the reservation. Actual project read/auth
identity and the original fixed deadlines dominate consumer and all finalizers.
The result remains VISIBLE_ONLY_UNPROVED, not hidden PROJECT completeness or
G1/FIRST/R2/send authority. Independent direct and real OAuth/TLS+C6/proof/quota
workflows retain the original counts/images on refusal; first-stat failures
close newly acquired original file/directory descriptors only when cleanup can
still prove the candidate inode. A reused numeric FD naming a foreign inode is
preserved. Concurrent name drift or persistent cleanup-stat failure can leave
cleanup unconfirmed, never grant authority or justify blindly closing a slot.
The pre-open named identity is cleanup-only, not admitted original authority.
Existing strict
quota APIs and all pre-existing tests remain unchanged. This development slice
does not close overall REQ7 or replace current exact-tree full/check; field
verification is NOT RUN.

Default REQ7 read preparation now holds actual ALL mixed settlements alongside
the original C6 and retained inventory. Units, project identities and counts
must agree before selecting only this project's genuinely unsettled units;
historical settled units are not pending source or OAuth candidates. The
actual mixed quota reader continues charging permanent fences. Protected
ETH/IB source replay and four fresh project gates remain original-held, with
read/auth/target checks after the last original finalizer. Independent direct
and real native cross-project/protected-source workflows assert no count,
CLAIM or mutation. This is read-only VISIBLE_ONLY_UNPROVED preparation, not
FIRST/R2 admission, hidden PROJECT completeness, whole REQ7 or exact-tree
full/check. Existing refusal expectations and original deadlines remain;
field validation is NOT RUN.

Private `_hold_owned_original_business_history_reads` acquires fresh fixed
History/activity/insertion/row reads from the actual retained catalog unit's
immutable business originals. Every original operation, including NOOP and
operator cells, is compared without recompiling action/wire or changing count.
Shared fixed read shapes may be deduplicated, never operation identities.
Original business/History descriptors remain held through inventory finalizers;
same-byte inode replacement refuses before yielding. The actual project
authentication, read issuances and original deadlines are checked throughout
and after finalizers. Independent direct and actual protected ETH/IB native
OAuth/TLS workflows require five issued reads (including supplied identity),
unchanged originals/count and no CLAIM/mutation. Existing NOOP/cold recovery
tests remain. This helper alone is a continuity observation, not source
provenance, FIRST/R2, G1, a send permit or current full/check.
Field/Cloud/device/power-loss validation remains NOT RUN.

Default read-only preparation now actually acquires the fixed business/History
reads for each selected original unit after actual current source/C6 replay.
Its business holders outlive the old source/catalog/C6 finalizers. Each genuine
private guard checks originals only while LIVE; after all business holders
close, issued-only checks use every helper's frozen actual read registry,
original authentication/owners/target and unchanged original deadlines, never
a closed FD/inventory verifier. Copies, fabricated guards, interrupted scopes
and revoked actual reads HOLD. Failed scopes cannot become CLOSED or revive.
Independent direct and protected ETH/IB OAuth/TLS workflows retain literal
eight-read/no-count/no-CLAIM/no-mutation and unchanged-original expectations,
last old finalizer same-byte inode replacement, actual postclose read revocation
with external successful revoke/restore facts, genuine copy refusal and failed
consumer scope. This is still VISIBLE_ONLY_UNPROVED preparation: no FIRST/R2,
hidden PROJECT completeness/G1, sending, whole REQ7 or current full/check.
Existing tests and original 30-second limits remain; field validation NOT RUN.

The genuine LIVE business-read guard can privately hand back its original
issued identity/History responses and fresh copies of the fixed business-read
dictionaries. It takes no caller selectors or callbacks; copies, fabricated,
CLOSED and FAILED guards cannot supply inputs. Repeated handback preserves
actual response object identity, update/insert order and insert row=None,
without allowing caller dictionary edits to change the frozen packet. Actual
original/read checks surround the handback, retaining the original deadlines.
Normal close discards that packet; FAILED scopes revoke it permanently.
This remains read-only: the helper pins the initial catalog/count/namespace,
so it cannot surround a count or CLAIM append. A future FIRST/R2 consumer must
use its protected append-aware original scope, not relax the read-only guard.
Independent direct and actual protected ETH/IB OAuth/TLS workflow tests cover
this boundary, copied/closed/failed holders and unchanged count/originals.
This handback is not default FIRST/R2 wiring, G1 or sending authority; whole
REQ7, current full/check and field/Cloud/device/power-loss validation remain open.

REQ7 C25 default Stage-L last-observation display uses the existing worker's
fixed private cache, an authenticated GET-only public projection, and three
read-only default publication-area labels. Independent literal direct tests
and actual worker/emitter/C6 -> persisted file -> CGI -> generated JavaScript
workflows retain pending progress, archive-gap unknown counts and local C6
completion without online permission. K, revision (including initial zero),
N and counts cross the browser boundary as exact decimal strings, never JS
floating-point numbers; missing facts remain unknown. Only fixed display
fields cross the boundary: no device/project/evidence identity, raw ACTION,
wire, credential, source path or arbitrary exception text. Unsafe/replaced
images and malformed projections display unproved, never idle/GO. This does
not enable the uninstalled manual/K relay, default FIRST/R2 or online sending;
last observation is explicitly not current admission. Whole C25/REQ7,
current full/check and all field validation remain open.

The manual listener workflow additionally carries authenticated CGI settings
intents through the actual listener, durable queue, broker and LK-P K event /
current / outbox chain. Independent literal expectations require K3/revision0,
one K7/revision1 operator:nvis event, exact replay without rewritten settings
originals, and wrong UID or GID rejection before enqueue with queue/settings
inodes and bytes unchanged. No C6 publish, count, CLAIM or online permission
is issued. This evidence-only extension passed on its first run; no production
implementation changed and no artificial initial RED is claimed. Only kernel
peer credentials/transport are simulated on macOS; fixture 1201/1202 are not
approved deployment identities. The exclusive non-login CGI identity, actual
Apache/root relay installation and corresponding REAL_ENV remain unverified.

The LIVE original-business guard now overlaps its actual two directories and
seven fixed images into a private duplicate-FD graph before the strict
read-only scope closes. No paths are reopened, no caller selector/verifier is
accepted, and no initial namespace/count snapshot is transferred as append
authority. Actual issued response identities, authentication and unchanged
deadlines remain checked after strict closure. Same-byte replacement and
issued-read revocation irreversibly refuse the graph. First-stat interruption
cleans only still-owned duplicate inodes; foreign FD reuse is preserved.
Successful cleanup must confirm all nine slots closed and recheck the actual
issued reads after the last owned cleanup: skipped foreign cleanup or final
revocation cannot return success. Independent direct and real protected ETH/IB
OAuth/TLS workflows retain their literal no-count/no-CLAIM/no-mutation and
unchanged-original expectations. This is a necessary original-image handoff,
not installed default FIRST/R2, G1 or a send permit; whole REQ7, exact-tree
full/check and field validation remain open. No existing tests or deadlines
were removed, skipped or weakened.

The fixed private `_consume_current_project_online_original_inputs` now uses
the same actual acquisition core as the unchanged read-only preparation API.
It takes no caller-selected unit, source, guard, permission or callback. Each
genuine original unit keeps its own qualified source and business guard; its
image graph is acquired while strict readers are live. Current cycle and
fixed policy/W1 originals dominate strict closure, graph verification and
cleanup. Independent real ETH/IB workflows require the actual outer original
verifier's refusal after last-finalizer same-byte policy/W1 replacement, not
merely the final generic HOLD (the normal G1-unproved path also holds).
Preservation is witnessed before each owned temporary fixture is cleaned;
fault variants use distinct complete source trees. Old mixed settlement,
quota, close order, postclose issued-read and deadline expectations remain.
The W1 fault fixture restores its original inode only after the actual
post-finalizer verifier has rejected and both originals were witnessed;
the replacement is retained separately. This isolates the next real IB
scenario without refreshing its original device/inode-bound snapshot or
altering any production recovery path.
The default worker now calls this fixed consumer exactly once after ALL UNSENT
disposition, instead of the old preparation wrapper. Its original owner/auth
handoff, cycle checks and every outer finalizer remain; typed HOLD preserves
the prior read-only reconciliation result/status, whereas operator interruption
and cycle drift do not become success. Independent direct and actual OAuth /
four-read default-worker workflows require one new-consumer call, zero legacy
calls and no FIRST/R2/count/CLAIM/mutation; the original UNKNOWN/count/files and
cycle identities remain unchanged. Their nonqualifying-cycle fixture does not
prove entry into the nine-FD graph. A separate actual default-worker workflow
now builds the protected three-panel source and genuine ETH/IB C6 originals:
real count-zero reconciliation returns ((), None) without OAuth, then the
actual consumer qualifies before its first real token refresh, issues eight
owned native TLS reads and overlaps two directory/seven file originals.
External assertions require actual verification after strict reader closure,
the original outer input verifier, final nine-FD EBADF, unchanged original
cycle/catalog/WIRE/count and no FIRST/R2/CLAIM/send. It fails against the held
exact pre-dispatch worker function and passes against the current function;
only the old function is substituted in memory for RED, never main-tree bytes
or genuine consumer/issuer implementations. This fixture borrows its already
held actual project/spreadsheet owners, so it is not first lock acquisition or
actual owner revocation evidence; the existing runtime workflows retain those
contracts. No legacy preparation mode or expectation is removed.
At this earlier business-image-only stage, PROJECT completeness was unproved;
the private input edge refused before FIRST/R2 COUNT/CLAIM/launcher and did
not authorize sending.
Whole REQ7, exact current full/check and all REAL_ENV remain open; no scenario
was omitted or merged.

Default G1 quota-original reception now also uses the confirmed dedicated-from-
creation / one historical Cloud project deployment precondition. That owner
confirmation is not API evidence, runtime provenance or new Cloud authority.
The actual fixed consumer enters the genuine dedicated quota holder while its
strict current source/read scopes are live, before business image overlap.
Five original quota descriptors per real ETH/IB C6 fixture (one directory and
four files) remain unchanged across every strict input finalizer and business
image cleanup. The quota-only verifier is never a closed-reader callback;
actual issued reads are rechecked after its own finalizer. Legacy quotas with
no saved project origin retain read-only HOLD; no HEADER is backfilled from
today's credential. A direct boundary test separately requires final-close
read revocation to HOLD and preserves the exact operator interruption.
The native workflow creates new genuine project-bound quota originals through
actual fixed OAuth/native TLS, not by editing an old HEADER. Its independent
post-sanitizer assertions require both original five-FD graphs, post-strict
fullstat/byte continuity, final EBADF and every old nine-business-FD, eight-read,
unchanged-cycle/catalog and zero COUNT/CLAIM/send expectation. Initial RED
reached this missing-overlap assertion after fixture-only CA/JSON wire fixes;
those earlier fixture failures are not claimed as requirement RED. Dedicated
capacity and STOP_CAPACITY remain accounting observations, never permission
to send. Default NEW/FIRST/R2, ALL/FIFO/cadence, current full/check, REAL_ENV and
whole REQ7 closure remain separate and unproved. No existing automation was
removed, skipped, weakened or given a longer deadline.

Native C25 audit COUNT/CLAIM original reception: the public allocation reader
and counted holder interpret the actual catalog-anchored allocation and ALL
project origins, retaining their own immutable descriptors across subordinate
reader finalizers. The final original-image check precedes descriptor closure;
ordinary refusal exposes only typed HOLD, while operator interruption survives.
FIRST may reuse one actual interpretation of the immutable catalog only inside
its live issuer/context/process/thread-bound scope. Every borrower still checks
the actual owner, ALL named/held full stat and bytes, exact namespace and every
native or explicit legacy C6 bridge origin. No caller cache, callback, unit list,
qualification result, count/claim authority or refreshed deadline is accepted.
Mutable journals, COUNT/CLAIM, C6/source qualification and issued reads keep
their original independent checks; the sole exact dispatch-name allowance is
not a launch permit. Closed/copied/rebound context, foreign thread, original
replacement and cross-context exit revoke the scope and clean owned originals.
Independent direct expectations cover the issuer and finalizer boundaries;
actual protected ETH/IB workflows cover native audit COUNT=1 UNKNOWN, CLAIM=1,
one fixed local request, receipt replacement and original issued-read expiry.
The ETH branch carries both independently authored original K events; the IB
branch retains the original unaudited contract, not a second audit claim.
The original 30-second contract and all earlier workflows remain unchanged.
These local cases do not prove default worker G1, second-unit DELIVERED/archive,
whole REQ7 or exact full/check; all corresponding REAL_ENV cases remain NOT RUN.

Native C25 COMPLETE/DELIVERED receiving retains the catalog-anchored original
HEADER/ASSIGNMENTS rather than reconstructing the one-unit legacy allocation.
The real C6/NV/catalog/GLOBAL and four independent child/TLS completion reads
must precede DELIVERED; broken native anchors never fall back to legacy images.
COUNT/CLAIM retains the strict mutable settings graph. Completed-pair K changes
and recoverable outbox archival instead retain immutable catalog/C6/EVENT
originals while their existing transaction holders validate mutable current,
outbox and appended events. The immutable leaf alone grants no authority.
Independent literal-event direct and real multi-script workflows cover native
delivery hashes, same-byte allocation replacement, owned directory acquisition
and cleanup refusal, operator-interruption identity, open-time ancestor rebind,
foreign FD reuse, normal archival and paired K append/replay. Existing legacy
archive and K-transition expectations remain unchanged. The directory's private
original handoff captures its checked identity inside acquisition, before any
recipient stat, so cleanup never adopts a foreign reused slot. This development
slice is not native second-unit delivery, default G1/NEW/send, whole REQ7,
current formal full/check or REAL_ENV approval; no case was omitted or merged.

Native C25 default local settings discovery now obtains its binding/unit locator
from the original local DELIVERED HEADER's exact embedded native allocation
image, not a nonexistent legacy folder or caller coordinates. The embedded
image's canonical SHA and actual project/tracker identity are checked before
ALL original catalog/COUNT/C6 and the actual COMPLETE/DELIVERED pair are joined.
Locators never authorize missing projections or K changes on their own; the
actual shared native allocation must still match. Legacy delivery bytes remain
unchanged. Locator/journal originals outlive subordinate pair/C6 finalizers and
are verified before the real sheet parent closes, with conditional original-FD
cleanup. Independent direct expectations and true fresh-process workflows
cover default discovery/archival/replay with empty parent context, tampered unit,
recomputed foreign-project locator, native anchor loss/legacy shadow, removed
native locator, same-byte original replacements and last-pair-finalizer drift.
The explicit-unit and default cold tests retain their original 10-second bound.
This closes only the first native unit's local default settings entry, not
second-unit delivery, ALL historical delivered events, online worker/G1/NEW,
whole REQ7 or current formal full/check. Field cases remain NOT RUN.

Local C6 after native historical delivery now uses a separate fixed original
handoff: strict ALL catalog/COUNT/C6/delivery semantics finish and their opaque
issuer is revoked before generation creation. Actual project/sheet locks and
checked duplicate original file, directory, ancestor and namespace FDs overlap
that transition; no closed semantic verifier or reopened replacement becomes
authority. Only real generation handles issued by this same live writer admit
exact additions under its original generations directory. All old receipts,
events, settings, COUNT/UNKNOWN, foreign project originals and delivery pairs
stay fixed. The new opaque read-only K context rejects forged/unregistered
copies and set-K, and revokes before all cleanup. Raw sheet graph/LOCK OFD
outlives sheet-token revocation for a final original check; conditional cleanup
retains foreign reused FD slots. Publication keeps its established safe 0755
owner contract, not the private journal's 0700 contract, while named/held
identity, unsafe modes and directory replacement remain checked.

Independent directs cover new generation handoff, first recipient stat failure,
last raw/sheet finalizer receipt replacement, actual lock exclusion, normal0755,
same0755 replacement and0777 refusal. The actual protected multi-script normal
COMPLETE/DELIVERED/archive → fresh preview → new eligible cycle → default local
C6 workflow passed after the original publication-policy defect was explained
and fixed. The real receipt-rebind and last-settings-finalizer workflow checks
also passed, with former native and C6 issuers revoked before the late fault.
No local pass closes hidden G1, whole REQ7 or current exact-tree full/check.
REAL_ENV remains NOT RUN.

New native delivery after an older event's original archive uses its own fixed
raw ALL handoff, not the local C6 grant. Old native semantic issuers revoke
before exclusive new STARTED/HEADER/DELIVERED writes; actual project/sheet
locks, original files, namespace and ancestor FDs overlap that boundary. The
selected new audit must still have its exact projection. Only names derived
from its actual native allocation and COMPLETE enter the raw graph; the real
writer FD overlaps read acquisition. Original writer and folder source cleanup
uses acquisition-time identity, refuses recycled foreign FD slots and preserves
the actual incoming operator interruption. Source folder close is inside the
existing tail stack, before the final retained graph check. Real workflows
cover normal selected-only archival, old HEADER replacement after STARTED,
missing new projection before creation, foreign writer/folder slots, operator
interruption and same-byte old HEADER replacement after actual last folder
close. Partial/new evidence remains retained HOLD, not acknowledgement.

The default worker now enters fixed C25 disposition only after its OAuth/read
sheet owner closes, while the actual project writer, current target and cycle
originals remain held. Fresh ALL C6/catalog/native audit/C19 originals select
completed current-project units, never APPLIED labels or caller IDs. A new
pair is created only when both exact derived names are absent; a partial pair
is refused, never repaired. After this sheet scope finishes, fresh ALL native
discovery issues a private temporary union and archives only selected original
events; it revokes before finalizers. Typed C25 HOLD preserves the historical
read-only reconciliation observation, with a fixed failure diagnostic, not a
C25 success claim or sending authority. First-unit actual worker disposition,
old-archive/new-unit selected-only disposition, partial-pair refusal and late
cycle-original drift refusal passed their actual workflows. The original later
unit disposition fixture creates that unit BEFORE the older archive; a separate
default-worker workflow now creates its actual new C6/NV/catalog AFTER the old
archive and delivers only the new event. That workflow and the unchanged
partial-pair/late-cycle refusals passed together, without increasing their
existing bounds. A separate allocation workflow also constructs
the second C6/NV/catalog only AFTER the first original projection is archived.
Its literal revision1 assignment excludes the old delivered event; old pair,
COUNT1/UNKNOWN and raw evidence stay original. A fixed private allocation
handoff acquires ALL genuine prior delivery evidence before the first NV
STARTED write, then revokes semantic issuers. Actual preparation-owned additions
are frozen before old/current FD cleanup, never inferred from directory names.
Original shared and catalog namespaces stay checked through the last raw tail,
under the existing actual catalog image budget. Real late-old-close delivery
HEADER rebind, shared extra and catalog extra cases refuse at the NV boundary.

The separate counted-foreign workflow completes, applies and archives a first
project through actual native C6/NV and four TLS reads, closes ALL its owners,
then creates a second real project. A newly acquired original foreign owner
retains its genuine lock through the raw tail; C6/settlement semantics and NV
preparation authority still revoke first. Existing caller tokens remain borrowed,
not reissued or closed. The raw tail observes that foreign owner live with all
semantic registries revoked, then final owner cleanup removes it. Identical
literal event0 inputs in the two projects remain separately assigned; old
inode/bytes and COUNT1/UNKNOWN stay unchanged, with no protected mutation.
The three whole modules plus five real after-archive/cross-project workflows
passed 274 tests; this is local development evidence only. Both independent
cold-process orders also passed: the original pre-archive creation and the new
AFTER-archive creation retain literal K7/revision1, no pending audit and two
COUNT1/UNKNOWN units, with all original inode/bytes unchanged. The new fixture
explicitly retains legacy one-unit refusal before using a fresh real default
writer's ALL native discovery to archive the second event. It does not widen
the legacy pair's exception to other missing projections. G1/NEW, whole REQ7, current
exact-tree full/check and all field cases remain OPEN.

The receiving slice's adjacent regression also passed 169 tests across the
whole local commit, publication, state-owner and global-attempt modules plus
default-worker direct/isolation, real three-script collector dispatch and
remote-history direct/isolation/manifest contracts. Complete logs bind the
exact dirty candidate; these runs do not approve the ledger or constitute a
clean-tree formal full. The earlier three non-REQ10C full timing causes remain
UNKNOWN; isolated or ordered local PASS is not their root-cause closure and
does not justify a blind full rerun. Ordinary release gates remain closed.

### G1 authenticated Cloud-project origin (2026-10-11 receiving slice)

The owner confirmed that the target spreadsheet has been dedicated to this
tool since creation and developerMetadata has never been written by any other
Cloud project. This is a deployment precondition, not an API observation or
field/full proof. New `prepare_owned_project_metadata_reservation` originals
persist the non-secret project id obtained from the actual fixed OAuth/read
acquisition in their canonical HEADER, covered by INITIALIZED. No token,
credential bytes, caller completeness/dedicated flag or permission is stored.
The new held owned reader requires matching actual current authentication and
template-read provenance throughout consumption. Same-project credential
rotation requires a new actual acquisition; a different project is refused,
also when consuming ALL catalog or mixed quota originals. Legacy images remain
readable as visible-only observations but cannot acquire authenticated origin
by replay, repair or today's credential. All fences, quota bytes and UNKNOWN
counts remain unchanged; this slice still returns VISIBLE_ONLY_UNPROVED,
never inventory_complete, FIRST/R2 or a send permit.

`test_cases.test_req7_metadata_reservation` retains its existing direct and
real OAuth/TLS→enrollment/global/History/catalog/quota workflows and adds
independent strict origin-shape, same-project rotation, copied acquisition,
legacy-no-upgrade and foreign-project refusal expectations. Four initial RED
methods are retained. The first implementation run's single new fixture
failure compared deliberately renewed TLS certificates with tracker state;
the fixture now compares ALL durable tracker originals by inode and bytes.
The whole module passed 49 tests without deleting, skipping, relaxing or
changing any existing test. Manifest mapping remains the existing primary
issue-tracker-local direct rule and native durable-quota multi-script workflow;
no production path or canonical target was added. REAL_ENV, full/check, G1
complete inventory/default send integration and whole REQ7 remain separate.

The following necessary G1 accounting edge is separately tested first:
`_hold_owned_project_dedicated_catalog_metadata_capacity` relies on the owner's
dedicated-from-creation / no historical foreign metadata writer deployment
contract. It requires actual issued unfiltered metadata/template reads, current
fixed authentication and matching saved project provenance for EVERY retained
quota. Under that supported precondition it accounts for DOCUMENT and the
same Cloud project's PROJECT entries plus ALL permanent fence reservations;
normal outcome is DEDICATED_PROJECT_CAPACITY / inventory_complete, overflow
remains STOP_CAPACITY. This is conditional accounting, not an API proof of
hidden-project history, a COMPLETE settlement or a live transport capability.
Copied acquisitions, a foreign actual project or any legacy missing provenance
refuse without repair, count change or reservation reclamation. The earlier
pure/legacy/owned visible-only APIs and their independent expectations remain
unchanged. Default-worker NEW/R2/FIFO integration and current full/check are
still separate obligations; this helper alone cannot enable sending.

The dedicated mixed counterpart requires ALL original C6/COMPLETE/APPLIED/key
settlement proofs for historical units without a quota family, and matching
saved Cloud-project provenance for every existing pending quota. Both permanent
wire fences remain charged, whether already visible remotely or still reserved;
overflow remains STOP_CAPACITY. It does not accept a caller settlement or
completeness flag, create missing originals, adopt a legacy quota, release a
reservation or change COUNT/UNKNOWN. The old mixed API remains visible-only.
Independent literal normal/overflow/missing-original workflows and a direct
unissued-source rejection were first RED; real local OAuth/TLS and immutable
C6/settlement/quota sources are used rather than mocked capacity results.
This necessary mixed-accounting edge is not default FIRST/R2/FIFO send wiring,
whole REQ7 completion, field validation or current full/check approval.

Owned NEW History preparation accepts only the actual project authentication,
issued template identity and issued full History read, without a caller plan,
coordinate, freshness flag or verifier. The immutable unit's two sheet IDs
must match the actual fourteen-sheet identity (including Update_History).
Creation remains count-zero/new-only, pins all three retained images through
final inspection, and rechecks issued sources through cleanup. Same-byte
replacement or source revocation leaves retained HOLD without repair, rollback,
COUNT or CLAIM. The legacy plan-based offline preparation is unchanged.
Independent direct and actual local OAuth/TLS/global-journal workflows were
initially RED; these prerequisites do not themselves wire default NEW/R2,
prove G1 send admission, complete REQ7, or replace current full/check.

Owned NEW business preparation takes an actual C6 generation and issued
same-project template/activity/insertion/row responses, not a supplied manifest
or read plan. ALL original operations including NOOP are re-decoded; the C6
manifest/publication and newly created four business images overlap their
original FD scopes through C6 finalizers. Independent expectations first RED
include substitution after the last inspection and after C6 cleanup; late
failure retains initialized HOLD with zero COUNT/CLAIM, never adoption or
rollback. Counted UNKNOWN cannot recreate these images. The legacy offline
creator retains its existing behavior; default NEW/FIRST/R2 integration and
current formal full/check are still separate, uncompleted requirements.

Owned quota creation now overlaps all four quota originals through its actual
creator folder cleanup and rechecks the issued identity/metadata sources after
the final original graph closes. Independent real OAuth/TLS workflow failures
first reproduce identical-byte RESERVATION replacement and actual issued-read
revocation at cleanup; both must retain INITIALIZED with zero COUNT/CLAIM and
cannot repair or recreate the existing family. Legacy offline behavior is
unchanged. This necessary default NEW boundary does not itself enable sending,
close FIRST/R2/FIFO, approve current full/check or validate a real Cloud target.

Owned History, BUSINESS and quota creation now transfer the actual first
O_EXCL writer FD and its checked final full identity directly into the held
original graph. They do not reopen same-byte replacements as new originals.
The first creator directory stays live through a checked overlapping directory
capture; actual file identities/bytes and complete names freeze before creator
cleanup. History/quota graphs outlive that cleanup; BUSINESS shares the real
C6 graph and outlives its finalizer. Fixed RAW bounds remain 2 MiB and BUSINESS
16 MiB, while wire/manifest remain 1 MiB; no caller-selected limit or verifier
is added. Three independent real OAuth/TLS workflows first reproduce the
write-to-reader replacement failures, plus independent direct first-FD/bound
and no-reopen checks. Interrupted images remain retained HOLD, count0 and zero
CLAIM, never repaired/adopted. This closes only this necessary creation seam,
not default NEW/FIRST/R2/FIFO, current full/check or real Cloud acceptance.

Actual creator-directory close interruption is also covered by independent
owned History and quota workflows. Both first reproduced leaked original FDs;
cleanup now attempts every remaining owned graph even when the creator close
raises a BaseException, and rethrows the same primary interrupt rather than
masking it with a later verification or cleanup error. Borrowed BUSINESS/C6
graphs remain owned by their outer finalizer. Existing count, CLAIM, immutable
bytes, RAW bounds and legacy offline expectations remain unchanged. This is
local cleanup evidence, not power-loss, real-device or current full proof.

The fixed dedicated-quota overlap now duplicates the actual ALL pending quota
directory/image FDs before strict mixed accounting exits. Its first yield is
after every old strict finalizer and quota close; it checks original issued
identity/metadata provenance and immutable quota bytes throughout real native
count changes, without reviving the closed count/namespace snapshot. Legacy
visible-only and strict readers retain their existing contracts. No caller
unit, completeness flag, inventory, FD, budget or verifier is accepted; the
overlap retains the fixed 16 MiB unique-image bound. Independent direct refusal
and real C6/COMPLETE/APPLIED/key + OAuth/TLS workflows cover actual reserved
count with originals still live, identical-byte rebind at the last strict
finalizer and issued-read revocation at overlap cleanup. This quota-only graph
does not itself retain ALL other catalog/C6/FIFO originals or grant G1 send
permission. The native writer must separately supply those real protected
boundaries; default NEW/FIRST/R2 integration and current full/check remain open.

The fixed native count path can borrow its already-live original catalog
selection instead of issuing a second catalog graph. The public issuer remains
non-nestable. Borrowing requires the actual registry/token/owner, binding,
selected unit, process and thread, with the original graph checked on entry,
inside and exit; another member alone cannot change the selected writer.
Independent direct expectations first RED cover no second issuance, different
selection/owner refusal before count, and closed/copied context refusal. A real
C5/C6 ETH/IB workflow holds the outer catalog across fresh original reads,
COUNT, CLAIM and the fixed local encrypted request. This immutable catalog
overlap does not by itself retain every mutable OTHER family continuously
between COUNT and CLAIM, close FIFO/default NEW/FIRST/R2, or establish current
full/check or real Cloud acceptance.

The private last-catalog-unit COUNT/CLAIM holder now pins ALL shared old
families before count interpretation, including OTHER mutable journals and
the selected original dispatch prefix. Three raw graphs share one fixed
16 MiB unique-image budget; only the actual creator may append one derived
ATTEMPT and one CLAIM, plus first dispatch HEADER/INITIALIZED when absent.
New readers capture exact identities/bytes while exclusive writer FDs remain
live. Original project/C6 and OTHER APPLIED/key or committed UNSENT checks
remain separate necessary gates, not supplied settlement flags. Actual FIRST
and R2 wire holders retain this graph through consumption, child checks and
exit, without changing count, UNKNOWN, wire, cadence or FIFO expectations.
Issuance requires the same live ContextVar/registry/process/thread and owners;
reset failure revokes issuance without bypassing cleanup. Semantic finalizers
finish before the raw graph's last check and newly acquired owners close last.
Independent direct and real mixed-project workflows first RED cover normal
handoff, identical-byte OTHER rebind after COUNT and after project finalizers,
first creator fstat refusal, foreign FD reuse and opaque-context revocation.
These are local necessary handoff/cleanup proofs, not full REQ7, default
NEW/FIRST/R2 integration, current full/check, real Cloud or power-loss proof.

The same private COUNT/CLAIM holder also receives an already issued live ALL
write-aware graph. A nested receiver must use the identical writer, spreadsheet
owner and unit plus the same binding; it borrows the original verifier without
reopening paths, issuing another graph or deriving another next-count allowance.
Entry and exit recheck the receiver identity and original graph. The original
issuer keeps its key, budget and cleanup responsibility; an exited/copied
context, changed arguments or raw original rebind cannot become fresh issuance.
Operator interruption stays the primary exception while exit validation and
owned descriptor cleanup still run. Independent initial RED and direct tests
cover no reacquisition, foreign arguments, revoked contexts and interruption;
the actual protected ETH/IB C6/OAuth/TLS FIRST workflow retains outer ALL
originals across COUNT, CLAIM, the fixed request and cleanup. This does not solve
default selection, foreign-owner lifetime, G1 admission, NEW or the current
full/check gate; the old R2 cadence, deadlines and immutable-wire tests remain
necessary and unchanged.

The fixed default input receiver now locates the genuine ALL-last unit from
original project origins/C6 while retaining newly acquired foreign project
owners beyond both semantic primer finalizers. Existing ACTIVE owners remain
borrowed. A locator is not evidence or permission: the strict current input
scope independently joins one actual prepared row and passes that exact unit
object to the write-aware ALL holder. Business/quota cleanup and ALL semantic
and raw finalizers run while original cycle/policy/W1 holders remain live;
foreign-owner cleanup runs last. No closed primer/core verifier is reused.
Independent direct RED covers original foreign lock continuity, caller
selection/unissued refusal, non-current ALL-last refusal and exact primary
interruption. A genuine ETH/IB protected-worker/C6/OAuth/TLS workflow observes
the actual graph after strict closure and checks live original cycle/source
guards outside production HOLD sanitizers at the final ALL boundary. The old
quota orchestration test keeps all interruption/read-revocation assertions;
its synthetic selection prerequisites are not native-owner proof. This input
edge still refuses before COUNT/CLAIM/send. G1/NEW/FIFO admission, complete
REQ7 integration, current full/check and REAL_ENV remain unproved.

The same fixed receiver is also a private live context for the remaining
default dispatch composition. It yields only the actual selected row, source,
settings/W1, issued responses/authentication, dedicated quota observation and
genuinely overlapping business images, after the old strict readers complete.
The old business guard remains CLOSED and cannot be revived; only the new
original image verifier works until its own exit, then rejects with its typed
HOLD. The old input-only wrapper delegates exactly once and still never counts,
claims or sends. Direct expectations retain the original quota-before-strict-
close contract and reject caller unit/verifier/permission labels. A genuine
two-panel dedicated-quota/C6/OAuth/TLS workflow observes live issued reads and
images, both complete context exits, and typed post-exit revocation outside
production sanitizers. None/STOP quota is not admission, and a yielded packet
must never be retained as authority for a later launch. Default G1/FIFO/FIRST/
R2 execution and whole REQ7/full/check/REAL_ENV remain separate open duties.

The uninstalled fixed default dispatch driver now composes that actual live
receiver with original FIRST or shared R2 and the existing counted mutation
launcher. Only the selected row's original unit and complete dedicated quota
observation may reach COUNT; STOP/visible-only/incomplete quota and exhausted
counts still refuse. Response/authentication identities, original deadlines,
all semantic/image finalizers and primary operator interruption remain intact.
Independent direct tests cover selection/refusal/finalizers; the genuine ETH
and IB C6/OAuth/eight-read/TLS401 workflow verifies one COUNT/CLAIM, retained
UNKNOWN, actual child termination and all original business/quota FD closures.
The durable dispatch namespace remains exactly HEADER/INITIALIZED/CLAIM-n,
not an invented dispatch-started marker. The old zero-count worker workflows
remain unchanged; this private driver is not installed as default sending.

Original business-image acquisition performs a complete LIVE check before and
after capturing the actual nine descriptors, retaining all later explicit and
exit checks. FIRST/R2 source replay additionally has a bounded private scope
for continuously held original regular-file FDs: every use verifies the actual
name/inode and rereads all current bytes; no digest, qualified result, deadline
or permission is cached. The ordinary directory-only reader still opens its
leaves normally. Independent direct and real converter/analyzer/receipt tests
cover in-read drift, same-byte new inode, first-stat failure, recycled foreign
slots, interruption and descriptor overflow, with conditional owned cleanup.
These are local receiving/composition evidence, not complete REQ7, default
NEW/G1/FIFO, current full/check, Cloud or power-loss proof.

The private R2 driver now retains the same immutable catalog/origin graph as
FIRST, using the existing fixed-selection write borrower when an actual outer
issuer already holds it. Every borrowed use still checks all held stat/bytes,
owner, registry and namespace; mutable COUNT/CLAIM, source qualification and
actual issued deadlines are independently reread, never cached or extended.
The initial native FIRST-to-R2 test refused after the real read deadline;
failure-only diagnostics identified expiry, rather than assuming load from an
isolated PASS. An independent direct test was initially RED for the missing
retained scope. The genuine ETH/IB workflow now obtains a new OAuth/eight-read
set for R2, retains the original WIRE, records COUNT/CLAIM 1 then 2, and keeps
both HTTP401 responses UNKNOWN with confirmed child/FD cleanup. Its interval
fixture supplies only elapsed boot/monotonic time; the actual shared admission
opportunity still validates and pairs the count. Original first/exhausted,
source drift, read-expiry and receipt-rebind expectations remain unchanged.
This driver is still uninstalled: default NEW/G1/FIFO, whole REQ7 and current
full/check remain open. The old read-only worker tests retain their original
expectations, relocated into a shared fixture with retry mode disabled.

The nonallocating catalog preparation now retains ALL earlier catalog/C6/
settlement originals under the actual project and spreadsheet owners without
creating an NV family or inventing insertion keys. The original source
compiler binds that live preparation to the same writer, receipted generation,
publication and sheet. Switch and all-update ETH/IB Cabling register exactly
once through actual C6; Cabling missing keys must still use the original NV
allocator, never this scope. Both legacy NV registration entrances reject the
new preparation, and its append requires the actual sealed C6 origin.
Settings audits without NV still require their actual allocation originals and
outside anchor; absent or replaced allocation cannot become a legacy unit.
Independent tests first refused unsupported compilation/legacy entrances and
audit readback. Genuine protected three-panel workflows check exact update
coordinates and preread digest, preserved IDs/WIRE, no NV/count namespace,
another real live writer refusal, unique C6 registration and a fresh strict
reader's same-process original readback (not an independent cold-process
restart). Existing mixed-insert and allocation-corruption tests remain intact.
The production paths already have direct rules and the multi-script
`req7_protected_source_native_nv_catalog_c6_originals` workflow mapping; no
ignored inventory or approval exception is added. This is a preparation seam,
not installed default NEW/G1/FIFO, overall REQ7, a current full/check proof or
permission for real Cloud/SSH/device operations. REAL_ENV remains NOT RUN.

The terminal prod-cycle lane now installs the fixed original FIRST/R2 driver,
not the compatibility read-only consumer. It accepts only the actual cycle
store and retains the original target, writer, spreadsheet and cycle owners
through reconciliation, independent UNSENT disposition, dispatch and C25
finalizers. CONFLICT and count-six UNKNOWN stop before dispatch. No caller
unit, clock, callback or send flag is introduced. The compatibility entry and
its existing zero-COUNT workflows remain read-only.

Independent RED/direct and genuine protected ETH/IB C6/OAuth/TLS workflows
cover FIRST and historical-four-read-to-identical-R2, as well as historical
CONFLICT stopping before another COUNT/current eight reads and actual
COUNT-then-read-expiry retaining UNKNOWN without CLAIM/send. The latter keeps
the original successful quota/cycle finalizer checks and nine-FD cleanup;
it does not infer success from a mocked completion. No fence with the exact
unchanged original History is narrowly UNKNOWN, never COMPLETE or permission;
partial append, missing audit, present fence with missing rows, foreign fence
and original drift retain the existing CONFLICT/refusal expectations.

Terminal transport observations are published only after all outer finalizers
succeed. UNKNOWN/rejection and unproved HOLD have fixed read-only states in
the authenticated CGI and generated browser. An old APPLIED prefix cannot
mask a new attempt's HOLD, and a durable sixth attempt displays exhaustion
without claiming remote COMPLETE. The cache never becomes another send permit.
The native fixture borrows already-held actual owners; it does not prove
independent first acquisition or cold-process restart. Earlier paragraphs
describing an uninstalled private FIRST/R2 driver describe their historical
milestones, not this new terminal seam. Default NEW bootstrap/allocator,
whole REQ7, current formal full/check, Cloud/device/power-loss and REAL_ENV
remain open. Historical dedicated-table/same-Cloud-project confirmation is a
deployment premise, not runtime or full proof. Approval ledger is runner-only.

The first-catalog reconciliation seam now observes absence only beside the
actual existing enrollment originals. All three images are pinned before its
semantic inspector, and the same owner, exact namespace, bytes and full stats
must survive that reader and the final actual owner checks. Missing/partial/malformed
enrollment, an interrupted catalog witness, same-byte replacement or a late
witness (including at the final sheet-owner return boundary) fail closed. It never
creates enrollment, catalog, NV, COUNT or CLAIM, performs OAuth, proves remote
nonce mirroring, or returns a NEW permit. Existing catalog families still use
the complete original reconciliation path; no typed HOLD is swallowed as first
use. Independent direct and actual writer/spreadsheet/enrollment/catalog
workflows cover this zero-write observation. Default NEW compilation and
registration, first-use remote provisioning, whole REQ7 and current formal
full/check remain open; no existing assertion or approval is removed.

Native preparation can now borrow only its own original, already-closed ALL
delivery handoff for a read-only K scope. The actual project writer and held
spreadsheet owner, unique retained prior-delivery raw graph, current settings
FDs, preparation and opaque issuer must remain identical at every read. No
caller event list, cached K or reentrant sheet lock is accepted. Foreign writers,
unissued/revoked/copied contexts and revocation during actual chain validation
fail before a K result returns; map deletion cannot fall back or permit set-K
or completed-pair mutation/cleanup. Revocation precedes settings finalizers,
and the preparation/raw graph is checked again after those original FDs close.
An actual finalizer's unissued delivery tail refuses scope return and preserves
the original interruption and faulted files. First use without an old delivery
keeps the ordinary strict K contract. Independent direct and genuine archived
delivery/C6/NV/catalog workflows cover this leaf handoff, not the still-open
qualified-source/current-cycle receipt/compiler/default NEW integration or
whole REQ7/full/check. No automation or field case is removed or weakened;
REAL_ENV remains NOT RUN and the approval ledger remains runner-only.

The NEW native Switch compiler now derives immutable business values once
inside its own two complete original manifest replays. The pure builder does
not acquire sources, accept a caller manifest through a public compiler, cache
qualification across calls, or confer ownership/send authority. Both manifest
boundaries, four original C6 observations, actual nonallocating preparation,
both owners, original business/History images and final capacity checks remain
required. Standalone source, legacy Switch and Cabling compilers keep their
existing replay boundaries. Independent RED/direct and genuine archived
delivery/current C6/native preparation workflows cover the literal boundaries
and original-template drift after pure derivation: compiler refusal precedes
registration, and an unregistered preparation's cleanup HOLD cannot substitute
for that refusal. Actual project authentication, seven issued reads, their
unchanged deadlines and receiver/finalizer tails are separate verification
obligations; this optimization's local related PASS is not their proof or a
current full/check. No automatic or field scenario is removed or weakened;
REAL_ENV and whole REQ7 remain open, with runner-only approval.

The current native Switch receiver obtains actual project authentication and
seven fixed issued reads before same-changeset compilation. Its unchanged
issued-read/authentication tail runs after the actual K/settings, raw-source
and retained-directory finalizers. Local normal and post-K/settings issued-read
revocation workflows check actual successful compilation, all seven native
reads and zero registration/count/CLAIM/WIRE change on refusal. An initial
negative failed before this boundary because its literal mode lacked the
fixture's root-template preparation; independent RED/direct caught that
prerequisite, and only the mode registration was corrected. That early ERROR
is not the expected refusal. These local receiver results do not close the
outer preparation/owner finalizers, default NEW driver, G1, whole REQ7 or
current full/check, and REAL_ENV remains NOT RUN.

The native nonallocating preparation now keeps the receiver's original issued
read/authentication packet in a context-owned, one-time bound tail. After its
ACTIVE preparation registry entry is revoked (not its durable catalog entry)
and all settings/catalog/source/delivery finalizers have been attempted, a
fixed verifier checks the original issuer, unchanged
deadlines, actual manifest outcome row count and both still-live outer owners.
The tail also checks the same state slot, bound state and packet object after
all delegated guards return; equal-valued replacement is not continuity. A
missing/replaced slot cannot downgrade a bound invocation to never-bound
standalone compatibility. Strong references are cleared only after that tail,
including failures; an original interruption remains primary and all other
owned cleanup slots are still attempted. No acquisition, refresh, caller
callback, row plan, permission or reopened K/raw scope is added.

Independent RED/direct tests cover the original state and cleanup contract.
The genuine current-cycle Switch workflow covers normal registration and
revocation of the actual original read only after registration, preparation
revocation and original FD cleanup; it records the target verifier's own HOLD
so an unrelated cleanup failure cannot produce a false positive. The initial
stale-module fixture failure is preserved separately from the phase-proven
RED. These tests do not close the final outer-owner boundary, bootstrap,
three-sheet/default NEW/NO_SEND driver, whole REQ7 or current full/check.
No existing automatic or field scenario is removed, skipped or weakened;
REAL_ENV remains NOT RUN and approval remains runner-only.

The same fixed Cabling receiver's WIRE branch is also exercised with actual
current C5/C6, OAuth and all six issued reads for each one-row ETH/IB fixture.
Only the original G/M/N/S/T update runs and their History/fence are compiled;
the existing A IDs and operator cells are not written. Independent live C6
registration then creates the unique catalog/project origin and reads it back
under the real owners. All prior original files and pending settings outbox
remain unchanged, with no NV reservation, attempt journal, COUNT or send.
This additional positive regression needed no further production change and
is not represented as a new failing reproduction. It closes this receiving
edge only, not insertion allocation, bootstrap, default NEW, G1 or full/check.

The fixed current-cycle Switch receiver also supports an actual all-NOOP
NO_SEND result through that same nonallocating preparation. A separate byte
coherence check is necessary only, not source/registration/send authority;
send-intent remains WIRE-only. Only the context's original bound receiver
packet can take the normal unregistered exit. A separate one-time issuance
anchor retains the actual packet/unit identity between verifier calls and is
checked again after delegated guards; an equal packet/unit or same-unit-id
NO_SEND substitute is not a new issuance. Both strong references are revoked
only after final cleanup verification. Its state must remain exactly
zero-write before and after delegated original issuer/authentication guards
and after all preparation cleanup: no registered=True fiction, catalog,
origin/indexed unit, additions, append, NV, intent, COUNT or CLAIM. All original
source/C6/K/compiler checks and unchanged read deadlines remain in force.
Settings audits stay pending; there is no audit-only request or empty fence.

The fixed nonallocating Cabling receiver now derives one ETH/IB target from
the genuine preparation identity and the actual current C6 generation and
publication originals. It accepts no caller family, qualified source, row,
plan or compiler callback. Shared source/K/receipt and issued-read scopes
remain the same as the Switch receiver. Every manifest key must have exactly
one original active row; missing/Closed or row reuse refuses before History,
compilation or NV allocation. Original A IDs are observed, never rewritten.
All-update WIRE registration remains a separate live operation.

An all-NOOP Cabling compiler may make a necessary read-only NO_SEND
observation only in the genuine nonallocating preparation. Empty-wire
coherence, exact original enrollment nonces and source identity, unchanged
preparation issuer and full zero-write state are checked before and after
the final delegated graph guard. Independent RED showed that the graph
guard alone could accept a late registered/origin/additions change; that is
not successful NO_SEND. NV preparations cannot cancel, and append/origin
entry points remain WIRE-only before modifying any record or namespace.
The original issued packet/anchor tail verifies the actual derived sheet's
fixed read roles after every preparation cleanup, without renewed deadlines.

Independent direct and real fresh C5/C6 + OAuth/TLS workflows cover both
Cabling families, original row revocation after cleanup, and inactive-key
refusal with target-stage facts kept outside sanitized exceptions. Literal
business expectations come from authored source fixtures and the existing
compact-JSON key digest contract, not the compiler's ACTION/WIRE output.
The earlier fixture mistakenly hashed a newline-terminated journal image;
its failed logs are retained separately from the missing-factory and
WIRE-only-observation RED. No test/assertion/timeout or field scenario was
removed or weakened. These are local receiving slices, not insertion/NV
factory integration, bootstrap, the default three-sheet NEW driver, the
final outer-owner boundary, G1, whole REQ7 or current full/check proof.
REAL_ENV remains NOT RUN and approval remains runner-only.

The fixed Cabling NV receiver takes only a genuine live NV preparation
and derives its unique target from actual current C6. Both ETH/IB activity
images are acquired through actual project issuers and compared separately
with the complete retained original columns. No caller keys/plans or new
reservation are accepted. Only this NV branch may append missing/Closed
keys with their original reserved IDs; the nonallocating branch still
refuses them. Direct and fresh C5/C6/OAuth/TLS workflows cover both families,
literal NV40000 insertion above an independently authored NV39999 seed,
and actual other-column drift to NV49999. Target-stage refusal is proved
while both issuers/authentication remain valid, before insertion/History/
compiler/registration, with original reserved IDs and NV bytes unchanged.

The receiver binds its actual WIRE unit, both column issuers, remaining
read roles, authentication, reservation observation and outer owners once
to the preparation's original context-local packet. Semantic preparation
authority is revoked and every original cleanup is attempted before the
final read/authentication tail, with unchanged original deadlines. Packet,
observation and column coherence are checked before and after delegated
guards. Actual post-cleanup other-column issuer revocation refuses without
undoing completed registration or changing original IDs. Independent RED
also caught a final authentication-return column mutation missed by an
entry-only body check. NV remains WIRE-only and cannot cancel as NO_SEND.
Unbound standalone preparations keep their existing contract. An original
once-issued context marker survives clearing the packet and record slots,
so a previously bound receiver cannot be downgraded into legacy; the marker
is not cancellation, a new issuer or send authority. Source/
fixture errors, target RED and complete GREEN remain distinct evidence.
These are necessary local receiving/cleanup slices, not bootstrap, default
three-sheet NEW, final outer-owner cleanup, G1, whole REQ7 or current
full/check. Existing assertions, deadlines and field scenarios remain.

Default native preparation also has a fixed current C6 locator discovery
entry under the real project writer, before acquiring the outer sheet owner.
It replays actual current C5/K/W1 and protected C6 twice while original
cycle/history/source holders remain live, then completes every finalizer.
The underlying live context also keeps those actual holders across its
consumer body and repeats the complete snapshot after the body. A real
RECEIPT rebound after yield must refuse before successful context completion;
the simple closed reader is only a wrapper which returns labels after that
context has fully closed. Neither API yields a verifier or source permit.
Only plain generation/publish labels leave this scope: not qualified-source
objects, closed verifiers, enrollment/NEW eligibility or send authority.
Each later preparation/compiler must independently revalidate its genuine
current originals. Missing-factory direct/fresh-workflow RED is retained;
the initial combined run also exposed source readers importing a temporary
K spy before rejecting an unissued writer. Entry now rejects that writer
before source-provider imports. Actual same-byte RECEIPT replacement after
its genuine identity read refuses at the held history guard and preserves
both original and replacement, without returning a locator prefix. This
negative was initially PASS with the retained holder contract, not invented
RED. The helper is not yet the installed default NEW driver or bootstrap.

The fixed current Switch creator now derives its generation/publish from that
live context, issues its own initial template-identity read, creates a genuine
nonallocating preparation and invokes the fixed receiver/compiler. WIRE is
registered against the original current C6; NO_SEND closes with zero new
catalog/NV/origin/attempt/COUNT and unchanged pending K outbox. Only a report
tuple leaves this entry, never a compiler, guard or send permission. The
original initial read/authentication is rechecked after preparation cleanup
and after all source-holder finalizers while the external owners remain live;
it is not replaced by a fresh read, reopened K or renewed deadline. Independent
missing-entry RED and actual post-source-cleanup issuer-revocation RED are
retained. The WIRE fixture error is separately diagnosed: changing evidence
must preserve its stable MONITOR business-key prefix, otherwise it tests
missing-key insertion instead of the intended active-row update. Literal
two-row L-only WIRE/History expectations are unchanged. These direct and real
protected C5/C6/OAuth/TLS flows do not close bootstrap, the three-family default
NEW dispatcher, final external-owner cleanup, G1 or current full/check.

Fixed ETH and IB creators now use the same unchanged current-source/initial-read
tail with their own constant family entrance; callers provide no family,
generation, keys, plans or compiler. Actual active-row receivers independently
resolve the genuine prepared unit against current C6 and keep the original NV
IDs. All-NOOP closes zero-write; all-update WIRE registers its unique original
unit with literal G/M/N/S/T runs and no NV allocation or attempt. Both actual
families retain the post-source-cleanup initial-issuer revocation test. These
are nonallocating creators only: missing/Closed Cabling still HOLD at the
receiver, never silently substitute a row or an ID. Runtime selection of the
genuine NV allocator, bootstrap/default NEW, final outer-owner/G1 and full/check
remain OPEN, not discharged by these local creator reports.

The Cabling creators now derive their necessary keys from actual protected C5
before bounded reads, classify the owned target activity image and, only for
missing/Closed keys, acquire the other owned Cabling column and enter genuine
NV preparation. No caller keys, ID/high-water, row or allocator fallback is
accepted. Both original full A-column bodies (including Closed/unrelated IDs)
feed the existing durable allocator; the fixed receiver independently compares
its actual two columns to the retained originals and registers the same C6.
The initial identity and selection-column issuers are checked after all
preparation/source cleanup without fresh reads or deadline renewal. Active-row
creation adds its necessary target-classification read but never creates NV;
the old standalone receiver expectations are unchanged. Current Closed factory
refusal is retained as initial RED; missing-key and selection-issuer negatives
are additional independent regressions, not invented REDs. Bootstrap/default
NEW, final external-owner/G1 and current full/check still remain OPEN.

Independent direct tests reject incoherent empty-wire/audit/zero-write state.
The archived fixed-creator continuation has a separate dual-owner locator;
the original strict locator and ordinary K reader are unchanged. Actual ALL
COMPLETE/DELIVERED originals issue initial read-only K, with exact completed
context/guard enrollment. Both K and completed identities revoke before the
new preparer's ALL pin. The initial raw graph overlaps that actual pin; only
then may native preparation proceed. The actual preparation's delivery raw
stack moves to the outer source scope and its original freeze still runs
before preparation revocation, so raw delivery checks follow source/settings
cleanup. No closed K/ALL/preparation verifier, caller events or copied budget
becomes a permit. Independent missing-entry RED and the exact registration
defect RED are preserved separately from complete actual workflow evidence.
This continuation remains under local verification; its report is not send,
G1, final external-owner, bootstrap/default NEW or current full/check proof.

The real fresh three-panel C5/C6 + OAuth + seven owned TLS-read workflow
covers both normal all-NOOP exit with original files/outbox unchanged and
actual original-read revocation after the preparation registry and FDs close.
The negative records the target verifier's own HOLD, not an unrelated cleanup
failure. Fixture setup/order/canonical-module errors are preserved separately
from the phase-proven pre-fix RED. This does not close bootstrap, Cabling or
the default three-sheet NEW driver/final outer-owner boundary, G1, whole REQ7
or current full/check. REAL_ENV remains NOT RUN; no scenario is removed,
skipped or weakened and the runner alone may update approval.

REQ7 fixed Switch/ETH/IB NEW-originals bridges keep creation and preread stages in
one fixed call. It retains the actual compiler's issued images, finishes the
entire native locator/preparation cleanup, then creates GLOBAL, History,
BUSINESS and quota under independent live C6 originals. It never refreshes
reads, adopt an existing pending unit, loosen namespace guards, COUNT or
sends. The new actual workflow supplies a real journal-bound remote nonce
pair; older empty-metadata candidate fixtures remain unchanged. Direct tests
and actual active-row/NV-insert workflows are required; default NEW, final full/check
and REAL_ENV remain separate unclosed work.

The actual compiler retains its original four-field BUSINESS response mapping
in a same-call, once-bound private data packet. NV's other-column read and
None-row insert stay distinct; the original NV/nonallocating read-tail shapes,
source/column checks and cleanup deadlines remain unchanged. Closed native
verifiers never become permission for the independent preread stage.

The fixed terminal worker now invokes the next current native NEW selector
before independent FIRST/R2. ALL counted UNKNOWN blocks NEW without OAuth or
current-source reads; zero-count historical settlement needs the actual FIFO
reader's full UNSENT witness/pair, joined to mixed settlements inside live
scopes with a complete non-overlapping ALL partition. Exact first catalog
absence reuses the three-original local enrollment check, not a lock/name
subset. All readers close before creation and no closed verifier is adopted.
AUTO derives actual family presence in Switch/ETH/IB order inside the current
C5/C6 locator; same-call successful NO_SEND alone advances, generation/publish
and family drift refuses before reads/writes, and first WIRE stops. Creation
HOLD never falls through to dispatch after a partial prefix. FIRST/R2 still
reacquires and validates its own original graph; selector results are not GO.
Whole terminal NEW-to-FIRST/cold-bootstrap/archive composition, current full/check and
REAL_ENV remain unclosed; no existing test is removed or weakened.

The actual new Switch and ETH NV-insert originals now also feed the independent
fixed FIRST driver in local multi-script workflows: one original COUNT, one
CLAIM and one bounded TLS request with exact WIRE, returning UNKNOWN without
manufacturing COMPLETE/APPLIED. NV None-row BUSINESS mapping stays unchanged.
The fixture refreshes retained inventory before issuing owners, just like its
existing preread/quota refresh; unissued or earlier registry objects never
become accepted production tokens. Actual current fourteen-sheet identity
requires Whitelist 112 (Dashboard 104); decoder equality and original tests
are not relaxed. This local composition is not complete terminal/bootstrap/
archive proof, nor current formal full/check or REAL_ENV acceptance.

Archived delivery raw reception retains each exact named edge once across
LIVE readers, with continuously held duplicates keyed by full original stat
and descriptor flags. Equal bytes on different inodes/names do not merge;
conflicting captured expectations or changed retained flags refuse before
reuse. Namespace additions, original deadlines and every semantic admission
remain unchanged. Independent RED/direct and C25 allocation regressions cover
this storage-only deduplication. The actual archived NEW-to-FIRST workflow is
still OPEN: its original template-identity read exceeded its unchanged deadline
before FIRST. Local regression PASS is not that workflow or full/check proof.

The genuine native preparation K reader preserves the existing four-graph
contract: P-S-P-parser-P-S-P, including settings-return drift. A proposed
two-pass pure-parser reduction was rejected because it contradicts the
original independent workflow expectation. Its local candidate observations
are not current-tree closure. Direct and real archived-preparation workflows
retain original/budget/issuer/finalizer refusal checks; no existing expectation,
deadline, namespace allowance or verification boundary is reduced.

Native NV replay reuses only an exact directory/file capture in the same LIVE
catalog graph; it still rereads current bytes and checks full stat and names.
Catalog's initial marker-only capture acquires other existing members normally,
never refreshing or repairing the marker. The independent retained-inventory
BorrowedOriginals reader keeps its original path. Actual complete/partial-capture
tests and the entire NV module guard this storage change, including unchanged
creation, cold lineage, count, inventory and same-byte-replacement expectations.

Native ALL-delivery semantic discovery also keeps one immutable capture for
each same-graph named edge. Actual initial RED observed 15 stored directory
records for 13 edges and 58 file records for 54 edges. The fixed discovery
captures delivery HEADER, anchored allocation originals and admitted C6 files
once, but each repeated request freshly checks original named/fullstat/names/
bytes, descriptor flags before and after I/O, and the original sealed budget.
An absent, conflicting, removed or changed original is not reacquired or
refreshed. Ordinary catalog/NV capture and mutable append, COUNT and settings
paths do not opt into this immutable storage mode. The original four K graph
checks and all semantic/finalizer boundaries remain unchanged. Independent
direct and real archived-creator discovery tests cover this storage slice;
their success cannot establish complete NEW-to-FIRST, full/check or REAL_ENV.

Fixed NEW original preparation now owns one actual original source/ancestor
FD scope across locator acquisition, receiver, preparation finalizers and
independent preread creation. The inner receiver only borrows that same live
PID/thread/ContextVar pair; partial, foreign or revoked holders refuse. Ordinary
standalone receiver issuance and pipeline nested-issuer refusal are unchanged.
Each digest still reads current bytes, and current named/held original checks,
descriptor bounds, qualification, four K graphs and original read deadlines
remain intact. After owned source and directory cleanup, both WIRE and NO_SEND
recheck the actual original initial/selection/receiver reads and authentication;
no closed preparation/K callback or renewed observation is adopted. Independent
direct RED and actual archive-to-NEW entry RED cover the missing scope; control
order tests are not genuine issued-response proof. The first workflow attempt's
obsolete-module fixture ERROR is retained separately, not counted as valid RED.
Complete archived NEW-to-FIRST and current full/check remain OPEN.

Native qualification now uses the exact Switch windows just queried by its
own observed projection for the following response-independent pure derivation.
The original projection API still queries both families itself; the final
public projection, protected IB and completed-cycle replays remain independent.
Four composed Switch/IB legs, original per-K four-graph verification, actual
archive role/completion hashes and source deadlines are unchanged. No caller
window, cached eligibility, permission or renewed source observation is accepted.
Independent direct RED and actual worker/emitter/IB three-panel workflow RED
precede this change. A real archive changed after the initial projection pair
must be refused by the final genuine source reader, not just an object comparison.
This query reduction is not proof of timing closure, complete archived FIRST,
formal full/check or REAL_ENV acceptance.

The live source-file borrower now makes one complete fresh ancestor walk per
acquisition. Its directory chain already checks every named/held ancestor on
both first acquisition and reuse; only the immediately repeated walk after
pure tuple unpacking is removed. Original parent and leaf checks, actual byte
reads, borrow/chain exits, scope verification, revocation and conditional FD
cleanup remain unchanged. New independent direct and real analyzer/receipt
workflow tests first fail on the duplicate walk; both complete pipeline test
modules then pass (65 tests). This is not a qualification cache, deadline
renewal, reduction of any K graph or proof that archived NEW-to-FIRST has closed.

Archived FIRST source input reception now has a fixed internal read-only K
scope under the actual existing project and spreadsheet owners. It acquires
the same genuine ALL completed-delivery, settings and raw original holders as
creator discovery, but yields no creator bridge and rejects any retired,
received or attached creator state. Its last K/settings/raw checks outlive
source and C6 finalizers; no-claims discovery and ordinary K remain strict.
Two independent direct tests first fail on the missing entry; the 59-test
direct related run passes. These control-order tests do not prove genuine ALL
or actual FIRST reception. The new real archived FIRST input-core workflow
still errors in its preceding NEW phase: the original initial identity read
expires after business preread (1.173422416 seconds past the original deadline).
FIRST is not reached, so its acceptance and subsequent COUNT-aware K/source
reception remain OPEN. Original reads are not renewed, and no unchanged full
rerun, approval ledger or formal full/check proof results from these tests.

Archived creator local manifest derivation is now moved before its earliest
bounded identity read, while the actual creation-locator K/C5/C6 holders are
LIVE. Only immutable plain manifest bytes/id and current receipt relations
cross the existing raw bridge into the genuine preparation record. This is
not a qualified-set cache, K/nonce issuer, caller manifest parameter or skip
flag. The receiver independently acquires/requalifies actual current inputs
and checks exact canonical bytes, SHA, metadata, all source fields, operations
and selected receipt relation. Partial/replaced/drifted migrated slots refuse,
not fall back. Standalone no-bridge compilation keeps its original order.
The actual compiler's two fresh manifest freezes and original receipt/nonce,
four K graph, source/finalizer/read/authentication checks remain unchanged.
Two pure-data direct tests first fail; a 61-test direct/control regression then
passes on its recorded tree. These are not real issuer acceptance or deadline
closure; the strengthened archived NEW-to-FIRST workflow must verify that
plain intent was produced before the first actual read, without any renewal.

The actual received bridge/old-graph relation, not presence of optional record
fields, now selects the migrated branch. ENTRY and END require the same live
registry, owners and exact intent object in both bridge and preparation slots;
deleting both slots cannot downgrade to standalone. Independent registry/control
RED and related tests cover that selection; a real archived bridge/preparation
fault workflow removes both slots before compiler reads or registration.
FIRST typed refusal also retains its original exception as suppressed internal
context for bounded diagnostics: public message/cause/traceback suppression stay
unchanged. Its independent direct RED reproduces the prior information loss.
The previous actual NEW returned and FIRST input failed before yield; that error
is unresolved and cannot become PASS from direct/control results. No ordinary
full proof, current approval or REAL_ENV success is implied.
The intent tail is registered before the source borrower so LIFO closes the
actual compiler K/C6/source and source borrower before checking intent and then
the original issued reads. A static order test first fails on reversed order;
65 direct/control tests subsequently pass. An additional real archived workflow
changes both intent slots after the actual source borrower exits while prep and
bridge remain live. Static/control results alone do not prove that last boundary.

On the recorded exact dirty tree, the three real archived workflows completed
with two PASS and one ERROR: whole intent loss at receiver entry and intent loss
after the actual source borrower exits both refuse as required. FIRST input-core
reception still errors during a new original read acquisition, before issuing
that response; its root cause is not established by the launcher’s sanitized
exception. The complete 1061.165-second log and unchanged BEGIN/END identities
are retained. This is not whole FIRST/COUNT, runner approval or full proof.
The synthetic archived FIRST read fixture now delegates the same original
read/supervisor once and temporarily observes exception positions in only those
two original code objects, with line/opcode tracing disabled and at most eight
role/line/type entries. It retains no messages, locals, traceback objects or child
bytes. Nonsecret launch/supervisor/owned-child/TLS/elapsed facts locate failures;
the observer is restored in finally, and clocks, deadlines, assertions and native
responses are unchanged. A bounded diagnostic run, not a full retry, must resolve
the acquisition stage before claiming its cause or modifying any implementation.

The bounded FIRST acquisition diagnostic subsequently records original
supervisor deadline expiry with zero HTTP requests and a TLS-fixture ValueError.
An independent actual high-descriptor test first errors, then exposes a specific
RED: the server's select() rejects original descriptors above its fd-set range.
The fixture now uses DefaultSelector for the same listener/cancellation sockets,
without changing connected handshake/body limits, native client deadlines or
cleanup assertions. Four targeted cases pass: genuine high-descriptor TLS,
preconnection startup, idle cancellation and the original connected-without-TLS
timeout. This deterministic fixture repair does not establish the previous
FIRST's exact failing descriptor or replace a rerun of its actual full workflow.

The archived FIRST observer must be installed at the actual post-reload
dispatch boundary, after the native read fixture is installed. Earlier
pre-reload hooks were replaced by fixture reload; their unexecuted source-order
claims are corrected in the retained evidence, not counted as acceptance.
The corrected actual case records nine original local images before identity,
nine successful native reads, and final freshness refusal. Four source
qualifications each take about eighteen seconds; bounded pre-read profiling
locates most cost in the actual read-only K's four ALL-original graphs.
Neither budgets nor these graphs are relaxed.

All actual current-source scopes now remain LIVE until every unit's fresh
business/continuity and last capacity/originals IO completes. Their original
second source qualifications and complete receipt/cycle/target/owner tails
occupy the last source-replay boundary, after complete original K/W1 comparison.
Only-older selection still executes the independent current-source qualifier.
No early suffix, closed verifier or cached qualification can replace this tail.
New order controls first RED, then related tests PASS; actual archived CORE and
late Switch-archive drift with unchanged K/W1 must independently verify this
composition. COUNT/send, whole REQ7, runner/full/check and REAL_ENV remain open.

The actual archived FIRST input core subsequently passes with nine native
reads and ordinary K still strict after its issuer closes. Whole FIRST then
exposes a distinct positive-fixture defect: historical quota was created by
the legacy constructor without authenticated project provenance. Only that
positive archived-FIRST scenario now creates its quota initially from genuine
OAuth/TLS identity and metadata reads; its literal project-origin assertion
precedes archive. Legacy quota refusal and original-byte preservation remain
unchanged. The corrected whole scenario receives actual dedicated G1, then
refuses before COUNT because the independent source replay uses ordinary K
after outbox archival. The actual late-archive-drift negative still passes.

Each short COUNT/source facts domain now joins the exact LIVE original
COUNT/CLAIM packet before acquiring the original ALL completed-settings K
reader. No original join preserves ordinary strict K; foreign identities
refuse. Both source qualifications, receipt/cycle tails and all K graph checks
remain. The short read domain closes before any ATTEMPT/CLAIM write, so no
strict count snapshot crosses that mutation. Its last original join check
follows issuer revocation and all original finalizers; an interrupted caller
retains its original BaseException if the join is simultaneously revoked.
Three direct controls first FAIL on the absent entry; the interruption case
first ERROR on replacement of the original exception. The resulting 107
GLOBAL/remote direct tests pass on their recorded dirty tree. These controls
do not prove actual ALL intermediate-UNKNOWN reception, complete FIRST or
timing closure; the original whole scenario must still pass. No full/check,
approval ledger or REAL_ENV success is implied.

The subsequent complete FIRST diagnostic observes the second continuity
rejecting an expired original read while all recorded non-clock predicates
remain true and the retained count is still zero. Its traced facts duration
is diagnostic, not an uninstrumented performance measurement. The narrow
completed-source K factory now borrows the actual COUNT issuer's still-held
ALL-project C6 rows and original verifier, rather than constructing that same
graph again. The loan is private, owner/context/record bound and revoked before
the issuer's semantic/raw finalizers; absent joins keep the cold path. Both
source qualifications, strict K graphs and fresh original checks remain.
Four independent registry/lifetime controls first fail on the absent API,
then pass; 113 GLOBAL/remote direct tests pass on their recorded dirty tree.
An initial diagnostic command used a nonexistent test class and reports its
original ERROR; the corrected explicit selection is separately retained.
These are not actual C6, timing or complete-FIRST closure. The real archived
workflow additionally forbids duplicate top-level C6 reconstruction under a
live COUNT join and must independently pass all original count/wire/cleanup
assertions. Full/check, main approval and REAL_ENV remain open.

The first real workflow with that narrow loan still reports one ERROR: the
second continuity check observes deadline expiry, count remains zero, and the
traced facts domain takes 52.795 seconds. This does not close timing or justify
a larger deadline. Independent controls additionally reproduce a tail operator
interruption being hidden by an ordinary body error, and eleven unrelated COUNT
graph checks for eight C6-only rechecks. The loan now preserves operator
interruption priority and checks the original COUNT graph at entry and final
boundary, while every C6 recheck still validates the live join and real original
C6. The new control's two-boundary assertion is evaluated after lexical exit,
not before its final boundary runs; its original premature assertion failure is
retained, with no reduction in required boundary checks. The resulting 115
GLOBAL/remote direct tests pass. Actual whole-FIRST timing is still unproved;
no repeated full, approval-ledger update or REAL_ENV result follows from this.

The source factory and its two immutable delivery/allocation leaves now borrow
that same original ALL C6 only through a genuine registered prior-source
issuer. Every call checks its unique bridge/raw/owner/context relationship,
including after the delegated original verifier; a second bridge inserted by
that verifier refuses. ORIGIN holders and row unit/project/C6-fact alignment,
DELIVERED/C19/settings images, all four K graphs and late raw-only finalizers
remain. No handoff keeps the cold path; the selected COUNT unit is not changed
when an older delivery leaf reads ALL C6. Three absent-entry controls first
FAIL, and a separate second-bridge behavioral control first FAIL; 135 related
direct tests pass. The real workflow additionally refuses cold reconstruction
in those two source leaves. Real FIRST and its unchanged read期限 must still
pass on this candidate; controls do not constitute actual graph/timing proof.

The subsequent three-scope real FIRST still reports one ERROR after its second
continuity check: the issued-read deadline has expired, Count remains zero,
and the facts domain takes 45.945 seconds with global exception tracing active.
A bounded compile-only/literal-call control measures observer overhead but does
not identify how much of that real duration it explains. Normal behavior runs
now leave both acquisition and COUNT tracing off; the existing exception
observers are retained behind an explicit test-only diagnostic option. A new
control initially FAILs on the missing observer scope, then proves default-off,
explicit opt-in, preservation of an external observer and original exception,
and restoration after exit. The synthetic expired-read diagnostic still runs
with opt-in and refuses; it is not actual read evidence. Production deadlines,
all Count/WIRE/cold-reconstruction assertions and original owner checks are
unchanged. One original normal workflow without this fixture's global tracing
is the next bounded comparison, not a full rerun or a claimed timing closure.

That ordinary no-trace run completes with one ERROR and zero Count, with a
35.814-second facts observation. Its public boolean HOLD hides the earliest
refusal, so the preceding traced expiry is not backfilled as this run's proven
cause. Observer overhead is not the sole issue. The next explicit diagnostic
profiles only the genuine facts entry through all its finalizers, retaining
call counts plus cumulative/self times by source file and definition line.
It does not profile normal runs by default, alter deadlines, omit tail checks,
replace original results or constitute normal timing/acceptance evidence.

The explicit facts profile localizes the repeated work: two original source
qualifications cause 129 actual K reads, 527 C19 cold observations and 350516
directory reads in that single profiled domain. The profiled duration is not
normal timing evidence. The narrow repair only loans already-proved C19
semantics inside a genuine COUNT/source/C6 leaf: all existing raw, catalog,
origin, C6, allocation, match, proof, STARTED and DELIVERED checks remain on
every verification. Its actual original graph sync preserves proof-file,
completion-folder and enrollment/History INITIALIZED recovery barriers plus
the original shared parent; entry/retention and final leaf verification still
perform complete cold semantic proof. All other callers stay cold. Two new
real-FD controls initially report three absent-helper FAILs, then prove native
file/folder/parent barriers and refusal of failed sync or same-byte replacement.
148 related GLOBAL/remote/allocation direct tests pass. The real normal workflow
also requires actual C19 synchronization and forbids recursive cold decoding
in the ready intermediate loan; unchanged Count/WIRE/freshness and every
original tail assertion still must pass. No full/ledger/REAL_ENV closure follows.

The next ordinary FIRST still reports one ERROR with Count zero. Its public
HOLD does not identify the original refusal. The first boundary diagnostic
installed hooks before the fixture reloaded GLOBAL; its missing hook markers
make it invalid as cause evidence. The corrected diagnostic binds the current
post-reload module and preserves all original delegates and tails. It observes
the actual receipted facts returning, then the original template-identity read
refusing on expiry while registry, raw input, owner and binding predicates are
true. This is a diagnosed pre-COUNT expiry, not a justification to refresh or
extend the original deadline.

The following narrow repair retains complete cold C19 entry/retention/final
proof but uses its exact recovery-barrier footprint between those boundaries:
both original STARTED files, every GLOBAL journal file including all ATTEMPTs,
History/enrollment INITIALIZED and their directories, six C19 originals and
their completion directory, with the original shared-parent barriers. The
entire held graph, including unrelated C6 images not synchronized in this
subset, is still verified before and after. A genuine read-only prior-source
leaf can use this same intermediate loan before COUNT; its actual cold C6
verifier rechecks the unique original source bridge, owners and false roles
on every delegated call. This also covers the creator's initial read-only
prior-source domain, not a blanket claim that all NEW paths remain cold.
Three independent controls first report missing-API FAIL/ERROR, then prove
the exact FD barriers, sync-error and unsynchronized same-byte-replacement
refusal, and source relation lifetime. 151 related direct tests pass on their
recorded dirty tree. The actual workflow must observe both this pre-COUNT
source domain and the existing COUNT domain, with unchanged wire, freshness,
count, claim and cleanup assertions. Real FIRST, full/check, approval and
REAL_ENV remain unclosed.

That normal workflow reports one ERROR before issuing FIRST reads: its newly
added observer incorrectly requires native K registration while the original
source factory is still constructing its raw graph. The original traceback
locates this assertion, not a production expiry; its shorter elapsed time is
not performance-success evidence. A new observer control first FAILs on an
absent helper, then separates raw source construction/finalization from an
actually registered K with the same context, writer and owner. Three observer
controls pass. The real workflow still requires nonempty observations from
both genuine live pre-COUNT K and COUNT domains; construction alone cannot
satisfy either assertion. All source, wire, deadlines and cleanup contracts
remain unchanged. Its next normal rerun tests this corrected observation,
not a blind full or a claim that FIRST already passes.

The corrected ordinary run again reports one ERROR, now after all nine actual
reads return with original child exit zero and the dedicated-project quota
observation succeeds. Count remains zero; its receipted-facts timing is 14.437
seconds. The public count HOLD still hides this run's earliest refusal, so the
older diagnostic's expiry is not adopted as its proven cause. The observer
phase error is no longer the refusal. A bounded post-reload, no-trace/profile
diagnostic of these same original holders and issued reads is the next step;
there is no full rerun, deadline extension or approval update.

The post-reload diagnostic on that exact tree proves the next refusal: actual
receipted facts return in 14.997 seconds, then the original template-identity
read is expired by 5.027 seconds, while registry/data/writer/owner/binding still
agree. Quota and COUNT are not entered. This is evidence for reordering local
work, not a new deadline or an environmental excuse.

The fixed FIRST receiver now starts an independent source/receipt body before
the nine online reads. Its original core body and all its suffix checks remain.
The existing COUNT graph still enters inside the live core prepared scope,
overlapping its actual originals; it binds the SAME actual selected row/unit,
dual owners, process/thread and original Count packet. A private lexical
registry retains the one-use body, not a returned callback/DTO or cached facts.
The FIRST initial facts consume it under a NEW short source K, execute its
entire original source/receipt/cycle/target/owner suffix, and close that K before
COUNT. Subsequent facts and R2 retain their independent full source reads.
Missing/revoked/foreign or same-value substituted identities refuse; failed
consumption is permanent. Exception cleanup revokes first, attempts cleanup,
and preserves the original operator interruption over a secondary close error.

Four independent order/lifetime controls first FAIL, then pass; a separate
cleanup fault first produces an ERROR when it replaces KeyboardInterrupt,
then the repaired cleanup preserves the original interruption. The full related
175 direct controls pass on their recorded dirty tree. One initial command
used a nonexistent allocation test-class name and reports ERROR; its output
is retained, not counted as a suite PASS. The genuine FIRST workflow now also
observes actual pre-read prefix acquisition and full suffix/new-K closure before
the actual COUNT call, preserving every earlier read/wire/COUNT/CLAIM/cleanup
assertion. Whole FIRST and formal full/check remain unclosed until their own
exact-tree runs; no approval ledger or REAL_ENV status is changed here.

The next genuine ordinary FIRST does cross the original pre-COUNT refusal:
all nine native reads return with child exit zero, the initial receipted facts
finish in 8.188 seconds, and actual COUNT durably returns one UNKNOWN intent.
The following independent full facts take 14.001 seconds, then the lane
refuses before CLAIM/send. The complete run remains one ERROR (406.137 seconds),
not a FIRST PASS, and UNKNOWN is not rolled back. The public boolean HOLD
does not prove this run's earliest post-COUNT cause; an old expiry diagnosis
is not silently adopted for the new failure.

Independent review of the new receiver finds two further lifecycle faults:
used-but-failed prefixes or substituted state could fall back to cold facts,
and a failed normal body exit could be attempted twice. Three controls first
produce four behavioral FAILs. The issuer now retains an independent private
identity anchor for its original packet, dual owners, row/unit, body/observer,
argument references and Count packet, plus separate used/succeeded/failed and
exit-attempted state. Only the complete original suffix, Count tail and NEW
short-K normal exit establish success; failed consumption remains poisoned,
and subsequent successful facts still perform their own full original reads.
Missing fields, same-value substituted row/packet and source/context drift
refuse, and cleanup uses the original anchor, not mutable packet cleanup slots.
A deleted-row control first reports a KeyError ERROR, then exact field-set
validation gives typed HOLD without a cold fallback. 180 related direct
controls pass on their recorded tree. An initial workflow import failed with
Python's static nesting limit; the two new observers were moved into the same
existing ExitStack, preserving all assertions and restoration. That import
failure is retained and not counted as a workflow execution or acceptance.

The Count join also anchors its stable writer/token/binding/project/owner/unit/
process-thread context and original verifier reference, rechecking them after
the actual delegate and at every later getter. Independent END controls first
FAIL on same-value unit, callback and context replacement, then refuse without
calling the foreign observer. Legal append-aware directory/file additions are
not frozen or weakened by this relationship check. The next bounded diagnostic
targets the original post-COUNT refusal on this candidate, not a normal/full
rerun or a deadline change.

That exact-tree post-reload diagnostic completes with one ERROR in 393.357
seconds. Its single valid hook covers seven original holders: initial facts
return in 7.575 seconds; actual COUNT returns one UNKNOWN; the next independent
full facts return in 13.896 seconds. The immediate original template-identity
read then refuses on expiry (remaining -11.179 seconds) while registry, data,
writer, owner and binding still agree. This is now a proved post-COUNT expiry,
not an inferred load issue or a reason to refresh the original read. No CLAIM,
send, rollback, full approval or REAL_ENV closure follows. The unchanged related
runner preflight selects full fallback and exits 2 at EFF E-3 because this
reviewed development tree still has dirty/untracked content; it starts no suite
and changes no ledger. Its output is not counted as a test PASS or SKIP.

### REQ7 actual Count/source raw overlap prerequisite (2026-10-13, OPEN)

The complete FIRST path has six independent facts boundaries: before COUNT,
after COUNT, CLAIM consumption, last pre-Popen, post-send and normal wire exit.
Moving only a second body prefix cannot replace the last four real observations.
The next necessary structural work is original graph acquisition before the
nine native reads and a genuine Count-backed source receiver, not a deadline
extension, cached qualification or resurrection of a closed K/ALL verifier.

The actual Count issuer now retains its three original graph objects in an
independent registry record; its own closure verifies the same record/objects
before and after each delegate and revokes that record before finalizers.
The new raw-overlap prerequisite compares every shared named file/directory
edge by actual parent identity, complete original identity, bytes and names.
Both source and receiver must cover the complete original shared namespace;
only the actual OS-owner lock FD is separately bound, never ignored by suffix.
Deleting a shared parent record cannot reclassify its children as project
evidence. Unshared source originals remain untouched and strictly verified.
The future fixed receiver must additionally prove their genuine project/root
anchors and retain semantic/owner tails; this prerequisite returns no authority.

Three initial controls report API-absence FAIL. The first implementation run
reports three fixture ERRORs because its literal original files were not 0600;
only fixture modes were corrected, without changing expected behavior. The
actual catalog/dual-owner Count controls independently report two API-absence
FAIL, then pass: same-value unit/registry replacement and stale context refuse;
the genuine creator may append COUNT1 UNKNOWN, but the old strict source cannot
then be refreshed or adopted. A shared-parent deletion control initially has
one behavioral FAIL and a reused-fixture-path ERROR; a fresh owned fixture
gives two behavioral FAILs, and complete-root coverage fixes both. Latest six
controls pass. Earlier 238 related controls pass on their recorded pre-parent-
fix tree only, not as proof of a later source tree. Continuous K transfer,
whole FIRST, full/check and REAL_ENV remain OPEN. No ledger is edited.

The actual FIRST coordinator now prefetches only the original read-only Count
graph after strict source/business entry and before native read issuance. It
anchors the same row/unit, Count key/packet/three graphs, verifier and owner
references; IO-tail borrowing cannot acquire a new graph. Borrowers close before
the prefix-owned Count issuer; failed prefetch is poisoned. Five lifecycle/order
controls and a genuine dual-owner catalog/creator workflow retain independent
expectations. The workflow's source body is explicitly a lifecycle stand-in,
not native K or whole FIRST proof. The earlier recorded tree has 246 related
PASS. The genuine whole workflow now also observes this boundary and the first
actual read without dropping its existing prefix/Count/wire assertions; it has
not been rerun because the continuous K receiver remains unfinished.

The next data-only receiver independently duplicates complete raw source files,
directories, ancestor/project FDs and namespaces while both sides are live.
Only exact shared namespace and original Count creator mutable-directory checks
delegate to the still-live original Count closure; old files, catalog .units,
nonshared namespaces and project roots remain strict. Unknown unanchored parents
refuse. Cleanup owns its independently captured slots and cannot adopt a foreign
substituted list. It does not enroll K, use decoded values as source admission,
or retain a closed semantic verifier. The eventual fixed factory still requires
the genuine ALL project set, complete independently held settings/current/outbox/
INITIALIZED originals, C19 recovery barriers and Count-internal tail ordering.

Three API-absence controls first FAIL. The first implementation gives one PASS
and two ERRORs from the fixture's stale reloaded sheet-owner module alias; the
fixture now selects the actual canonical registry without replacing guards, and
all three PASS. Cleanup and unknown-root negative controls initially report
ERROR through the original Global finalizer's typed refusal; these are preserved
as ERROR, not retrospectively relabelled behavioral FAIL. The cleanup/root fixes
retain their original expectations. One related command initially requests a
nonexistent remote test class and reports one loader ERROR (228 tests total).
Correcting only that explicit command gives 277 PASS in 36.330 seconds, raw
SHA256 `01578b66150e78ecb494424106bbb5c4641e411265b6e0ef330a0da5cc814528`,
on diff `d8673021930eab4647b4a712e8f13bca374991ef9e019c901453a7ff6092bca0`.
This is related/direct and actual raw-creator evidence, not full/check or later
documentation-tree proof. No repeated unchanged FIRST/full, deadline extension,
ledger update, real-device validation or ordinary release approval follows.

### FIRST original Count/source reception checkpoint (2026-10-13)

The fixed pre-IO receiver now joins the genuine LIVE source factory to its
original Count key/packet/three graphs. Count first owns an independent settings
tail stack; only then is the SAME settings scope moved with `pop_all`. Actual
images, event/entry identities, ALL project set and original C19 recovery FD
groups are captured before old semantic/K revocation. Barrier FDs must already
belong to the independently retained graph; no unretained foreign FD is adopted.
Later short read-only K scopes borrow these originals and Count-held C6, not a
cold ALL reconstruction or closed source verifier. They cannot modify K, COUNT,
CLAIM or source qualification. Full original source/receipt checks remain.

Every metadata verification brackets real delegates with the same identity
checks; failure permanently poisons reuse. Count's independently bound source
relation drives its tail even if the exposed mirror is erased. Semantic tails
close first, settings finalize next, original raw/Count graphs follow, and the
actual owner tail closes last. All original cleanup slots are attempted, with
operator-interruption priority preserved over secondary ordinary HOLD.

Independent RED evidence remains unaltered: initial transfer controls were
1 FAIL/2 ERROR (the original Global finalizer hid the inner missing-tail
assertions); short-K API controls 2 FAIL; actual END-metadata drift 1 FAIL;
unretained-barrier control first 1 ERROR from premature fixture restoration,
then 1 behavioral FAIL with restoration deferred until closure; original
metadata-tail erasure/interrupt controls 2 FAIL. The first 296-related run also
had one lifecycle-fixture ERROR because its settings maps were tuples; that
stand-in now uses the actual holder's map/bytes types without changing its
enrollment/revocation assertions. A stale pre-fixture exception-class import
caused one later ERROR; the test now asserts exact post-reload exception identity.
The additional whole-workflow observer exceeded Python 3.9 static block nesting;
moving only that observer into the existing private ExitStack fixes compilation.

Actual native archive/second-unit workflows prove same-scope transfer, two short
K lifetimes and read-only mutation refusal, actual Count=1 UNKNOWN without CLAIM,
END drift poison, erased-mirror refusal and interrupt-safe original cleanup.
The latest selected direct/related/native Count=1 command is 296 PASS in 65.011s,
complete raw SHA256 `7e2a45914856fd3722143d81f2a23a3943d7d82a00deddcf70b2abd2e80e2a1b`,
on diff `139a4ed31046b73cbbe0ca9614994a3d51504130ee98e08e3f69b665d0bff062`.
That evidence predates this documentation update and is NOT full/check or whole
FIRST proof. A new whole FIRST run is justified by this materially different
original-scope path and bounded native Count=1 evidence, not by isolated PASS
alone. Its six facts boundaries, source/receipt checks, four K reads, C19 barriers,
COUNT/CLAIM/send and all tails still require actual acceptance. REAL_ENV NOT RUN;
no ledger approval or ordinary formal-full success is claimed.

The changed whole FIRST run then ended with 1 ERROR in 341.254s, complete raw
SHA256 `17df5a254accb0b8a3f85c22ab9e9fef8add07bb339d8d6665c2f7ed0c3f82db`,
on frozen diff `8f68439131329c50c08dcd3b443582e49d84ce988abe7fd174cd51920fb4bd4b`.
Its earliest traceback is the new fixture's C19 observer, before first IO:
it wrongly requires an independently decoded expected unit to be the same
object as Count's actual issued unit. The observer now independently requires
identity with Count's packet unit AND equality with the expected unit value.
No production behavior, original sending/recovery assertion or deadline changed.
The new literal observer contract has an initial 1 FAIL, followed by 3 PASS in
29.115s including actual received Count=1/global short-K workflow; complete raw
SHA256 `7e88e53c583d46ed43b62b30a53dd17035ba57ff04a4fc4e4d249a31057d29ab`,
on diff `854989d0dabc9f7ee7a4af27224352a95fb764b3baf0dd55cc9ebb65e736b249`.
These are diagnostic/related results, not whole FIRST acceptance. One whole
FIRST rerun is now justified by the proved correction of its actual failing
fixture condition, not isolated PASS or an assumed resource-load explanation.

That ordinary whole FIRST rerun is still 1 ERROR in 386.491s: all nine actual
reads exit 0, G1 capacity/inventory is present, Count becomes 1 UNKNOWN, and no
CLAIM/send occurs. Complete raw SHA256
`9017ca65d72cde91da3e36ee2786b1b96635ea211ecf3edb3a6639df27635cd9`
binds frozen diff `01ab4495425dd16156fc3bfb73b07a7f4074d1a0e6abf5dd96f4b0f82d2736da`.
The original lane suppresses the earliest cause; this ordinary log alone does
not establish a timeout explanation. A single fixed post-reload diagnostic,
with explicit facts profiling and no changed clock/deadline/assertions, then
retains the original template-identity refusal: original registry, writer,
owner, binding and response data all match, but the original read is expired.
Complete diagnostic raw SHA256
`5eff9c94fe8cecb00b8fdf96b6fb65f390dde99c80be5830d4636c7acdade091`
has physical BEGIN 1 / END 329 and exit 1. It is not ordinary acceptance or
unprofiled timing proof. The two profiles show 64/128 actual K reads producing
792/1558 complete Count checks; the latter performs 4,384,202 fstat,
2,652,729 stat and 130,302 listdir calls. The necessary next repair is this
verification-domain amplification, not relaxed expiry, cached PASS, omitted
original source checks, or another unchanged full run. Count/UNKNOWN is retained;
whole FIRST, full/check, subsequent demands and REAL_ENV remain unclosed.

The narrow repair keeps the existing original C6 loan around the ENTIRE
metadata body, so its two full Count boundaries still check OTHER APPLIED/key/
UNSENT originals and each project namespace. All five C6 checks remain; body
checks still reread original settings, all retained raw data, the constructor-
bound Count raw closure and every original C19 barrier. No old PASS is reused,
no deadline changes, and the older receiver `verify()` contract is unchanged.
Identity checks occur after real loan entry and after its complete finalizer;
any refusal permanently poisons reuse and original tails still close.
Two independent native controls initially FAIL: complete Count calls are 6
instead of literal 2 (raw `cc3f60112f14364b59185e34705d3b700730aad1913ef4d445768ad12cdfff76`),
and exposed raw-verifier substitution is accepted
(raw `88418da4359f1ce7cb26830bb99e181b01faefd7fc4a2dac2a40821d5f9ad8b1`).
After the repair these controls, last actual raw-delegate metadata drift and
actual Count=1 UNKNOWN/no-CLAIM replay give 4 PASS in 89.829s, complete raw
`dc0468d181776ca8356eb735ba2feb1370d64258b6b467e2a313e015bd843d6f`
on diff `1e79dd12a334ff2048b96bada456e781a2beeeafe65a64634e2bdec189f5a06d`.
The drift test observes the new actual raw delegate but retains its two-call,
HOLD, permanent-poison and all-original-cleanup expectations. Related and
ordinary whole FIRST acceptance of this repair are still required; this is not
a timing result or runner/full/check approval.

The first narrowed tree's direct/related command gives 297 PASS in 63.564s,
raw `e3df2321466b6b421aa76fb77ba8e28d14988e9a358e4168360f96d412083693`.
A necessary final source boundary was then independently reproduced: during
the last actual full Count delegate return, the owned old delivery HEADER is
replaced with the same bytes/new inode and its retained original is kept.
Metadata previously returned before source refusal at Count terminal cleanup:
1 FAIL in 18.406s, raw
`d19b34c09141467cd63eed85c802c586b33e372d12e5296fc3fe58b3d39e0e70`.
Same raw-source checks now follow each Count raw delegate and the completed
original loan finalizer, before returning K; no reopened graph or shifted
permission. The source fault, literal two full boundaries, END metadata drift
and native Count=1 replay give 4 PASS in 88.177s, raw
`e78d2af91f3c2295decd47b246aa5d148a0ea2fe97bb9d1b43ba4e22660bcb23`,
on diff `4857c3f02300331235dd775aaa50dae16756ff28447505047d6e0cc9a4e511a6`.
The 297 result predates this last repair; none is whole/full proof.

On the final source-tail repair, 296 direct/related controls pass in 37.584s
without rerunning the already separately proven native Count=1 case. The
current code is justified for one ordinary whole FIRST acceptance attempt by
the actual amplification diagnosis, two-boundary implementation and independent
native refusals/cleanup proof, not just the selected test count. During that
attempt source and tests stay frozen; an error requires its original cause
analysis before any further whole/full run. No full attestation exists here.

That ordinary attempt ends with 1 ERROR in 386.966s, exit 1, complete raw
`158669e0ff239995d0f7c78857a5f4fee4cfcefbd087760f0af5fb4f89df8c54`,
physical BEGIN 1 / END 268, on frozen diff
`7f8661de80f16d509f309dcaaa2bf5caf516a7ae548974304443573f5821f9e1`.
All nine real reads exit 0; initial/post-Count facts take 6.353s/12.129s;
Count remains 1 UNKNOWN and no request is sent. The inner exception is still
hidden by the lane's boolean finalizer. These timings do not prove the current
failure is deadline expiry, nor does the related PASS close FIRST. Next is one
bounded original-delegate/CLAIM-entry diagnosis, without profiling overhead,
guard substitution or a new ordinary/full acceptance attempt. All original
source checks, deadlines, cleanup and assertions stay unchanged.

The bounded no-profile delegate diagnosis is complete: 1 ERROR in 383.452s,
exit 1, raw `428133fd2990029cfb1804af4cebc6a004467ef187b85a042d3e25befbe86340`,
physical BEGIN 1 / END 326, diff
`1efd53d393117999ebdde497aaf63e4800e98c8bf8f11f3fc2e7489f006235e3`.
Post-COUNT facts return before the original template-identity guard refuses:
registry/writer/owner/binding/data match, but the same deadline is expired.
CLAIM was never entered. This diagnosis retains ordinary UNKNOWN and is not
an uninstrumented timing or full proof. Source inspection shows fixed fan-out
times K reads, not an established recursive/exponential call cycle.

The received short-K scope now retains ONE actual C6 loan over its complete
read-only lifetime. Each K read still freshly verifies original settings,
source/Count raw images, original C6, C19 barriers and identities. Full
Count/OTHER/APPLIED/key/UNSENT checks dominate the loan ENTRY and complete EXIT;
K revokes before that exit, followed by final original source checks. The
standalone metadata verifier still owns its original two-boundary loan. No
PASS, admission, counter or write capability is cached or transferred.

Independent initial evidence is retained: original short scope traverses
full Count 14 times instead of literal 2 (1 FAIL), and ordinary body refusal
overrides a real cleanup interruption (1 ERROR), raw
`267cfa24928258f2b2862936988fe9fedf7b6679d8abd9b75a0590c25ca6d297`.
The first repair has six related PASS in 80.510s. Caught/restored metadata
drift then independently gives 1 FAIL, raw
`61dfc1b122dcf0d93f227586fd07eeab03f3b0be0fc4b40c4f6377ef7349734a`;
the issued verifier now poisons immediately, even if its caller catches HOLD.
Four native source/END/poison/boundary controls pass in 79.591s. A later
selection has one loader ERROR from the misspelled UnitCatalogTests class;
its 171 actual cases pass and the correctly named missing class gives 125 PASS
separately. The failed command remains failed, not a successful suite.

The short-K callback itself cannot attest its own substituted pointer/code.
Two actual controls first FAIL, raw
`ad0e2554ca73f416b7a28cd8a449dd8e86cfc12b7dea3783a88dda148c9d1561`.
Admission now uses a separately anchored original scoped checker; final read,
revocation and post-loan source boundaries independently check the same
callback/code/images. Both controls and scope/source boundaries pass. Partial
issuance interruption independently exposes a retained new registry record:
1 FAIL, raw `7622875fe8e63d9614d7dbad1f06016014bfed00d2ede9e4bdcfb5dc1e1d1f68`.
Protection now precedes the FIRST publication and always revokes the owned
records/reset token actually acquired, preserving the original interruption.

The final related command is 298 PASS in 107.015s, including all four selected
direct classes, native partial issuance cleanup, literal two-boundary short K
and actual Count=1 UNKNOWN/no-CLAIM workflow. This supports one new ordinary
FIRST attempt on the changed verification mechanism; it does not substitute
for that attempt, the whole REQ7 acceptance, runner/full/check or REAL_ENV.
Source/tests freeze for the attempt; no unchanged full rerun, deadline
extension, skipped assertion, manually edited ledger or ordinary release
approval is authorized by these related results.

The ordinary short-K attempt remains 1 ERROR in 376.280s, exit 1, raw
`e0f73fef89a09a0e63dfa8c5e57d4386c2c9ddae96ff466a5289100703af3d39`.
The no-profile original-delegate diagnosis then remains 1 ERROR in 373.291s,
raw `01e67983536f703b3a7c232cbf56166084bf8b2f873147c3d2e14565a398cf75`;
the genuine template_identity deadline is expired after post-Count facts,
while registry/writer/owner/binding/data match. CLAIM is not entered. Both
bind frozen diff `ad2ec25fbb37958da04629b511c5f01045ecae11afc76d4e413199de571a66a9`.
One explicit current-path facts profile is 1 ERROR in 376.809s, complete raw
`ebd96deceb731161b83121e2ff46a1155cc56f634ec2bb5f8c61dbdf6a1a6412`,
physical BEGIN 1 / END 329. Its second facts invocation includes 2,076 raw
graph verifications and 62,174 directory enumerations (2.753s self time).
These diagnostic timings include observation overhead, not normal acceptance.

The raw graph now shares a coherent directory names view only within ONE
verification phase and only for identical full inode image/FD flags. Every
actual FD use still stats/checks flags; changed images trigger fresh reads.
Expected claims/prefixes/immutable identities remain original. A second fresh
phase after all real file/project delegates rechecks claims and prefix sets;
unrelated name additions do not become a new refusal rule. Nothing persists
to the next verifier, and both receiver raw calls, all K/C6/barriers, named
edges, original slots, file bytes, cleanup and deadline checks remain.

Independent direct RED is 3 FAIL in 0.119s: literal two views per call gives
18 instead of 4 across two calls, and a relevant namespace insertion during
real pread returns without refusal. Raw
`1e58534c3882bc32120d8b3cb79d18136f24f3739164ace932209b7d80346fb3`
retains the failures. Repaired creator controls give 22 PASS in 0.268s; adding
the unrelated-prefix control plus genuine short-K two-Count-boundary and
post-revocation last-source replacement workflows gives 25 PASS in 46.870s,
raw `9014ee5a71f569bc389e104ac23312887bd9cbf5f5cf6a00ec16115784455c67`,
physical BEGIN 1 / END 33. This is a materially changed coherent-read mechanism
supported by independent refusals and real workflow evidence, justifying ONE
ordinary FIRST attempt, not an unchanged full retry or a total speed claim.
The whole REQ7/full/check and every REAL_ENV result remain OPEN/NOT RUN.

That coherent-view ordinary FIRST attempt is still 1 ERROR in 372.749s,
raw `90b970df8f1b965136368a564259daf7bc9a003cb6be82d8c3cee6560bfd0635`,
physical BEGIN 1 / END 268, diff
`d4c5f48591b64ca105ec61f897926dc14dc381c4d572f85c91d5fcc19d83b866`.
Facts take 3.806s/7.051s, Count is 1 UNKNOWN and no CLAIM/send occurs. This
run's suppressed inner predicate remains UNKNOWN; the prior exact expiry
diagnosis is not presented as a new exact-tree diagnosis.

The next necessary amplification repair concerns the fixed receiver's own
complete raw sweeps: the former nested order was raw/mutable/raw, Count raw,
raw/mutable/raw. There is no intermediate result or permission boundary.
One original raw sweep now precedes and one follows the complete mutable +
original Count raw + mutable body. Original collection identities and FD
flags are checked BEFORE the first sweep, again after Count and after the
last raw delegate. No getter/Count/C6/OTHER boundary, original file/namespace,
C19 fsync, source tail, deadline, standalone verifier or poison expectation
is removed. The standalone record verifier keeps its original two sweeps.

Independent actual receiver control first gives 1 FAIL (literal 2 versus 4
complete raw sweeps); the source replacement control already PASS is retained.
Two-case RED raw `80a11bfa879c39732ef77f892c1b76f4b457241bf258a0857f33601dae1d6143`,
46.948s. The two controls, original metadata END refusal and short-K original
loan boundaries then give 4 PASS in 93.736s, raw
`b8d8078cbdf2b8cd86738eea3575fad8afdeba249578e862e916c55a05749196`.
Five direct classes plus original Count raw pointer substitution, source
replacement after K revocation/full loan exit and Count=1 UNKNOWN/no-CLAIM
give 321 PASS in 99.601s, raw
`ac1f9d6a0dc35aab694c47092346f7eef6041321ea7be122d86bb379581330d2`,
physical BEGIN 1 / END 338, on changed diff
`295eda7eef7883203fca86ae1627ec65fc9ebe0729bc66de3f7f02fb58e9f502`.

One unchanged-behavior whole FIRST run will use only a bounded failure-only
original read-guard observer: single original delegation, no success output,
holder/Count/facts wrappers, trace/profile or guard/deadline substitution.
It records non-secret original tuple equality and whether the actual deadline
was already expired BEFORE the failing original call; its pure control checks
single delegation, identical interruption and no success output. Observation
is diagnostic, not ordinary timing or runner/full/check proof. Source/tests
stay frozen; failed/partial results remain failed, not a reason for blind full.

2026-10-14 continuation: that failure-only whole FIRST run completed with
1 ERROR in 382.024s (raw `c3463e81acfc88dd2acf5e9df5e788776b17ec19f94792f62a91b4707b4d8f00`).
It reached the fixed mutation-entry guard, but the original template identity
was already expired before that guard by 3.874s; the other captured original
tuple predicates matched. Count=1 UNKNOWN remains, not successful full proof.

The next necessary repair encloses ONE complete actual qualifier (or the
entire older replay) in a fixed Count-received source evaluator. Complete
retained source/Count raw checks precede and follow that whole computation;
each interior K still verifies fresh settings, original refs/code/FD flags/
mutable edges, C6 twice and C19 barriers. No callback, caller witness, prior
qualification, cache, renewed read deadline or intermediate permission enters
this evaluator. Ordinary K, receipt verification, full Count/OTHER loan exit
and the last original source check keep their previous contracts.

Two structural controls initially FAIL before implementation. The first
actual boundary probe then FAILs in 354.255s (raw
`e0c3da29ef0e4b1dd4265c924c882153f4cee5df8a651577fa9fce576d8ae77c`):
the prefetched Count receiver was selected before short K existed, so the
factory refused before any qualifier returned. This is not successful native
evaluation evidence. Routing now requires the actual received short K;
original native K remains the path while only prefetch exists. Its independent
structural control also first FAILs. A separate genuine owner workflow first
FAILs for a self-attested registry tuple (raw
`25274cfeef29f54b57d5c735e529a61580bbc5076764cdf884c76df10b91e6b1`).
The factory now anchors its original tuple through the genuine Count/source
metadata BEFORE invoking any callback, and refuses/poisons that genuine
receiver even if the caller catches the refusal and restores the registry.
Two direct classes plus this native refusal give 85 PASS in 21.144s (raw
`e2e70e01561095da3407fbbfcb4c19a4f8ccd11bcb8208f27e2b3c19349502ce`).
The next actual boundary probe is justified by these two verified repairs;
whole FIRST, full/check approval and REAL_ENV remain unproved.

The subsequent real-short-K probe (raw
`23b40624d714e25636a82dae4a159bdb36145b53bfb433742ea77edf73a6daad`)
remains 1 ERROR in 378.013s. Its observer was installed only in the original
input scope, which ended before Count-wire evaluation; it therefore did not
observe that evaluation. The unchanged whole workflow reached Count=1 UNKNOWN
and a sanitized mutation-launch HOLD. The current underlying primitive is
UNKNOWN; the earlier run's expiry cannot explain this new failure by itself.

An independent observer-lifetime structural control first FAILs. Installing
only the same evaluator observer in the actual post-reload Count-wire scope
then gives 3 pure controls PASS in 0.223s (raw
`70375035361e81b34f12ca4b58f3b07565bd66572f90117002aeb03ac6a213cc`).
On unchanged production/test diff
`227754cf7ae9b1b24a6f1016d033e110edabb537aecc099fd61e68d2d00ad196`,
the actual positive boundary probe gives 1 PASS in 376.980s, raw
`1c7e92b4b5a51d789b71709d625332da56741a80fd866239ee212ddddcf8239f`
(BEGIN 1 / END 168). It independently requires four full raw checks enclosing
the genuine qualifier return, followed by original resource and K-registry
cleanup. Same-bytes DELIVERED inode replacement at that return and caught then
restored original metadata drift give 2 PASS in 749.358s, raw
`40d7f7367d7db7b883662007f64c3dd987ee3165389fed49747053351ca0d470`
(BEGIN 1 / END 380). Both require refusal and permanent poison, never a source
result. Each deliberately stops before mutation; these results are NOT whole
FIRST, runner approval, formal full/check or REAL_ENV proof.

The next single unchanged whole FIRST diagnosis retains the original sealed
failure-only read observer and adds single original delegates for wire-launch,
request preparation, the actual fixture Popen facade and supervision. It
records only fixed stage counts and the first original exception type/code
file/line, no credentials, child bytes, profile/trace, clock replacement or
changed deadline. Three pure observer controls PASS (raw
`ec2c5592e82a3c5b9d58280e8ba71868f23e8903dee6c0a8a54d7d415d17ac56`).
This addresses the specific missing primitive evidence, not a reason to rerun
formal full blindly. The whole workflow's original behavior assertions remain
unchanged; source/tests freeze during that run, and approval remains OPEN.

That single whole diagnosis completed with 1 ERROR in 379.340s (raw
`38ae77f29a047624f6002be561657719aba325ec319a4ae341a52716ee78de7a`,
BEGIN 1 / END 316, frozen diff
`574e70685bd9acadd48390933f24d6e64067cb8bb39ae6ee6a580c9580547fcd`).
The original consuming wire check returned; the second, non-consuming
pre-Popen check refused. The sealed original read observer confirms that this
run's template-identity deadline was already expired by 0.944s BEFORE its
failing call, with the other eight captured original predicates matching.
Actual mutation Popen and supervision counts are both zero, and Count=1 stays
UNKNOWN. Facts durations were 1.508 / 2.949 / 2.775 / 2.723s. These observations
explain this run, not older failures or a missing full proof. No unchanged
whole/full rerun is justified; the next step is a tests-first necessary cost
repair retaining original deadlines and every actual commit/IO boundary.

The corrected exact-code/actual-parameter C19 observer gives a genuine native
RED: expected ENTRY/EXIT (2 total, 1 before qualifier return), observed
(126 total, 125 before return). Raw log SHA256
`21ec56afd8003bdbd43ebc8dfa89c46c31e0f9c006643e4e9feb756a06ea086e`,
BEGIN 1 / END 187, 1 FAIL in 376.005s; the earlier zero-count observer failure
is not this behavioral RED. Only the private fixed non-yielding evaluator's
interior K sync is removed: complete original C19 groups remain synchronized
at evaluator ENTRY and complete EXIT before any result returns. Every interior
K retains fresh original identities/code/FD flags/settings/namespace checks
and both actual C6 calls. Ordinary K, complete loan finalizers and independent
source checks remain unchanged. Native ENTRY/EXIT fsync-failure controls must
prove refusal, permanent poison and owned-resource cleanup. No performance,
whole FIRST, runner approval or full/check success is claimed from this change.

After that narrow change, all 93 allocation-module tests PASS in 5.284s
(raw `41bfede7b8adc96eb9ad93bed335aa34385c7fca7e4693259372b5c89f2a833d`).
An earlier class-selection command has a preserved loader ERROR for a nonexistent
class; it is not a production failure or a successful complete selection.
The actual normal, ENTRY-fsync refusal and EXIT-fsync refusal probes then give
3 PASS in 1097.638s, raw
`cd63b170a0803016e545e04852b8630b7e7c6e0ba351457f5e73ae5082beea50`
(BEGIN 1 / END 514), frozen diff
`f1a2d21706c4306866acca23897f5a6698690794b19f202df2ceccc83fd38257`.
The positive case requires exactly two complete C19 syncs and four full raw
checks; both injected failures require refusal, permanent poison and original
resource/K-registry cleanup. These deliberately stop at the source evaluator,
before mutation. Existing DELIVERED/metadata refusals and whole FIRST still need
the changed-tree regression; no full/check or REAL_ENV approval is implied.

Both unchanged negative expectations on the changed source now PASS in
732.042s (raw
`cb0bfc64acd4a0937ac0b3e7e6df358a79e8d520766aa14ec7732fd194fa4436`,
BEGIN 1 / END 380, frozen diff
`4292be5212102213f8832f7995942240f0f19896298e276e59a57199633572c2`).
Same-bytes DELIVERED inode replacement still refuses at the evaluator return;
caught/restored metadata still refuses immediately and cannot revive K.
Together with 93 direct and the three native C19 boundary controls, this
justifies one changed-source whole FIRST development diagnosis, retaining the
original failure-only observers, behavior assertions, deadlines and commit/IO
checks. Its purpose is to measure whether the verified interior-sync removal
also resolves the previously measured pre-Popen expiry, not to assume that it
does. An unchanged retry or formal full is not authorized by these local PASSes.

That changed-source whole FIRST diagnosis completed with 1 ERROR in 387.404s,
raw `ad833839bc2f4f378835e4d76c96f3615dff382587b503c85a3a3084ea9b21fd`
(BEGIN 1 / END 316; original session 18819 reaped exit 1). The second,
non-consuming pre-Popen wire check again refuses: template identity was already
expired by 1.210s BEFORE its original delegate, while the other eight observed
identity predicates match. Count=1 remains UNKNOWN; request returned once,
mutation Popen/supervision remain zero. Facts durations are
1.505 / 2.828 / 2.781 / 2.791s. The verified C19 change therefore is not whole
closure. No unchanged whole/full retry follows this failure. The bounded next
repair examines the two genuine K reads inside the complete current receipt
reader, outside the existing fixed source evaluator. Both receipt K reads and
its original C6/XLSX/admission/cycle recovery checks must remain; an actual
fixed non-yielding receipt computation must have independent full original
ENTRY/EXIT and last-return drift controls. Ordinary/older paths, original
deadlines and every Count/consume/pre-Popen/post-send/finalizer gate remain.

The current receipt boundary probe gives a genuine native RED: both actual K
reads and the entire original receipt function returned, but the independently
expected four full raw checks observed eight. One FAIL in 378.953s, raw
`5fed6e59f623dfa7ae71792d3046b9d70c7cd0c7658cb3a11677e704daca1fc2`
(BEGIN 1 / END 183; original session 75898 reaped exit 1). This is not a
fixture-observer failure and does not establish whole FIRST timing. Two direct
contract tests also fail before implementation (raw
`f81258aa76fb27da36212388db9136dc517583ca190077592d321649d8cd76cb`).
The new fixed receipt computation retains the entire original receipt reader,
both actual K reads, full current C6/XLSX/admission/cycle checks and the final
generation recovery tuple. Complete original metadata bodies dominate ENTRY
and EXIT; no data result, qualification or permission returns between them.
Both fixed factories use the independently anchored original eight-tuple;
missing received slots cannot silently select the ordinary path. The actual
source prefetch retains its original issuer and ordinary path. Existing source
and new receipt fake-tuple controls require zero forged callbacks, immediate
poison and refusal after restoration. All 148 allocation/direct/these two
actual registry controls PASS in 44.878s (ordinary module-only 95 also PASS
before the final admission-route change). Actual receipt normal/last-return
DELIVERED drift tests still require the changed-tree run; no whole FIRST,
formal approval, full/check or REAL_ENV success is claimed.

The changed-tree receipt normal and last-return DELIVERED controls completed
with 2 PASS in 734.647s, raw
`318a6a89633125513e55c08b036c61824be8b4d0564f18df21f26839f8c1623d`
(BEGIN 1 / END 341; original session 72487 reaped exit 0). The new factory is
also reached by the genuine local prefix before COUNT; both controls stopped
there with Count=0. They prove complete computation boundaries, both original
K returns, permanent refusal/poison and cleanup, but not post-Count safety or
whole FIRST closure. The existing DELIVERED negative now delegates that actual
prefix unchanged and selects only an independently observed persisted Count=1
UNKNOWN. It retains the same inode-replacement fault at the entire receipt's
last return and additionally requires Count=1 UNKNOWN after refusal. This is a
stronger critical commit-boundary expectation, not removal of the earlier
coverage or a new corner-case matrix. No formal full/check follows local PASS.

The strengthened actual post-Count receipt negative PASSes in 378.779s,
raw `a2127af4844426650a489a3e7202c09e6ca27a711fc2f981d750f318f338fb61`
(BEGIN 1 / END 170; original session 8022 reaped exit 0), frozen diff
`cb8e6ff0dbcc024ee0d39ffd6420b891990f9e677245091c739c35be6421124d`.
The original Count returns 1 UNKNOWN, and independent observations immediately
before the same last-receipt-return fault and after the factory refusal both
remain 1 UNKNOWN. The actual two K returns, complete original receipt return,
immediate poison, identical primary interruption, full original cleanup and
empty K registries are required. Related allocation/observer contracts give
96 PASS in 5.350s. Full physical logs, including expected cleanup tracebacks
printed after the unittest summary but before END, are retained in their
original order. No cleanup traceback is substituted for the factory refusal.
Together with the genuine receipt RED and unchanged related admission controls,
these changed-source computation and commit-boundary results justify one whole
FIRST development run. That run checks whether the bounded receipt repair
resolves the previously measured pre-Popen expiry; it does not assume it does.
There is no changed deadline, omitted facts/IO gate, formal full retry or approval.

That changed-source whole FIRST run completes with 1 ERROR in 390.360s,
raw `5f5cb1537a76aaa7e6e83e052e091312744f65a2793e3eb0f4dd2526a6062b99`
(BEGIN 1 / END 316; original session 23263 reaped exit 1), frozen diff
`21667faf6a7c4a916ec62cf1c47b89f4eef80d194840739709c1e0de748989fb`.
At the second non-consuming wire check the original template identity is
already expired by 1.402s BEFORE the original delegate; all other recorded
identity predicates match. Request preparation returns once, mutation Popen
and supervision remain zero, and actual Count=1 UNKNOWN is retained. Facts
take 1.515 / 2.774 / 2.774 / 2.764s; the receipt boundary repair is not timing
closure. The first duration is the genuine previously-entered prefix's full
suffix; later facts execute fresh source/receipt at both ENTRY and EXIT. They
cannot reuse the consumed prefix or be expected to cost only one suffix.
No unchanged whole/full retry follows. The next bounded diagnosis delegates
the two fixed module factories and their actual qualifier/receipt cores once,
records numeric durations only, and deliberately stops after their complete
next ENTRY/EXIT pair with independently observed Count=1 UNKNOWN. It neither
wraps captured C6/guards nor changes reads, deadlines or results. Its explicit
DIAGNOSTIC_ONLY result is not whole FIRST, a send or runner/full approval.

The bounded component diagnosis completes in 386.093s (original session 83400
reaped exit 0), raw
`e4d53aa648b860a31949813e465345278ae933ef43b84382c03d760641b38474`
(BEGIN 1 / END 165), frozen diff
`69f180617cac1d66f9bcf26193ea0b0e489de3d18e18e5a797e275dc7fdd0fb1`.
Three actual qualifier cores take 1.206 / 1.176 / 1.212s inside source factories
of 1.236 / 1.205 / 1.242s. Receipt cores take about 0.017s and complete receipt
factories 0.044–0.049s. Persisted Count=1 UNKNOWN is independently observed.
The original diagnostic interruption and cleanup refusals remain physically
present; the intentional bounded stop is not a whole FIRST PASS.

This identifies the core read chain, not the receipt shell, as the remaining
cost. A narrow original-C6 file check now replaces three pre-read fstats with
two fresh held samples enclosing the real pread. Both held samples and the
nofollow named sample must equal the originally captured complete nine-field
identity; exact 0600, owner/type/link checks and original bytes remain required.
No owner, namespace, complete pre/post phase, two C6 calls or recovery barrier
is removed. Independent actual-file tests first give 2 FAIL in 0.195s, raw
`fcdeb9ae11532f1735f0d9b93c23c62870b44f9991ac51e147cd758c1bb2b911`:
the old sequence has three samples before each read and detects mode drift
only after two recovery fsyncs. The revised entire six-case original-C6 class,
including unchanged barrier-failure, same-byte replacement and six capture-gap
controls, gives 6 PASS in 0.529s, raw
`b6ebb1e3592ba6430faa49a8f20aa4cab4d30c34f9a9fb30e53f7e9b089746e9`.
Actual read-time mode drift is now refused before either recovery barrier.
The related six C6 direct, two real COMPLETE/APPLIED workflow and allocation
selection subsequently completes: 103 PASS in 11.140s, raw
`5ca20173c869f5ece35d08027e004599b42bf4f290ef0fabb23120e0efd05f08`
(BEGIN 1 / END 113). The earlier whole remote-module selection was deliberately
interrupted after being found too broad for this development slice; its original
KeyboardInterrupt and child exit -2 remain in raw
`ef8eaa555f698b333858680c99c67c5d48164d6f09c943275ae0533f755fd1ff`.
That interrupted run is NOT a completed suite or PASS; no existing case is removed.

A single-core profile in the same bounded diagnostic completes in 380.052s,
raw `748be848643a4db955ae864e2872ee7ea84b5c71e8e8dfa1713e193a3cf53055`
(BEGIN 1 / END 166), with Count=1 UNKNOWN and no observer error. Only its first
genuine qualifier core is profiled, adding measurement overhead: 1.609s versus
the two unprofiled cores at 1.215/1.222s. It records 176,620 original ancestor
entry checks, 233,188 stat and 268,547 fstat calls in that core; it does not prove
ordinary timing, full FIRST closure or a runner approval.

The actual IB provenance digest path now acquires the held original parent and
file together BEFORE any digest-body stat/read, then checks the live leaf and
the complete fresh ancestry again before return. Remembered parent descriptors
are lookup data, not old verification results; the original file acquisition
still performs its fresh complete entry walk. Every actual byte is reread and
hashed, the ordinary pre-open regular-file check is retained, and no callback,
deadline, FD ownership or qualification result is cached. Independent direct
and real analyzer/receipt workflow initially give 2 FAIL (duplicate warm entry
walk), raw `7d0afcbbd70d1d5d12e867ebf46cab146055e1853472846303b30a9e68ef695c`.
Review catches and independently reproduces two initial refactor regressions:
ordinary nonregular pre-open order (raw `bc17a2c45d0faee942864fd7f46d8598a9cb42e35b775fe28a5da821b532d09e`)
and canonical-parent rejection (raw `0c87b57c66ea746e417e5642fb89315f2f17dab0f34539e0c612c21972a32e39`).
Both are repaired without weakening their refusal expectations. Final pipeline
direct, provenance direct/workflow and three real receipt scenarios give 52
PASS in 4.266s, raw
`9a3a3f514e2ad858abfe24c057f5bae34e2e1187bcf4979b725d68ea06827709`.
The manifest explicitly connects the real pipeline/provenance workflow. This
is local slice evidence, not the still-open original-read deadline, whole
REQ7 or current formal full/check proof.

The same original-component bounded diagnostic after this change completes in
374.404s, raw
`58235cca0e8d83ea4f6d405bb12113145a7e123f012fa84208c2aea50b06f948`
(BEGIN 1 / END 165), frozen diff
`3e984f2ed648784c60ed105cce3a9cc34676cea69dc9b9f07ffec7dbc23a0b81`.
Three genuine source cores take 1.129 / 1.125 / 1.124s; their complete factories
take 1.157 / 1.153 / 1.153s. Initial facts take 1.466s and the next ENTRY/EXIT
facts 2.622s before the intentional stop. Count=1 UNKNOWN and original cleanup
refusals remain physically present. This measures a modest improvement, not
closure of the whole original-read deadline, a send, or a formal approval.

Two remaining consecutive exit walks are independently reproduced: the archive
witness and directory duplicate perform two identical ancestry checks after
their last I/O. Their original context exit now supplies the one complete fresh
exit walk; no earlier read/dup exit is reused. Initial two subcases FAIL (8
ancestors expected, 16 observed), raw
`45a3a7c92a895bcf20c9af4eed83c4f98f34be5c59ef2f925356a654322cab19`.
A real ancestor replacement during dup is still refused and the duplicate
closed. Pipeline/provenance direct and a real producer-to-receipt workflow
complete 49 PASS in 4.561s, raw
`0908b5e92dc981d1b1ad33f6681460304e541a58c4ef79ba943d67cc2f0a6764`.
This is a related slice result, not whole FIRST or current formal full/check.

One changed-tree ordinary original whole FIRST subsequently completes as one
ERROR in 383.951s (original session 21669 reaped exit 1), raw
`2011948b17fdf06da9cb10ce85ad86e32997b2f4aa19c52570b87278696f53bf`
(BEGIN 1 / END 312); its known original 2362-byte prefix remains unchanged.
Nine native reads return 0, G1 quota/inventory is present, Count reaches
1 UNKNOWN, and complete facts take 1.463 / 2.660 / 2.609 / 2.617s. The ordinary
run exposes the real sending refusal but not its innermost stage/predicate;
the previous 1.402s-expired observation is historical, not this run's cause.
No full retry follows. One bounded diagnosis reuses the sealed four-stage and
failure-only read observers, delegates each original primitive once and keeps
all clocks/deadlines/results unchanged. Its three pure controls check only the
observer, not native behavior or an approval.

The bounded original stage diagnosis completes as one ERROR in 375.084s,
raw `e4352b6a5a3b7c57ee666d071475dbb6050e2b9ce5d824b79171e00ffc393d27`
(BEGIN 1 / END 316). The second nonconsuming wire fence finds original
template identity already expired by 0.337918s; all eight other identity
predicates match, one request preparation returned, and Popen/supervision
counts remain zero. Count remains 1 UNKNOWN. This is a proved failed
boundary, not an inference from standalone PASS or a full proof.

One-use consumption is now a private DATA-only mark at the same original
preparation boundary. It returns no grant and calls no semantic verifier.
The original complete fresh verifier still runs immediately before Popen,
followed by the original request/token wall-expiry check, and after send;
scope tails and the total 60-second budget remain unchanged. Startup or NI
never rolls back consumption. Clear independent RED is two FAIL, zero ERROR
(`7f74fc5cf90876bc15512d845579a4b30db446047901eb8e55fd28aec47fdd25`),
then three PASS (`b2603f2b349673b41b8dbbcf02221c4eb0f646c6ec57b0c5e9673e4dd92c9027`).
The first 167-case related run retains one FAIL: its old second-read ordinal
injects drift at post-send after early semantic duplication is removed.
The fixture now delegates the complete original at the actual nonconsuming
pre-Popen fence and preserves zero Popen/child/request, original ctime drift,
UNKNOWN and no second attempt assertions. All 167 related cases then pass
in 75.942s (`77c23dba81b11bfd2ab220467263e27b208ba7e3458b2251a9fa720e24669253`).
The three preparation/final-fence cases are additionally strengthened to
require the actual sender exception outside original cleanup, and pass on
those final test bytes (`6f5b6060434761c2f6999834dcf65d587e102b8bafed59a1d8571e5db837948f`).
These related results do not prove cumulative whole FIRST, current full/check
or real Cloud/device acceptance. No approval ledger is changed.

One ordinary changed-tree whole FIRST recheck still fails: original session
45580 is reaped exit 1, one ERROR in 393.498s, complete raw
`0d0b38b8ea9c7cc77fbe8118b2871dbb425e07356b531ff09018106f1aeb4c6f`
(BEGIN 1 / END 312, old 2455-byte prefix preserved). Nine native reads return
0 and G1 quota/inventory is present; Count is 1 UNKNOWN, initial facts take
1.479s and later facts 2.734 / 2.669 / 2.662s. The sender refuses, but this
ordinary log does not expose whether the first failure is prelaunch, post-send,
request, Popen or supervision. Do not inherit the previous second-wire expiry
diagnosis after the sender's number of semantic wire calls changes.
The unchanged sealed stage/failure-only observers remain applicable: the
first observed wire now means actual pre-Popen, not the DATA mark; zero wire
events means not observed, not successful admission. Three pure controls pass
(`22ca62ec5d033a15962490cb018f3c254a3329e657d31ef027a2844092caaf83`).
One bounded diagnostic follows to locate the actual earliest failure, not a
blind full/whole retry, larger timeout or approval.

### REQ7 fixed non-yield original-read groups (2026-10-14, development only)

The bounded original stage diagnostic was reaped with one ERROR: actual
pre-Popen verification, Popen and supervision returned, but post-send rejected
the original template identity read already 0.899376583 seconds past its
unchanged 30-second deadline. The separate explicit owned-TMPDIR whole test
also remains one ERROR (371.548s, complete raw
`73cd91aa7fde7350ff25efeb3b735ff173d72c292f0b92b9117df6ffe82f2953`).
Neither failure is a PASS or evidence that changing temporary paths fixes it.

The private fixed read group now freshly checks common target (and, for
project reads, original credentials) at both boundaries of a non-yield
evaluation. Every actual issued read keeps its exact original packet identity,
shape, full body, path, owners and original deadline. After the last real
token/owner operation, the actual target is rechecked, then all original token
fields and read registry entries are checked again. One final monotonic sample
checks EVERY original deadline, including the first item while the last item
was evaluated. No cached PASS, new issuer, renewed deadline or send permission
is produced; public single-read APIs remain unchanged.

Only contiguous checks in the W1/template/nonce gate and the two business
continuity tails are grouped. Decoding, original-file replay and per-row
semantic work remain between separate fresh checks. Direct and actual owned
OAuth/TLS multi-script tests independently reproduce missing groups; return
boundary tests reproduce real target drift, equal token-object substitution
and expiry after the last original authentication delegate (four FAILs before
the boundary repair). All original assertions and raw failed logs are kept.
Current direct/workflow mappings already cover the three production paths.
Local groups do not close whole FIRST, REQ7, current full/check or real-device
acceptance. No approval ledger is edited.

The corrected return-boundary five direct/actual workflow cases pass in
13.875s (`3b4a6e777d1f852778b61e90868be96204d9ca17ae95740155b12cd0b0af6705`).
The unchanged public single-read suite plus related preread direct and real
business-creation workflows then pass 58 tests in 46.718s
(`f486971a17b376515d206484f13429b2b087024e8f1fd2d5443aaa9aa4878939`).
These are local regressions, not an approval or completed cumulative FIRST.

### REQ7 fixed read acquisition and observation windows — owner 2026-10-14 - historical / superseded

This dated section records the previous30+30 contract and its original test
evidence. The owner approval on2026-10-15 below supersedes only its read
observation duration; historical results are not relabeled as60s proof.

Owner delegated the simple time contract to the main window. Read acquisition
still has a total30s budget from `read_once` entry: preparation, child launch,
real supervision, complete response, all stream cleanup and final original
project token/target/dual-owner checks must finish within it. Mutation remains
60s. Successful completion then issues the original process-local read once,
with a separate fixed30s observation window. Getters, groups and finalizers
check that original deadline without renewal. Existing source/credential/owner
revocation checks remain; the observation is neither CAS nor a write permit.
Compared with the historical shared deadline, maximum observation age from
attempt start can now approach60s. This explicit contract change is not a
larger transport timeout or a relaxed test timeout.

Independent lifecycle direct tests and genuine owned OAuth/TLS read workflows
first recorded4 methods/9 assertion FAILs (`1a71b452...523573`); issuance failure
controls recorded3 methods/5 assertion FAILs (`91905af8...4b7f97`). Moving issuance
after cleanup, checking final originals, retaining interruption and retracting
partial registrations produced6 PASS/1.647s (`fdf33151...335698`), followed by50
launcher/supervision regressions PASS/16.103s (`b28faf99...792840`).
Review then found a final-auth RETURN boundary. The first fault hit the earlier
supervisor cleanup and passed (`63c9c543...e49fb2`), so it is not the new boundary's
RED. Targeting the fourth actual target check independently reproduced two
FAILs (`c652c777...9743dd`); a pure recheck of the same original auth registry,
token fields and expiry after the last source I/O repaired it. All direct cases
and both genuine project/legacy lifecycle workflows pass13 cases/3.634s
(`742a5148...37405b`). Old failures, old assertions and complete raw logs remain.
Current manifest already binds this script to direct and multi-script workflows.
This is local lifecycle evidence, not whole FIRST, current full/check, runner
approval, actual Cloud/VM/SSH validation or overall REQ7 completion.

### REQ7 fixed60s observation approval — owner 2026-10-15

Owner explicitly approved successful-read observation30s ->60s. Acquisition
remains a total30s from `read_once` entry, including real supervision, complete
response, confirmed termination, all stream cleanup and final actual
token/target/dual-owner verification. Only after all of that succeeds is one
observation sample taken, issuing an original fixed60s deadline. Getters,
groups, source checks and finalizers never renew or replace it. Existing
issued records are not retimed. Mutation60s, token wall expiry and original
source/owner/credential revocation checks remain unchanged. From acquisition
entry to observation expiry the maximum can approach90s; this does not
increase the transport/acquisition budget or prove remote atomicity/CAS.

The independently updated literal direct, actual TLS project/legacy and
cohort expectations first recorded3 methods/4 assertion FAILs,0 ERROR in
3.211s against the old30s implementation. After the observation constant
alone changed to60s, the complete launcher module passed41 tests in33.598s.
All acquisition/final-source/cleanup/interrupt/partial-registration/exact-
expiry rejection scenarios remain. These are local scoped results, not
whole FIRST, full/check, approval or actual Cloud/field verification.

Earlier notes that describe a fixed30s successful-read observation remain
historical evidence under their original source identities. Current
successful-read consumers, including the one-child/four-original cohort,
use the approved60s contract without renewal. Any old30s reference to
acquisition, supervision or cleanup still denotes the unchanged30s budget.
No test or field scenario is removed and no new field permission is granted.

### REQ7 adjacent catalog replays and a metadata-fixture failure (2026-10-14)

The bounded original FIRST diagnostic remains one ERROR/357.480s (complete
`394cd5e4...bd889`, 374 physical lines). Its failure-only group observer records
the original template-identity observation already expired by0.042038s before
the post-supervision wire check; the recorded raw/body/owner/binding/shape agree.
Actual fixture Popen and supervision each entered/returned once. This proves
this run's stage, not retrospective causes for other sanitized failures or a
successful send/settlement. No observation or transport deadline was extended.

Two same-checkpoint catalog replays are now removed: `_inputs` still returns
only after its real original context ENTRY/EXIT, and the writer borrower still
checks originals AFTER membership before yielding; only its adjacent extra
exit replay is removed. All external source/facts/PRE/POST checks remain.
Independent actual-owner/catalog controls first record2FAIL (2vs3 and3vs4)
plus the already-correct real membership-rebind control PASS, then3PASS0.325s
(`299a06b4...3c479` -> `2ef98b27...9fdc0`). The initial3ERROR fixture run
(`2b1963e0...fc190`) is retained separately, not called behavioral RED.

The first whole related global module records103 tests/oneFAIL9.287s
(`75ec207a...a322`). A failure-only original injection observer establishes an
AttributeError during mtime restoration (`4b7e184f...c4dd2`): the synthetic-root
fixture omitted native `st_atime_ns`. An independent native-metadata expectation
first FAILs (`e73ba4fe...46571`); only that fixture field is added. The new control's
stale pre-open-atime assumption also FAILs (`266b035f...e19fd`, `f794ec0e...448d8`)
and is retained; its independent native stat is captured after actual open,
before the synthetic fixture. Original same-inode rewrite/restoration/rejection
assertions remain unchanged. The control and original fault workflow then2PASS
(`2305c1b1...e6089`), and complete global/owner modules119PASS8.789s
(`32277b90...7f3a`). The failed119-case round was started before the immediately
preceding targeted result was accepted; retain that sequencing mistake and do
not describe it as a successful prerequisite or as full proof. Later runs
explicitly require the targeted command's completed exit0 before dispatch.

These are local current-slice regressions. No performance gain, completed
ordinary FIRST, runner approval, current full/check or REAL_ENV PASS follows.

### REQ7 one original C6 per fixed K checkpoint (2026-10-14)

Only the fixed non-yielding evaluator's adjacent `c6_verify(); c6_verify()`
becomes one complete original replay. Each real K getter retains separate
PRE/POST checkpoints; standalone K and the evaluator's complete source/C19
ENTRY/EXIT remain unchanged. There is no cached qualification or renewed clock.
Independent direct RED is one FAIL (`e0cc87ad...dfa2`); the actual original
Count/K checkpoint workflow also first FAILs `[1,1] != [2,2]`
(`c276ec08...9dfa`). After the minimal implementation, direct and that real
checkpoint control PASS. The newly written negative fixture FAILs separately
(`7081ee87...556`): its deliberate primary poisoned the scope before the actual
tail, so that result is not a successful tail refusal proof.

The repaired negative uses the genuine protected qualifier return, original
C6 closure, actual same-byte/new-inode DELIVERED replacement and complete EXIT
refusal. Three intermediate fixture ERRORs are preserved: reading a mocked
function's `__wrapped__` (`8fe20bfa...6c4`), intercepting the pre-Count prefix
(`78c50915...dc2`), and observing an early-import code identity rather than the
current retained callback (`244c72ff...820`). Only Count=1 is targeted; the real
Count=0 prefix delegates unchanged. A short independent same-name reload/real
closure control PASSs (`4dafaccd...9e5f`). Original callback code is now observed
from the actual packet closure, never invoked or substituted by the observer.

The actual native negative then PASSs1/313.894s (`6037fbf8...dd15f`), complete
223 physical BEGIN/END lines, original4413-byte prefix preserved. The genuine
qualifier returns while unpoisoned after an actual internal C6 delegate; full
raw EXIT refuses the replaced original before any result escapes, original
receiver/slots close and Count remains1/UNKNOWN before and after. The expected
controlled stop occurs only after that refusal. Original diagnostic traceback
output, including the later original global finalizer refusal, remains in the
raw log. This is one scoped failure mechanism, not a successful ordinary FIRST,
performance claim, full/check/approval or overall REQ7 completion.

The complete settings-allocation direct module plus the observer control then
97PASS4.787s (`f671021a...ab81`), original related process2150 reaped exit0,
106 physical BEGIN/END lines with unchanged command/tree/diff identities.
These direct regressions do not substitute for the remaining true Count/K
workflow selection, ordinary complete FIRST or exact-tree runner full/check.

The seven true Count/K/registry/restoration/last-delegate workflows also then
PASS7/123.388s (`628302ac...b34e`), original71391 reaped exit0, 35 physical
BEGIN/END lines and known8670-byte prefix unchanged. They preserve one real C6
loan, complete Count boundaries, two independent actual K checkpoints, copied
registry refusal and irreversible poison after caught drift. The next ordinary
FIRST is justified by this substantive implementation change and these scoped
regressions; an actual performance gain and normal complete send remain to be
measured. It is not an unchanged retry or formal full proof.

That changed ordinary FIRST did not complete: original process50138 was
reaped exit1, one ERROR/327.845s, log `91f11f5d...5fd` (321 physical
BEGIN/END lines, original3783-byte prefix preserved). Five actual source facts
returned, but the Count lane's original EXIT refused; Count remains1/UNKNOWN.
The raw traceback does not expose the earliest failed predicate or whether
the real request/Popen/supervision/post-wire boundary completed. The older
1.709s expiry diagnosis must not be retroactively assigned to this run.
Next is one bounded failure-only original group/stage diagnosis, not another
ordinary FIRST or full retry; clocks, original deadlines and guards remain
unchanged. Scoped regression PASS does not close this failure.

The one bounded current-tree group/stage diagnosis subsequently ERRORs1 in
329.886s (`93cc1aa0...cd82`, original23972 reaped exit1, complete318 physical
BEGIN/END lines, both2583/4416-byte prefixes preserved). In this diagnostic
run only, the first failed single read is `template_identity`: its original
registry/body/shape/writer/owner/binding match, but its fixed observation
deadline has expired1.814629s before the original lane EXIT delegate.
The actual request2, fixture Popen1, supervision1 and wire2 all returned.
This does not retroactively identify the ordinary run's unknown predicate or
turn a returned wire check into successful settlement/COMPLETE. Count remains
1/UNKNOWN. Static review finds no same-boundary replay removable from the
Count facts/source/wire checks across intervening real I/O; neither deadline
relaxation nor deleting that EXIT gate is an accepted repair. Further work
must address an evidenced mechanism, not repeat the same ordinary/full run.

### Fixed four-template read acquisition (2026-10-14; core integration under verification)

The fixed consumer boundary `_acquire_current_project_template_reads` now
delegates once to the actual cohort and retains all four per-kind original
read gates. Independent control and real TLS workflow tests first FAIL3 for
the absent interface (`fbda7198...5650`), then PASS3 (`61b888d2...800a`): one
actual owned child/four requests, and a partial fourth response returning no
observations. The control-only test additionally rejects short/extra result
tuples before consumer admission. At that boundary-only checkpoint the online
core still selected its old single-read loop; those results did not prove
worker selection or FIRST closure. Manifest explicitly binds this boundary.

The subsequent actual-core routing oracle and genuine preparation workflow
first FAIL2/34.423s (`de728533...0c84`): no cohort selected and four original
scalar child acquisitions, respectively. After minimum routing to the fixed
consumer, the unchanged independent expectations plus source-bound direct
class PASS8/51.458s (`61c0f38c...42a4`). The three core fixtures record logical
responses separately from one real cohort child/four actual TLS requests;
metadata drift remains after its actual fourth completion. Entry and each
original response's source/use checks, final source replay, POST/EXIT,
deadlines and old scalar creator/reconciliation paths remain. No timing gain
or repair of the older whole-FIRST CountEXIT expiry is claimed from this
scoped preparation result. Its remaining negative scenarios and actual
archived NEW→FIRST→Count/CLAIM/wire must still be verified.

Original negative selection then PASS3/FAIL1 (`bd6eb6e4...53b4`,170.800s).
Quota inode replacement, post-finalizer expiry and business-original finalizer
replacement remain rejected. The postclose revoke failed because its old
fixture patched the convenience `_reads` wrapper, while the core actually
entered `_inputs` and bound fresh reads directly; no revoke was injected.
Independent structural RED1 (`ed5e76dd...6039`) preceded the minimum fixture
repair: delegate actual inputs/bind, wait for genuine CLOSED, revoke the exact
row registry, restore only at outer cleanup. Production refusal is unchanged.
The first paired run retains its new structural selector FAIL (it counted
the two registry-lock `with` blocks as source holders) and genuine revoke
PASS (`db6a8edd...a89c`). Selecting the literal source-holder `with`, without
changing the expected count or refusal contract, then PASS2/50.539s
(`5608e38d...85a1`). This is targeted closure of that fixture problem, not
an unchanged full retry, whole-FIRST success or current full/check proof.

The one changed-core ordinary archived NEW→FIRST run then ERRORs337.509s
(`41c26bbd...2accb`), original10233 reaped exit1 and complete317 physical
BEGIN/END lines read with the old3783-byte prefix/inode retained. Genuine
business reads return and quota/inventory compose; Count1/UNKNOWN is retained.
Five actual source-facts calls return in1.3285/2.3587/2.9784/2.3851/2.3880s,
but the Count-lane EXIT still raises `GlobalAttemptHold`. Its exact original
predicate is not revealed by that ordinary log; neither it nor the earlier
one-C6 ordinary failure is retroactively called a proved expiry. Cohort/core
integration is therefore not whole closure or successful settlement. No
ordinary/full blind rerun follows; the existing sealed single-delegate
failure-only group/stage diagnostic is statically compatible with the
current eleven-field original registry, and its unchanged3 preservation
controls PASS (`28a8eeb4...90bb`). Any next execution is a bounded diagnosis,
not formal proof, and must retain the exact current source and complete END.

The new internal `OwnedProjectTemplateReadCohort` performs only the original
fixed identity/header/whitelist/metadata native shapes, once each in order,
inside one owned supervised child. Metadata remains its original restricted
read-only search POST. This is not a Google atomic snapshot or arbitrary batch.
Acquisition30s starts at the single group entry; only complete correlated
four-response bytes, confirmed child termination, all stdio cleanup and last
original authentication/target/dual-owner checks allow one observation start.
The four previously unissued originals receive that one fixed60s observation
deadline. No existing observation is renewed; mutation60s and consumer
source/POST/EXIT checks remain unchanged. Combined output retains2MiB and
private input32768-byte caps. Partial/foreign/reordered/trailing frames,
last-source failures and interrupted registration leave no cohort originals.

Independent initial5FAIL are interface-absence RED (`ab2ddd...5370`); the same
five codec/issuance/cleanup/final-owner/deadline/registration controls then
PASS (`7d6d2b...71dc`). The previous one-reply TLS fixture initially ERRORs
against an independent four-real-connection expectation (`6b6a3b77...0a26`),
then its bounded1-or4 extension PASSs that control (`64078820...217a`), with
old one-reply behavior and3s/4s bounds retained. Actual original project SDK
authentication, one real child, four native TLS requests and complete cleanup
PASS2/2.620s (`36f82d1d...c519`), including a partial fourth HTTP reply that
issues nothing and cannot retry. These are scoped production/transport
boundaries, not timing gain, ordinary FIRST, successful settlement, installed
worker selection, full/check/approval or overall REQ7 completion. Existing
single-read tests remain; integration must use the genuine cohort factory and
actual four-request fixture, not bypass old scenarios or fabricate responses.

Both complete existing read-launcher/native-TLS modules then PASS57/34.875s
(`90d0c542...6d7d`), original41417 reaped exit0 with stable81 physical
BEGIN/END lines. This includes all original single-read native/owner/cleanup
scenarios and the new fixed-cohort cases. No failure, skip or weakened
expectation is used to obtain this scoped result. Actual current FIRST
integration, performance/whole completion and exact-tree full/check remain
OPEN; the older exit-expiry failure is not declared repaired by this result.

The subsequent current-core failure-only diagnostic is complete, not a full
proof: original session3818 reaped exit1,335.413s, raw
`e25bb36cddec28053beabe776f5209043da204271b20bff0cff28df036c74757`,
physical BEGIN1/END314 with stable identity. In this diagnostic specifically,
template_identity was already expired1.317174917s before the original Count
EXIT check; original registry, writer/owner/binding/shape/data still matched.
Actual request2/Popen1/supervision1/wire2 returned, Count1 remains UNKNOWN.
This does not retroactively establish the predicate of earlier ordinary logs.
No deadline extension, original finalizer removal, cached validation, Count
reset or ordinary/full retry follows from a partial PASS. The next bounded
change tests fresh grouped template checks at each unchanged pure guard-loop
boundary; interleaved full original graph checks and all distinct cleanup
boundaries must remain.

The six pure four-template guard loops now each use one fresh existing project
read-group check, with exact four keys and original response objects verified
before and after delegation. No group result/PASS is retained. The original
per-kind acquisition and interleaved `originals -> single read -> originals`
loop remain unchanged, as do all separate yield/image-close/finalizer tails.
Independent direct/routing/TLS initial REDs are `f29e80e0`, `8c809ec7`, and
`67b0c51a`;12 current direct and genuine TLS/group-source controls PASS3.617s
(`82307d65`). Five unchanged genuine core/business/quota/expiry/postclose
scenarios PASS251.668s (`d1f0c768`), original52250 reaped exit0 with stable
BEGIN1/END24. These scoped results do not establish a timing gain or complete
FIRST/settlement/full/check. A bounded current changed whole scenario may now
be tested once; another failure requires evidence-based diagnosis, not blind
ordinary/full reruns or a longer deadline.

That bounded changed ordinary scenario still ERRORs338.871s, original73400
reaped exit1 and full stable317physical lines read (`cf281feb13c68cd42be0f7264af29d68b0a8c069ed0aee0fb2338248a7f312e8`).
The actual five business children returned0; dedicated quota/complete inventory
and Count1UNKNOWN remain, with five actual facts replays returning. The
original Count-lane EXIT raises GlobalAttemptHold; this ordinary log does not
expose its exact rejected predicate. The six-loop optimization is therefore
not whole closure or proven timing gain. No formal full is launched. The
sealed failure-only observer may be used once to identify this current tree's
actual original deadline/identity predicate, preserving all deadlines and
original delegates; results cannot be assigned retroactively to this log.

The subsequent unchanged failure-only observer completes ERROR340.373s,
original92028 reaped exit1, raw `7560bc581c8bc3fdd15b0888ddf6c99d23d08944d0bef154f7d2827dc2f5dad7`,
stable physical BEGIN1/END314. In that diagnostic alone template_identity was
expired0.399929542s before the original Count EXIT, other original relations
matched, and request2/Popen1/supervision1/wire2 returned with Count1UNKNOWN.
The separate ordinary log's exact predicate remains unassigned.

The business binder's pure acquisition-current loop now groups only shared
auth/target reads, freshly on each call. Exact original acquisition tuples,
container identity, order, first identity plan and common provenance are
retained. Every scalar HTTP acquisition and its original/inventory fences,
1000-operation/16MiB business bounds,2MiB per read, dedup/None and CLOSED
issued-only tail remain unchanged. This is not a business batch/cohort or a
cached validation. Independent direct2API-absence RED (`9873b90d`) and actual
prepare routing RED (`0c6d7fa7`,31.322s) precede implementation; the latter
finishes actual old first-panel transport before rejecting zero group hits.
Current24 direct/control/real prepare/postclose tests PASS103.060s
(`ec491091`), followed by3 unchanged genuine quota-rebind/last-finalizer
expiry/business-original-rebind cases PASS133.134s (`749886ff`). Actual
group observations preserve each real response/auth object; all original
logical/physical IO, zero COUNT and source/cleanup expectations stay. Manifest
workflow `req7_default_original_business_reads_post_all_finalizers` already
maps these production/test paths. No timing gain, complete FIRST, approval or
full/check is inferred; a further bounded whole requires an explicit basis
on this substantive code change, and another failure requires diagnosis.

The subsequent code-changed original archived-delivery/new-originals/FIRST
scenario passes323.056s (one existing test, original session3736 reaped exit0).
Its complete log has stable BEGIN1/END29, SHA
`665bc5016f85719048eeb0fae5dd79fdaa7aae73a7d43a2c25ae01e8633209b7`,
and identical BEGIN/END source diff `cd02e3d2`. All five actual business
children return0; dedicated quota, complete inventory, Count1UNKNOWN and
the original final transport/source assertions remain intact. This is
local workflow evidence on that recorded tree, not a full-suite proof,
measured timing gain, real Cloud/device acceptance or authority to clear
UNKNOWN. Earlier failed ordinary/diagnostic logs remain distinct. Formal
related/full/check still require the reviewed clean-tree runner prerequisites.

The six-module related regression completes707 tests in2308.222s with exactly
one FAIL, not a successful related/full proof (raw
`4e5dcedee78fa2b02aeb5ed28533cad5adbf617e1bc68a6366d317a3faa52905`,
BEGIN1/END972). The second native delivery fixture observes the obsolete
`_hold_delivery_authority` leaf, whereas creation after an existing original
pair now uses `_hold_delivery_entry_authority` and the original native creator.
An independent fixture-routing RED (`076c2d83`) precedes changing only those
observer hooks. The genuine original second-delivery scenario and routing
control then PASS23.937s (`aa6e226f`); original event bytes, first-pair inodes,
outbox cleanup and both UNKNOWN counts remain mandatory. This diagnoses the
specific fixture failure; it neither relabels the707 run nor replaces full.

Count raw-tail phase acquisition has a separate real cleanup fix. Two literal
direct lifecycle controls and two actual Count/settings/catalog workflows
initially FAIL (`4d13b189`): phase set interruption/allocation failure leaves
original settings/raw slots unclosed. The issuer now captures its original
binding and fixed close function before guarded phase acquisition. Failed
acquisition closes only those strong original resources, without a forged
phase, semantic Count/C6 verifier or K/source permission; first NI is retained
and only an actually obtained token is reset. The first revised selection
still reports two fixture FAILs (`34b44aa6`); a bounded callback-only diagnostic
(`6bc877c5`) proves its raw namespace check incorrectly omits the genuine
Count1 append. The fixture now permits exactly literal ATTEMPT-1 in only the
counted graph, retaining all raw checks and forbidding masked callback errors.
Four new controls plus six unchanged tail controls PASS1.010s (`90aaaa18`).
The actual workflow keeps Count1 UNKNOWN, no CLAIM, all original FD closure
and registry revocation; no timeout or behavioral expectation is weakened.
Manifest direct and `req7_native_c25_count_claim_original_replay` mappings
already cover these existing modules. Exact-tree formal related/full/check,
field acceptance and ordinary publication proof remain separate and OPEN.

Native TLS response ownership has an independently reproduced cleanup defect:
a `Connection: close` response can own a detached socket makefile after the
connection has released it. An ordinary caller retaining a denial traceback
must not keep that response open. Three independent literal direct controls
and one genuine owned TLS/Sheets read workflow initially FAIL4/ERROR0
(`2e266a0a`); the minimal fix closes response then connection, attempts both
independently and preserves the first original BaseException and its cause.
The unchanged four controls PASS (`0700c766`), followed by all46 cases in the
TLS-input, native-wire and Sheets-read-plan modules PASS21.063s (`37c59831`).
Each case is followed by the unchanged original parent FD census; no forced
GC, adopted numeric FD or arbitrary socket close is used. The workflow holds
only a weak response reference before its assertion; its own finally rescue
does not count as product cleanup evidence. Existing direct and
`req7_exact_native_business_read` mappings cover this change. This is a real
local cleanup fix, not proof of the specific six FD failures in the prior
full run (their original FD/field remains UNKNOWN), current full/check,
Cloud/device acceptance or broader permission. Acquisition30s, read-only
observation60s and mutation60s are unchanged; prior failed logs are retained.

### REQ7 confirmed publication versus reporting — owner 2026-10-20

The owner approved only this narrow distinction: after required durability,
original/target verification and critical owner/FD cleanup have all succeeded,
a later stdout or explicitly non-critical logging failure may be reported as
committed with reporting failure. It must not retry initialization or grant
business sending. A visible final link alone is not confirmed durable commit;
required fsync, identity-check and critical-close failures remain UNKNOWN/HOLD.

A private publisher diagnostic candidate now records visibility separately
and returns plain COMMITTED_CONFIRMED DATA only after all required closes.
Independent diagnostic direct3 initially FAIL3, then the same3 PASS; original
exclusive-link refusal and healthy source-reader controls PASS2. These are
synthetic protocol DATA with native private filesystem operations, not TLS,
Cloud, a worker permit or completion of the publication protocol. The old
post-fsync/close cold-reader refusal failures and assertions are retained.
Moving an in-memory flag does not distinguish otherwise identical cold
on-disk states, so the publisher remains unintegrated. Actual confirmed
publication followed by reporting failure, real TLS/cold-reader closure,
current full/check and REAL_ENV remain unproved. No new residual risk for
critical failures or power loss was accepted.

### H private native-lock/recovery workflow — 2026-10-20

`test_h_feedback_real_lock_recovery_workflow` adds two independent controls
using actual Feedback discovery/revalidation, deployment-lock acquisition,
runtime stop and private global-writeback-state recovery. The lock and flock
are not mocked: an independently opened descriptor must find the lock busy
during revalidation, stop and recovery. The received original lock FD must
be closed on exit and the same lock must then be independently available.
The positive control really removes only its private validated published
writeback state; the malformed-private-PID negative control must retain
state, authority and PID identity/bytes, with no recovery or signal attempt.
Its exception must be the original runtime contract error from the PID
parser, not merely an arbitrary CLI-normalized exception. Only a private
synthetic proc tree is used; every signal attempt is explicitly forbidden.

Removing the sole stop call from an in-memory private Feedback AST makes
both new literal controls fail. This is an oracle-mutation RED, not a product
defect or production fix. The first private harness failed earlier on an
existing non-root-owned finish-state fixture; that log is retained and is
not counted as the oracle RED. The fixture now uses a nonexistent private
finish-state leaf and the real absence check, without faking root ownership
or writer authorization. The tightened private controls plus the original
runtime direct control PASS3. The integrated run is recorded separately in
the current work list/evidence receipt; repeated private/integrated cases
are not additional unique coverage. Production scripts and original test
assertions are unchanged. Manifest registration includes the actual lock
and finish-state source members. This is not real process stopping,
full FD census, injected-close safety, device acceptance or full/check;
the existing REAL_ENV cases remain NOT RUN.


### SCP local package-source holder library — 2026-10-20

The parent content holder freezes only explicitly needed local regular package
originals using held ancestor/file descriptors and one streaming SHA per path.
Repeated request DATA can reuse those hashes; source identity drift poisons
the group without refreshing the baseline. Its total-FD cap and acquisition
deadline are internal static/cooperative checks, not hard I/O supervision.
Entry failure closes held originals without changing replacement files; an
uncertain close remains HOLD on subsequent close calls without retrying slots.
Original operator exception objects and existing causes survive cleanup faults.

The associated direct and real planner/holder/receiver-PTY workflows use only
private files and executable source stubs. Request/dispatch bytes and the
returned record remain DATA, not authenticated native dispatch or fsynced
companion evidence. The original main entry remains HTTP-only, and SCP
preflight/nonempty execution payloads retain SCP_CONTENT_BINDING_REQUIRED.
Native parent/fork source export, reliable request-content journal and manager
ACK are still OPEN. Unknown cleanup residues, asynchronous descriptor handoff,
hard I/O supervision and simultaneous resource/cleanup-failure classification
are not proved by these local cases. Existing REAL_ENV remains NOT RUN;
no full/all/require-full or release proof was produced.


### LOCAL original-package stage companion — 2026-10-20

The reviewed driver extension holds one real package owner in the original
parent scope and borrows that same object into real readiness children.
An actual active namespace lease binds the five original request/script/runner
objects to a file-fsynced, directory-fsynced, critically closed package-source
companion. It remains LOCAL / NOT_EXECUTED / UNKNOWN DATA, never a dispatch,
native observation, completion or ACK authority. File/directory sync, source
acquisition, provider-source close and writer-finish failures revoke the group;
later scopes, fresh baselines and repeated uncertain FD closes remain refused.
Cached foreign/None providers cannot replace the held fixed sibling source.

The seven new canonical modules cover 18 whole tests; uncertain FD cases run
their unchanged assertions once in an owned child, not twice as unique coverage.
Literal driver hunk inverses preserve the original frozen upstream source SHA,
as do all existing access/layout/template source checks. This is not hard I/O
supervision, a native SCP bridge, cold upgrade recovery or device acceptance.
The CLI remains HTTP-only; SCP preflight/execution remains HOLD. Existing
REAL_ENV cards stay NOT RUN and normal full/release gates are unchanged.


### SCP declaration/request DATA and empty-wire boundary — 2026-10-20

The renderer now accepts the explicit lexical SCP method and can create an
original REQUESTED/UNKNOWN/NOT_EXECUTED graph instead of rejecting its method.
This is planning only: no source secret, package grant, native dispatch or ACK
is created. The existing shell still rejects SCP without its unimplemented
content bridge (exit64); actual OS/BIOS/CPLD Bash EOF controls verify zero
nv/ssh/scp/curl calls and no fetch/install, ACK, package or switch-file output.
HTTP remains a separate real request control, not a relabeled SCP workflow.

The CLI remains HTTP-only and native SCP executor/preflight/nonempty payload
remain HOLD. The shell/template bytes are unchanged; the renderer change is
only a fixed method-set/message hunk with an independent literal inverse and
the original frozen source hash. Declaration capability PASS is not a working
SCP pull, manager ACK, device upgrade, full proof or release approval.


### SCP original-request content DATA — 2026-10-20

Explicit SCP declaration scopes retain their selected original package owner in
the original parent, share it with real readiness children and persist the fixed
scp-source-request.json under the original namespace lease. This separate schema2
contains only request nonce, five original prerequisite hashes and needed-package
size/digest DATA. LOCAL schema1 and its full source lifecycle remain unchanged.
CPLD burn/refresh are one retained set; a changed second source poisons the shared
parent/child group before any companion/dispatch/ACK. File/directory sync and the
existing critical writer finish must all return; uncertainty revokes the group.

These REQUESTED/NOT_EXECUTED/UNKNOWN facts cannot reconstruct live authority.
CLI remains HTTP-only; native SCP, source preflight and nonempty execution payload
still HOLD. Local synthetic-package DATA tests are not a transfer, manager ACK,
device/power-loss acceptance, hard I/O supervision or full/release proof.

### REQ7 initialization safety gates — partial implementation, 2026-10-20

The ordinary worker and initialization CLI require the actual bound final
record and thirteen original evidence files, not INITIALIZED/OBSERVED-DATA,
None, a DTO, PASS or DONE. The read-only reader retains original project,
target and spreadsheet owners, source identities and cleanup checks. It is
not an issuer, repair path, second activation or business-send permission.

The canonical reporting module includes a producer-only UNIT seam and an
actual owned TLS/readback-to-normal-worker negative; the separate return-value
module is UNIT only and does not prove a completed-project positive. The
existing real completed-record positives and their loss/tamper/rebound tests
remain unchanged and OPEN/FAIL without a legal final publisher. Refusal tests
do not close the final commit/cold-reader protocol; critical fsync/close errors
remain UNKNOWN/HOLD and old cold-reader failure assertions remain intact.
No full proof, ledger approval, Cloud/field acceptance or release is implied.
