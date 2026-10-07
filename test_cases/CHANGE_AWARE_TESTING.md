# 脚本变更影响测试

`test_cases/run_related_tests.py` 把每个受管 Python、CGI、Shell 路径映射到直接测试和至少一个
多脚本 workflow/scenario。关系定义在 `script_test_manifest.json`，上一次测试通过的精确
SHA-256 保存于 `script_test_approved_hashes.json`。

## 安全原则

- 工具只选择和执行已有 `unittest`，绝不生成、修改测试方法或更新断言。
- runner 启动的 `unittest` 子进程固定使用 `/dev/null` 作为 stdin；测试不得读取操作员终端，需要交互的行为必须显式注入 reader 或 fixture。
- 成功后只原子更新批准哈希；测试失败、测试期间文件变化或异常退出都不更新。
- 新增/删除脚本、未登记路径、软链接目标变化、缺失测试模块或单脚本伪 workflow 都会失败。
- 同一真实文件的软链接别名作为独立发布入口登记；任一别名或目标变化会展开全部别名测试。
- 未识别的显式/Git 变更路径回退到全量测试，不会静默跳过。
- `path_rules[].complete_tracked_support: true` 只接受 repository-relative POSIX 的直接子项
  glob。runner 通过 held directory/file descriptor 验证 authority root、每个匹配成员的
  non-symlink regular/single-link 身份并哈希，再把磁盘集合与 `tracked_support` 双向精确核对；
  新增未绑定成员、缺失 pinned 成员、特殊文件、链接或验证期间 rebinding 都会在测试选择前
  fail closed。该字段与 `full_suite` 都必须是真正 JSON boolean，未知 path-rule 字段也会拒绝。
- `outputs/` 是交付物和构建 bundle 的固定根，不属于可执行源码 inventory；其中即使包含
  `deploy-upload-archive.py` 等已冻结副本，也不会被误判为新的生产入口。真实脚本仍从源码根
  登记，任意其他 hidden/ignored 路径不会仅因 Git ignore 自动获得豁免。

这样可以自动验证“某个实现改动是否仍满足已有合同”，但行为需求变化仍应先由开发者或
Codex 按 `CASE_TEMPLATE.md` 增加/修改独立预期，再修改实现。让实现自动改测试预期会同时
接受同一个错误，因此被明确禁止。

## 日常命令

`script_test_manifest.json` 的 `test_suites` 把每个 `test_*.py` 精确归入一个主测试域。以下
命令由同一个 runner 统一调度；分类运行只用于开发定位，不会更新批准哈希：

```bash
python3 -B test_cases/run_related_tests.py --list-suites
python3 -B test_cases/run_related_tests.py --suite deployment-runtime -v
python3 -B test_cases/run_related_tests.py --suite packaging-sync --suite repository-governance -v
```

当前主测试域为 `repository-governance`、`packaging-sync`、`deployment-runtime`、
`configuration-generation`、`monitoring-collection`、`ztp-runtime` 和 `vm-validation`。分类是
互斥且完备的；新增、删除或重复归类测试模块都会使 manifest 校验失败。

不需要 public authority 的选测在无 Git 环境也可比较批准哈希并运行；通过后自动更新哈希：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py -v
```

显式指定本次变更（仍会并入尚未批准的哈希变化）：

```bash
python3 -B test_cases/run_related_tests.py --changed ztp/manual-ztp.py --list
python3 -B test_cases/run_related_tests.py --changed ztp/manual-ztp.py -v
python3 -B test_cases/run_related_tests.py --changed-file changed-paths.txt -v
```

Git 环境可加入工作区、暂存区、未跟踪文件，CI 可指定比较基线：

```bash
python3 -B test_cases/run_related_tests.py --git -v
python3 -B test_cases/run_related_tests.py --git-base origin/main --no-approve -v
```

全量、只读检查及持续观察：

```bash
python3 -B test_cases/run_related_tests.py --all -v
python3 -B test_cases/run_related_tests.py --check --require-full
python3 -B test_cases/run_related_tests.py --watch --interval 2 -v
```

`--list` 不执行且不写批准文件；`--no-approve` 执行但不更新哈希。`--watch` 对同一失败
指纹只执行一次，文件再次变化后才重试。

## PF1–4 选测预检

```bash
python3 -B test_cases/run_related_tests.py --all --preflight
python3 -B test_cases/run_related_tests.py --suite repository-governance --preflight
```

`--preflight` 在 manifest 校验和实际选测后，只检查能力，不启动 unittest、不改 ledger；
不能与 `--list`、`--list-suites`、`--check` 或 `--watch` 合用。预检通过不是测试通过，
不产生或刷新 full-suite attestation，也不代替完整 Python/依赖环境、历史谱系或真实 fixture 验证。
实际执行的 all、广泛回退、suite、related 和 watch 自动执行相同预检。全量按实际 discovery
模块计算能力，不能只看 baseline 或命令行是否出现 `--all`。

- public publication workflow/contract、public project fixture workflow、public S workflow
  选中普通 V3 字节时，复用 `test_public_publication_workflow._assert_clean_and_ledger`。
  staged、unstaged、untracked、仅 ledger 脏或必需的 Git/authority 不可用都报 `EFF E-3`，
  要求先提交已审阅的源码/测试候选。不另写 porcelain 判定，不豁免 ledger。
- 精确匹配固定已批准历史模块哈希时，保留该模块自己的 staged-proof 合同；历史同伴文件不能
  豁免另一个已选中的当前模块。此分流不证明历史验收成功，也不修改冻结 P capsule。
- public publication workflow、ztp release core review 和 runner preflight 的真实 loopback
  测试需要 AF_INET/TCP `127.0.0.1:0` bind；探针在 finally 中关闭，不 listen、不 connect、
  不启动 sshd。失败报 `EFF E-1`，要求仅对相应 fixture 在允许 loopback 的环境中 scoped rerun。
  AF_UNIX-only 和其他无关 direct 选测不增加此要求。
- 能力失败退出 `2`，不启动测试子进程，不改变批准文件，不算 skip。若内容未变但 Git stat
  信息陈旧，先显式运行 `git status` 刷新 index、重跑预检，再提交仍报告的变化；预检本身不做
  隐式 index 刷新。linked worktree 不满足当前 P 的 `.git/index` 权威，须回 main checkout。
  watch 保留失败状态指纹；同一字节状态不自动重试，环境/Git 修复后必须退出并重启 watch。
  真正 fixture 后续失败仍然阻断批准。

`--list`、`--list-suites`、`--check --require-full` 不执行上述 Git/绑定预检，保留原有只读
语义和证明检查。真实操作系统限制的证据见 `TC-REAL-RUNNER-PREFLIGHT-001`，H 和最终发布
门禁均不因 PF 能力通过而关闭。

当前 complete authorities 是 Cumulus `03-templates-j2` 的全部直接子 `.yaml.j2`，以及
Cumulus/NVOS 配置根的全部直接子 `default*.yaml`；生成输出目录不属于这些正向 authority
roots。Jinja 全量合同还逐项解析 include/import/from-import/extends 的单个静态 basename
引用，要求闭包完全留在 pinned 集合内并拒绝动态/list/nested/missing/cycle 引用。authority
成员变化会使旧 full-suite attestation 过期，但 related 选测保持 related；一次 related 成功
只能写当前普通 snapshot，不能生成或携带已经过期的全量证明。

runner 位于 canonical `test_cases/`，不会进入 upload/sync 生产包。开发期间建议一直运行
`--watch`。成功的 `--all` 会在批准 ledger 中额外记录 full-suite attestation，绑定当前完整
snapshot、Python 解释器、版本、平台和架构；普通 related 通过本身不会伪造这份证明。本机
macOS 正式 load 在实际生成前先运行 `--check --require-full`；有效证明直接复用，只有退出码
4/5 才运行一次 `--all` 并再次复核，退出码 2 或其他治理错误直接阻断。DAY0 项目输入与运行
输出不属于 governed snapshot，因此同一环境的 fresh clone 携带有效 ledger 且只修改项目输入时
不会重复 full suite；load 的项目合法性、生成与发布门禁不缓存。成功后仍运行
`--check --require-full`。Linux load 与
macOS dry-run 不运行开发测试。正式 `sync-code` 或 `tar-for-upload` 只执行
`--check --require-full`：精确证明有效就直接复用，缺失或过期则在任何打包、网络或远端写入前
停止并要求重跑本机正式 load，绝不自行回退执行全量。`--check` 返回 4 表示字节未批准，
`--check --require-full` 返回 5 表示全量证明缺失、过期或来自不同环境；两者都必须阻断发布。

正式 macOS load 同时启用 `.githooks/pre-push`。hook 只验证当前 checkout HEAD，并要求 approval
ledger 已被 Git 跟踪、其当前字节已经提交到该 HEAD，随后用 load 绑定的精确 Python 再执行
`--check --require-full`。这样 push 的对象本身携带有效 proof，而不是仅依赖未提交工作树状态。
非 HEAD tip、未提交 ledger、stale proof、错误 intent 或错误环境一律阻断；删除远端 ref 不要求
proof。默认 push 只接受 release proof。owner 授权的 AIR/prod 验证可以显式设置
`HTTP_VALIDATION_ONLY=1`，此时 runner 精确增加 `--validation-only`，只接受已提交且与当前字节
匹配的 ISSUE-0016 validation proof；它不能替代最终生产发布 proof。

## 新脚本、新功能和新场景

1. 在 `script_test_manifest.json` 的 `scripts` 中登记路径及真实 canonical target。
2. 加入一个直接 `test_rule`，并加入覆盖至少两个真实脚本的 workflow/scenario。
3. 在 `test_cases/test_<area>.py` 写独立预期；多模块状态边界使用 transaction/integration/scenario。
4. 先执行 `--list --changed <path>` 检查影响集合，再执行测试。
5. 发布前执行 `--all`；通过后批准哈希与 full-suite attestation 才会原子更新。

## 退出码

- `0`：映射有效且测试通过，或没有变化。
- `1`：相关/全量 unittest 失败；批准哈希保持不变。
- `2`：manifest、路径、安全/能力预检或测试期间 TOCTOU 失败。
- `3`：显式请求的 Git 变更发现失败。
- `4`：`--check` 发现尚未批准的脚本、测试或 manifest 变化。
- `5`：`--check --require-full` 未找到与当前精确字节和执行环境一致的全量测试证明。
- `130`：持续观察被 Ctrl-C 中断。

## Full proof 失败后的诊断与重跑闸门

### R22 generation report 暂存前像改写不得发布或清理

独立 direct 在完成 prepare 后注入同 inode 内容改写、同字节/恢复 mtime ABA，
以及 held 目录打开后晚注入，分别检查 commit/discard；真实私有 SETUP→LOAD→
report workflow 要求原 commit 拒绝后，cleanup 也必须 HOLD 并保留证据，父
candidate 不变且 parent/report/selector 均未发布。首轮 direct 的有效发布失败
污染了后续共用 fixture，原日志保留：`outputs/test-diagnostics/r22-report-stage-preimage-red.log`，
inode157924532、size141710、SHA256
`95375acd9e26292848e73cf859643004d917c99cb7ce3cc7a7f17a22107bbb8a`，2FAIL/6ERROR。
每个负例改用独立私有输出目录，原实现两个方法八处有效 FAIL，无 ERROR；日志
`outputs/test-diagnostics/r22-report-stage-preimage-isolated-red.log`，inode157924632、size132286、
SHA256 `5ff36555bd9c657a532138e4327387db1b9759a8c9a5cfb65357c59f96b26f62`，
物理72行 Ran 2、74行 FAILED(failures=8)、77行 ACTUAL_UNITTEST_EXIT=1、
78行 FROZEN_STATE_MATCH=True、80行 DIAGNOSTIC_END=1，实际 exec exit1。

候选将暂存身份绑定为 prepare 完成时的 dev/ino/mode/nlink/uid/gid/size/mtime_ns/ctime_ns，
commit/discard 初检及 held 目录内最终核验都对照原身份与 SHA，再 replace/unlink；
正常自有清理控制保留，wire schema/业务断言/原时限不变。targeted 两方法 OK，日志
`outputs/test-diagnostics/r22-report-stage-preimage-green.log`，inode157933659、size127383、
SHA256 `15cc94183f0017a16e3c9952f19def9f462f8e6fa3f37596824603693a94290b`，实际 exec exit0。
完整 LOAD、report contract/workflow 三模块505项 OK，日志
`outputs/test-diagnostics/r22-report-stage-preimage-modules.log`，inode157933768、size285545、
SHA256 `3acf6a79854949dd6a749f59ae3389727bd32b64f65c4295102909126f8acdf0`；
读前后 stat 身份稳定，已知181996字节旧前缀 SHA 不变，物理1395行 Ran 505 in
44.163s、1397行 OK、1422行 ACTUAL_UNITTEST_EXIT=0、1423行 FROZEN_STATE_MATCH=True、
1425行 DIAGNOSTIC_END=0，实际 exec exit0。

manifest 既有 generation_report direct 与 generation_report_lifecycle 真实多脚本映射
覆盖此窄修，REAL_ENV 同卡补前提、证据、清理与风险。不是 prepare 未完成时的清理
修复，也不是非合作写者原子隔离、report 持久 WAL、B finalizer、旧 A 激活或完整
R22。未运行正式 related/full、未改 ledger；原时限故障诊断与正式 full/check 仍 OPEN，
不把本次 bounded PASS 当作正式 full 重跑权限。

### R22 generation report 原前像同 inode 改写与 ABA

独立 direct 在 prepare 后覆盖同 inode 的合法旧报告、同字节写回并恢复原 mtime，
以及 commit 已持有输出目录后晚改写；真实 SETUP→LOAD→report workflow 覆盖最后
一个边界，要求拒绝并保留外来 inode/字节、未消费 candidate、父记录与 selector 缺席。
首轮 direct 三处有效 FAIL，workflow 因夹具未先提交父记录而 ERROR；原日志
`outputs/test-diagnostics/r22-report-preimage-aba-red.log`，inode157841743、size130513、
SHA256 `a1c664112fac6808c5208fb599e7bd6d7a4de83ecdf4ba912038c4e5ff838169` 保留。
补真实父提交与下一候选预备后，原实现两个方法四处有效 FAIL，完整原日志
`outputs/test-diagnostics/r22-report-preimage-aba-red-parent-bound.log`，inode157842122、
size129930、SHA256 `623a3a12abb6d07e8b03207691eb6d2dad1001b2b550c40c57d262b892dc214e`；
物理40行 Ran 2 tests、42行 FAILED(failures=4)、46行 ACTUAL_UNITTEST_EXIT=1、
47行 FROZEN_STATE_MATCH=True、49行 DIAGNOSTIC_END=1，实际 exec exit1。

原 helper 只按 dev/ino 允许 overwrite。候选将 prepare 的旧 report 前像绑定为
dev/ino/mode/nlink/uid/gid/size/mtime_ns/ctime_ns；验证读前后元数据一致，commit
初检及 held 目录内最终 replace 前均对照原绑定，不接受改写后的同 inode。报表 wire
schema、业务预期、原时限与所有既有断言不变。两个方法 GREEN 原日志
`outputs/test-diagnostics/r22-report-preimage-aba-green.log`，inode157842619、size127544、
SHA256 `1f265614c1ee131a920830cab4e3898b2b292121b2e79cd04602238eb0e2219a`，实际 exec exit0。

完整 LOAD、generation report contract/workflow 三模块503项 OK / exit0，原日志
`outputs/test-diagnostics/r22-report-preimage-aba-modules.log`，inode157843026、size285206、
SHA256 `caa92a97e77e146ad710650bef56bd197959d3e8faf09a47ed0adde280ad8b01`；
读前后 dev/inode/size/mtime_ns/ctime_ns 稳定，物理1393行 Ran 503 tests in 30.732s、
1395行 OK、1419行 ACTUAL_UNITTEST_EXIT=0、1420行 FROZEN_STATE_MATCH=True、
1422行 DIAGNOSTIC_END=0，实际 exec exit0。manifest 已有 generation_report direct
与真实 generation_report_lifecycle 映射，REAL_ENV 同卡补前置/证据/清理与风险。
该窄修是内存 prepare 前像检查，不是 report 完整持久 WAL、非合作写者原子
compare-and-replace、B finalizer 或旧 A 健康激活；Linux/断电、原 bootstrap/REQ19
原因与正式 full/check 仍 OPEN，不手改 ledger、不因本次 bounded PASS 盲重跑 full。

### R22 generation 暂存目录换绑不得递归清理

两个独立 direct 分别在真实目录 rename 后、首 payload 同步失败前，将原暂存名
换为外来目录；真实私有 SETUP→LOAD→report 预备 workflow 在 rename 后注入。
要求外来 inode/独立哨兵、已安装 generation 或移走的原暂存目录保留，且 HOLD、
不提交 parent/report/selector。原实现仅按名称 exists 调用 rmtree，三个方法有效 FAIL。
RED `outputs/test-diagnostics/r22-generation-stage-owner-red.log`，inode157776906、
size129807、SHA256 `20efc3126368785447986d583ea39e5a025b1249cabf081126f1b6824478da70`；
物理34行 Ran 3 tests、36行 FAILED(failures=3)、41行 ACTUAL_UNITTEST_EXIT=1、
42行 FROZEN_STATE_MATCH=True、44行 DIAGNOSTIC_END=1，实际 exec exit1。

候选持有原暂存目录 FD，清理前核原 dev/ino 与物理父目录身份；名称换绑保留并 HOLD。
首轮候选三项日志 `r22-generation-stage-owner-green.log`（inode157781712、size128625、
SHA256 `167b57dbbccbd4c1f09e77062f238f06ba304dfba85d0b506da32e4a315d0092`）
exit1，以及首轮501项 `r22-generation-stage-owner-modules.log`（inode157783912、
size285271、SHA256 `1816e19a5318992f34365786bb45bf4a7dd03c18583b4519baf388f197fa8f4a`）
exit1 均完整保留。唯一 ERROR 为新增 workflow 使用不存在的
PreparedGenerationReport.committed 属性；在该轮冻结结束后修为独立暂存报告字节
前后相等与原正式报告缺席检查，原 HOLD、目录 inode/哨兵、parent/selector 断言不变。
targeted 重跑3项 OK，日志 `outputs/test-diagnostics/r22-generation-stage-owner-green-rerun.log`，
inode157809858、size128047、SHA256
`7e3f93b19b56867fdaf7103ee2299e08360b73b1ede886092cb7765aed2207b3`，实际 exec exit0。

完整 LOAD、generation report contract/workflow 三模块501项 OK / exit0，原日志
`outputs/test-diagnostics/r22-generation-stage-owner-modules-rerun.log`，inode157810027、
size284623、SHA256 `242a5f974a8b14be753ada6742de757e8acc30ebd3ccd7c5d9209fea9fceeead`；
读前后 dev/inode/size/mtime_ns/ctime_ns 稳定，物理1391行 Ran 501 tests in 29.026s、
1393行 OK、1415行 ACTUAL_UNITTEST_EXIT=0、1416行 FROZEN_STATE_MATCH=True、
1418行 DIAGNOSTIC_END=0，实际 exec exit0。现有 LOAD direct 与
generation_report_lifecycle workflow 映射不变，REAL_ENV 同卡补边界/前置/清理风险。
该窄修不是目录内部任意新增成员的所有权、非合作写者原子隔离或 generation 持久 WAL
全写集证明；B finalizer、旧 A 激活、原 bootstrap/REQ19 根因、Linux/断电及正式
full/check 仍 OPEN，不自动批准、不手改 ledger、不从 bounded PASS 跳到 full 重跑。

### R22 generation selector 暂存对象的清理所有权

独立 direct 要求随机暂存名先被外来常规文件/软链接占据时不删除，另在 selector
replace 失败前移走自有链接并原名插入外来文件；真实私有 SETUP→LOAD→report→
selector workflow 要求 report 原字节、外来 inode/字节与 selector 缺席保留。
初轮 RED 的一个 direct 因 Darwin /var 与 /private/var 别名在注入器内提前拒绝，
原日志 `outputs/test-diagnostics/r22-selector-temp-ownership-red.log`，inode157706681、
size131759、SHA256 `a491856dda54ef36b1cb9595ae9aaa950e3c007ca265f820498537e98e74f2e1`
保留，不算该注入的生产失败。夹具改为物理父路径后，原实现三个方法四处有效 FAIL，
原日志 `outputs/test-diagnostics/r22-selector-temp-ownership-red-canonical.log`，
inode157710120、size130784、SHA256
`3f0106fb8ba593ce4aaa5aa1be441a8d9e048f244daa8dc47cd95aaa4bed2d12`，
物理41行 Ran 3 tests、43行 FAILED(failures=4)、49行 ACTUAL_UNITTEST_EXIT=1、
50行 FROZEN_STATE_MATCH=True、52行 DIAGNOSTIC_END=1，实际 exec exit1。

候选去掉无条件 finally unlink；仅本次成功创建、类型/单链接/文字验证并记录身份的
暂存链接，在清理时全部原身份与文字仍一致才 unlink。原断言不变，三个方法 GREEN：
`outputs/test-diagnostics/r22-selector-temp-ownership-green.log`，inode157711209、
size128148、SHA256 `3a092d41046c496b2313bf659ccdf626027796aef7fc07ac7da161ca303c0aa4`，
物理10行 Ran 3 tests、12行 OK、18行 ACTUAL_UNITTEST_EXIT=0、19行
FROZEN_STATE_MATCH=True、21行 DIAGNOSTIC_END=0，实际 exec exit0。

完整 LOAD、generation report contract/workflow 三模块498项 OK / exit0，原日志
`outputs/test-diagnostics/r22-selector-temp-ownership-modules.log`，inode157712266、
size283742、SHA256 `98ba815ae48b8ef40eacfa72377255f1c6f4562d2fd75b12d108dfa27f86a47f`；
读前后 dev/inode/size/mtime_ns/ctime_ns 稳定，物理1386行 Ran 498 tests in 29.574s、
1388行 OK、1409行 ACTUAL_UNITTEST_EXIT=0、1410行 FROZEN_STATE_MATCH=True、
1412行 DIAGNOSTIC_END=0，实际 exec exit0。首次全 stat 相等核验因读访问时间不一致
停止，未据该次读取作结论；重新使用上述内容身份字段稳定核验后才确认此完整结果。
现有 LOAD direct 与 `generation_report_lifecycle` 映射覆盖新增案例；REAL_ENV 同卡
补前置、证据、清理与风险。不是任意非合作写者的原子 compare-and-unlink，也不关闭
完整共享 WAL、B finalizer、旧 A 激活、原 bootstrap/REQ19 根因或正式 full/check。
不运行自动批准、不手改 ledger，不以本次 bounded PASS 套用 full proof。

### R22 封存 generation 最终权限须先于文件同步

独立 direct 与真实私有 SETUP→LOAD→report/selector workflow 在 umask077 下，
要求所有 payload FD 的最终0644权限先于文件 fsync；原实现先 fsync0600 后按路径
chmod，两项有效 FAIL / exit1。RED 原日志
`outputs/test-diagnostics/r22-generation-final-mode-red.log`，inode157676626、size129019、
SHA256 `7cd222307629d802b86c429571f52b5d77ac35ee56f6ff2fb1f09b71dad2fd4e`。
候选只在原 held stream FD 上 fchmod0644→fsync，保留 payload、子目录/代次目录同步、
安装及 selector 顺序。两项 GREEN / exit0 原日志
`outputs/test-diagnostics/r22-generation-final-mode-green.log`，inode157676780、size127777、
SHA256 `4ee894d9f86b6bd6f868cc85cc0d5d4a8a048203385160cd7a6a14f9e6a2ad4c`。

完整 LOAD、generation report direct 与 workflow 三模块495项 OK / exit0，原日志
`outputs/test-diagnostics/r22-generation-final-mode-modules.log`，inode157676920、size282692、
SHA256 `ce65f37f468402f5d64c42d86240ea759ee68ec632fd27f33353f8236b834658`；
读前后 stat 相同，物理1381行 Ran 495 tests in 31.094s、1383行 OK、1402行
ACTUAL_UNITTEST_EXIT=0、1403行 FROZEN_STATE_MATCH=True、1405行 DIAGNOSTIC_END=0，
实际 exec exit0。现有 `generation_report_lifecycle` 仍覆盖真实 SETUP/LOAD/report 脚本，
LOAD direct 映射不变；REAL_ENV 同卡补记授权隔离、持久性见证与清理风险。
这只是最终权限的同步顺序，不闭合 generation/report 全写集 WAL、B finalizer、旧 A
显式健康激活、非协作写者竞态或断电见证；不是 related 自动批准或正式 full/check，
ledger 不手改，原 bootstrap/REQ19 根因和完整 R22 仍 OPEN。

### 2026-10-07 单次完整诊断的同步遗漏与有界修复

2026-10-07 owner 单独批准的一次完整诊断使用当前 `3123e81680bc959c4b714e5b869437622f8a5ba7`
/ tree `221d43c2a1c8ec37099ac43ae84e41d4b661aadc`，运行
`python3 -B test_cases/run_related_tests.py --all --no-approve -v`。
完整原日志 `outputs/test-diagnostics/r22-3123e81-authorized-full-diagnostic.log`，
inode156760820、size885087、SHA256
`b8c6538fee43b25849b1a98455335621459f0212c351e3aea1610bd98c5275bc`，
读前后 stat 相同且已知旧前缀不变。物理第5586行 Ran 5003 tests in 3000.722s，
5588行 FAILED (failures=20, skipped=5)，5757行 ACTUAL_RUNNER_EXIT=1，
5762行 FROZEN_STATE_MATCH=True，5764行 DIAGNOSTIC_END=1，实际 exec exit1。
这不是正式通过证明，也没有批准 ledger 更新。

逐项 traceback 分类为两个可验证的同步遗漏：一项是杀前证据 helper 已显式登记
tracked_support，但独立完整清单预期遗漏该唯一诊断路径；另外19项是生成手册遗漏
`test_cases/subprocess_timeout_evidence.py` 和 `test_cases/test_subprocess_timeout_evidence.py`，
导致目录完整性、生成一致性及其下游公开/打包 workflow 拒绝。修复只补独立路径合同并
按原生成工具更新维护目录，不从实现自动生成测试预期，不删原失败方法、放大时限或
改历史锚点。已有 direct 清单/目录断言及真实生成/打包 workflow 作为独立 RED 与回归。
本次没有捕获原 bootstrap15s/REQ19 probe10s 的再次超时；19项下游手册门禁失败亦不能
证明其被门禁挡住的历史子流程已通过，因此两个原时限故障的原因仍 unknown。
修复后的有界回归仅解释本次20项失败，不自动授权另一次 full，不取消上述历史诊断闸门。

首轮修复后有界集运行76项，75项通过、公开 current-lifecycle clone 一项失败；原日志
`outputs/test-diagnostics/full-diagnostic-manual-support-repair-bounded.log`，inode157628418、
size146671、SHA256 `7fdb8d9b0ddfb0cbd59b85d01999e7c05f89d6053a10d6f96939c5b8d74ac55e`，
物理 Ran 76 tests in 66.072s、FAILED (failures=1)、ACTUAL_UNITTEST_EXIT=1、
FROZEN_STATE_MATCH=True、DIAGNOSTIC_END=1 与实际 exec exit1 一致。其子流程
仍为513/515的旧手册差异；源码核实 `_copy_public_candidate_held` 从 held index 的
exact blob materialize，而非未提交 worktree，故独立工作树目录/生成/打包断言已经通过
不能代表 index clone 已更新。候选先提交使受测 index 字节真正更新，再原样重跑该有界集；
不改 exact-five、持有 index 权限、断言或时限，不把这次失败称成功。

三文件候选提交 `7f99dacb9972d8f3fcb185aca128d38619ba4734` / tree
`2f8eeac54c32125b8f5dd52074e3c08f75b2257b` 后，同一76项有界集合完整 OK / exit0，
原命令、断言、时限不变。日志
`outputs/test-diagnostics/full-diagnostic-manual-support-repair-committed-bounded.log`，
inode157661494、size143125、SHA256
`7a2a2f7d30ebf9c1c07a475941fdf1aa28e3a03efd3119de0d9f03976af06c4b`；
读前后 stat 相同、旧前缀匹配，物理83行 Ran 76 tests in 68.647s、85行 OK、
220行 ACTUAL_UNITTEST_EXIT=0、221行 FROZEN_STATE_MATCH=True、223行 DIAGNOSTIC_END=0，
实际 exec exit0。包含完整 ImpactManifestTests、DocumentationCatalogTests、诊断 helper
direct，以及真实 upload manifest 与 current-lifecycle no-local public clone 的 exact-five
packaging workflow。独立原路径、未知路径/映射拒绝、生成一致性、index blob 权限与打包
合同继续执行；原两轮失败日志不改。ledger 仍为 SHA256
`19e865c310d16e2a3161a488865c38e66b2aeeb38cd2e09d86d64767243bbe11`，不自动批准、
不以此局部集替代20项下游完整历史回放、正式 full/check 或原超时根因证明。

全量失败必须先解释原因；单独重跑失败用例通过，只是一次诊断结果，不能据此直接再跑
full。失败、未知原因、日志缺失或中断仍保持无证明状态，不能以“偶发”“环境”概括未核实的
缺陷。本规则同样适用于 related 失败后准备进入正式 full 的情况。

1. 保存原始命令、精确 HEAD/tree/status、Python/平台/依赖身份、完整日志和退出码。
   读日志前后核 stat/inode、已知旧前缀 SHA256 和完整物理收尾；文件换绑、前缀改变、
   截断或输出未收齐时停止推断，不把末尾一段输出当作完整通过证据。
2. 逐项分类并提供证据：实现缺陷、夹具/隔离/清理缺陷、环境前提不满足、启动/调度/
   资源竞争或原因待核。多个失败不得自动归为同一原因。当前空闲时的资源观察不能证明
   失败发生时的环境；单项 PASS 不能证明原始前序、残留状态或并发条件已消失。
3. 优先小范围重现原始失败条件：保留前序、输入和断言，检查进程树及运行/僵尸状态、
   子进程输出、锁/端口/文件身份、清理行为和阶段耗时。必要时给失败断言补充有界现场
   信息；这属于诊断增强，不是修复或验收。冻结的历史测试不得改锚点、断言或历史字节。
4. 真实缺陷先写独立 direct 预期；跨脚本边界补真实 workflow/scenario，核 manifest 和
   REAL_ENV，再修实现。禁止删测试、增加 skip、弱化断言、仅为通过而放大时限、复制
   实现结果为预期或手改批准 ledger。环境原因须验证原前提已恢复，不能只等待后重试。
5. 下一次 full 启动前明确记录：原始原因及证据、实际修复或已验证的条件变化、相关回归
   结果、未闭风险，以及为什么这次不会仅重复原失败条件。原因仍未知或关键条件未经
   验证时继续诊断，不盲目重跑 full。诊断次数或连续单项通过次数本身不构成放行依据。
6. 放行后仅在精确候选树上运行正式 full；期间冻结源码/测试。只有完整 exit0、runner
   自动生成的 ledger 单独提交、干净树的 `--check --require-full` exit0 才算本地正式
   证明。局部回归和旧树证明不能代替它；本地 proof 不关闭独立 Linux/设备/断电见证卡。

### 原超时子进程的杀前有界证据（仅诊断）

bootstrap 15s 与 REQ19 私有 probe 10s 夹具在 `Popen.communicate()` 原异常边界，
于 `subprocess.run()` 原 kill/reap 之前记录私有子进程是否已退出、PID、state/comm
及仍可核父子关系的后代；不记录 argv/environment，也不查询已退出且可能复用的根 PID。
观察预算 0.75s、最多16个进程，查询失败/超限明确 unknown/partial；不扩大原测试时限、
不修改 argv/input/check/断言，不杀后代，不替代标准 run 清理。成功路径不执行进程查询。
观察器异常不能覆盖原 TimeoutExpired；两夹具继续保留原 cmd、timeout、partial output
和 cause。应用阶段与管道所有者不从进程状态反推，仍可为 unknown。

新增 helper 只用于串行私有夹具的局部 Popen 上下文，已登记 tracked support、path rule
及三个消费测试模块。新证据只适用于实际捕获它的那一次超时，不能补造历史故障现场；
原 bootstrap/REQ19 原因未证实，正式 related/full 重跑闸门仍关闭。诊断增强不是实现修复、
批准 ledger 或 full proof，不因局部 PASS 放行重跑。

### R22 Q comparison 原缺席目录与恢复中断候选

真实 LOAD→SETUP 强杀的独立负例确认两处边界：暂存 mkdir 后尚无 WAL 行时，
原恢复会退休 WAL 并留下未知暂存物；已登记 Q 目录 rmdir 后/父同步前强杀，
下一恢复会退休 WAL 而未同步 Q 父目录。日志
`outputs/test-diagnostics/r22-q-comparison-boundaries-red.log`，inode147558183、
size2578、SHA256 `acfcb1f806b145f80225ebb22cbbd11749a81f1643abb25c5d0bfb3965f0e163`，
含两项真实 workflow FAIL，另外两项是命令误填测试类名的加载 ERROR，后者不作为
缺陷 RED。正确类名的 direct 在 `r22-q-comparison-boundaries-direct-red.log`
证实再入未同步；该日志的 orphan direct 用了非规范 /var 相对链接输入，不能作为
该缺陷 RED。修正输入路径、保留预期后，`r22-q-comparison-orphan-direct-canonical-red.log`
1 FAIL / exit1，inode147565822、size864、SHA256
`3542fdad3713a4151c971c57774b1c04c6d89d6437107bee8b879a081a5bf470`，
原恢复未按未知暂存物拒绝。

候选新增闭合 typed 行、真实 writer 委托与精确 no-replace 安装；未知暂存前缀只
作 HOLD，已登记目录的缺席也重新同步父目录。八项 direct/真实 workflow 完整
GREEN / 21.841 秒 / exit0，`r22-q-comparison-boundaries-green.log`，inode147572207、
size1435、SHA256 `dbfc63565696b177c1bc2e69f204cc6ff4510033ec75803bd775a9e1cee848fb`。
原断言与全部失败日志保留。补充边界修复之前的三模块435项通过不适用于补充后的
精确候选，仍需重新模块回归。正式 related/full 闸门继续 CLOSED：历史 bootstrap
15s 与 REQ19 probe10s 的原失败现场原因未证实，单项或原前序 PASS 不放行 full。
不改 ledger；本候选不关闭完整 comparison 数据迁移、完整 R22 或 REAL_ENV 卡。

上述目录边界候选三模块完整 439 tests OK / 443.359 秒 / exit0，日志
`r22-q-comparison-complete-candidate-modules.log`，inode147603806、size135903、SHA256
`1a9c953c992b65e1936a977b684701f925509260bd0a6b148254fbf8f257f5db`；
112828字节旧前缀 SHA256 `2a510537eabf5da0a2595b8a8a95e1357bddd18366f0c279b4a88390d45e522f`
保持，12项源码/测试/文档/manifest/ledger/运行态 manifest 冻结核验全部一致。
随后审阅发现登记后 inode 捕获风险，439项不适用随后的修复。新增 direct 与真实
SETUP 换绑负例在 `r22-q-comparison-install-owner-canonical-red.log` 两项 FAIL / exit1，
inode147816832、size1737、SHA256 `2f64278308457bc47330589c804a17ab061d08a5bf621e59e23940c0a7a82022`，
证明外来暂存 inode 已被误装入 Q 目标，后续 HOLD 过晚。更早的
`r22-q-comparison-install-owner-red.log` 中 direct 的空 mock 未执行 rename，产生
FileNotFoundError，不作为该 direct 的独立 RED；改为 spy 原 primitive，预期不变。
修复使用登记时捕获的原元数据，在安装前及安装后核 dev/ino/mode；四项 GREEN / 4.065秒 /
exit0，`r22-q-comparison-install-owner-green.log`，inode147818875、size728、SHA256
`3a80d14bf19a230d2a2de809f2d5fb546fcaf436654e267a8544844b9a0e5963`。
最终候选需再核完整 LOAD/optimize 模块及相关真实 workflow；没有正式 related/full 批准。

### R22 main 未结清 WAL 须在服务启动前 HOLD

仅成功出口拒绝仍允许带未结清 SETUP WAL 的 B 先执行 start_services，再由末尾
守卫停下。独立 direct 及真实 SETUP 完成→受控 main 的启动请求负例要求零启动
调用；原实现两项均调用一次，3 tests / 2 FAIL / 4.178 秒 / exit1。无 WAL 的
明确启动正例仍正常返回。原日志 `outputs/test-diagnostics/r22-main-wal-prestart-red.log`，
inode146853888、size5366、SHA256
`7e1c370da847eba191373c60e636e13bad59e2d674a87b98b0c8d735ee63c003`。
实现只在非 dry-run 服务门禁、preflight 之前再核原 SETUP WAL 闸门；保留既有
末尾检查和提交后停服/HOLD 路径，不清理 WAL、不回 P/A，不提供 B finalizer。
三项 GREEN / 4.886 秒 / exit0，日志 `r22-main-wal-prestart-green.log`，
inode146858770、size585、SHA256
`fa294cde7cd5d7cd1672e2ddd2fdbfeb3ad982abb6fc2c938c1c60fd56b41677`。

完整 LOAD 模块及八项选定真实 SETUP workflow 共 338 tests OK / 50.643 秒 / exit0，
日志 `r22-main-wal-prestart-regressions.log`，inode146861444、size106630、SHA256
`a5bbbba514b289148cfea59cb286c1b8487dc8cc3acf0918ada8154e021f2565`；前后 stat 一致，
81703 字节旧前缀 SHA256
`885114047fefd76aef61577790def17b1147bc2e1c007bca748c8655e1ba0f5f` 未变。
物理第990行 Ran、992行 OK、缓冲 stdout 后第1025行退出标记与实际 exec exit0 一致。
源码/测试冻结，原 manifest、ledger、运行态 setup manifest 身份/摘要保持；沿用已有
LOAD direct 和 generation_input_binding_setup_load_c2 映射。

本地 supervisor 服务端口是替身，只证明真实 main 不调用启动端口；实际 SETUP 子进程、
私有 parent primitive 与原 WAL 保留被执行，不是 root 完整入口、真实服务状态或 B
健康验收。WAL 缺席不授权完整 B 退休或旧 A 激活。正式 related/full 未运行，原
bootstrap15s/REQ19 probe10s 原因和重跑闸门继续 OPEN；不手改 ledger，不把局部
GREEN 冒称完整 R22 或 full proof。

### R22 main 未结清 WAL 不得报告整体完成

原 main 在父 B 及后续步骤返回后直接报告成功，没有重新检查切换产生的 SETUP WAL。
独立 direct 与真实 LOAD→SETUP 完成→受控 main 要求未结清凭据仍在时返回 1，
不打印 load 完成；保留已提交 B、原 WAL 字节/inode，调用既有停服清理、不恢复 P/A。
无 WAL 的正常出口正例维持返回 0。三项原实现 2 FAIL / 6.317 秒 / exit1，
日志 `outputs/test-diagnostics/r22-main-unclosed-wal-red.log`，inode146797284、size6313、
SHA256 `9501916b96d53041336c99389ca3094577f4ea439f8b2ae5b63cf47c7cd956a7`。
实现仅在非 dry-run 的 completed_successfully 之前再次调用原未结清 WAL 闸门。
三项修后 OK / 6.380 秒 / exit0，日志 `r22-main-unclosed-wal-green.log`，
inode146800932、size574、SHA256
`4638b4eac5f42fbbbaf4c214e2682e59bda4d3936a382c4b8ab4a601d3e51c4e`。

完整 LOAD 模块及七项选定真实 SETUP workflow 共 335 tests OK / 50.799 秒 / exit0，
日志 `r22-main-unclosed-wal-regressions.log`，inode146803299、size106179、SHA256
`cb690f8e90b2db2454fdc648243cd1b298d16cbcb37ec30e6e54f27a354c10d4`；读前后 stat
一致，64379 字节旧前缀 SHA256
`4127f8fb099fd9bb8b6e507af15c8f904e99d958867a5816f9d5cd05eb73dffc` 未变。
物理第987行 Ran、989行 OK、缓冲 stdout 后第1022行退出标记与实际 exec exit0 一致。
测试期间源码/测试冻结，manifest、approved ledger、运行态 setup manifest 身份/摘要未变；
沿用 LOAD direct 及 generation_input_binding_setup_load_c2 多脚本映射。

实际 SETUP 子进程和私有 parent commit primitive 被执行；main 输入/生成/report/服务
端口受控替身，项目夹具隔离。这不是完整同一项目 A→B 根入口、真实服务、完整 B 健康
finalizer 或 WAL 成功退休证明。WAL 缺席不授予健康/旧 A 激活权限。
这是有界诊断回归，不是正式 related/full；原 bootstrap15s/REQ19 probe10s 原因与重跑
闸门仍 OPEN，未以单项或此局部 PASS 盲目重跑、未手改 ledger，完整 R22 仍未验收。

### R22 SETUP WAL 登记须拒绝同 inode 改写历史

新链接、实体 latest、infra/logs 三个登记 API 在写入候选 WAL 并 fsync 后，原先只核
原 WAL 的 dev/ino/mode/nlink/size/mtime。另一个写者将同 inode 改写后还原原字节、
尺寸和 mtime 时，旧登记仍覆盖原凭据；真实 LOAD→SETUP 的实体 latest 流程继续到
首个 Q 共享写入。独立 direct 三项和真实两脚本 workflow 要求在覆盖 WAL/下一共享
写入前拒绝，保留原 inode、原字节、P manifest/链接、实体目录，不启动服务。

首轮 RED 日志 `outputs/test-diagnostics/r22-registration-wal-history-red.log` 保留，
inode146679632、size4758、SHA256
`47785668d22dae0b26abc4978f7d1d1394e8d05d8c0e71e1db74e17e1c6d43f8`；其中 infra
用例的目标临时路径未 resolve，先被已有规范路径门禁拒绝，不能列为该 ABA 缺陷证据。
仅修正此夹具输入，不改断言后，四项均按目标缺陷 RED：4 FAIL / 4.844 秒 / exit1。
日志 `r22-registration-wal-history-canonical-red.log`，inode146681705、size4083、
SHA256 `f5be71a35ba904383518399e3443635ea53b371299de9b29f357bdd767b7ed38`。

实现为三处原守卫补 uid/gid/ctime 及有界原字节/模式再读；不解析变化后的 WAL 来
重新授予覆盖权，原正常登记及已有冷恢复合同不变。四项修后 OK / 3.105 秒 / exit0，
日志 `r22-registration-wal-history-green.log`，inode146683802、size696、SHA256
`c37962a988d5bfeb4ebb8220e3399c8d41a7cd1d74cf030e7c68c375a912be9f`。
完整 LOAD 模块与七项真实新链接、实体 latest 正负例、infra/logs、Q manifest 及
sample 冷恢复 workflow 共 333 tests OK / 53.675 秒 / exit0，无 skip。日志
`r22-registration-wal-history-regressions.log`，inode146685791、size105980、SHA256
`1e22fc29638d66f5111c28f6b2760624b2b69b235e3b9a54b4c82bf0bd1a70ec`；已知 85195
字节前缀 SHA256 `5350e8cef78b1da55010ec1fd6fc51e978f19b806712e4090251bbf4ea79af5e`
未变，日志前后 stat 一致，完整物理 Ran/OK/退出标记和实际 exec exit0 一致。
源码/测试/manifest/ledger/runtime 原 stat/摘要保持；manifest 原 direct 与多脚本
workflow 映射已核。这里是有界诊断回归，不是正式 related 或 full proof。

这不提供原子 compare-and-replace、任意非合作写者免疫、新写集或旧 A 激活权限；
仍要求排他锁及其它写者静默。完整 R22、REAL_ENV、原 bootstrap15s/REQ19 probe10s
原因与正式重跑闸门仍 OPEN；未手改批准 ledger，未以局部 PASS 重跑 related/full。

### R22 SETUP WAL 未识别合同不得恢复、登记或退休

WAL 的 checksum 只核字节，不证明当前 reader 理解全部写集。schema2 恢复曾忽略
未知 body/envelope/链接字段和 JSON 重复字段，可能在未处理的新写集仍存在时还原 P、
删除原 WAL。新增独立 direct 与真实 LOAD→SETUP 死亡→新 LOAD 冷恢复负例要求：即使
checksum 正确也在任何恢复写入前拒绝，原混合 P/Q 链接、manifest、WAL inode/字节/
mtime/ctime 保持不变，不启动服务。仅知 parent 的额外字段原先已被身份比较拒绝，
该正向防御也保留，不将它列为新增缺陷。

统一 decoder 对 envelope/body、全部已实现写集 row 和目录身份字段使用闭合字段集，
所有 JSON 对象拒绝重复键；登记新链接、Q-local latest、创建目录、实体 latest、
infra logs、Q manifest intent 和冷恢复都使用该 decoder。未知版本或义务不得靠忽略
字段放行；增加写集必须同时明确 schema/reader/独立测试。保留原 Q parent 前像缺失
的明确 HOLD 诊断，不把恢复 API 的只读核验结果当成服务激活权。

证据均位于 `outputs/test-diagnostics/`，不是正式 related/full：

- `r22-wal-contract-closed-fields-red.log`：2 tests / 7 FAIL / exit1，SHA256
  `16f79528ba75ba38752816a0e504a587d2b389508bd39377360d8ae9982e3db9`。
  第一项恢复错误地删除 WAL 后，矩阵重建文件权限成为 0644，后五项被 private-mode
  闸门掩盖；保留原日志，夹具显式重建 0600，不修改原拒绝/状态断言。
- `r22-wal-contract-closed-fields-corrected-red.log`：2 tests / 6 FAIL / exit1，
  inode146483605、size4798、SHA256
  `45debba28db493782f1e79ff6e17bb20911fa59ba3900d0329e17f99e8941f2d`。
  原实现确实接受未知 body/envelope/link、重复 body/link，真实冷恢复也错误退休凭据。
- 修后两个新增测试完整 OK/exit0，日志 `r22-wal-contract-closed-fields-green.log`，
  SHA256 `8054fc8cc7a88965e461e72f43af781c4cababf4d116f051a73ffccf7f5312cd`。
- 完整 LOAD 模块加八项真实正常/异常登记与冷恢复 workflow，共 325 tests / 1 FAIL /
  exit1；日志 `r22-wal-contract-closed-fields-regressions.log`，inode146487601、size105804、
  SHA256 `94260be6ea0e925885af08fe87b0c9544eb7e02d46611f4c9e33e493698ee6c8`。
  旧 85126 字节前缀 SHA256
  `612e9bc1e57653525dacc8eb3dd3a49ba09ef8e594a7996d44611915d5524c97` 保持。
  唯一失败为新 reader 把缺失 Q parent 前像的明确诊断改成通用 fields 错误；原因已定位，
  实现恢复原诊断，旧断言不变，不归为环境/超时，不盲目重跑完整 suite。
- 受影响的缺失前像、未知合同、只读/登记入口和真实冷恢复四项完整 OK/exit0，日志
  `r22-wal-contract-q-parent-diagnostic-fix.log`，inode146522223、size889、SHA256
  `d51a8f82c93b5e1b9742076c1c85c4f20601590bd4df3aee152177ef68b5c5d2`。
  不把该局部验证写成最终完整模块、related 或 full 通过。

生产路径的既有 direct/workflow manifest 映射不变；REAL_ENV 的 R22 卡仍 OPEN。
此修复不补齐 legacy comparison 写集、分组 DHCP 冷恢复、整个 LOAD 的 B 健康收口或
旧 A 显式健康激活。原 bootstrap15s 与 REQ19 probe10s 原因仍待核，正式重跑闸门未
解除；approved ledger 不变，未形成当前树正式 proof。

### R22 实体 latest 冷恢复写前所有权复核

原恢复在预检后、实际 unlink/rename 前未重核源指针和备份所有权：同目标的新 symlink
可能被删除，自己的 unlink/父同步之后换入的未知备份可能被搬到 latest，随后错误
退休 WAL。独立 direct 与真实 LOAD→SETUP 死亡→新进程 LOAD 冷恢复三项先失败，
原断言保留；这是真实恢复写入缺陷，不归为先前 bootstrap/REQ19 超时或环境问题。

恢复持有原目录、匹配 release 和父目录的 NOFOLLOW FD；名称/FD 复核含 dev/ino、
mode、uid/gid、nlink、size、mtime/ctime 及原始 symlink 文字，父身份核 dev/ino/mode/
uid/gid。自己的合法变更之后更新对应期望；每次源删除、备份移动、恢复后及 WAL
退休前再核。补充独立注入证明：第一次实现会在预检与 FD 捕获之间接受新备份，
故捕获原目录和 release 必须再次绑定 WAL 保存的原 dev/ino 与目录类型。
所有持有 FD 在外层 finally 关闭。原 schema2 字段集和 manifest 映射不变。

证据均为 `outputs/test-diagnostics/` 内的有界 unittest 诊断，不是批准 runner：

- `r22-materialized-write-owner-red.log`：3 tests / 3 FAIL / exit1，inode146532546、
  size2946、SHA256 `fa62186de8440fb959315510b18b81d5f52129c56fab5c30ee8d55f6d167eae3`。
- `r22-materialized-write-owner-green.log`：初次三项 OK / exit0，SHA256
  `3bc94ed8c3c82a7afc9bb28b2777d4ef22fe220a9987d494a464986784e6dc9f`。
- `r22-materialized-preflight-pin-red.log`：补充捕获前换绑 1 FAIL / exit1，
  SHA256 `0366a7f1787955a5fbb8bce7fa215c226fc6f71d0f70d4df7d8c66f6a506bcfa`。
- 绑定原 WAL 身份后，完整 LOAD 模块加六项真实正常/异常冷恢复 workflow 共
  326 tests OK / 49.679 秒 / exit0，无新增 skip。日志
  `r22-materialized-write-owner-regressions.log`，inode146544784、size104468、SHA256
  `d76b122c526f7c788f3e8ff3cdfbb74967e34d867fcc2fa7b8bdc187ea7f4fa0`；已知
  101348 字节前缀 SHA256
  `90201a5073984abac2014e8b54c824aedd30e5822b6bbf36fe36516191c29674` 保持。
  物理 Ran/OK/退出 footer 完整，实际 exec exit0；运行前后源码、测试、manifest、
  ledger 和本地 runtime manifest 的 stat/摘要不变。

发生在本算法自己的 unlink 后的换绑可使 latest 缺席；HOLD 不消费未知备份，也不
继续改 P manifest/链接、退休 WAL 或启动服务，不冒称零先前写入或完整回滚。
持有 FD 和复核不是原子 compare-and-unlink/rename，不证明所有子项内容、任意祖先/
非合作写者免疫或跨断电。legacy comparison 完整写集、分组 DHCP 冷恢复、整个 B
成功收口、旧 A 显式健康激活、Linux/断电及 DEV ACK 仍未闭。REAL_ENV 卡仍 OPEN；
原 bootstrap15s/REQ19 probe10s 原因仍待核，正式 related/full 重跑闸门未解除，
未更新批准 ledger、未形成当前树正式 proof。

### R22 DHCP 盘上前像只读核验的 parent 目录持有复核

此前 `inspect_dhcp_a_preimage` 只在解析 record 时比较 parent 目录，未持有该目录
FD 或在返回前复核；最后一轮 leaf 核验后，即使原 parent 文件 inode/字节被移到
新目录，也会报 `b-visible`。独立 direct 与真实 SETUP→保留 DHCP A/B 事务→新进程
LOAD 只读核验两项先 RED（2 FAIL / 6.125 秒 / exit1），原断言不变。日志
`outputs/test-diagnostics/r22-dhcp-inspection-parent-owner-red.log`，inode146576039、
size2612、SHA256 `c88d0cdf291564a92c8fcaee5341f3304585c68ca6c3d0c25cb557a7c426fe8e`。

核验现在持有 owner 指定 parent 目录的 NOFOLLOW FD，打开时比较完整名称/FD 身份，
用该 FD 核 record 的目录绑定，并将其加入既有返回前完整 FD/名称复核（含 ctime）
及 finally 关闭。换绑须 HOLD；注入后的原/新目录、原 parent inode/字节、A/B/
backup/record 原样保留，零恢复、清理或服务命令。两项修后 OK / 5.823 秒 / exit0，
日志 `r22-dhcp-inspection-parent-owner-green.log`，inode146578861、size469、SHA256
`36f6986269608c53761f08132a466e245e28a9cbdc0b84c7df9827ba3250498d`。

完整 LOAD 模块与四项真实持久凭据/新进程 pending HOLD/只读正负流程合计 325 tests
OK / 48.116 秒 / exit0，无 skip；这是有界 unittest，不是正式 related/full。日志
`r22-dhcp-inspection-parent-owner-regressions.log`，inode146584360、size104393、SHA256
`47a9d17628c462ef9cb671629ee82fad32ab6961079b9b215803278156c6ca32`；原 100679 字节
前缀 SHA256 `a4ad108463de26d6d75d968703c7e9475e8f08c0397eb7bbc84c06014b1815c3` 保持。
完整物理 Ran/OK/退出标记与实际 exec exit0 一致，源码/测试/manifest/ledger/runtime
运行前后 stat/摘要不变；manifest 的 LOAD direct 与真实多脚本映射原样有效。

此修复不解释原 bootstrap15s/REQ19 probe10s 超时原因，也不放行正式重跑；ledger
不变。只读结果仍不是后续写入权限，不证明原子组快照、任意祖先/非合作写者免疫、
完整 grouped DHCP 冷恢复、B 健康收口、旧 A 显式激活或 Linux/断电见证；REAL_ENV
的 R22 卡仍 OPEN，完整 R22 未验收。

### R22 parent-only 成功不得提前清理 DHCP A 凭据

DHCP API 曾在四文件安装及 parent replace/目录同步成功后删除 A backup、staged 和
`a-preimage.json`，但 report、代次指针和服务健康仍在父 LOAD 的后续阶段；SETUP WAL
仍在时，这会丢失完整 B 接受之前的 A 证据。新增 direct 与真实 SETUP→LOAD 两项
先 RED：2 FAIL / 7.049 秒 / exit1。完整日志
`outputs/test-diagnostics/r22-dhcp-parent-only-cleanup-red.log`，inode146629562、size2835、
SHA256 `6e8c51b47025a0d735bbe45ed7841ae37f738e63e037ce59e090fb7ecc8b4075`。

候选只改变清理时机：已提交并同步的 parent 下，SETUP WAL 名称任意占据均保留
DHCP 事务及已核原凭据，不解析未知 WAL 以制造删除权；lstat 错误则 HOLD，保留
原证据。未确认 B 同步、坏 backup、部分 A 恢复的原保留合同不变。无 SETUP WAL
的正常成功和完整 A 恢复仍验证原清理断言；真实跨项目 success 用例则依据测试在
安装前已经持有的真实 SETUP WAL，独立要求延后清理，不再把 parent-only 成功当
作 whole B 健康。没有从实现结果生成预期，没有隐藏实际 WAL 或删原正常断言。

新增两项修后 OK / 5.278 秒 / exit0，日志 `r22-dhcp-parent-only-cleanup-green.log`，
SHA256 `0afe79ce1bddfbc270a2a870b70cf9b486ef17855cf3276b9eb69936cb09a33e`。
另核 WAL namespace 无法读取、真实成功备份同步及持久凭据共五项 OK / exit0，
日志 `r22-dhcp-parent-only-cleanup-boundaries.log`，SHA256
`7bfea1158716fc07999f4266d68850f4dab63a0a1ccb2800f177849f0d636f0b`。
完整 LOAD 模块及六项真实成功/前提交恢复/新进程只读和 pending HOLD 流程共
329 tests OK / 59.710 秒 / exit0，无 skip；日志
`r22-dhcp-parent-only-cleanup-regressions.log`，inode146640452、size106012、SHA256
`3f361dd4ff3154f824299ee64bccaf2c37799e30dab488638d4db61a4a47771b`，已知 101365
字节前缀 SHA256 `58c7994e6f76554e4e7ecc019d99c2d6933c957600761e81ca28404e3dc11291`
保持；完整物理 Ran/OK/退出标记与实际 exec exit0 一致。源码/测试/manifest/ledger/
runtime 前后 stat/摘要不变，原 direct 与真实多脚本 workflow 映射已核。

保留不是恢复/服务激活或成功退休授权；本次不实现整个 B 健康 finalizer、跨重启
DHCP 分组恢复、旧 A 显式激活或任意非合作写者免疫。WAL 缺席也不能被当成健康
证据；禁止人工删除 WAL/事务来重入。REAL_ENV 仍 OPEN；原 bootstrap15s/REQ19
probe10s 原因待核，未以局部 PASS 重跑正式 related/full 或改 approved ledger。

### R22 related 的 bootstrap 超时诊断记录（未收口）

代码候选 `01cf5bcd08758a26146dd1b857f291411ca55d3f` 的 related 原日志
`outputs/test-diagnostics/r22-created-dir-reentry-related.log` 完整为 3154 tests、
1 ERROR / 4 SKIP、exit 1（SHA256
`6b232cabeeb43c9285eb793b357582f5dd3a489719937c0a55a38329db000cf2`）。
错误是 bootstrap direct 的 401 subtest 达到原有 15 秒时限；原报告没有子进程部分输出、
事件末尾或后代进程状态，私有临时目录已清理，故原始原因仍为**待核**，不得推断为 R22
实现错误或已证实的环境竞争。

诊断增强只在测试夹具保留有界 stdout/stderr 尾部及经前后身份校验的事件尾部，仍抛出
`TimeoutExpired`，原 15 秒、原输出属性和认证断言不变；后代状态未捕获时明确记 unknown。
两项独立诊断预期先 RED 后 GREEN。按原前序 entrypoint → Apache boundary → bootstrap
direct → 真实 rendered workflow 的小范围复核，外加诊断预期，36 tests 完整 exit 0，日志
`outputs/test-diagnostics/r22-related-bootstrap-original-prefix-diagnostic.log`（SHA256
`98dab6d299d2f534dccbfb395a0de3c5558fc4cb81ee573e2f60766b8c2de7b7`）。
该结果只说明本次小范围未重现，不解释原超时、不更新 approved ledger，也不满足下一次
related/full 的原因收口或重跑闸门。R22 新修复与整树正式证明仍须分别如实报告。

后续诊断证据审阅发现 `_timeout_event_evidence` 原先只比 dev/ino/size/mtime，
同 inode 写后恢复原 bytes/size/mtime 会被误报 stable。新增独立 direct 在实际读取 FD
之后完成该 ABA，要求 stable=false、tail 为空且原事件文件内容保留；原 reader 1 FAIL /
exit1，日志 `outputs/test-diagnostics/r22-bootstrap-events-ctime-red.log`，inode
144208683，size 981，SHA256
`259a6c5ff1164a9a7191a5b041be1a0d3388408429f6d2ea2ed4da1c19c23352`。
修复仅给前后 FD/name 身份增加 mode/nlink/ctime，并在诊断中保留初读的 mtime/ctime；
不稳定时仍不输出事件尾部。原 15 秒、超时输出属性、认证/重试断言和错误类型不变。
三个诊断 direct 完整 OK / exit0，日志 `r22-bootstrap-events-ctime-green.log`，
inode 144208691，size 616，SHA256
`842a2f73eb91b7c028fc4d58e9d5d09a63b077e11cc503e81d9130d71d1b0ec8`。

按原 entrypoint→Apache boundary→bootstrap direct→真实 LOAD 渲染 workflow 前序
再次小范围复核，完整 37 tests / OK / exit0（58.763 秒），不是正式 related/full：
`r22-bootstrap-events-ctime-prefix.log`，inode 144209228，size 6001，SHA256
`608b068c3350e8f4734d86761d44f4a93df487d340a0fb88d083aee1c673b7cc`。
读前后 stat 一致，旧 3668 字节前缀 SHA256
`78329b66b76e4ad19da50b91d6cf8a8ac6b742c8164580b7232b9fafdb91c50b` 未变，
完整 Ran/OK 在物理 `R22_BOOTSTRAP_EVENTS_CTIME_PREFIX_EXIT=0` 前，exec exit0 一致。
原 3154 tests related 失败日志的 inode/完整 SHA256 再核一致，未改原日志和认证断言。
该修复只消除诊断日志的假稳定风险；新复核未重现超时，不解释历史 401 的 15 秒超时，
后代状态仍 unknown，不能据此放行正式 related/full 或称 R22 恢复完成。approved ledger
保持原字节，Linux/断电、完整写集、显式旧 A 健康激活及其它未闭项不变。

### R22 未确认 B 的 DHCP API 重入首写前拒绝

已可见但目录持久化未确认的同一父候选再次进入 DHCP 安装 API 时，原路径会
先建立第二事务、备份并安装变化后的输入，直到最后 parent commit 才 HOLD。
新增 direct 与真实 SETUP→LOAD 故障→同一候选重入 workflow 要求任何 DHCP
命令之前拒绝，保留第一次 B/A 字节、事务及 backup inode 和 Q manifest/链接/WAL。
固定 A/B 预期及故障后追加输入独立于实现；两项原实现 2 tests / 4 FAIL /
exit1（各有 open/fsync 两个 subtest，12.997 秒），完整 RED 日志
`outputs/test-diagnostics/r22-dhcp-uncertain-reentry-red.log`，inode 145519200，
size 4150，SHA256 `5ad44b790de6ce1b4b4ba2f918b413c0121a82339866d11124d4c506aa4a6ce1`。
候选只增加未确认可见父候选的入口 HOLD，不修改未提交候选的原安装/清理合同。
新 direct/workflow 加原保留备份、成功清理、precommit 回滚清理和真实 SETUP
备份保留例共 6 tests / OK / exit0（15.703 秒）；完整日志
`r22-dhcp-uncertain-reentry-green.log`，inode 145523546，size 1439，SHA256
`8a95584cc8bb2416c381716f0bb1aa2688bd72777395efa947f13e575afb932d`。读前后 stat
一致，完整 Ran/OK 与物理退出标记、实际 exec exit0 相符。原两个测试仅抽取
相同断言/真实脚本步骤到私有 helper，原预期和 open/fsync 两个边界均保留。

manifest 原 LOAD direct 和 generation-input-binding 多脚本 workflow 映射有效；
REAL_ENV 继续 OPEN。此检查依赖同一进程内候选的 visible/synced 状态，不是
跨重启凭据或所有孤儿事务闸门；文件命令/dhcpd 仍为私有端口替身，不证明真机、
完整 B schema、Linux/断电、完整 WAL 写集或旧 A 健康激活。原正式 related/full
unknown 超时重试门禁不解除，不手改 ledger 或套用上一候选的模块诊断。

本候选完整 LOAD transaction 模块加四项相关真实 SETUP→LOAD workflow（重入、
备份保留、visible parent 同步失败、健康 parent commit 拒绝冷 P 回退）诊断为
292 tests / OK / exit0（46.361 秒）。这是完整 LOAD 模块加明确选择的 workflow，
不是整个 workflow 模块或正式 related/full。完整日志
`outputs/test-diagnostics/r22-dhcp-uncertain-reentry-load-workflows.log`，inode
145532273，size 99084，SHA256
`f0344bf3051259d38a08510b78a28f4cc899a2d39b9d5ad37712a0cb20308b64`，读前后 stat
一致，运行中 95513 字节旧前缀 SHA256
`684184b91612555f1c9394c9bbc9574aa40a2ccd357997ca04fc858de56db21e` 未变。
物理第 936 行 Ran、938 行 OK，原用例缓冲 stdout 后 971 行
`R22_DHCP_UNCERTAIN_REENTRY_LOAD_WORKFLOWS_EXIT=0` 与实际 exec exit0 相符。
运行期间源/测试冻结，approved ledger、manifest 和运行态 setup manifest 字节未变。

### R22 部分 DHCP A 恢复不得删除原备份候选

旧安装算法在 parent replace 前失败后尝试回滚；恢复复制返回非零或抛 OSError 时，
finally 仍删掉唯一完整 A backup/staged/事务。新独立 direct 和真实 SETUP→实际
LOAD 安装 API workflow 以固定 A/B 字节、一次预提交拒绝、一次恢复复制故障覆盖
该窗口：2 tests 的四个 subtest 均在原实现备份被删除处 FAIL / exit1。完整 RED 日志
`outputs/test-diagnostics/r22-dhcp-restore-failure-evidence-red.log`，inode 145640130，
size 4244，SHA256
`e987e2c4bc3a7dbea8f43469d8cadf7c2692f38bae8933daf6aee0005c95367f`。

候选在第一条回滚命令/提示之前标记恢复未完成，只在所有原恢复命令正常结束后
清除此状态。非零、异常或中断不能授权 finally 清理 A 备份；原错误继续传播，
事务/0700 backup/固定原 A 字节/B staged 保留并报告 HOLD，不提示手工删除。
parent 候选仍未提交，故障目标保持缺席的部分恢复状态，不能假报完整 A；已保留
的事务由新进程前置闸门拒绝。SETUP 后的 Q manifest/共享链接/WAL 原字节保留，
无服务启动。原正常成功、完整预提交回滚清理、B 可见但未同步及新候选拒绝四个
合同原样保留，新例与其共 6 tests / OK / exit0，日志
`r22-dhcp-restore-failure-evidence-green.log`，inode 145644602，size 1360，SHA256
`34a109d1ddd38033955c32e52a03ecc6d47653f40d29c4e25bf6d4fa0e352034`。

完整 LOAD 模块加五项相关 workflow 共 301 tests / OK / exit0（55.937 秒），完整
日志 `r22-dhcp-restore-failure-evidence-load-workflows.log`，inode 145650290，size 100480，
SHA256 `cc7af3a4a21d1a0449536281b09f01e29f6a3086257e26cdbf44392e27a16a87`。
读前后 stat/inode 稳定，运行中 97347 字节旧前缀 SHA256
`ff3622d3855426b0d89242814b5e94582a1ce4ca336bba5ecdff01b0dc08a118` 未变。
物理第 946 行 Ran、948 行 OK、原缓冲 stdout 后第 981 行完整
`R22_DHCP_RESTORE_FAILURE_EVIDENCE_LOAD_WORKFLOWS_EXIT=0` 与实际 exec exit0 一致。
源码/测试冻结，approved ledger、manifest 与运行态 setup manifest 未改。文件命令
和 dhcpd 是私有端口；这里不是 root 真实入口、完整恢复后校验或恢复 fsync/断电
证明，更不是旧 A 健康激活或 R22 整体验收。原 bootstrap/REQ19 超时原因仍待核，
只做诊断回归，不因局部 PASS 盲跑 related/full，不手改 ledger，现场卡继续 OPEN。

### R22 DHCP A 恢复命令 exit0 后仍须验证预像候选

前一部分恢复保留候选只检查 rm/cp 退出码。新 independent direct 和真实
SETUP→实际 LOAD 安装算法 workflow 在恢复 cp 返回 0 后分别注入错误字节、
0644→0600 模式及 regular→悬空链接，原实现继续传播原预提交拒绝并清掉备份，
没有恢复后验证。2 tests / 6 FAIL / exit1 的原日志
`outputs/test-diagnostics/r22-dhcp-restore-postverify-red.log`，inode 145732513，
size 8815，SHA256
`da349b26e218b6440f9711b74579b989f924d1141745572f71dce695ba21d1c0`。

候选在首次备份前冻结原 A 缺席/regular/原始 symlink 预像。regular 使用持有的
NOFOLLOW FD 读取摘要/size，名称及 FD 的 dev/ino/mode/uid/gid/nlink/size/mtime/ctime
读前后须一致；symlink 不跟随目标。恢复后逐项核 bytes/size/mode/uid/gid/mtime
或原链接文字/叶元数据/缺席。错误或无法读取仍保留恢复未完成状态、原备份和事务，
报告 HOLD 并由磁盘残留闸门拒绝新 LOAD；不以 inode/ctime 相等要求 cp 重建原 inode，
也不把一组顺序读取当作原子比较。原正常健康成功和完整预提交回滚清理保留。

新两项与原三项清理/部分失败合同共 5 tests / OK / exit0，完整 GREEN 日志
`r22-dhcp-restore-postverify-green.log`，inode 145739341，size 1178，SHA256
`25bd829b0bc748ec234e86b21bf914f24ad9c4155d137ad546e1e9763ae4737b`。
缺席/regular/原始悬空链接、未知 directory/FIFO 及打开时名称换绑 direct 2 tests
OK / exit0（leaf-boundaries 日志 SHA256
`928bf0e1dbbb21a4958ad9319c44484017c2d871c994735579ae7b47901b27db`）；
真实旧 A 链接与原缺席经完整恢复仍清理的 direct/workflow 2 tests OK / exit0
（old-shapes 日志 SHA256
`c895d04884b487ab8fafbdc188caf2e55da0b753582f26c666f5a231351a6976`）。
日志均核完整物理 Ran/OK/FAILED/退出 footer、读前后 stat/inode/SHA 稳定及实际退出码。

manifest 原 LOAD direct / generation-input-binding 真实多脚本 workflow 映射有效。
文件命令、dhcpd 和服务为私有端口，不证明完整 root 入口、ACL/xattr/硬链接拓扑、
目录祖先竞态免疫、持久 DHCP receipt、恢复 fsync/断电、B 成功 WAL 退休或旧 A
显式健康激活；REAL_ENV 仍 OPEN。原 bootstrap/REQ19 超时原因待核，局部诊断 PASS
不解除正式 related/full 重试闸门，不手改 ledger，不套上一候选的旧 proof。

最终候选的完整 LOAD transaction、完整 DHCP optional workflow 模块，加六项
明确选择的真实 SETUP→LOAD 恢复/保留/重入/冷拒绝 workflow 诊断为 334 tests /
OK / exit0（65.544 秒），不是整个 generation-input-binding workflow 模块或正式
related/full。完整日志 `outputs/test-diagnostics/r22-dhcp-restore-postverify-load-workflows.log`，
inode 145750085，size 116568，SHA256
`067e125c16832c419f8eaf98f024bba7714c5018bc4ca6a3f75f463722cce44d`。
读前后 stat/inode 一致，运行中 64757 字节旧前缀 SHA256
`85cffdd03ecc9405a57332f9b65152c4bbc0d83097946f744bc927206d6b43af` 未变；
物理第 1085 行 Ran、1087 行 OK、原 fixture 缓冲 stdout 后第 1175 行完整
`R22_DHCP_RESTORE_POSTVERIFY_LOAD_WORKFLOWS_EXIT=0` 与实际 exec exit0 一致。
运行期间源码/测试/文档冻结，approved ledger、manifest 与运行态 setup manifest
身份和字节均未改；该源候选仍未批准，不能写作 R22 正式 full 落地。

### R22 已后验证的 DHCP A 恢复同步失败仍须保留备份候选

前一候选只核恢复文件预像，没有恢复 regular/父目录同步步骤，就清理 A backup。
新的独立 direct/真实 SETUP→实际 LOAD 安装 API workflow 注入文件 fsync、目录
open、目录 fsync 失败。首轮日志 `r22-dhcp-restore-sync-red.log`，inode 145788627，
size 10448，SHA256
`722547c9fb46f451b22cc107c6adf2e65277072e690ff6c4aa639485519ad023`
完整 2 tests / 6 FAIL / exit1：四个文件/目录 fsync subtest 因原实现缺少同步失败；
另两个目录 open 注入误命中安装前 pending 扫描，是夹具阶段错误，不能当作修复 RED。
保留原日志/断言，仅将目录 open 注入限定到独立 precommit 拒绝后的恢复阶段，
生产字节未改。修正夹具后的全部六个 subtest 均因缺少恢复同步步骤 FAIL / exit1，
原日志 `r22-dhcp-restore-sync-phase-corrected-red.log`，inode 145795288，size 8885，
SHA256 `1b6db33f8822ded08962d144b4e0123efb1b95b37563c172a09067bee0fad97a`。

候选在所有恢复命令 exit0 且预像后验证完成后，通过持有的 NOFOLLOW 目录 FD
逐个打开恢复 regular 文件，核名称/FD 身份、fsync 文件、重核，再 fsync 父目录、
重核目录身份与全部原预像；symlink/缺席由父目录同步。文件/目录同步、读取、
身份或预像校验失败仍以 LoadError/HOLD 保留原 backup/staged/事务，阻断新 LOAD；
全部成功才解除恢复未完成标志，正常预提交拒绝仍传播原错误并走原清理路径。
新 direct/workflow 与健康成功、正常四文件恢复、旧链接/缺席正例共 6 tests / OK /
exit0（26.686 秒），日志 `r22-dhcp-restore-sync-green.log`，inode 145812217，size 1402，
SHA256 `d90bfbd277dd339685bd12d15a2d3416406650410a6f6a1ad363b3b01476fc51`。
正例独立断言文件逐个同步→目录同步的顺序，不以 fsync mock 次数代替恢复内容。
另有打开时目录换绑、目录同步后内容漂移两个 direct 负例，要求 HOLD、关闭持有
FD 且不跟随未知目录/错误宣称稳定预像；不主张顺序读回是原子 compare-and-write。

manifest 原 LOAD direct 与 generation-input-binding 多脚本 workflow 映射继续有效，
REAL_ENV 卡继续 OPEN。本地私有文件端口/同步注入不证明真实 root 入口、其它写者
竞态免疫、完整 grouped receipt/WAL、备份本身持久性、Linux 断电、B 成功收口或
旧 A 显式健康激活。原正式 bootstrap/REQ19 超时原因仍待核，本诊断 PASS 不放行
related/full，不手改 ledger 或套旧证明。

目录换绑/同步后漂移的完整负例日志
`outputs/test-diagnostics/r22-dhcp-restore-sync-identity-boundaries.log`，inode 145832390，
size 431，SHA256
`8b51180821489f74dde360263546c201db01472af7e46773e47865611c273a43`，2 tests OK / exit0。
最终候选的完整 LOAD transaction、完整 DHCP optional workflow 模块，加七项明确
选择的真实 SETUP→LOAD workflow 共 338 tests / OK / exit0（86.782 秒）。完整日志
`outputs/test-diagnostics/r22-dhcp-restore-sync-load-workflows.log`，inode 145832601，
size 117203，SHA256
`156980fdfb2e9c410e7e7bb8a6a851e69a693431feba5718885396e7bed7def1`；
读前后 stat/inode 一致，运行中 61231 字节旧前缀 SHA256
`61538b3ccf8c1ae9d764f4f63f929bd1554de7c8b0faae3085b074f97a0bcc62` 未变。
物理第 1090 行 Ran、1092 行 OK、原 fixture 缓冲 stdout 后第 1180 行
`R22_DHCP_RESTORE_SYNC_LOAD_WORKFLOWS_EXIT=0` 与实际 exec exit0 相符。
运行中源码/测试/文档冻结，approved ledger、manifest 与运行态 setup manifest 的
完整身份和字节未改；这不是整个 generation workflow 模块或正式 related/full，
该源候选仍未批准，不称 R22 整体正式落地。

### R22 DHCP A backup 读回必须在首个 B install 前完成候选

前一算法只确认 cp 命令返回，没有核备份与初始 A 预像，就覆盖 A 并正常提交 B。
新 independent direct 与真实 SETUP→实际 LOAD 安装 API workflow 在备份复制返回
0 后分别注入错误字节、0644→0600 模式、regular→悬空链接；原实现三个分支均
成功返回并清理事务，2 tests / 6 FAIL / exit1 的独立拒绝断言稳定失败。原日志
`outputs/test-diagnostics/r22-dhcp-backup-prewrite-red.log`，inode 145919750，size 7513，
SHA256 `b607fcc374fcd58d5128c5e4f8420b1623d5a2f7a024be884aac99c155ffcca2`。

候选只在备份命令全部结束后、第一条 B install 之前，读回所有原 A backup 与
初始 leaf 预像比较，原缺席也必须在备份空间缺席。读取失败或类型/内容/元数据不符
时保留 backup 未验证标志，以 LoadError/HOLD 留存 0700 backup/staged/事务，
原 A 四文件不变、零 B install、parent 未提交；不把错误备份当作完整 A，也不
授权清理。新进程残留事务闸门继续拒绝。已验证备份的正常成功、完整恢复以及旧
链接/原缺席恢复继续走原合同。新两项与原四项共 6 tests / OK / exit0（38.212 秒），
日志 `r22-dhcp-backup-prewrite-green.log`，inode 145948236，size 1412，SHA256
`af5c56bf8957d52da8018cd795833330923f227ff5649e563be91b9c39d1d1e9`。
追加 backup held-FD 打开 PermissionError 负例，原断言保持，direct/workflow 的
四类备份分支共 2 tests / OK / exit0（46.076 秒），完整日志
`r22-dhcp-backup-prewrite-read-negative.log`，inode 145983403，size 511，SHA256
`9d7abc046de71c88eda362a6ab7f38ee44b6e911829a5b744a8d579f8b470172`。
均核物理完整 Ran/OK/FAILED/footer、读前后 stat/inode 稳定和实际 exec 退出码。

这只是第一次 B 覆盖前的字段集读回，不是原子 compare-and-write、完整 backup
WAL/receipt、备份文件/目录 fsync、掉电见证、备份之后的同 UID 篡改免疫、完整
root 入口、B 成功退休或旧 A 显式健康激活。排他锁与其它写者静默仍为前提。
manifest 的 LOAD direct 和实际 SETUP/LOAD workflow 映射仍有效，REAL_ENV 继续
OPEN。原 bootstrap/REQ19 超时原因仍待核；诊断 PASS 不解除 related/full 闸门，
不手改 ledger，不套上一个源候选或历史 full proof。

最终候选的完整 LOAD transaction、完整 DHCP optional workflow 模块，加八项
明确选择的真实 SETUP→LOAD workflow，共 340 tests / OK / exit0（202.083 秒）。
完整日志 `outputs/test-diagnostics/r22-dhcp-backup-prewrite-load-workflows.log`，
inode 146018409，size 117572，SHA256
`7f770b0690c7fa56c9673c2dcd7fac552870ae29231c87cb53d498023ac70a7e`；
读前后 stat/inode 一致，运行中 61231 字节旧前缀 SHA256
`98ec4598a3643159d3690fe7c0f5bf42e361a444f64e5105de03840cbfc885cf` 未变。
物理第 1093 行 Ran、1095 行 OK、原 fixture 缓冲 stdout 后第 1183 行完整
`R22_DHCP_BACKUP_PREWRITE_LOAD_WORKFLOWS_EXIT=0` 与实际 exec exit0 一致。
运行期间源码/测试/文档冻结，前后完整身份/字节复核一致，approved ledger、
manifest 与运行态 setup manifest 未改。该诊断不是整个 generation workflow
模块或正式 related/full，不是性能验收，源候选仍未批准，R22 整体继续 OPEN。

### R22 DHCP 原 A backup 写前同步候选

前一读回候选仍未在首次覆盖 A 前同步 backup payload 或目录链。独立 direct 与
真实 SETUP→复制 LOAD 安装算法 workflow，对 backup regular、backup 目录、
transaction 目录、runtime 目录的同步错误均要求零 B install、原 A 不变、parent
未提交、0700 backup/staged/事务零清理并 HOLD；两个正向检查独立要求同步顺序。
原实现完整 4 tests / 10 FAIL / exit1（21.781 秒），原日志
`outputs/test-diagnostics/r22-dhcp-backup-sync-red.log`，inode 146183693，size 13646，
SHA256 `b4d16ab29ac7dde63a4438159e117bf78a3953916d2ecc03112329640fdde1c8`。
失败注入原来未被执行，因为实现缺少对应同步；成功顺序检查在首次 B install
前同样失败。新正例在通过写前顺序后应正常提交 B，夹具增加该分支的成功状态分类；
原拒绝/顺序断言不变。原日志完整保留，不把此分类补充称为生产修复。

候选持有 NOFOLLOW runtime→transaction→backup 目录 FD、核备份目录 0700，
复用 held-FD 文件同步和 leaf 后验证，先同步 regular backup 和 backup 目录，
再同步 transaction、runtime；每步重核完整目录身份及原 A/backup 预像。
任一错误均传播 `DHCP A backup durability unconfirmed; HOLD`，不覆盖 A、不
提交 parent、不删除原证据。原链接和缺席由目录同步，健康成功和完整 A 恢复
正例继续走原合同。新四项加原备份读回/恢复同步/旧形状三项共 7 tests / OK /
exit0（21.437 秒），日志 `r22-dhcp-backup-sync-green.log`，inode 146199636，
size 1656，SHA256
`40878c3ebc24d9f68bac4eb0e7e0a5ff6d5f6c0091339283600f70cb34501249`。
追加 direct 拒绝打开期间 runtime/transaction/backup 换绑、同步后备份漂移，
保留未知对象并验证所有持有 FD 关闭；这些是补充负例，不冒称先 RED。

LOAD direct 与 generation-input-binding 真实多脚本 workflow 映射继续有效，
REAL_ENV 卡 OPEN。本地同步异常注入/返回成功不等于完整持久恢复 receipt/WAL、
祖先原子比较、非协作写者免疫、Linux 断电、B 成功退休或旧 A 健康激活。
原 bootstrap/REQ19 超时原因仍待核，本诊断 PASS 不解除 related/full 重跑闸门，
不手改 ledger、套旧证明或称完整 R22 已正式验收。

完整 LOAD transaction、完整 DHCP optional workflow 加十项明确选定的真实
SETUP→LOAD workflow，首轮完整为 346 tests / 1 ERROR / exit1（122.041 秒），
原日志 `outputs/test-diagnostics/r22-dhcp-backup-sync-load-workflows.log`，inode
146222638，size 120257，SHA256
`4a6d7a23cc5dba09726165a4c0d2d98a6b8311831e7f00ee11a848f962a06098`。
运行中 111709 字节前缀 SHA256
`d0a78008f1f7a948fffae251d6df55a05f58347aa45a4752725dbaac57525ee7`
未变；物理第 1123 行 Ran、1125 行 FAILED、缓冲 stdout 后第 1210 行
`R22_DHCP_BACKUP_SYNC_LOAD_WORKFLOWS_EXIT=1` 与 exec exit1 一致。
唯一错误有明确原因：`test_air_scoped_setup_empty_hosts_cross_install_and_start_checks`
的 `install -d -m 0700` 私有端口只调用默认 mkdir，没有应用 -m，backup 实际
为 0755。生产原命令明确要求 0700，新写前门禁正确拒绝；不能称为环境超时。
增加独立 backup=0700 夹具断言后，原端口单项 1 FAIL / exit1，日志
`r22-dhcp-backup-sync-fixture-mode-red.log`，inode 146294205，size 4890，SHA256
`d24584f3f2a2a48163d77f958fc672c1e3d2ea71f8931b91d3dbd78a1986dcf9`。
仅补端口按原 install 的 -m 设置目录权限，原所有拒绝/回滚/启动断言、生产
0700 门禁不变。受影响完整 DHCP optional workflow 模块 28 tests / OK / exit0
（0.774 秒），日志 `r22-dhcp-backup-sync-fixture-mode-green.log`，inode 146295246，
size 15458，SHA256
`f86e8deec684daa0305ffbecde7031ba93ed3610d2eff508745320b66f338aaf`。
按已定位的单一夹具原因复核整个受影响模块，不将首轮 346 项冒称全通过，也
不以此启动正式 full。旧 bootstrap/REQ19 超时原因与正式 related/full 闸门仍未闭。

### R22 DHCP 四文件持久写前凭据候选

原 A 字段集只有进程内存，备份目录不能独立说明完整四文件前像、缺席项或拟提交 B。
新增 direct 与真实 SETUP→复制的实际 LOAD 安装 API workflow，独立要求首条 B
install 之前存在 0600/schema1/prepared-a 凭据，明确四个固定文件的 A 字节摘要、
metadata、四个 B 摘要及 parent 前像/候选身份；另注入凭据文件 fsync 失败要求零 B
写入、原 A 不变、0700 backup/事务保留。原实现 4 tests / 4 FAIL / exit1，完整日志
`outputs/test-diagnostics/r22-dhcp-persistent-preimage-red.log`，inode 146360708，size 6645，
SHA256 `eb7c507e0c632ca27c4149dc34df1e747eedb40be0bb2e7682952a1acbf2418c`。

候选通过 held NOFOLLOW runtime→transaction→backup 目录链建立固定清单，
O_EXCL 创建 `a-preimage.json`、fchmod0600、完整写入并 fsync 文件，重核原 A/backup
及目录身份。随后原 backup 文件/目录链同步将凭据名称一并持久化，再核原 record
身份/字节/ancestry 才允许 B 写入。清理前同样核原 record，不把未知同名凭据作为
删除备份的权限。校验和是完整性绑定，不声称抵御可重写全部 authority 的同 UID 写者。

初次追加“只移动 receipt 文件”的负例因原 file ctime 核验而已通过：日志名虽为
`r22-dhcp-preimage-ancestry-red.log`，实际 1 OK / exit0，不能冒称 RED。进一步把
runtime 原目录移走、创建未知同名 runtime，再把整个原事务移入，record 文件自身
完全不变；原 leaf-only verifier 未拒绝，独立 direct 1 FAIL / exit1，日志
`r22-dhcp-preimage-runtime-rebind-red.log`，inode 146374909，size 888，SHA256
`385a31e4d092bcec765f4b1577b2542494b77783a07dfd75d281cc87009faaf9`。
候选在 record 读取前后另核 runtime/transaction/backup 的 dev/ino/mode/uid/gid。
新项加原 backup 同步/链接缺席恢复正例共 7 OK / exit0（9.879 秒），日志
`r22-dhcp-persistent-preimage-regressions.log`，inode 146374975，size 1907，SHA256
`4be9b51ef81fff6a6d1ba513756d12404807e2690754330bc453eeda103b2a48`。

完整 LOAD transaction、完整 DHCP optional workflow 加四项明确选定的真实
SETUP→LOAD workflow，完整 343 tests / OK / exit0（54.584 秒），日志
`outputs/test-diagnostics/r22-dhcp-persistent-preimage-load-workflows.log`，inode
146379441，size 118343，SHA256
`9ff7bc096790813fbbd45515c179f8a3059278adf7195a5e7d904c26ad3d3c0d`。
读前后 stat/inode 稳定，已记录 112117 字节旧前缀 SHA256
`e6d413302a78ed84f6856dcfffffd4ca0a02a5b7acbf27f57bcd5bd81a63781a` 未变。
物理第 1092 行 Ran、1094 行 OK、fixture 缓冲 stdout 后第 1186 行
`R22_DHCP_PREIMAGE_LOAD_WORKFLOWS_EXIT=0` 与 exec exit0 相符；运行中源码/
测试冻结，manifest、approved ledger 和运行态 setup manifest 身份/字节未改。
既有 direct 与 generation-input-binding 多真实脚本 workflow 映射有效，REAL_ENV
R22 卡继续 OPEN。本次不是整个 generation workflow、related 或正式 full。

本凭据不提供冷恢复 API、A 服务启动权限、完整 P/Q/WAL/receipt 事务整合或 B
健康成功退休；正常 DHCP mount 的既有成功清理边界也尚未扩展到整个 LOAD 成功。
不能称完整 R22 已落地或本地正式验收。原 bootstrap/REQ19 超时原因仍待核，
不因这些局部 PASS 放行 related/full，不手改 ledger 或套旧证明。

### R22 四文件盘上前像的新进程只读核验候选

新增 independent direct 和真实 SETUP→DHCP parent 同步失败→新 Python 进程
读取复制 LOAD API workflow，要求只从盘上核对四文件 A/backup、已可见 B 和
parent，零外部命令、零恢复/清理/启动，保留全部原名称、身份及字节。原版本无
该接口，3 tests / 2 FAIL / 7 ERROR / exit1（11.241 秒），日志
`outputs/test-diagnostics/r22-dhcp-disk-preimage-inspection-red.log`，inode 146420402，
size 9435，SHA256 `024485d157cdb634595c3b7fced4865ddef0e8767a4081800a7cd006fcd67998`。
这是新增能力的 RED，不把缺接口错误描述为原流程已发生自动恢复或数据破坏。

实现的 owner 显式输入决定可读路径，JSON/checksum 不可授予另一 runtime 或 parent
路径读取权。held NOFOLLOW 目录链、同 owner/private/single-link 有界 record、唯一
JSON keys/schema/phase/checksum、固定四文件及父候选字段均先核；读取所有 backup
和 runtime/parent 后，再核组内 leaf identity/bytes 与 FD/名称，未知状态只 HOLD。
parent B 摘要一致仅报告 b-visible，不称 directory_synced、健康或恢复/激活许可。

首轮实现复核 3 tests / 1 ERROR / exit1，日志
`r22-dhcp-disk-preimage-inspection-green.log`，inode 146425144，size 2064，SHA256
`9069747a60c6acc19971744324a0b27b227824490c22f095bf196357b63d702b`。
确切原因是 direct 夹具把原 preparation 的 /var 路径 resolve 为 /private/var，
违反同一 literal parent 身份；workflow 的原路径正例已通过。只纠正夹具传入原
project 路径，生产路径门禁不放宽；并为六个负例分别断言具体拒绝原因，防止一个
前置错误掩盖全部负例。不将该日志名中的 green 冒称完整通过。

追加独立“backup 内额外未知子项”要求保留该对象并 HOLD；新 reader 首版没有
核闭合集，1 FAIL / exit1，日志 `r22-dhcp-disk-preimage-extra-backup-red.log`，
inode 146429659，size 1169，SHA256
`3b5cbf0f5af5b024fb9ee9ac6371ea0b77022901cd01abd69063f05502c2d612`。
候选核 held backup 目录的完整名称集合，原 missing 对应缺席，不采纳未知子项。
修正后的正例/六类拒绝/未知子项/fresh workflow 共 4 OK / exit0（11.422 秒），
日志 `r22-dhcp-disk-preimage-inspection-corrected-green.log`，inode 146429740，
size 738，SHA256 `340f7c8ca583ec1d62dbf92ef134c1bb9659ce275d4b8cc97c995149f82307c7`。
原链接、原缺席与未提交 B parent 的补充正例 1 OK / exit0，日志
`r22-dhcp-disk-preimage-old-shapes.log`，inode 146434295，size 275，SHA256
`33193e402f04c382c2efb165e4852426a4cb0fe443cd6f15990551b09979bafc`。

完整 LOAD transaction、完整 DHCP optional workflow 加四项明确选择的真实
SETUP→LOAD workflow 完整 347 tests / OK / exit0（47.409 秒），日志
`outputs/test-diagnostics/r22-dhcp-disk-preimage-load-workflows.log`，inode 146434376，
size 118743，SHA256 `f02bcf13314234b44e2a4b1e46e6e1ac192e452452fe757705b18ba450cc5b32`。
两次完整文件读取 stat/inode/全文件 SHA 稳定；物理第 1097 行 Ran、1099 行 OK，
缓冲 stdout 后第 1189 行 `R22_DHCP_DISK_PREIMAGE_LOAD_WORKFLOWS_EXIT=0`
与实际 exec exit0 一致。运行前后源码/测试/文档/manifest/approved ledger/
运行态 setup manifest 的完整身份及字节保持。既有 direct、多真实脚本 workflow
映射有效，REAL_ENV R22 卡仍 OPEN。

返回只读字典不可用于后续写授权，API 关闭 FD 后不承诺状态冻结；本能力不执行
全组恢复，不验证全套 release 健康或 root 完整入口，不关闭 Q/P/WAL/receipt
整合、B 成功收口、旧 A 显式激活、Linux/断电或 DEV ACK。普通新 LOAD 仍须
HOLD，原 bootstrap/REQ19 超时原因未知，局部 PASS 不解除 related/full 重跑闸门。
本次没有正式 related/full，也没有自动批准 ledger 更新，不称 R22 全部正式落地。

### R22 未结清 DHCP 事务的新进程写前闸门候选

内存候选重入闸门不能保护新 LOAD。独立新候选 direct 和真实 SETUP→父 B
目录 open/fsync 失败→新 Python 进程导入复制的 LOAD 安装 API workflow，均在
原实现越过残留事务后触发禁止 installer 的预期失败，分别各有两个 subtest。
原 RED 日志 `outputs/test-diagnostics/r22-cold-pending-dhcp-red.log`，inode
145585927，size 9115，SHA256
`d35a0bb407fe291432aceef89de81d5a6b97f44697e02acbd7e74920d173c2dc`。
其中 main 的首轮失败来自夹具未满足 Supervisor 固定 `/root/.ssh` 前提，不能算
闸门缺陷证据；仅补齐该既有前提、实现未改时，main 独立 RED 证明项目解析仍被
调用，完整日志 `r22-cold-pending-dhcp-main-red.log`，inode 145591000，size 1204，
SHA256 `e1f615385a1fa10e40cabc44d2bb1cbee6169def5e23e5b7b69d049f40ec0802`。

候选对运行目录的未知事务前缀做只读 NOFOLLOW held-dirfd 有界扫描。普通管理
LOAD 在锁内、项目解析前拒绝，安装 API 在源验证/绑定或任何命令前再拒绝；不
解析、删除或恢复未知凭据。文件/目录/悬空链接/FIFO 前缀都 HOLD；runtime 非目录、
扫描错误/超过 4096 项、名称换绑或同 inode 名称集 ABA 均 fail closed。不存在或
干净的真实目录允许原流程，不创建目录。原 A/B 固定独立字节、第一次事务及 backup
完整身份保持；新候选不能替换 parent B，不执行新 installer 或 cleanup。

三项缺陷案例和原正常成功/提交前失败清理正例共 5 tests / OK / exit0，日志
`r22-cold-pending-dhcp-green.log`，inode 145596542，size 1203，SHA256
`4ef94afb99d2ede68cac5558037ce1dca1dae2d19d276b5f53627e75c2836dfa`。
五项额外拒绝/只读 direct / OK / exit0，日志 `r22-cold-pending-dhcp-guard-negatives.log`，
inode 145604904，size 832，SHA256
`e3cfe292bc748bc2a462f03023efc67de79b071dbd2d5eecb510511ee136b31a`。
完整 LOAD 模块加四项相关真实 workflow 共 299 tests / OK / exit0（55.858 秒），
日志 `r22-cold-pending-dhcp-load-workflows.log`，inode 145606399，size 100085，SHA256
`792aa6ad463582cae7e0298dea6143c25ec1dfdb9d484031afec859f05679c69`；
读前后 stat 一致，旧 96501 字节前缀 SHA256
`70759ab782c8db30ded417b9b3c2af3624ceb19f3e95a63f38095279f8e257c4` 未变。
物理第 943 行 Ran、945 行 OK、原缓冲 stdout 后第 978 行完整
`R22_COLD_PENDING_DHCP_LOAD_WORKFLOWS_EXIT=0` 与实际 exec exit0 一致。
源码/测试冻结，manifest、approved ledger 和运行态 setup manifest 未改。

这不是正式 related/full：前述 bootstrap 15 秒及 REQ19 probe 10 秒原始原因仍待核，
不能因这组局部 PASS 放行盲重跑。新进程只是拒绝已知命名前缀，不提供完整 DHCP
receipt/WAL 冷恢复或原子 compare-and-write；仍要求正常写者静默。完整 root 入口、
断电持久性、B 成功收口、旧 A 显式健康激活和 DEV ACK 未闭，REAL_ENV 卡继续 OPEN。

### R22 未确认 B 时 DHCP A 备份保留候选

父 B 目录 open/fsync 错误已传播 HOLD，但 `mount_and_test_dhcp` 的 finally
仍删除 A backup、B staged 及事务目录。独立 direct 和真实 SETUP→实际 LOAD
安装算法 workflow 要求可见 B/已安装 B 保留，原 A 固定字节备份及 0700 目录
不清理，明确报告 HOLD 与事务路径；健康同步成功和 replace 前拒绝还原 A
两个正向清理合同保留。原实现 4 tests / 4 FAIL / exit1（direct、workflow
各有 open/fsync 两个失败 subtest，两个正常清理例通过）；完整 RED 日志
`outputs/test-diagnostics/r22-dhcp-uncertain-evidence-red.log`，inode 145371162，
size 4809，SHA256 `91c8e283aa156b2a083021da550a30aa785d91a5a7d4e8105e10633d9b192e1d`。
候选只在 visible 且 directory_synced 未确认时保留事务，禁止自动回 A 和清理；
其他原清理路径不变。四项新例加原 replace 失败回滚和 main 同步失败停服例
6 tests / OK / exit0（8.946 秒），完整日志 `r22-dhcp-uncertain-evidence-green.log`，
inode 145378400，size 2651，SHA256
`a2c35b359ec51ac57aa9abf7bf760a506699fd7f57d2b4e33f1aa3b691b18f4b`，读前后 stat
一致，完整 Ran/OK 与物理退出标记及实际 exec exit0 相符。

workflow 执行实际 SETUP 子进程、copied LOAD 与排他部署锁，保持 Q manifest/
链接/WAL 原字节；DHCP 命令和语法检查只以限制写入私有目录的端口替身运行，
固定预期 A/B 字节独立于实现生成。它不是完整 root main、真实 dhcpd 验收或
Linux/断电见证；保留文件也未证明全组 fsync、不是可自动恢复 receipt/WAL。
manifest 原 LOAD direct 与 generation-input-binding 多脚本 workflow 映射有效，
正式 related/full 原 unknown 超时门禁不解除，不手改 ledger；完整写集、旧 A
显式激活、B 健康成功收口和 DEV ACK 仍 OPEN。

两个完整 LOAD transaction / generation-input-binding workflow 模块及正常导入
用例诊断 356 tests / OK / exit0（271.094 秒）；日志
`outputs/test-diagnostics/r22-dhcp-uncertain-evidence-modules.log`，inode 145388345，
size 116645，SHA256 `13899b433a7bc1aae156e950e96a328a59c5a4d5fb741228ff112fab497d0d6b`。
读前后 stat 一致，100850 字节旧前缀 SHA256
`7dabc2630e0bb770aae646fa6943a65be42efc73fb5754f480fa5d5ce2f91919` 保持不变；
物理第 1108 行 Ran、1110 行 OK，原用例缓冲 stdout 后 1120 行
`R22_DHCP_UNCERTAIN_EVIDENCE_MODULES_EXIT=0` 与实际 exec exit0 一致。
运行期间源/测试未改，manifest、approved ledger、运行态 setup manifest 原字节
未变。本结果仍只是局部模块诊断，不是批准 runner 或正式 full/check。

### R22 父 B 可见但目录同步失败的 HOLD 候选

`commit_prepared_release` 原实现忽略 parent directory open 错误，并把 fsync
失败仅写为 warning；B 已 replace 后仍向调用方返回成功。两个 direct 与真实
SETUP→父 LOAD 提交 API→新 LOAD 冷恢复 workflow 独立要求报错、不进入后续
成功步骤、保留可见 B/Q manifest/链接/WAL，拒绝 P 冷回退。原实现 4 tests /
4 FAIL / exit1（workflow 有两个故障 subtest，另含健康同步正例），完整日志
`outputs/test-diagnostics/r22-parent-visible-sync-red.log`，inode 145226743，size
5082，SHA256 `97887b2f9abf1e786ab6e44d80a3b58dd199a0e14e257c4f0782c325fff0f525`。
候选保持 `committed=True` 表示可见 B，新增 `directory_synced` 区分成功；
open/fsync 失败传播 LoadError，重复调用同一未确认候选保持 HOLD。main 的
失败清理应停服、不还原 P 链接/旧 prefix、不提交报告/选择器，状态文字不能
冒称持久提交成功。该独立 main 断言先 RED（1 test / 1 FAIL / exit1），日志
`r22-parent-visible-main-state-red.log`，inode 145240494，size 2785，SHA256
`f49588c606b380742f85dc0b7d2f84d8eadbbbc301687953b2abf20fca32f569`，随后修正提示。

最终 scoped direct/main/workflow 及原健康 SETUP→parent commit 正例 6 tests /
OK / exit0（15.333 秒）；完整日志 `r22-parent-visible-sync-main-green.log`，
inode 145241002，size 2404，SHA256
`651e95af1980fa47a24c10d1072fb7d79eff9c8db643e484c7b22f3acf40dd03`。各日志读取
前后 stat 一致，完整 Ran/FAILED 或 OK 与物理退出标记/实际 exec exit 相符。
manifest 原 LOAD direct `day0_release_operations` 和真实多脚本
`generation_input_binding_setup_load_c2` 映射保留。workflow 的 B marker 是独立
最小 payload，main 运行平台/服务接口是受控替身；不声称真实根入口、完整 B
schema 或服务验证。此修复不实现父 B 健康成功收口/可重入退休 WAL，亦不解除
原 bootstrap 15 秒、REQ19 probe 10 秒原因 unknown 的正式 related/full 重试门禁；
approved ledger 不手改，Linux/断电、旧 A 显式激活及 DEV ACK 仍 OPEN。

两个完整 LOAD transaction / generation-input-binding workflow 模块及其正常导入
用例诊断为 352 tests / OK / exit0（228.248 秒）。完整日志
`outputs/test-diagnostics/r22-parent-visible-sync-modules.log`，inode 145251175，
size 115733，SHA256 `3311ac49a7b60fcda798dc084f5621bbc6ec0d6f494f88c947bdf263a765f69d`；
读前后 stat 一致，运行中已核 100169 字节旧前缀 SHA256
`be6b34da2871f51b5a2cb55b93ca5873e380a2b80ee4ffc0fdcab4a097b6133d` 保持不变。
物理第 1101 行 Ran、1103 行 OK，经过原用例缓冲 stdout 后第 1113 行
`R22_PARENT_VISIBLE_SYNC_MODULES_EXIT=0`，实际 exec exit0。源/测试运行期间未改，
manifest、approved ledger 和运行态 setup manifest 原字节未变。这是局部完整模块
诊断，不是 related runner、正式 full/check 或 R22 整体验收。

### R22 materialized latest 临时链接写集候选

实体 latest 迁移原先未登记 `.latest.tmp.<PID>`，创建临时链接后死亡时冷恢复会
还原原目录并退休 WAL，却遗留该链接；把临时名换成无关文件仍会执行恢复写入。
原 writer 还会删除预占临时名。新增两个 SETUP direct 与真实 LOAD→SETUP 强杀→
新 LOAD 冷恢复正/负 workflow 独立表达拒绝/恢复合同，原实现 4 tests / 4 FAIL /
exit1（12.168 秒）。完整 RED 日志 `outputs/test-diagnostics/r22-materialized-temp-red.log`，
inode 145048265，size 5209，SHA256
`92517b4f464a08155e0e2bde3efb08253ccc901a5758e49965eb098d4baa671d`。
前后 stat 一致，旧 647 字节前缀 SHA256
`57fef2313dc2fe03c16f5eb0fb2e1377aec95f2e8ec2fddb73927c5661fe8d97` 未变；
四项失败均是合同未满足，不是路径或依赖错误。

候选在首次原目录 rename 前拒绝占用名并登记准确临时 Q 链接值；登记之后的碰撞
也不得删除。WAL 上下文中的迁移异常只交外层完整恢复预检，保留所有证据，避免
局部 cleanup 在未知状态下先还原源。原非 WAL 迁移合同保持。四项新例加原真实
pointer replace 后死亡恢复正例 5 tests / OK / exit0（20.183 秒）；完整日志
`r22-materialized-temp-green.log`，inode 145056776，size 1024，SHA256
`8e94112f8f3692097c3397e598b6f5006fa3da439c4a23be48a57e813ab5ffb5`，读前后 stat
一致、完整 Ran/OK 与物理退出标记/实际 exec exit0 一致。manifest 原 SETUP direct
`day0_release_operations`、`generation_input_binding_setup_load_c2` workflow 映射有效。
这不是批准 runner 或正式 proof；原 bootstrap 15 秒及 REQ19 probe 10 秒未知原因
门禁不变，approved ledger 不手改。父 B 成功收口、完整写集、旧 A 显式安全激活、
Linux/断电与 DEV ACK 仍未闭。

三个完整 SETUP plan / LOAD transaction / generation-input-binding workflow 模块
诊断为 363 tests / OK / exit0（286.807 秒）；完整日志
`outputs/test-diagnostics/r22-materialized-temp-modules.log`，inode 145072681，size
116625，SHA256 `f9bf785897ca55c705fe0c1eb23106641912a16c38e52b06e16d110d90a37e69`。
读前后 stat 一致，旧 101311 字节前缀 SHA256
`7535f9fad4c84c4561653029dcc8b3be4c68148a2e5017000c11c982bb0124c9` 未变；物理
Ran/OK 后有缓冲夹具 stdout，末尾 `R22_MATERIALIZED_TEMP_MODULES_EXIT=0` 与实际
exec exit0 一致。过程中一次日志 stat 改变的读取消推断，后续稳定快照再核；不把
运行中的片段当证明。runtime `.setup_manifest` 与 approved ledger 前后原摘要
不变。局部模块回归不清除原 unknown timeout、不授权盲重 related/full。

### R22 Q parent 预像读前身份冻结候选

原 `_setup_switch_q_parent_authority` 先读取内容，再取身份；同字节新 inode 在首次
读取之后替换名称会被接纳，原先缺席的名称在首次读取之后出现也会被记录成缺席。
两个独立 direct 与真实 LOAD→SETUP 调用边界要求先拒绝、不发布 WAL、不启动 SETUP。
首轮日志 `r22-q-parent-freeze-owner-red.log`（inode 144896156，size 18690，SHA256
`64965dfadcb77c09a339d773936f31f82ec4b08163337824c5ee007d51c91913`）包含 direct
私有路径的 macOS `/var` 别名错误，不能将这两项当实现 RED。仅将夹具项目路径
规范到实际目录后，原实现 3 tests / 3 FAIL / exit1（4.379 秒）；两个 direct 不抛
LoadError，workflow 实际继续启动 SETUP、发布 WAL。有效 RED 原日志
`outputs/test-diagnostics/r22-q-parent-freeze-owner-red-canonical.log`，inode 144898485，
size 17458，SHA256 `e1a7ea625342fe851dfae9f504ce18738c92e0ec06ef67ea31e7bcf009ec48a5`。
原拒绝断言未放宽；SETUP 后续夹具错误不作为根因或通过证据。

候选在首次读取之前冻结 parent 文件完整 dev/ino/mode/nlink/size/mtime/ctime 或缺席，
有文件时先持有原 inode；读取后重核名称、held FD、摘要和父目录身份。未知新 owner
不继承原预像，原缺席状态出现文件必须 HOLD；所有拒绝均保留原/替换对象，不启动
服务。三项新负例及五项原有 parent 门禁/未提交恢复/真实 SETUP→parent commit
正负例合计 8 tests / OK / exit0（6.693 秒）。日志
`r22-q-parent-freeze-owner-green.log`，inode 144901979，size 1414，SHA256
`b8c00e202472ea9ff27c2e5cbc22ca1f9483af169b54f336e10066ad5ee2b980`；上述日志读前后
stat 稳定，完整物理收尾及实际 exec 退出码一致。manifest 的 LOAD direct 和真实
generation-input-binding workflow 映射继续有效。两个完整 LOAD transaction 与
generation-input-binding workflow 模块诊断为 345 tests / OK / exit0（202.339 秒），
日志 `outputs/test-diagnostics/r22-q-parent-freeze-owner-modules.log`，inode 144908631，
size 113310，SHA256 `606a0b901b113a587cf79cc731e650e314861a1c7bc1ca88dc59a819cee91ef5`。
读前后 stat 一致，旧 98558 字节前缀 SHA256
`f7b549eca914b3667dea721e0bb02240809e3c99ba3a7e6332916855f9e5f4f2` 未变。
物理 Ran/OK 后有缓冲的测试夹具 stdout，最终退出标记与实际 exec exit0 一致；
不是批准 runner，未更新 ledger。局部诊断不替代 related/full，
原 bootstrap 15 秒和 REQ19 probe 10 秒未知原因门禁不变，未手改 approved ledger。
父 B 成功收口、完整共享写集、显式旧 A 健康激活、Linux/断电和 DEV ACK 仍未闭。

### R22 infra/logs 源名称写前与备份恢复身份候选

副本预检仍不能授权之后的源名称操作。原恢复在删除 Q 指针之后、backup rename
之前未再次检查备份；未知替换备份被移入 P 后才在下一项 copy 检查时报错。
两个 source pointer direct（同目标文字新 inode、外来目标）证明后插入的指针仍被误删；
一个 direct 与真实 LOAD→SETUP infra 指针发布后死亡→新 LOAD 在 unlink/父目录同步
屏障替换备份的 workflow，证明外来目录已搬入 P。四项原实现全部 FAIL / exit1
（3.590 秒），原日志 `outputs/test-diagnostics/r22-infra-source-backup-owner-red.log`，
inode 144719182，size 5490，SHA256
`984851911d260b25f957da312c81710893772f41bd72b8c4377fb3a3d9255ec3`；
读前后 stat 一致，物理退出标记与实际 exec exit1 一致。原失败断言保留。

候选从已经验证的 source stat 冻结完整身份及链接原始文字（或缺席），在 source
unlink 与 backup rename 之前分别重核 source、已登记备份、Q 根及其物理父目录。
自己的 unlink 只将预期更新为缺席；自己的 rename 后仅接受已登记原目录身份，
再绑定实际恢复后的完整名称身份。未知指针零恢复写入保留；unlink 后才发生的
备份漂移保留未知备份、封存原目录、Q 副本、原 WAL 与 receipt，P 源保持缺席，
明确 HOLD 而非先将未知目录写入 P 再报错，不启动服务。

四项新增负例与嵌套 duplicate hardlink、原 direct/真实目录恢复正例 7 tests / OK /
exit0（10.566 秒）；日志 `outputs/test-diagnostics/r22-infra-source-backup-owner-green.log`，
inode 144721385，size 1382，SHA256
`4cdc43bd89b371039d41ea939ea1d6f15fa36ef5baab41a8e8f376c3a986d8aa`。
另补实际恢复 API 的 unlink 后父同步失败→重入正例 1 test / OK / exit0；日志
`outputs/test-diagnostics/r22-infra-source-unlink-reentry-green.log`，inode 144726392，
size 300，SHA256 `ff8ee1f61cee2b987231c2e3a876fcd7471bcf5123f0cab8750e76b9788a4225`。
两份日志读前后精确 stat 一致且完整收尾与 exec exit0 一致。
随后六个完整模块的诊断回归为 416 tests / 1 ERROR / exit1（291.583 秒），不是
正式 related/full。原日志 `outputs/test-diagnostics/r22-infra-source-backup-owner-modules.log`，
inode 144728681，size 125966，SHA256
`bca4a5949c7e1f4f87ae9889fb955edc8c498f23bad07392745df79372bc282b`；
读前后 stat 稳定，旧 98270 字节前缀 SHA256
`898f7d760e65665cb2a39c4931923bd46075f6a76d54469cc42e6b2ca348226f` 未变。
物理 Ran/FAILED 后有缓冲 stdout，最终退出标记与实际 exec exit1 一致。
唯一 ERROR 是 REQ19 orphan receipt collector 的真实 `bash -s` 达到原 10 秒时限。
静态核验该 fixture 应在 probe 开头检查 `.logs-migration.*`，由 Bash 内建命令报错退出，
尚不进入外部命令、服务或网络分支；不调用本次修改的 LOAD 恢复函数。但原报告没有
部分 stdout/stderr 或后代状态，临时目录已清理，不能由此确定启动、目录检查、退出
回收或前序影响中的哪项造成超时；原因仍待核，不能笼统归为环境。

保持 REQ19 contract→workflow 两模块前序、原输入/argv/10 秒与原断言，只在调用边界
记录有界现场的小范围诊断为 52 tests / OK / exit0（5.774 秒）。日志
`r22-req19-original-prefix-timeout-diagnostic.log`，inode 144881178，size 11496，SHA256
`9e8f7e9e6d83ebc3cfaea2cbe104c713db80498a482f09a066ce4750c7da3826`。
本次目标 probe 用 `/bin/bash`，没有 BASH_ENV/ENV 或导出函数，0.305 秒返回原拒绝
exit1，原临时 receipt 前后身份未变；这些仅说明本次条件，不能证明失败时条件相同。
未重跑六模块或正式 full。

为避免下次再次丢失现场，REQ19 私有 probe 的 TimeoutExpired 现在保留原 cmd、
timeout、output/stderr 属性及 cause，报告最多各 2048 bytes/characters 的输出尾部；
阶段及未捕获的后代状态仍明确 unknown，不把观察不足包装成原因。两个独立诊断
预期原先 2 FAIL / exit1，日志 `r22-req19-timeout-evidence-red.log`，inode 144884482，
size 1663，SHA256 `d8578ae5a468c6bcd5ef5a008f34d2c2287c8b1caeb5d2d65d5dd78b6b07f99b`；
增强后 2 OK / exit0，日志 `r22-req19-timeout-evidence-green.log`，inode 144884635，
size 417，SHA256 `b6f710dbcd255626efebf6b3bdfe30c334c489def8b4b1644eb051541162341a`。
对增强本身的 REQ19 两完整模块回归 54 OK / exit0（6.698 秒），日志
`r22-req19-timeout-evidence-modules.log`，inode 144884795，size 8117，SHA256
`44ab9689070c2002cfc37f444dff47ab859e184ce52cff7eb29444c8ce1d294e`。
上述日志均读前后 stat 稳定、完整物理收尾与 exec exit 一致；增强不是超时原因修复，
不更改原时限、拒绝断言、approved ledger，也不关闭原 416 项诊断失败或正式重跑闸门。
本候选不宣称原子 compare-and-unlink/rename、任意非合作写者免疫、完整共享写集、
父 B 成功收口、完整旧 A 激活或 Linux/断电。正式 related/full 的原 bootstrap
原因未收口门禁不变；局部 PASS 不授权盲目重跑或手改批准 ledger。

### R22 infra/logs Q 副本清理所有权候选

receipt 身份固定后，原 recovery 仍在一次 preflight 后按名字删除 Q 日志副本。
两个 direct（首写前、原目录 rename 恢复后）与真实 LOAD→SETUP infra 指针发布后
死亡→新 LOAD preflight 后替换同内容新 inode 的 Q 副本均 FAIL / exit1。
原日志 `outputs/test-diagnostics/r22-infra-copy-owner-red.log`，inode 144534044，
size 3009，SHA256 `1605d8fc16adaf13963b4ec2fa6fd31b93e6d7493f5f92c3640f9b640eab4b1b`，
3 tests / 3 FAIL（4.900 秒），物理退出标记与实际 exec exit1 一致。

候选冻结已经验证的 P 原目录与 Q 根身份、嵌套目录身份、原文件和 Q hardlink 的
dev/ino/mode/size/mtime 与独立 receipt 摘要；首写前、每次清理前和 receipt 退休前重核。
预检期间 root 换绑不得被后读的同名新 root 自动收编，两项独立负例先 FAIL 后修正。
自己的清理仅将相应 Q 名称/目录的预期改为缺席，不删除后来的重现对象。
漂移发生在源恢复后时保留已还原源、未清理副本、receipt 和 WAL，不报完成、不启动服务。

reader 另有读取期 ABA 和打开 FIFO 前未拒绝的独立 RED；原断言及 15 秒 bootstrap
时限均未改动。reader 现在先 lstat regular、非阻塞/no-follow 打开，在同次读取中比较
打开前/FD/名称的 nlink/ctime。存活 P 文件的 nlink/ctime 会因清理自有 Q hardlink 变化，
不能把它们作为跨清理阶段不变值；独立嵌套重复 hardlink 正例覆盖此区别。
不以此声称任意非合作同 UID 写者免疫、全恢复窗口 ABA 冻结或原子 compare-and-unlink。

新增八项与两个原有真实目录恢复正例 10 tests / OK / exit0（7.526 秒），日志
`outputs/test-diagnostics/r22-infra-copy-owner-root-reader-green.log`，inode 144556123，
size 1769，SHA256 `1e17a1570e3f41465451004fb20bb6598597a77cd5cfbe1126252fb7314ab095`。
前后精确 stat 一致，物理完整 Ran/OK 和退出标记与 exec exit0 一致。
既有 LOAD direct 与真实多脚本 workflow manifest 映射有效；正式 related/full
仍被 bootstrap 401 原因未收口门禁阻断，不能从这些局部诊断生成批准 ledger。

四个完整 release/generation workflow/optimize/setup plan 模块 359 tests / OK / exit0
（271.827 秒）；日志 `outputs/test-diagnostics/r22-infra-copy-owner-modules.log`，
inode 144567879，size 115863，SHA256
`40f7487b8d5381bc683e6017ce7e2098acc8370ec82d568a9a404ab5535506ef`。
读前后精确 stat 一致；旧 98601 字节前缀 SHA256
`fd8773bf5567a418db668c16b0eb944c8f7a01b29b2d063fa19fea35dbf6fd62` 未变，
完整 Ran/OK 位于物理 `R22_INFRA_COPY_OWNER_MODULES_EXIT=0` 之前，exec exit0 一致。
另补查 REQ19 完整 direct/workflow 两模块 52 tests / OK / exit0（9.581 秒）；
日志 `outputs/test-diagnostics/r22-infra-copy-owner-req19-modules.log`，inode 144706959，
size 7839，SHA256 `1832cdefdacbb774066ca6fdfbc666d9352921c52c9bc6110acbc76c5509f218`，
读前后 stat 一致且物理退出标记与 exec exit0 一致。批准 ledger 与运行 manifest
保持原身份和摘要；两组均为诊断回归，不是正式 related/full proof 或整树批准。

### R22 infra migration receipt 的恢复期删除权候选

原 preflight 校验 receipt 后只返回 has_receipt，恢复函数在收尾按路径 unlink。
独立 direct 注入同字节新 inode、同 inode/尺寸/mtime 保持但 ctime 改变的 ABA，
以及原日志目录 rename 恢复后替换 receipt；真实复制 LOAD→SETUP 在 infra 指针发布后
强杀→新 LOAD preflight 后替换 receipt，四项原实现均 FAIL / exit1。
首轮 workflow 的注入器错误地观察 replace，而该实体迁移实际使用 symlink；原日志
`r22-infra-receipt-owner-red.log` 保留，不把夹具失败算作 workflow 缺陷见证。
修正死亡观察点而未改生产代码或预期后的 `r22-infra-receipt-owner-red2.log`，
inode 144386606，size 3812，SHA256
`eec93871d440929d3314bb77a82beeabfd0e3b53a639df66096765143c2383f6`，
4 tests / 4 FAIL / exit1（3.845 秒），物理退出标记与 exec exit1 一致。

候选保留 receipt 原物理父目录、完整元数据身份及 reader 的字节/模式快照，
在 preflight 后核、首写及每次 source/Q/receipt 名称变动之前重核；原缺席状态也须
仍然缺席。首写前漂移零恢复写入，中途漂移保留已恢复源、Q 副本、替换凭据和 WAL，
不启动服务。四项新增测试 GREEN / exit0（6.118 秒），日志
`outputs/test-diagnostics/r22-infra-receipt-owner-green.log`，inode 144393520，size 814，
SHA256 `995d85171f864e1ec2da3cac80d2ea08ebfabbf8f51e4224a81ed658689b6f00`。
这些身份/字节检查不是原子 compare-and-unlink 或任意非合作同 UID 写者免疫。
正式 related/full 仍被原 bootstrap 401 超时原因未收口门禁阻断；不能因局部 GREEN
重跑正式 full、改 ledger 或声称完整 R22。现有 direct/workflow manifest 映射保留。

四个完整 release/generation workflow/optimize/setup plan 模块 351 tests / OK / exit0
（225.599 秒）；日志 `outputs/test-diagnostics/r22-infra-receipt-owner-modules.log`，
inode 144398633，size 114677，SHA256
`0e0bdc782714bd586f55ff65b57e09701148d7f76c82bf9be4d2459e1b0adbde`。
读前后 dev/ino/size/mtime_ns/ctime_ns 一致；旧 96513 字节前缀 SHA256
`7db8a6a06b65ca8f443cf8fcd2ea85f4896e91a2329479984eaecd235a0f24bf` 未变。
物理 Ran/OK 在 `R22_INFRA_RECEIPT_OWNER_MODULES_EXIT=0` 之前，exec exit0 一致。
批准 ledger 与 TEST 运行 manifest 原身份及摘要未变；此结果仅模块诊断，不是批准证明。

### R22 P manifest 模式持久化与 Q alias 恢复重入候选

原 `_atomic_restore_setup_manifest` 在文件 fsync 后才 chmod，最终模式不在文件同步边界内。
两个独立 direct 和真实 LOAD→SETUP Q manifest 发布后死亡→新 LOAD 恢复 workflow
保留字节/权限/同步次序预期，修复前完整 3 FAIL / exit1，原日志
`outputs/test-diagnostics/r22-p-manifest-mode-sync-red2.log`，inode 144231980，size 5167，
SHA256 `fc810f55b5e994d345c64056daedec08f64de564e0a654a1aff2a054316d8c98`。
第一次 RED 的观察器暂存前缀漏了 manifest 本名已有的点，错误日志原样保留；先修
观察器定位，再于未修生产实现时重新取得以上 RED，不借夹具问题改权限预期。

仅修最终模式次序后，两个 direct OK，但真实 workflow 的第三进程重入 FAIL：
`r22-p-manifest-mode-sync-green.log`（inode 144234110，size 2762，SHA256
`653a74fc36cb3c7ad35703876c4a8d9b13281c54166dbe460004622fad92fd80`）。
真实 Q 临时 `.eth.csv.tmp.*` 的 raw target 为另一条共享 `eth.csv`；失败恢复已经把该
共享链接改回 P，重入按当前磁盘解析 Q target 被误拒绝。不是 bootstrap 超时或环境问题。
补独立 positive 和 cyclic alias negative，原 resolver 为 1 ERROR / 1 FAIL / exit1，日志
`r22-p-manifest-q-alias-red.log`，inode 144239960，size 3313，SHA256
`43a4b983084cc6ba30926ebdf96f0e362333fef29956f4eabbfae02e12b760ad`。

候选只在冷恢复预检中沿 WAL 精确登记的 Q alias 行解析最终目标；末端仍须原严格 Q
权限检查，循环/外部目标拒绝，所有实际行的父身份、磁盘 P/Q 状态、锁/停服和 Q 父前像
检查仍先于写入。manifest 在持有 FD 上 fchmod→flush/fsync→replace→parent fsync；
文件同步故障保留 Q manifest 与原 WAL，再由全新进程完成 P 收口。五个原 RED 预期
完整 OK / exit0，日志 `r22-p-manifest-mode-alias-green.log`，inode 144241580，size 940，
SHA256 `6e1923deeece654e4b65929b3634d0bd9cb6d9e28cb117b891863dd14c43b38c`。
另补未登记 foreign target 的零恢复写入负例。上述都是本地候选/诊断，不更新 approved
ledger，不解除原 bootstrap 401 超时原因待核导致的正式 related/full 重跑闸门。
完整共享写集、父 B 成功收口、旧 A 显式激活、Linux/断电见证仍 OPEN。

同一候选按 `test_load_release_transaction` → `test_generation_input_binding_workflow` →
`test_optimize_output_layout` → `test_setup_switch_plan_contract` 完整诊断回归，347 tests /
226.059 秒 / OK / exit0，日志 `outputs/test-diagnostics/r22-p-manifest-mode-alias-modules.log`，
inode 144243886，size 114001，SHA256
`5fe9f2915591dcb9c992c177bd866fd792669b66c0232342ea1893620887e936`。
前后 stat 一致，旧 101037 字节前缀 SHA256
`81fbacb1534e4fe8a638f1413b7401a9a106b4f1be1cc5be283ef20a44e52f20` 未变；完整
Ran/OK 在物理 `R22_P_MANIFEST_MODE_ALIAS_MODULES_EXIT=0` 之前，exec exit0 一致。
包括 foreign target 负例；全部原断言保留。approved ledger 和 TEST 运行 manifest 的
原 inode/摘要未变，原 related 3154 tests 失败日志完整摘要再次一致。这不是 runner
related/full，不产生正式批准；当前精确树仍需先收口原 bootstrap 超时原因再放行正式测试。

### R22 SETUP 回滚与次级清理的本地候选记录

SETUP 的进程内异常回滚原来按内存 `missing` 前像删除后来出现的同名链接，并在完整
WAL 预检前单独恢复 infra/logs。独立 direct 与真实 LOAD→SETUP 异常 workflow 已重现；
候选改为使用同一停服、持锁的磁盘恢复 API，未知状态在任何 P 恢复写入前 HOLD。
首轮完整模块 263 tests / 1 FAIL（日志 `r22-setup-rollback-wal-modules.log`，SHA256
`cd7c9d118a4f54738df949ca4c883e08f85bfb029aa8a0bffdb54e02704e46f6`）
证明自动恢复错误地移除了拒绝未授权 Q 写入后原合同要求保留的 WAL；保留该断言，修为
自动异常恢复即使已还原 P 也保留逐字节失败 WAL，另行显式恢复才能收口。不是以单项
PASS 直接重跑正式 full。

夹具另有两个独立隔离缺陷：SETUP manifest 未绑定私有根，以及 `addCleanup` 在
`tearDown` 后重新把 LOAD 的 ZTP 根绑定到已删除临时目录。各自新增独立预期并 RED→GREEN；
私有路径明确绑定，ZTP 生命周期只由已有 setUp/tearDown 管理。测试期间 TEST 运行目录
`ztp/.setup_manifest` 保持此次观察到的 inode、mtime 与摘要不变；未对缺失事前快照的
更早修改猜测还原，也不将该隔离缺陷推定为原 bootstrap 超时原因。

旧公钥、旧 NVOS、失效 latest/latest_yaml 与冲突清理的四个 unlink 边界也被 direct
重现为可删除未登记对象；真实 LOAD→SETUP 公钥清理的晚插入负例同样 RED→GREEN。
候选要求精确冻结 P 行、raw target、父目录身份与删除后父目录 fsync，补了合法 P 正例
及父目录换绑负例；尚无适用前像的 Q 自有路径保持 HOLD，不宣称完整写集已经实现。

上述候选及原始模块测试最终完整 270 tests / OK / exit 0：
`outputs/test-diagnostics/r22-setup-rollback-secondary-modules.log`，inode 142698827，
size 97739，SHA256
`0ed83941d7d6f986a4a39a28fad91674064e4f409ab7ae7748e3642c5f6fa7aa`。
读前后 stat 一致，已知旧前缀保持，物理末尾 `R22_ROLLBACK_SECONDARY_MODULES_EXIT=0`。
这是局部模块候选证据，**不是 related 批准、full proof 或整体 R22 验收**；批准 ledger
不手工更新，原 bootstrap 原因待核及 R22 的现场/其它本地未闭边界保持原状态。

随后两个 direct 及真实 LOAD→SETUP 的下一次写入屏障重现了 generic/sample unlink
之后缺少父目录 fsync 的缺陷（`r22-cleanup-unlink-durability-red.log`，3 FAIL / exit 1，
SHA256 `3f1d5aeb226a7478f29e4a4cdbc2e47e847490cdfbd65d4de22bdd76a915805e`）。
候选在实际删除边界使用同一冻结 P 检查和父目录同步，增加同步报错停止后续删除的预期；
真实 workflow 在删除同步完成后强杀，再用新 LOAD 按 WAL 恢复 P。四项定向 GREEN 后，
扩至 release transaction、真实 input binding workflow、sample 布局和 setup 写集盘点
四个完整模块，296 tests / OK / exit 0：
`outputs/test-diagnostics/r22-cleanup-unlink-durability-modules.log`，inode 142790184，
size 102891，SHA256
`49e2506a166495a4c0ff71e9e760debbc853d68c8da961c37b5fadf701b88450`。
读前后 stat 一致、已知旧前缀保持且物理末尾 `R22_UNLINK_DURABILITY_MODULES_EXIT=0`；
仍只是本地候选回归，不更新 related/full ledger，不替代断电见证或整体 R22 验收。

### R22 冷恢复 WAL authority 换绑的本地候选记录

独立 direct 重现读后同字节新 inode、同 inode/尺寸/mtime 改写仍可继续恢复，以及 P
后核验后被替换的 WAL 会被旧收尾删除；真实 LOAD→SETUP 强杀→新 LOAD 的后核验
注入同样失败。四项 RED / exit 1 的原日志
`outputs/test-diagnostics/r22-wal-retirement-owner-red.log`，inode 142900081，size 3234，
SHA256 `ca7f35551d8dea1bb6c2968af85acfa65edd7e755f300568e9af2cec03163dde`。
候选保持原 WAL inode 的 descriptor，恢复阶段及收尾前核对原文件/父目录身份和完整字节；
漂移 HOLD 并保留证据，不以文件名相同或 P 已恢复推定删除权。原时限和断言未放宽，
不将这项修复认作 bootstrap 原超时的原因或修复。

包含原有保留 WAL 重入和 Q manifest 恢复正例的定向 6 tests / OK / exit 0 后，四个
完整模块 release transaction、真实 input binding workflow、sample 布局和 setup 写集盘点
共 300 tests / OK / exit 0（180.282 秒）：
`outputs/test-diagnostics/r22-wal-retirement-owner-modules.log`，inode 142904246，size 103513，
SHA256 `7454d6432b32ece04f30336fd7d99121dd8cf96b02bd65151c809dda5e06e571`。
读前后 stat 一致、逐次旧前缀保持，物理末尾 `R22_WAL_OWNER_MODULES_EXIT=0` 与 exec exit 0
一致；TEST 运行目录 manifest 保持此前观察到的身份/字节，不触碰或猜测还原。
现有 manifest 的 LOAD direct 与 LOAD/SETUP 多脚本 workflow 映射已核，不新增脚本或跳过。

这仍是本地候选模块回归，不是 related 批准、full proof 或完整 R22 验收；ledger 未手改，
原 bootstrap 超时仍待核，未以这次 PASS 直接重跑 related/full。现场及不合作写者风险、
comparison 实体迁移、Q 自有前像、父 B 收口、main 显式恢复和旧 A 激活等仍需独立收口。

### R22 Q-local latest 前像的本地候选记录

独立 direct 与真实 LOAD→SETUP workflow 重现已有 Q latest 被错误当成缺席 Q-only 名称，
导致切换拒绝：原始 4 tests / 2 FAIL / 3 ERROR / exit 1（含 workflow 两个子场景），日志
`outputs/test-diagnostics/r22-q-local-latest-red.log`，inode 143019842，size 25987，SHA256
`62aa858fefadb865ec51f794298b657edf05fb86481778d0c11a1d7ed75c0083`。
候选为 ETH/NVOS 旧/新真实完成目录与 latest 原文字单独冻结前像，使用 Q 物理父目录
写入和恢复；不修改 P manifest 合同或自动接纳未知名称。
候选审阅又以独立负例重现 Q-local 提前返回绕过未知共享行、外部完成目录软链接被接纳，
并以 direct 重现 exact pointer replace 后未同步父目录；三个 RED 原日志分别为
`r22-q-local-writer-preflight-red.log`（SHA256
`f81c04d4c0f889da7477fcfd32d7e886d4d7c9fe8bb94809df478018d1ffe6da`）、
`r22-q-local-release-symlink-red.log`（SHA256
`54cb424d265900a58082fc60d20a7f725d70d7c4c86e5cea35c44196517c9d12`）和
`r22-q-local-pointer-sync-red.log`（SHA256
`809d03ef4f4460ba20a93a5b1770ab56cc6829ae547b297172a1d6ecdb893259`）。
修复保留原预期和时限，未知状态拒绝；指针成功替换后同步其父目录。

新增 8 项 direct/真实 workflow 完整 OK / exit 0 后，四个完整模块共
308 tests / OK / exit 0（210.512 秒）。日志
`outputs/test-diagnostics/r22-q-local-latest-modules.log`，inode 143057950，size 104962，SHA256
`792c9ff52fdce441a1c66a4e487167722bf68c04eae989e8137f4e912756a862`。
读前后身份稳定，已核旧 90543 字节前缀 SHA256
`3dc3dc8bd20d58a4e75479352ff2a26ceae2f432b636914010abf590f94d1b3b`，
完整物理末尾 `R22_Q_LOCAL_LATEST_MODULES_EXIT=0` 与 exec exit 0 一致。
TEST 运行目录 manifest 的已观察身份/字节未变。既有 LOAD/SETUP direct 与真实 workflow
manifest 映射沿用；REAL_ENV 补充三处死亡边界和独立现场核验，仍 OPEN。

这不是 related 批准、full proof 或完整 R22 验收；未手改 ledger，原 bootstrap 超时原因
仍待核，未凭模块 PASS 直接重跑 related/full。其它完整写集、父 B 收口、main 显式恢复、
完整旧 A 安全激活和 Linux/断电见证继续独立收口。

### R22 Q 父提交之后误恢复 P 的本地候选记录

原 WAL 未冻结 Q 的父提交前像：Q 已出现父文件、同字节替换既有父文件或缺少前像的旧
WAL 都仍可恢复 P。独立 direct 与真实 SETUP→LOAD 父提交/冷恢复边界共 5 tests，
4 FAIL / exit 1；日志 `outputs/test-diagnostics/r22-q-parent-preimage-red.log`，
inode 143180217，size 3536，SHA256
`44688ad03ca3b386b28efa7fcbcc9cb07baa1f89b5aa01cc17e59a62852bf432`。
候选在 WAL 写前冻结 Q 父文件缺席或完整身份/摘要，恢复全过程重新核对；变化 HOLD，
不删除提交文件或原凭据，不事后升级无前像的旧 WAL。既有且未变的 Q 历史父文件正例保留。

补充同 inode/mtime 复原和 P 后核验才出现 Q 提交的负例，真实 workflow 增强为 SETUP
完整提交 Q manifest 后调用真实 parent replace，再由新 LOAD 拒绝恢复。共 7 tests / OK /
exit 0，日志 `outputs/test-diagnostics/r22-q-parent-preimage-complete-green.log`，
inode 143188699，size 1152，SHA256
`206af5aca02fba153995484544e89dd8be83b5e8757882090072c1473adf1c7e`。
父候选字节是独立合成夹具；这不等于完整 B 发布、五 DHCP/YAML 制品或服务健康验收。
原断言和时限未放宽。

四个完整模块共 315 tests / OK / exit 0（227.553 秒），日志
`outputs/test-diagnostics/r22-q-parent-preimage-modules.log`，inode 143191157，size 105980，
SHA256 `ad9db3f930fec5b64294fb1204114d533eb5a61a0fa453f231537ea5c73f8ce2`。
读前后身份稳定，旧 93189 字节前缀 SHA256
`af3da1b8f31b1a0bd176aa9174e9d590f6418d907a635ad3fc8a7ce6581a063e` 保持，
物理末尾 `R22_Q_PARENT_MODULES_EXIT=0` 与 exec exit 0 一致。沿用 LOAD direct 与
真实 LOAD/SETUP workflow 映射，REAL_ENV 增加提交后边界与现场恢复风险，仍 OPEN。
本候选未修原 bootstrap 超时原因，未以局部 PASS 重跑 related/full 或编辑 approved ledger；
成功 B 的备份/receipt 收口、完整写集、main 显式恢复及旧 A 安全激活继续独立实现。

### R22 Systemd 未知状态误授权 P 恢复的本地候选记录

LOAD 原来独立调用 `systemctl is-active --quiet`，缺少命令直接返回空服务列表，任何
非零返回也均被当作停止；其绕过了服务后端既有的明确 active/inactive/unknown 合同。
独立 direct 与真实 LOAD→SETUP 强杀→新 LOAD 冷恢复证实错误/命令缺失仍可恢复 P。
首次 direct 夹具遗漏 Linux 平台身份导致 Darwin role 错误，原日志
`outputs/test-diagnostics/r22-service-unknown-red.log` 保留（SHA256
`3555b83c858cc23efc933ffded8bea72ad726f5a6709194c7f74df6f57de2bc6`）；
修正夹具平台身份、不修改实现/预期后，5 tests / 8 FAIL（含 subtest）/ exit 1，日志
`outputs/test-diagnostics/r22-service-unknown-red-linux-fixture.log`，inode 143326043，
size 5956，SHA256 `c76e6065189837149f7e95aaf4d0e8ade98bac174ed9401a1b38d5f259246869`。

候选复用 `ServiceRuntimeBackend.is_active` 严格合同，将查询 OSError 转为 LoadError，
未知状态在恢复首写前拒绝；既有 Systemd active/inactive 与 Supervisor 服务集合不变。
5 tests / OK / exit 0，日志 `outputs/test-diagnostics/r22-service-unknown-green.log`，
inode 143332957，size 874，SHA256
`b2379c018ae60cae3690be5cf6f5cbd6de949260deae37dd931bcdb6b48d60d8`。
真实 workflow 只用私有复制的 LOAD/SETUP 和注入查询边界，不调用实际 systemctl 或服务。

release、generation workflow、optimize、setup plan、service runtime 和 SSH preparation
六个完整模块 383 tests / OK / exit 0（240.335 秒），日志
`outputs/test-diagnostics/r22-service-unknown-modules.log`，inode 143337208，size 117206，
SHA256 `ab9fac30fc9ac6828794369fe2bf519053639a0cfbe1009e305429e28c7bf431`。
读前后 stat/inode 稳定，旧 91184 字节前缀 SHA256
`a2c3dd123dbabdf8339a41d7cd28d87790eceec4478d46970ec4009fbdb80ff6` 不变；物理
`R22_SERVICE_UNKNOWN_MODULES_EXIT=0` 与 exec exit0 一致。TEST 运行 manifest 身份/摘要
保持此次事前观察不变。沿用 LOAD direct 和真实多脚本 workflow 映射，REAL_ENV 仍 OPEN。
此窄修不是原 bootstrap 401 超时原因的解释；不凭局部 PASS 重跑 related/full 或改批准
ledger。完整写集、B 成功收尾、main 显式恢复、完整旧 A 激活及 Linux/断电见证仍未关闭。

### R22 旧 A runtime 恢复之前提前退休 WAL 的本地候选记录

独立合同要求完整跨项目恢复未完成时保留持久授权，不能将 P 链接恢复视为 A runtime
恢复完成。原实现先消费 WAL，再调用 runtime receipt API；失败或死亡会丢失凭据。
旧 direct/workflow 中“runtime 之前 WAL 已不存在”的预期与该合同相冲突，本次改为更严的
“原 WAL 字节仍在，完整后核验成功才退休”，保留原 P manifest、全部链接、目录清理和
不启动服务的断言；没有放宽任何时限或删除负例。

原实现 4 tests / 4 FAIL / exit1，日志
`outputs/test-diagnostics/r22-runtime-wal-retention-red.log`，inode 143473797，size 4727，
SHA256 `847778e3d7111a8bed92224566ffa48e57cfee1ddaa4a110735f7a303b2ec91d`。
候选保持原 WAL descriptor 和完整身份验证跨过 runtime 回调，返回后重核锁/停服，
以只读恢复验证重核完整 P/Q 和 Q 父前像，最后才能删除凭据。异常/死亡保留原字节；
同字节换 inode 和 runtime 后未知 P 对象拒绝且不清理未知对象。

direct 加入真实 receipt 加载器缺失负例；真实复制 LOAD→SETUP 强杀→新 LOAD 在 runtime
边界再次强杀，再由第二个新 LOAD 重入成功。此 workflow 成功 runtime 是见证替身，
不能称完整 A receipt/五 DHCP/YAML/运行计划恢复或健康激活通过。定向 6 tests / OK /
exit0，日志 `outputs/test-diagnostics/r22-runtime-wal-retention-complete-green.log`，
inode 143482436，size 1053，SHA256
`bb32e5212029adffd88a2535d3bd80cec2eb9ed5c261041c827dbcfc0cb9d49d`。

release、generation workflow、optimize、setup plan 四个完整模块 324 tests / OK /
exit0（236.500 秒），日志 `outputs/test-diagnostics/r22-runtime-wal-retention-modules.log`，
inode 143484649，size 107257，SHA256
`538f7f73c6cc4729b4f68714dcf2517f06d284e71d80ce322587011a9af16756`。
最终全日志读前后 stat/inode 一致，物理 `R22_RUNTIME_WAL_MODULES_EXIT=0` 与 exec exit0
一致，TEST 运行 manifest 身份/摘要未变。沿用 LOAD direct 与真实多脚本 workflow 映射。
此窄修不解释既有 bootstrap 401 超时根因；没有凭局部 PASS 重跑 related/full，也没有
编辑 approved ledger。完整 A 激活、其余共享写集、成功 B 收尾和 REAL_ENV 仍未关闭。

### R22 恢复授权读取期间同 inode ABA 的本地候选记录

`_read_rollback_regular` 原身份元组缺 ctime：读取期间同 inode 改写再恢复 A 字节、大小和
mtime，最终摘要虽正确，仍可能接受跨换代读取为稳定授权。独立 direct 使用实际 A receipt
加载/恢复 API；真实复制 LOAD→SETUP 强杀→新 LOAD workflow 检查 manifest 读取期间
ABA 在首个 P 恢复写入前拒绝，保持原凭据和混合盘面，不以实现产物反向生成预期。

首次 workflow 夹具尝试完整 SETUP 时先遇其未配齐输出前提，不能算 ABA 重现；保留
`outputs/test-diagnostics/r22-authority-read-aba-red.log`（SHA256
`7e3b206dfe70e4bdaaaae8bbcfff1177ae15e16c26ac251e052b8094063adbfc`）。
在不改实现/预期的情况下改用既有真实首链写入强杀夹具，direct/workflow 均因原实现接受
ABA 而 FAIL：2 tests / 2 FAIL / exit1，日志
`outputs/test-diagnostics/r22-authority-read-aba-red-crash-fixture.log`，inode 143618306，
size 2186，SHA256 `66e35a22dcb1e0e1b614c1a35f4842453bc71d940be786de942a52aaf0a1d175`。

候选只将 ctime 加入打开前、FD 和读取后名称的身份比较；原大小/链接数限制、O_NOFOLLOW、
模式和字节核验保留，拒绝在写前发生。新增负例及既有稳定恢复正例 4 tests / OK / exit0，
日志 `outputs/test-diagnostics/r22-authority-read-aba-green.log`，inode 143620269，size 1431，
SHA256 `eb26d7bb5bd10c547ba9e1708c834441023b2caa849b58642bd9aad169983668`。

四个完整 release/generation workflow/optimize/setup plan 模块 326 tests / OK / exit0
（215.760 秒），日志 `outputs/test-diagnostics/r22-authority-read-aba-modules.log`，
inode 143624335，size 107801，SHA256
`861fc3737e3832af65a64a903d5dc9351fc167e036ee3522ae5fc3d5bd0cadb4`；读前后精确 stat
一致，旧 97206 字节前缀 SHA256
`93aeb1f09b16ae840f7d5f9a47ad009922ad063cdfa6c7bca61872d903714f2d` 保持不变，物理
`R22_AUTHORITY_READ_ABA_MODULES_EXIT=0` 与 exec exit0 一致。TEST 运行 manifest 和
approved ledger 摘要未变，沿用 LOAD direct 与真实多脚本 workflow 映射，REAL_ENV 仍 OPEN。
此读取窗口窄修不解释 bootstrap 401 超时、不构成完整旧 A 激活或任意非合作写者免疫；
没有据定向 PASS 重跑 related/full 或编辑 ledger，正式证明仍未取得。

### R22 runtime 恢复文件的父目录持久化候选

原 `_restore_receipt_file` 在文件 fsync 后才 chmod，replace/unlink 后未同步父目录；
跨项目恢复可能在 runtime 名称尚未持久化时退休 WAL。独立 direct 与真实复制
LOAD→SETUP 强杀→新 LOAD workflow 原实现 3 tests / 4 FAIL / exit1，日志
`outputs/test-diagnostics/r22-runtime-parent-sync-red.log`，inode 143763027，size 3351，
SHA256 `dc497f76a7c7550a26a15a54ff6cbad622534ff45dafbf8abacea8a2a7f65921`。
另以独立 0640 模式（不同于 mkstemp 的 0600）验证模式同步次序，原实现 FAIL，日志
`r22-runtime-parent-sync-mode-red.log`，SHA256
`5a3fe5a08353d2c006c8d54422c73f3e186f0b913f9602438018249cf6383b3d`。

候选在持有写 FD 时设最终模式，flush/fsync 后 replace 并同步父目录；missing 前像
无论刚删除还是已缺席的重入，均须目录同步。同步错误继续抛出；真实跨脚本恢复保留
原 WAL，新 LOAD 成功同步后才能收尾。首轮新增三项 GREEN，日志
`r22-runtime-parent-sync-green.log`，inode 143765407，size 661，SHA256
`f470f9f8bd2b35b6713cb4a630979597d16459ea34aed15bf75e49288364e297`。
此 workflow 实际调用 runtime writer，但 receipt 层使用独立边界替身，不证明完整 A
制品恢复/健康激活。没有因定向 PASS 重跑正式 related/full；bootstrap 401 原因门禁仍 OPEN，
approved ledger 不手改，整树 proof 尚未取得。

补充缺席重入正例后，四个完整 release/generation workflow/optimize/setup plan 模块
329 tests / OK / exit0（216.257 秒）。日志
`outputs/test-diagnostics/r22-runtime-parent-sync-modules.log`，inode 143768698，size 108327，
SHA256 `8ae545c81dcce7d9a76b1200b946db738ce797e58a838b445ed6d96c895caa96`；
读前后精确 stat 一致，已知 88736 字节前缀 SHA256
`85e226e11b00e206d1b540ca829a353be25c8242b85715edc86d150261b18121` 未变，完整 Ran/OK
在物理退出标记 `R22_RUNTIME_PARENT_SYNC_MODULES_EXIT=0` 之前，exec exit0 一致。
LOAD 原 direct/workflow 映射有效；TEST 运行 manifest 与 approved ledger 摘要未变。
以上仅独立模块回归，未进入正式 related/full，也未形成自动批准证明。

### R22 旧 A receipt 发布前逐文件持久化候选

原 receipt preparer 只同步 stage 目录，payload 和 receipt.json 使用普通 write/chmod，
未逐文件同步；新 rollback-receipts 根名也未同步其父目录。direct 独立核查 0640 模式和
payload 同步错误，workflow 执行真实 SETUP manifest writer 与 LOAD active receipt API，
要求六个实际 receipt 文件在最终 rename 前已完成同步，metadata 同步失败不得发布。
该 workflow 的生成制品采用独立私有夹具、SETUP 清单输入限定一条实际链接，
不是完整 SETUP 主流程、完整 A 制品生成或健康激活。

初轮日志 `r22-receipt-payload-sync-red.log`（SHA256
`d3532ec9dcce012d691389d7c71dcd0cc94e8df8e244caecea7b884c3d27b972`）包含 workflow
私有 http_root 前提错误，不把该 ERROR 算作持久化缺陷重现；第二轮正例日志
`r22-receipt-payload-sync-green.log`（SHA256
`a760a85ef1b59181a6b94ee52a43db407fcaba5fdc29572ff0bebd2116512d7f`）包含 macOS
/var 与 /private/var 别名比较失败。两份原日志保留，不改生产安全根目录校验或成功断言。
修正私有 fixture 根路径后，原可执行 writer 行为四项均 RED：4 tests / 4 FAIL / exit1，
日志 `r22-receipt-payload-sync-red-canonical.log`，inode 143911239，size 6432，SHA256
`554f903ee3f238e6d2a9d7b327e8a65f927cd7cfbf5ee09efb23c350ac6cccce`。

候选使用新建私有 FD，设最终模式后 flush/fsync 文件；目录原同步与完整加载校验保留，
创建 receipt 根后先同步 output 父目录。payload/metadata 同步错误保留 A selector、
SETUP manifest 与原字节，清理本次自有 staging，不生成最终 receipt。正式 related/full
仍受此前 bootstrap 401 原因未收口门禁阻断，不能据这些局部回归自动重跑或修改 ledger。
新增四项加原有实际 A runtime receipt 恢复正例 5 tests / OK / exit0；日志
`r22-receipt-payload-sync-green-canonical.log`，inode 143911517，size 1964，SHA256
`a02399a958617d57427444a3f6c8994f3bbd0709325f985eee5c69aab2d95f07`，物理退出标记与
exec exit0 一致。模式和同步错误断言保持，不把夹具修正或局部正例称为整树证明。
四个完整 release/generation workflow/optimize/setup plan 模块 333 tests / OK / exit0
（216.553 秒）；日志 `outputs/test-diagnostics/r22-receipt-payload-sync-modules.log`，
inode 143912122，size 109620，SHA256
`2622d624531742320fbb95d9ff071d4ac50ca525597e75282eb6e9a456ecb1a8`。
读前后精确 stat 一致；旧 97551 字节前缀 SHA256
`d2c7b50c1e256c40d3e27f1315e14190d18b8f06aee903d1226273360b44e2b7` 未变，完整 Ran/OK
位于物理退出标记 `R22_RECEIPT_PAYLOAD_SYNC_MODULES_EXIT=0` 之前，exec exit0 一致。
LOAD direct/workflow 原映射有效；TEST 运行 manifest 与 approved ledger 摘要未变。
未以此独立模块回归更新批准证明，bootstrap 原因闸门与其余 R22 未闭项仍保持 OPEN。

### R22 runtime receipt 的受管项目公钥链接候选

真实 SETUP 的 `_process_pubkeys` 正常输出相对软链接，但 LOAD receipt 准备器使用
普通文件 nofollow reader，导致合法 A 公钥发布无法准备恢复凭据。独立 direct 和真实
SETUP 公钥发布/manifest writer→LOAD active receipt API 两项在原实现均 ERROR：
`outputs/test-diagnostics/r22-managed-key-receipt-red.log`，inode 144045702，size 4374，
SHA256 `801612050ef1bc629a4208db478c5531739d0a77f74f6ca08ef6267175bc647a`，
物理 `R22_MANAGED_KEY_RECEIPT_RED_EXIT=1` 与 exec exit1 一致；两份 traceback 均为
正常项目链接被 bounded single-link file 校验拒绝，不是夹具前提错误。

候选保持普通文件 reader 不变，专用适配器只允许当前项目同名 `.pub` 的规范相对链接，
其源须为非空、有界、单链接普通文件；schema2 冻结源的完整身份（含 ctime）、摘要、模式
及发布父目录身份。恢复前验证全部源，替换后保留原相对链接并同步父目录，后核验仍比对
源与父目录。schema1 的普通文件 receipt 继续支持，link 记录不得降级套用旧 schema。
源同 inode ABA、父目录换绑在任何 flat 写入前拒绝，不写回已漂移项目输入、不修改凭据。
外部目标、源别名和 schema 降级负例保持 fail closed。

首批 direct/真实 workflow 四项 OK / exit0，日志 `r22-managed-key-receipt-green.log`，
inode 144054967，size 2367，SHA256
`08c64cf79001a15fc04e5c1c153e8ae00f05ce22a93b26e3b80ebe214420d9d1`。
随后完整回归命令写错两个模块名：实际 release/generation workflow 完整模块的
318 项均通过，另两个 `_FailedTest` 导入 ERROR，因此该命令仍为 320 tests /
2 ERROR / exit1，不能报告为完整成功。原日志 `r22-managed-key-receipt-modules.log`，
inode 144059445，size 110162，SHA256
`6e1eaaa39d89f5973d8e1e37293b992b63b365caf7a69185e63f80cd94102038`；
读前后 stat 一致，旧 106782 字节前缀 SHA256
`7bb70a2df899f64a5ccc2f346f64d764040442b435db6a67fe1c8cb81f9383de` 未变，
完整 FAILED 后物理 `R22_MANAGED_KEY_RECEIPT_MODULES_EXIT=1` 与 exec exit1 一致。
两项 ERROR 明确是不存在的 `test_load_optimize_contract`/`test_setup_plan_contract`，
核 `rg --files` 后只补跑正确的 `test_optimize_output_layout` 和
`test_setup_switch_plan_contract`，未改变代码、测试、时限或断言，也未重复耗时核心模块。
补跑完整 22 tests / OK / exit0，日志 `r22-managed-key-receipt-missing-modules.log`，
inode 144161343，size 4055，SHA256
`bbeedd3500513976af726a405781f8950424ec4e1f44bf6e89b24235df8a65c8`；
旧 2476 字节前缀 SHA256 `64bf84c125006d33d27c2ccee8091a6f35c663e538c570c0159976ff22ae4ed5`
未变，完整 OK 后物理退出标记为 0、exec exit0。四个实际模块分两份记录覆盖共 340 项，
不合并为一次正式 runner/full 成功证明；首批七项新增预期均保留。

随后审阅发现候选适配器自身的缺席/名称重现竞态：首次 lstat 缺席后，fallback 读到重现
的普通文件，却只返回描述而没有 payload，可能先发布不完整 receipt 再被加载器拒绝。
新增独立断言要求拒绝时最终 receipt 不存在，候选原行为 1 FAIL / exit1：
`r22-managed-key-receipt-race-red.log`，inode 144190105，size 1159，SHA256
`bc0d302e6bc5b9f688d659fa789cb289317500f37b5e3cd8ccf9cfb27c757dd8`。
适配器改为名称重现立即拒绝；稳定缺席只返回 missing，由发布前的完整 key 集门禁拒绝，
不从第二个读取拼接凭据。最终 ReleaseTransactionTests 完整 258 tests / OK / exit0，
日志 `r22-managed-key-receipt-final-release-module.log`，inode 144190520，size 92267，
SHA256 `73c08f3a2c1e47e5fa43e331258ed15a0e643963f3dc85798a9a69ea9e714bae`。
同文件剩余 InfraNeutralFallbackWorkflowTests 与本次真实 SETUP 公钥→LOAD workflow
共 2 tests / OK / exit0：`r22-managed-key-receipt-final-workflow.log`，inode 144199905，
size 1519，SHA256 `1e7280fffae865268ce2350b3ec4fc54ebde18b9de65d34558f90085199c4e2d`。
两份最终日志读前后 stat/SHA 稳定，完整 Ran/OK 在物理退出 0 标记之前，exec exit0；
没有把修正前的四模块分组记录套用为最终源码的整组重跑证明。

LOAD direct 与真实多脚本 workflow 原 manifest 映射有效。workflow 使用独立私有
生成制品、实际公钥发布/manifest/receipt APIs，CONFIG 两链接被部分 B 替换后恢复，
IB 两链接未改变；不冒称完整 SETUP/main、完整跨项目 A runtime 或显式激活。
REAL_ENV 原 R22 卡继续 OPEN；同项目 mutable 源漂移和未知额外公钥所有权尚需另行收口。
此前 bootstrap 401 超时仍原因待核，正式 related/full 重跑闸门未放行；本次模块回归
没有修改 approved ledger，不构成当前精确树的 full/check proof。

## Full proof 性能诊断记录

本节只记录测量方法与优化判定，不改变上面的测试和证明门禁。正式 full proof 仍须由
`run_related_tests.py --all`（或明确授权的 `--all --validation-only`）执行；独立诊断
不能生成、替代或延长证明，不能跳过测试、修改断言或手工更新批准账本。

先前会话报告过一次 3,785 tests、2,897.740 秒的全量运行，但原始逐测试日志未保存，
此处未复核；它只是历史参考，**不是可审计计时基线**。人工观察到
`test_formal_children_share_one_isolated_dependency_capsule` 约耗时 12–13 分钟，
也不能据此推算补丁收益。该测试通过固定 SHA 在私有 clone 中重放 `origin/v2` 历史源码；
只改当前 V3 的解包或逐文件 `fsync` 不会加速这段历史回放，不得改历史锚点或弱化断言。

`run_related_tests.py --all --validation-only` 支持显式诊断参数
`--timings ABSOLUTE_NEW_PATH`，并原样传给 `validation_unittest.py`。默认调用、
测试发现、原有结果 JSON 字段和 ISSUE-0016 精确判定不变。提供该参数时，额外写一个
0600、独占创建的 JSONL 文件，每个已完成的 `unittest.TestCase` 记录 `id` 与
`duration_seconds`（包含 setup/test/tearDown 及子测试总时长）。路径须是仓库外、
已存在目录中的绝对路径，目标不能已存在；无效路径会在测试和 ledger 写入前拒绝。
中断可能使文件缺少未完成案例，不能把它当成完整证据。该参数仅能和
`--all --validation-only` 的执行模式组合；不能用于普通发布证明、check、list 或 preflight。

下一次本就需要运行 validation-only 全量套件时，可同时取得正式验证证明和诊断计时：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py \
  --all --validation-only -v --timings /tmp/http-full-timings-UNIQUE.jsonl
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py \
  --check --require-full --validation-only
```

`UNIQUE` 应替换为本次运行的唯一标识。成功的 validation-only 证明仍不是正式发布证明；
计时文件不进入结果 JSON、批准 ledger 或证明指纹，计时写入失败时全量运行 fail closed。

在没有并行 full proof、且当前 checkout 允许测试创建临时制品时，可单独诊断：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B -m test_cases.validation_unittest \
  /tmp/http-full-result-UNIQUE.json -v \
  --timings /tmp/http-full-timings-UNIQUE.jsonl
```

将 `UNIQUE` 换成本次运行的唯一标识；两个输出文件都不能预先存在。可用
`jq -s 'sort_by(.duration_seconds) | reverse | .[:20]' /tmp/http-full-timings-UNIQUE.jsonl`
查看最慢案例。记录命令、UTC 时间、HEAD、Python/平台身份、完整结果与计时文件、
`Ran ... in ...` 摘要及其他重型进程。先核对 `tests_run` 等于计时行数且 ID 无重复；
否则不形成新基线。该诊断不执行正式 runner 的 preflight/approval 流程，也不更新 ledger。

下一迭代先依据当前 V3 的实测热点和微基准评估优化。已通过可选计时安全透传给正式
`--all --validation-only`，让一次本来就要运行的治理套件同时留下诊断数据；这只增加
测量能力，**不是提速**。不得因计时输出修改三项已知 FAIL 判定或 proof 输入输出。
当前 V3 的另一个候选热点是约 499 个 Git 对象逐个启动 `git cat-file --batch`；批量读取
可能改变对象被替换时的可见性，未做前后微基准和恶意改写/竞态负例前不得落地。
十个逻辑 suite 不是隔离证明：测试会创建仓库临时项目、monitor 锁、loopback sshd 和
Git 检出，在证明共享写入、端口、引用及结果合并边界安全前，不启用 suite 并行。

### 2026-09-29 第二轮：collection worker 的结束唤醒

完整计时文件 `/tmp/http-full-timings-20260929-codex-test-dba95de.jsonl` 中，
`test_collection_cycle_handoff_workflow.CollectionCycleHandoffWorkflowTests.
test_all_scope_order_and_every_slot_echo_mutation_fail_closed` 耗时 163.011 秒。
该用例仍逐一运行全部 21 个异常变体；对其中一个变体在真实 Python 子进程内做
`cProfile`，发现 `run_interruptible` 的 6 次调用累计 6.566 秒，其中固定
`time.sleep(0.2)` 的 32 次调用累计 6.519 秒。历史固定 SHA 回放的 854.230 秒
用例不经过当前 worker，因此这个优化不影响它，也不能推算出全量 suite 的最终收益。

`monitor/switch-collection-worker.py` 改为在原有 200 ms 取消检查上界内调用
`Popen.wait(timeout=min(0.2, remaining))`，子进程提前结束时立即继续；超时、
取消、异常退出及残留进程组仍走原来的终止和清理路径。新增 direct 测试先确认
旧实现会因固定 `sleep` 失败，再覆盖上述四类边界。六次短子进程微基准由
0.205–0.208 秒/次降为 0.021–0.048 秒/次。上述真实跨脚本工作流用例在同一
macOS/Python 3.9 环境独立重跑两次，分别为 135.575 秒和 135.096 秒，较原始
163.011 秒减少约 27.4–27.9 秒（16.8–17.1%）。命令为：

```bash
/usr/bin/time -p env PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B \
  -m unittest -v \
  test_cases.test_collection_cycle_handoff_workflow.CollectionCycleHandoffWorkflowTests.test_all_scope_order_and_every_slot_echo_mutation_fail_closed
```

变更感知的 `run_related_tests.py --no-approve -v` 在本地 loopback 能力允许的环境下
以 `related-tests` 模式完成 50 个模块并返回 0；`--no-approve` 没有写批准账本。
本轮没有执行修改后正式 `--all`，不能声称已形成新 full proof 或全量提速数据。
此处使用的是 Python 标准库跨 POSIX 平台支持的 `Popen.wait(timeout)`；上述
运行证据来自 macOS，Linux 真机/容器还需单独验证。首次相关测试尝试在受限沙箱
因 AF_INET loopback preflight 返回 2，不能算测试失败或证明。
