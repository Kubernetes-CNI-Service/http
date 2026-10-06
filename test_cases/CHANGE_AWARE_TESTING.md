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
