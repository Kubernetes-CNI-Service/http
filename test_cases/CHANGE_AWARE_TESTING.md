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
