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
macOS 正式 load 在实际生成前运行 `--all`，成功后运行 `--check --require-full`；Linux load 与
macOS dry-run 不运行开发测试。正式 `sync-code` 或 `tar-for-upload` 只执行
`--check --require-full`：精确证明有效就直接复用，缺失或过期则在任何打包、网络或远端写入前
停止并要求重跑本机正式 load，绝不自行回退执行全量。`--check` 返回 4 表示字节未批准，
`--check --require-full` 返回 5 表示全量证明缺失、过期或来自不同环境；两者都必须阻断发布。

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

## Full proof 性能诊断记录

> 合入 http dev 主树时的说明（2026-10-25）：本节只收录随性能单元合入 DEV 的条目；条目内的测量和运行证据都来自 http-test 树（TEST），不是在 DEV 上测得的；DEV 合入后的验证见合并窗口记录。

### 2026-10-23 P 族原始对象按调用作用域闭合批量读取（C09）

> 合入 DEV 注（2026-10-25）：本小节原文是 http-test 树（TEST）上的记录，文中「本树」指 TEST 树；所列 RED/GREEN、计数、余量与收益都是 http-test 的历史证据或推断，DEV 没有运行这些测试。DEV 上 W1 的请求数、cat-file 次数与 ×4 余量须在合并窗口实测。

依据：owner 2026-10-23 聊天原话「采用C09，这么节省时间」（撤销 10-22「暂不采用」的选择），以及
「任何性能优化方案验证测试通过了就可以落地」。这是一份新合同；下文 2026-10-09 判定表、
2026-10-08 source guard 批量读取小节和其他条款的文字都不变。

范围：只改测试侧 harness `test_cases/test_public_publication_workflow.py`，在最后一个测试之后、
`if __name__` 之前纯插入一个区块：`_RawObjectPrefetchScope`、`_C09_SCOPE`（ContextVar）、
`_C09_BATCH_LIMIT = 32`、`_c09_first_parent_hint`，并把 `_read_raw_git_object`、
`_verified_commit_records`、`_raw_v3_first_parent_chain` 三个模块名重新绑定为分派器。原定义逐字
不变，并以 `_read_raw_git_object_single`、`_verified_commit_records_unscoped`、
`_raw_v3_first_parent_chain_unscoped` 保留。生产脚本、runner、manifest、批准 ledger、
`RAW_OBJECT_TIMEOUT_SECONDS = 1`、`P_V3_FIRST_PARENT_LIMIT` 和历史 P 回放都不变。

机制（落地的是 serve 形态 = lab `d31a2a0` + fix2 serve；区块字节与 lab pin 相同，见下方证据）：
1. 作用域：每次 `_verified_commit_records` 或 `_raw_v3_first_parent_chain` 调用 set 一个作用域，
   finally 中 reset。作用域之外（包括其他线程和后续调用）`_read_raw_git_object` 就是原单对象读取；
   请求的仓库与作用域仓库不同时也走原读取。
2. 批读：作用域内某次请求没有已复核的帧时，从计划中该对象的位置起取至多 32 个未尝试的
   (OID, kind)，用与原语相同的命令、环境和 `timeout=RAW_OBJECT_TIMEOUT_SECONDS` 运行一次闭合 stdin
   的 `cat-file --batch`。只含 1 个键的批次不运行（R3），该对象直接由原读取给出。
3. 逐帧复核：回显 OID、kind、规范 size、分隔符和 SHA-1，与原语逐项相同；复核通过的帧按请求逐个
   交出，只存在于本次遍历。
4. 失败即回退：子进程异常/超时、非 0、stderr 非空、缺头或尾部多余字节时整批不用；某帧不符时该帧
   及其后不用。作用域内第一次批次失败后不再批读（R2）。回退一律走原单对象读取，判定（异常或 1 秒
   超时）只由原语产生，批次本身从不抛出判定。
5. 计划（serve，R4）：只在帧交给消费者时才从该 commit/tree 计划子对象；不会读取消费者尚未接受的
   对象之下的对象，因此不需要 arrival 形态的额外裁定。
6. 链提示（R1）：链遍历前运行一次有界 `rev-list --first-parent --max-count=P_V3_FIRST_PARENT_LIMIT+1`
   （环境与原语相同、stdin 为 DEVNULL、超时 1 秒），在 anchor 或 S 处截断；异常、超时或非 0 都视为
   没有提示。提示只决定预取顺序，链的每一步仍由原逐提交读取和原断言判定。

与既有条款的关系：
- 「固定历史 P 回放保持原 SHA 和安全合同不变」：`_run_historical_p_test`、历史 SHA pin、回放
  超时 1500 秒与私有历史 checkout 都不变；回放子进程执行的是 V2 历史字节，不含本区块。C09 只改变
  当前 V3 侧（`_assert_v3_child_authority` 及直接调用这三个名字的当前测试）读取原始对象的方式。
- 「不能把同一次读取跨测试或提交边界复用」：作用域只活在一次遍历调用内；验证结束后再改写对象的
  postverification 测试仍由新的遍历重新读取并拒绝。
- 「不能用 metadata 替代原字节检查」：每帧都按原字节重算 SHA-1。不缓存模块或 namespace，不引入
  线程或进程池。
- 与 2026-10-08 source guard 批量读取的两处差异：(a) 坏帧之前已复核的前缀帧仍被采用（先例整批
  拒绝），每个被采用的帧都单独通过与原语相同的复核，给出的字节与单读相同；(b) 只复核 SHA-1：原语
  本身只接受 40 位 OID、只算 SHA-1，SHA-256 仓库中 C09 全部回退到原语，不引入新行为。32 上限、
  闭合 stdin、有限超时与先例一致。
- 读取时机：一次遍历内对象可能先于请求被读取（预取），交出的仍是按 OID 复核过的同一字节。

tests-first：`test_public_publication_v3_overlap` 新增 14 个用例。前 12 个（批量上限与闭合 stdin、
失败批次只回退原读取、作用域只在调用内、提示不能改变原链、原语在遍历外仍是一次闭合读取、真实 ROOT
的权威校验经原语读取全部对象且子进程少、11 种畸形批输出回退后结果相同、FIFO 提交有界、第一次失败
批次关闭预取、单键对象只来自原读取、正确提示不读 anchor/S、V2 原语语料在批次中回退相同）的字节
等于 lab serve pin；后 2 个是落地时补充的守卫：链提示失败、外来或以 anchor 开头时完全不预取且原链
不变，以及遍历内交出的每个元组与遍历外原读取逐字节相同。预期值来自字面夹具与 hashlib，计数由
字面形状手推（48 个对象；42 提交链 40 次读取；12 提交链 10 次读取）。在只含测试的提交上预登记的
RED 为 Ran 18、failures=12、errors=18（逐项见对应提交信息）；运行后须把 RED/GREEN 日志及其
SHA256 追加到本小节，本小节写入时尚未运行任何测试。

W1 的前提与余量：W1 对真实 ROOT 执行 `_assert_v3_child_authority`，需要 `refs/remotes/origin/v2`
指向 V2 anchor、HEAD 到 anchor 的 first-parent 链没有 merge、工作树干净且手册当前。first-parent
链上有 merge 提交的检出（例如 2026-10-23 的 G1 合并提交）中，W1 与既有 historical P 方法一样以
「V3 history must remain merge-free」失败，与 C09 无关；W1 要在无 merge 的链上判定。余量按静态
模型推断（该模型在 lab 树上复现 E1 读数：旧实现 1743 次 cat-file，arrival/serve 子进程 90/231）：
本树一次权威校验约 1935 次请求、serve 约 236 次 cat-file，×4 断言约有 2.0 倍余量【推断】。

负载敏感性：T1、T4、T10、W1 的子进程计数断言只在批次真实超过 1 秒时失败（R2 随即关闭预取，结果
仍正确但计数变多）；这类失败先查负载，不放宽阈值、不改超时。

证据位置（仓库外）：lab 链 `/Users/joeyyang/Desktop/claude-merge-test/lab-trees/http-perf-670-c09fix`
（f0570a3→874f3f5→d2fb233→d31a2a0）；提案 `http-perf-runs/proposals/PROP-02-c09.md`；serve 字节
重建与移植脚本、W1 模型在 `/Users/joeyyang/Desktop/claude-merge-test/step1.noindex/devC09-work/`。
重建用两个独立口径（钉住的生成脚本在内存中重放；独立重写同一组替换），两者逐字节一致，输入与
输出都等于 PREP pin（serve_e_ov `859f601d0e598d7b01b20ae84bc31da7b14f9c0ba83a06a0d15a2fe2324b5951`，
serve_f_wf `6cc7f664cf000fd0a4cd9c7d1017eed14592e2764907eebc7640c7b209420de4`）。本树的 workflow
文件去掉 d13c6a9 相对 670acfa 多出的两行后等于 serve_f_wf。收益量值只有 lab 读数：ABA-T 测的是
`d31a2a0`，每次串行 full 约 434 秒；serve 形态没有串行全量实测，按 ABA-T 口径推断约 377–390 秒。
这些不是本树的 full 证明。

注记：T6b 注释中的 `test_public_publication_workflow.py:5433-5442` 是 670acfa 行号，本树同一元组在
:5435-5444；注释说它「expected GREEN before and after」是相对 lab 的 `d31a2a0` 实现而言，在本树的
测试先行提交上它因检查 `_C09_SCOPE` 而 ERROR。为保持字节等于 pin，没有改这条注释。

manifest 不变：两个模块已在 repository-governance suite 和相关 path rule 中，没有新增生产脚本或
测试模块。`user-manual.html` 按模块 docstring 编目，两个模块的 docstring 不变，无需重新生成；
W1 本身会执行 `tools/update-user-manual.py --check`。本文件的改动在 runner 中属于未知路径，按规则
要求 canonical full。以上都不签发批准、不改 ledger；正式状态只看集成后的 full/check。

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
