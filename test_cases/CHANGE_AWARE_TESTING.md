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
2026-10-08 source guard 批量读取小节和其他条款的文字都不变。修正轮（同日，提交 a1fbece..本小节）
依据两份独立静态评审（`devC09-work/review/REVIEW-1-by-implementer-subagent.txt`、
`REVIEW-2-independent.txt`）修正链提示的输入门、补回归测试并更正本小节；评审不是 owner 裁定。

范围：只改测试侧 harness `test_cases/test_public_publication_workflow.py`，在最后一个测试之后、
`if __name__` 之前纯插入一个区块：`_RawObjectPrefetchScope`、`_C09_SCOPE`（ContextVar）、
`_C09_BATCH_LIMIT = 32`、`_c09_first_parent_hint`，并把 `_read_raw_git_object`、
`_verified_commit_records`、`_raw_v3_first_parent_chain` 三个模块名重新绑定为分派器。原定义逐字
不变，并以 `_read_raw_git_object_single`、`_verified_commit_records_unscoped`、
`_raw_v3_first_parent_chain_unscoped` 保留。生产脚本、runner、manifest、批准 ledger、
`RAW_OBJECT_TIMEOUT_SECONDS = 1`、`P_V3_FIRST_PARENT_LIMIT` 和历史 P 回放都不变。修正轮只改区块
内部（链提示与分派器），区块之外的字节与 112fd01 相同。

机制（lab `d31a2a0` + fix2 serve 形态，加修正轮两处改动）：
1. 作用域：每次 `_verified_commit_records` 或 `_raw_v3_first_parent_chain` 调用 set 一个作用域，
   finally 中 reset，抛异常时同样 reset。作用域之外 `_read_raw_git_object` 就是原单对象读取，
   包括后续调用；请求的仓库与作用域仓库不同时也走原读取。「其他线程看不到作用域」依赖解释器：
   CPython 3.9–3.13 的新线程从空 context 开始；评审 2 记得 3.14 free-threaded 构建默认让新线程
   继承 context，`contextvars.copy_context()` 与 `asyncio.to_thread` 也会把同一个无锁作用域对象
   带过去。本仓库用的 CLT 3.9.6 与 3.12 venv 不受影响，3.14 的行为未验证【推断】。
2. 批读：作用域内某次请求没有已复核的帧时，从计划中该对象最早未尝试的位置起取至多 32 个未尝试的
   (OID, kind)，用与原语相同的命令、环境和 `timeout=RAW_OBJECT_TIMEOUT_SECONDS` 运行一次闭合 stdin
   的 `cat-file --batch`。只含 1 个键的批次不运行（R3），该对象直接由原读取给出。同一批次可以含
   重复的 (OID, kind)，例如两个内容相同的文件；重复帧逐个复核后都被收下，各供一次请求。
3. 逐帧复核：回显 OID、kind、规范 size、分隔符和 SHA-1，与原语逐项相同；复核通过的帧按请求逐个
   交出，只存在于本次遍历。
4. 失败即回退：`run_batch` 内子进程 OSError/超时、非 0、stderr 非空、输出在某帧头之前结束或尾部
   有多余字节时整批不用；某帧不符（头不是 3 段、非 ASCII、回显 OID/kind/size 不符、长度或分隔符
   不符、SHA-1 不符）时该帧及其后不用，此前已复核的帧仍被采用。分派器调用 `run_batch` 时逸出的任何
   Exception（BaseException 除外）都按失败批次处理（修正轮新增）。作用域内第一次批次失败后不再
   批读（R2）。回退一律走原单对象读取，判定（异常或 1 秒超时）只由原语产生，批次本身从不抛出判定。
5. 计划（serve，R4）：只在帧交给消费者时才从该 commit/tree 计划子对象；不会读取消费者尚未接受的
   对象之下的对象，因此不需要 arrival 形态的额外裁定。
6. 链提示（R1，修正轮更正）：只有 head 与 anchor 都是 str 且完全匹配 `[0-9a-f]{40}` 时才运行提示；
   否则没有提示，原链逐提交读取单独判定（非 OID 的 str head 由原语在启动任何进程前拒绝，异常类型与
   消息与 37d2b35 相同；不可哈希的非 str head 在分派器取键时抛 TypeError，类型相同、消息不同）。提示是一次有界 `git rev-list --first-parent
   --max-count=P_V3_FIRST_PARENT_LIMIT+1 --end-of-options <head>`：环境与原语相同、stdin 为
   DEVNULL、超时 1 秒、`text=False`，stdout 按严格 ASCII 解码，stderr 不解码；在 anchor 或 S 处
   截断。非 0 退出以及函数内任何 Exception（超时、OSError、嵌入 NUL、解码失败等）都视为没有提示。
   捕获范围取 `Exception`：提示只决定预取顺序，任何失败都只等于没有提示。修正轮当时的理由是「G-a
   用 str stdout 模拟 rc=0 的提示」；第三轮复审指出这让 G-a 的两个 rc=0 子测试走了 AttributeError
   路径、失去区分力，第四轮已把 G-a 的模拟输出改为 bytes（见下）。`--end-of-options`
   需要 git ≥ 2.24（本机 git 2.39.5 实测接受）；更旧的 git 会让提示失败，只等于没有提示。提示只
   决定预取顺序，链的每一步仍由原逐提交读取和原断言判定。

与既有条款的关系：
- 「固定历史 P 回放保持原 SHA 和安全合同不变」：`_run_historical_p_test`、历史 SHA pin、回放
  超时 1500 秒与私有历史 checkout 都不变；回放子进程执行的是 V2 历史字节，不含本区块。C09 只改变
  当前 V3 侧读取原始对象的方式。直接调用者：`_assert_v3_child_authority`，以及 s_phase 与
  v3_overlap 中直接调用这三个名字的测试。间接调用者：`_tree_records`、`_tree_modes`、
  `_assert_historical_p_anchor`（经 `_resolve_published_v2_anchor`），以及调用它们的 V3 测试，例如
  `test_public_s_phase_workflow.py:715-722`。其他模块里同名的 `_tree_records`、`_tree_modes`、`_verified_commit_records` 是
  各自的定义，不受影响。
- 「不能把同一次读取跨测试或提交边界复用」：作用域只活在一次遍历调用内；验证结束后再改写对象，
  下一次遍历会重新读取并拒绝（T3）。对 C09 批路径起作用的回归测试只在 v3_overlap：T3 及修正轮的
  R4、XK、CM、LH、DU、PF、BX。workflow 中注入 `_read_raw_git_object` 或
  `_verified_commit_records` 的 hostile 语料（坏树、header spoof、cross-kind、FIFO、
  postverification 竞态、corrupt commit）都在 `@_historical_p_method` 方法体内，V3 下执行的是
  V2 历史字节的回放，对 C09 是死代码：既不会被 C09 打破，也不检验 C09。v3_overlap 原有 4 例用
  单文件仓库，按 R3 全部走原语。
- 「不能用 metadata 替代原字节检查」：每帧都按原字节重算 SHA-1。不缓存模块或 namespace，不引入
  线程或进程池。
- 与 2026-10-08 source guard 批量读取的三处差异：(a) 坏帧之前已复核的前缀帧仍被采用（先例整批
  拒绝），每个被采用的帧都单独通过与原语相同的复核，给出的字节与单读相同（PF）；(b) 只复核
  SHA-1：原语本身只接受 40 位 OID、只算 SHA-1，SHA-256 仓库中 C09 全部回退到原语，不引入新行为；
  (c) 批次可以含重复 OID 并收下重复帧（先例为「最多每批 32 个唯一完整 OID」并拒绝重复帧），每个
  重复帧单独复核，交出的元组与原语相同（DU）。32 上限、闭合 stdin、有限超时与先例一致。
- 读取时机：一次遍历内，对象最早在其父树交出后的批次中读取，到交给消费者之前可以隔任意多个批次
  （例：T1 中 zz/ 隔 2 批；根下 32 个子树、各含 32 个 blob 时，已读未交出的帧可达 62 个；第三轮
  复审的纯内存模型实测）。并发改写的窗口因此覆盖整个遍历，不是一批。若对象库在预取之后、消费之前
  被并发改写，原实现在请求时会拒绝，C09 交出的是更早读到并按 OID 复核过的真实字节；遍历中途失败时，
  已预取的兄弟对象是原实现不会读的。因此「判定与原语相同」以遍历期间对象库不被并发改写为前提；
  下一次遍历仍会重读并拒绝。

第四轮（主线程，2026-10-23，依据第三轮复审）：G-a 的 `foreign-or-malformed-ids`、`anchor-first` 两个 rc=0 子测试
改用 bytes 模拟输出，重新进入规划循环；对当前实现预期 GREEN，对「在 anchor/S 处 continue 而不是截断」的实现
为 RED（修正前这种实现没有任何测试能区分）。另注：4e66b2c 提交信息说「bytearray 的 commit payload 已经会打断
遍历」不准确——`partition`、`re`、`decode` 都接受 bytearray；链 API 只返回 str，外部观察不到差异，G-b 与 DU
的 `type(payload) is bytes` 断言负责 blob 侧。

tests-first：`test_public_publication_v3_overlap` 新增 23 个用例，模块共 27 个。
- 前 12 个的字节等于 lab serve pin：批量上限与闭合 stdin、失败批次只回退原读取、作用域只在调用内、
  提示不能改变原链、原语在遍历外仍是一次闭合读取、真实 ROOT 的权威校验经原语读取全部对象且子进程
  少、11 种畸形批输出回退后结果相同、FIFO 提交有界、第一次失败批次关闭预取、单键对象只来自原读取、
  正确提示不读 anchor/S、V2 原语语料在批次中回退相同。
- 落地守卫 2 个：G-a（链提示失败、外来或以 anchor 开头时完全不预取且原链不变）、G-b（遍历内交出的
  每个元组与遍历外原读取相同；修正轮在 G-b 内插入 4 行（3 行断言、1 行注释），断言 payload 为 bytes、其余三项为
  str/str/int、结果为 tuple）。
- 修正轮 9 个：G-c（head 或 anchor 不是精确 OID 时不启动提示进程，`--output=` 形 head 不触碰
  目标文件，含 NUL 的 head 抛与 37d2b35 相同的 AssertionError）、G-d（head 紧跟
  `--end-of-options`；stdout 或 stderr 不可解码时视为没有提示）、R4（A/ 下 33 个 blob、坏兄弟树
  bad/ 下的对象从不进入任何 cat-file 输入）、XK（100644 条目指向真实 tree 并进入多键批次，由原语
  报 identity/type mismatch）、CM（正常提示下链中段坏提交：报 object id，请求序列等于字面链，
  坏提交由单读判定，抛异常后作用域为 None）、LH（进入规划的说谎提示：夹带链外提交并与真实链交错，
  或夹带外来 OID；链不变，anchor/S 不被读）、DU（同批重复 OID）、PF（R2 之后前缀帧仍被采用）、
  BX（批次逸出的任何异常只回退，判定仍来自单读）。
预期值来自字面夹具与 hashlib，计数按 serve 规则由字面形状手推（48 个对象；42 提交链 40 次读取；
12 提交链 10 次读取；DU 2+2；PF 47）。另以纯内存模型交叉核对（`devC09-work/fix/model_selfcheck.py`，
不导入仓库代码，重写原语、遍历、链与区块及 a–e 五种错误实现，27 项预期 0 项不符【推断】）。
预登记：688cf3f 为 Ran 18、failures=12、errors=18；a1fbece 为 Ran 20、failures=3、errors=3；
4e66b2c 为 Ran 26 OK（守卫）；0181696 为 Ran 27、failures=2、errors=2；f91f315、be82506 与本小节
提交为 GREEN；逐项见各提交信息。运行后须把 RED/GREEN 日志及其 SHA256 追加到本小节，本小节写入时
尚未运行任何测试。

阈值来源（修正轮补记）：T1 的 ≤6 与 W1 的 ×4 是 lab 的 serve 步骤从 arrival 形态的 ≤5、×8 放宽来的。
这两处改动写在 C09 v2 设计文档的 serve 步骤里（PROP-02 引 `C2D:242`；设计期预测 serve 不超过 260 次、
按 ×4 判，见 `C2D:259`）。lab E1 的 serve 实测是子进程中位 231，×8 需不超过 217。评审 2 认为 ×4 是
看到 231 之后才定的；修正轮看到的设计文档（mtime 10-14 10:33）已含这两处改动，但无法确定它与 E1
的先后【推断】。无论先后，放宽须显式评审（PROP-02 Q5），并且与 AGENTS「预期值不得从被测实现反向
生成」存在张力。修正轮因此不看任何实现计数，只用设计规则与仓库数据重新推导上界：
- T1：字面形状 48 个对象。按 serve 规则：commit 计划为空，单读；root 计划只有 1 个键，R3 单读；
  root 交出后 [a.txt bulk zz] 一批；bulk 交出后 40 个子对象按 32+8 两批；zz 交出后 3 个一批。无失败
  时恰为 6 次 cat-file，≤6 就是设计值。arrival 规则下同一形状为 5 次，原 ≤5 是 arrival 的设计值。
- W1：一次遍历中 commit 与 root 各 1 次。之后每棵被交出的树 T 的 k_T 个子对象在计划中连续，深度
  优先遍历按序请求；键唯一且没有失败批次时，从该块开始的运行至多 ⌈k_T/32⌉ 次（非尾部的每次消耗
  该块 32 个键，尾部至多一次）。同一 (OID, kind) 出现在多条路径时，每个这类请求至多多出 1 次运行
  （宽松口径）。链在提示成功时为 ⌈L/32⌉ 次，提示失败时为 L 次；anchor 父提交读取在作用域外，1 次。
  请求数 N = 1 + Σ(2 + 条目数) + L。数据只取 git（`ls-tree -r -t`、`rev-list`），脚本
  `devC09-work/w1_design_bound.py`，输出在 `devC09-work/w1_design_bound.be82506.out`。be82506 上
  L=483、N=1947，上界在键唯一口径为 237，宽松口径为 474；本小节提交后 L 与 N 各加 1，
  上界不变。4×474=1896，不超过 N，所以只要提示成功、没有失败批次，即使按宽松口径，×4 也
  由设计保证。×8 只在键唯一口径下成立（8×237=1896），宽松口径下不保证。提示失败时
  宽松上界为 941，×4 不成立，这属于负载敏感性。
结论：≤6 与 ×4 都与独立推导的设计上界相容；本段推导取代「按实测放宽」作为来源。W1 的界随 ROOT 的
树形变化：目录增多（Σ⌈k/32⌉ 变大）或重复对象增多都会缩小余量。余量不足时先按本段重算，不得临时
放宽。

W1 的前提：W1 对真实 ROOT 执行 `_assert_v3_child_authority`，需要以下四项：
- `refs/remotes/origin/v2` 指向 V2 anchor（本克隆为 ce21fef）；
- HEAD 到 anchor 的 first-parent 链没有 merge（本分支线性基于 37d2b35，be82506 的链为 483 个
  提交，0 个 merge）；
- 工作树干净；
- 手册当前。
缺 origin/v2 时，W1 以 `_PublishedV2RefUnavailable`「remote-tracking ref is absent; authenticated
fetch required」失败；链上有 merge 时，以「V3 history must remain merge-free」失败。两者都与 C09
无关，既有 historical P 方法也会同样失败。此前本小节引用的「约 1935 次请求、serve 约 236 次
cat-file」来自实现者的静态模型 `devC09-work/w1_model.out`，对应 d13c6a9（1935）与
9333d0a（1939）。那两棵树的 first-parent 链上各有 1 个 merge，模型只沿第一父继续，所以这些数不是
本树的值；本树的值见上一段。实测余量仍须用 `devC09-work/diag_w1_margin.py` 记录。

负载敏感性：子进程计数断言只在批次或提示真实超过 1 秒时失败，结果仍正确，只是计数变多。
- 任一批次超时会触发 R2，影响 T1、T4、T9、T10、W1、DU、PF。
- 提示超时会让链读取全部变成单读，影响 T4、T10、W1、G-d[real-rev-list]。
- T7 另有 20 秒墙钟上限。
其余 C09 用例的断言在批次或提示超时后仍成立（失败批次的输入在运行前已被记录，判定不依赖计数）。
这类失败先查负载，不放宽阈值、不改超时。对比：原实现每次 W1 约 1948 次单读，每次都有 1 秒硬
超时。C09 让 P 族的硬性超时假红变少，风险转成这些用例的计数失败。

证据位置（仓库外）：lab 链 `<http-test lab tree http-perf-670-c09fix>`
（f0570a3→874f3f5→d2fb233→d31a2a0）；提案 `http-perf-runs/proposals/PROP-02-c09.md`；serve 字节
重建与移植脚本、W1 模型在 `<http-test C09 work directory devC09-work>/`，
修正轮的脚本在其 `fix/` 子目录。重建用两个独立口径：钉住的生成脚本在内存中重放，以及独立重写
同一组替换。两者逐字节一致，输入与输出都等于 PREP pin：serve_e_ov
`859f601d0e598d7b01b20ae84bc31da7b14f9c0ba83a06a0d15a2fe2324b5951`，serve_f_wf
`6cc7f664cf000fd0a4cd9c7d1017eed14592e2764907eebc7640c7b209420de4`。0b5728e 与 112fd01 的 workflow
文件去掉 d13c6a9 相对 670acfa 多出的两行后等于 serve_f_wf。修正轮之后区块不再等于该 pin。区块
（标记行至 `if __name__` 之前）的 sha256：
- 112fd01 `8deecadfa75496a8b689860a797544ce2ba425cccd0e5cc6749ed3b2248be203`
- f91f315 `6b013fe34ab3fc40d3544add1cf3b7534cfe4cbb8c80003a49423e0222c5217b`
- be82506 `4d04e22fe7b11f00d744c11b1b0388d3b124fab682b3ef0e94a3972c3136b30f`
整个文件的 sha256：
- 112fd01 `29ac8cf032bf64eaeaeecf3e2e234f96fe8716dae7b4faa9d5d4785288121330`
- be82506 `9564177ce52abfc526e0f2b11ae68067037880a8fe330dfd63663419b97c819d`
v3_overlap 前 31865 字节仍等于 serve_e_ov pin；修正轮只在其后追加，并在 G-b 内插入 4 行；第四轮把
G-a 的 rc=0 模拟输出改为 bytes（G-a 从 :594 起，不在 pin 内）。收益量值
只有 lab 读数：ABA-T 测的是 `d31a2a0`，每次串行 full 约 434 秒；serve 形态没有串行全量实测，按
ABA-T 口径推断约 377–390 秒。这些都不是本树的 full 证明。

注记：
- T6b 注释中的 `test_public_publication_workflow.py:5433-5442` 是 670acfa 行号，本树同一元组在
  :5435-5444。注释说它「expected GREEN before and after」，是相对 lab 的 `d31a2a0` 实现而言；在
  本树的测试先行提交上，它因检查 `_C09_SCOPE` 而 ERROR。为保持字节等于 pin，没有改这条注释。
- 688cf3f 的提交信息说 G-a「与 helper 名无关」，但 G-a 在 :664 断言 `_C09_SCOPE.get()`。
- T4 的说谎提示首元素就是被替换的 S，相当于没有提示；它的字节保持不变，进入规划的说谎提示由 LH
  覆盖。

manifest 不变：两个模块已在 repository-governance suite 和相关 path rule 中，没有新增生产脚本或
测试模块。`user-manual.html` 按模块 docstring 编目，两个模块的 docstring 不变，无需重新生成；
W1 本身会执行 `tools/update-user-manual.py --check`。本文件的改动在 runner 中属于未知路径，按规则
要求 canonical full。以上都不签发批准、不改 ledger；正式状态只看集成后的 full/check。

### 2026-10-23 opt-in 两阶段分片全量（PROP-14 G5Q-RA 落地形态，候选）

依据：owner 2026-10-23 原话「你有http-test的所有权限，你可以按照你的想法落地优化方案，不用问我
授权跑测试或者确认什么机制。」「任何性能优化方案验证测试通过了就可以落地」。本小节在下列门禁
范围内修订下文 2026-10-09 判定表「并行 SHA、扩大有状态 suite 并发」一行，以及「十个逻辑 suite
不是隔离证明」「并行 suite 仍未启用」「据此本轮不把 `--jobs` 接入治理 runner」三段的结论；
这些段落的事实记录与其余条款不变。默认串行 `--all` 的 argv、discovery、环境、输出与证明完全不变。

形态：`python3 -B test_cases/run_related_tests.py --all --sharded ABSOLUTE_NEW_DIR [-v]`，只在
macOS（APFS clonefile）提供。它执行与串行相同的 canonical discovery，按受管计划
`test_cases/full_shard_plan.json`（tracked_support，改动即要求 full 并使现有证明失效）分两阶段
运行：阶段 A 各车道在各自的私有 clone 中并行；阶段 A 全部结束且残留门通过后，阶段 B 只有一条
安静车道单独运行（计划结构上只能有一个阶段 B 车道，并发固定为 1）。计划单位只有三种：整模块、
`MODULE#i/k` 连续用例切片（显式边界用例 id）、`MODULE::ID` 单个用例。被拆到多个进程的模块不得
定义 setUpModule/tearDownModule，被拆的类不得定义 setUpClass/tearDownClass；`same_lane` 声明的
模块组（P 共享 fixture/publication 四模块）必须是同一车道的整模块；每个阶段 B 单位必须写明入选
理由。计划结构不合、单位指向不存在的模块/用例/边界、canonical 模块未分配、空车道、类在定义模块
之外被收集（G1 不变量）或 discovery 有导入失败行时，都在任何车道运行前 fail closed。

覆盖等价：协调器在一个私有 clone 中做 canonical 枚举（只导入，不运行），按计划把每个 canonical
行索引分配给唯一车道；每个车道在自己的 clone 中重做 discovery，摘要与行数必须与枚举逐字节一致，
否则 fatal。合并时逐车道核对：每条执行记录的索引属于该车道、id 与 canonical 一致、不重复；
缺失的行只能由该车道记录的已识别 setUpClass/setUpModule SkipTest holder 精确抑制（与串行
unittest 不运行它们相同）；随后全局核对每个 canonical 行恰好被执行或抑制一次。结果判定与串行
`wasSuccessful()` 相同：expected failure 不算失败，unexpected success、failure、error 都算失败。

跳过等价（2026-10-23 复审 M2 补充）：跳过也必须是串行会做的跳过，不能因车道环境不同而被当作覆盖。
canonical 枚举保留协调器的 TMPDIR（与串行子进程相同，不用私有 TMPDIR），在导入全部模块后记下每个
被类或方法装饰器跳过的行及其原因；每个车道按串行 `result.skipped` 的口径逐条记录跳过项（用例或
子用例 id，或 setUpClass/setUpModule holder）及原因，`audit.json` 逐车道写出 `skips` 与
`suppressed_ids`，并写出全部 `decorator_skips` 与汇总的 `skips`。全部车道结束后核对：枚举得到的
每个装饰器跳过都必须由其车道以相同原因报告（其类或模块 holder 已整体跳过时除外，与串行相同）；
其余每个跳过项只在运行时产生，必须是计划可选键 `runtime_skips` 中以完全相同原因列出的条目
（`runtime_skips` 缺省即不允许任何运行时跳过；条目必须仍指向 canonical 用例、类或模块，否则在车道
运行前按计划陈旧 fail closed）；同一跳过项重复报告也失败。当前计划只列出私有文档层门禁
`PrivateDocumentationContractTests.setUpClass` 这一处运行时跳过（全部测试模块静态普查的唯一运行时
跳过点）：它在没有被忽略私有层的 checkout 中跳过，在有私有层的 checkout 中运行，两种情况都与串行
一致。仍不能由本门禁发现的差异：枚举与车道共有、而串行没有的环境差异（clone 路径、独立会话、写入
日志而非终端的 stdout、去掉的 `GIT_*`）只影响的装饰器跳过，以及在车道中以与
`runtime_skips` 完全相同的原因出现、而串行不会出现的运行时跳过；这一部分由专用会话对照逐对比较串行
`-v` 日志的跳过行与审计 `skips` 闭合。本门禁不支持、遇到即 fail closed（串行会如实记录，当前树没有
实例）的跳过形态：同一跳过项被报告多次（例如参数相同的子用例跳过两次，或用例本体与 tearDown 各跳过
一次），以及在 tearDownClass、tearDownModule 或类/模块清理阶段抛出的 SkipTest。枚举只导入，导入期
写入的临时文件落在协调器 TMPDIR 而不受枚举的遗留清单记录；各车道在私有 TMPDIR 中执行同样的导入，
记入该车道的遗留清单（2026-10-24 起私有 TMPDIR 内容只记录、不阻断，见下文 S0 修订）。

门禁（任何一项都返回 1，批准 ledger 不变，证据全部保留在 ABSOLUTE_NEW_DIR）：主 checkout 必须是
干净的已提交树（clone 的 index/worktree/untracked、.git 形态与 HEAD/refs 逐项核对）；车道
clone、私有 TMPDIR 与私有 0700 pyc 前缀的 gid 等于用户主 gid；车道解释器身份与协调器一致；
每车道挂死守卫期限 `lane_deadline_seconds`（不得小于 9000 秒，即不小于下文记录的最近正式串行全量
墙钟 8,816.975 秒，车道不会因跑满该已记录的串行时长而被终止；套件增长使正式串行墙钟接近此下限时，
须先提高下限与计划期限；它不是任何测试的时限，到期后整进程组 TERM→KILL）；车道崩溃、提前退出、无 finished 记录、结果文件
缺失、fixture 错误、非成功结果；运行后 clone 的 tracked 字节变化、未跟踪且未忽略的遗留，以及 clone
未通过串行运行后的复核（与 `_one_cycle` 运行后相同：对该 clone 重新执行 `load_and_validate_manifest`
——源码清单、测试清单、部署选择器、support——再复读 `make_snapshot` 并与运行前的主 checkout 比较；
两者都能看到生产路径上被忽略的文件）；以 lane 进程组、argv 中的 lane 路径、工作目录
位于 lane 路径三种口径查到的残留进程（先在 20 秒内只观察不发信号，仍残留则记录后终止并判失败）；
车道私有 TMPDIR 或 `--sharded` 目录的 work 位于机器共享的 `/tmp`、`/var/tmp` 之下（按 realpath 与
各级祖先的 dev/inode 判定）；车道 clone 的被忽略文件出现计划 `leftover_allowlist` 未审阅的变化（新增
或原有的消失，只排除 `__pycache__/*.pyc`）。被审阅形态的被忽略文件变化与私有 TMPDIR 内容只逐车道记入
审计清单（见下文 S0 修订）。阶段 A 出现 runner 能直接检出的隔离或门禁问题（上列除「非成功结果」、
「fixture 错误」与「未审阅的被忽略文件变化」以外的任何一项）时不进入阶段 B；阶段 A 只有这三类问题时
阶段 B 照常运行，整次仍返回 1、不签证明。只表现为测试失败的隔离问题在此规则下按测试结果处理，同样不签
证明。全部通过后先删除全部 clone、私有 TMPDIR 与 pyc 前缀并核实已删除，
任一删除失败也返回 1；只有此后 runner 才按原流程复核 snapshot 与环境并原子写入批准。删除只对
unlink/rmdir 失败放开目录权限后重试，其余失败原样报告；清理中的任何异常都记为一条问题并返回 1，
`audit.json` 总会写出（ASCII 编码，非 UTF-8 文件名不会使其写入失败）。协调器的 git 调用与车道环境
都去掉继承的 `GIT_*` 变量（钩子上下文中的 `GIT_DIR`、`GIT_INDEX_FILE` 等会把 `git -C <clone>` 与
车道测试指向别的仓库；串行路径不变），只保留不指向任何仓库、只选择配置来源的
`GIT_CONFIG_NOSYSTEM`、`GIT_CONFIG_SYSTEM`、`GIT_CONFIG_GLOBAL`；残留门以绝对路径调用 `/bin/ps` 与 `/usr/sbin/lsof`。车道与
串行 `TestSuite.run` 一样在每个用例跑完后释放其实例，且从不持有未分配给本车道的用例实例。

证明合同：分片成功写入的 `full_suite_attestation` 与串行 `--all` 逐字节相同，schema、
`full_suite_attestation_is_current`、`--check --require-full`、11-load、sync、tar 与 pre-push
都不改；执行方式、计划摘要、各车道读数、遗留/残留与清理结果只写在仓库外的
`ABSOLUTE_NEW_DIR/audit.json`。`--sharded` 不能与 `--validation-only`、`--timings`、`--check`、
`--require-full`、`--list`、`--preflight`、`--watch`、`--suite`、`--list-suites`、`--changed`、
`--changed-file`、`--git`、`--git-base` 同用；REQ10C 例外的 validation-only 证明仍只能由串行
`--all --validation-only` 取得。没有任何跳过证明检查的参数。

前置条件（与串行 `--all` 相同，分片不放宽也不另加判定）：主 checkout 必须带有已 fetch 的
`refs/remotes/origin/v2`（历史 P 锚点），且 HEAD 到该锚点的第一父链无 merge、在既有上限之内；
这两项由历史 P 测试自身的 `_resolve_published_v2_anchor` 与 `_raw_v3_first_parent_chain` 判定，
缺任一项时 P 族测试在每个车道与串行中同样失败。车道 clone 由 clonefile 逐字节复制整个 `.git`
（refs、packed-refs 与对象），从不 fetch；clone 门逐项核对 HEAD 与全部 refs 与主 checkout 相同，
并拒绝 alternates/commondir/shallow/grafts，所以每个车道的 P 回放读到的是同一个本地 origin/v2。
没有 origin/v2 时 P 回放不会执行，此时的车道或全量时长不能当作分片或串行的计时读数。

启用顺序：消费者无法区分分片与串行证明，所以启用只靠落地顺序。引入本模式的提交、以及以后修改
分片机制（runner 中本小节对应代码）的提交，其证明必须由串行 `--all` 产出；只改计划分配的提交
不改变机制，覆盖等价仍由上述门禁逐次核对。在专用会话上完成预登记的「同版串行 `--all` 对分片」
至少 3 对计时与覆盖对照、并登记 REAL_ENVIRONMENT `TC-REAL-FULL-SHARD-001` 之前，本模式只作候选，
不用于正式 load、同步或发布证明。失败按本文件「全量失败」规则处理，不重跑、不放宽、不改时限。
私有 TMPDIR 与 clone 目录只是隔离手段，不是隔离证明；隔离证据来自上述门禁与专用会话对照。

S0 修订（2026-10-24，第一次真实分片运行，诊断而非证明）：

- 车道布局：S0 有 9 个用例只在分片中失败（req23 primary escrow 3、primary input window 3、primary
  temp producer 1、private metadata 1、`test_project_contracts` 的 monitor DOT held source 1）。它们都在
  「从 `/` 起登记每一级祖先目录的 stat 九元组并要求整个静默窗口内不变」的产品检查里 HOLD
  （11-load 的 b-primary escrow 与 saved optional P 复核、`b-xlsx_to_dot.py` 的 private primary
  workspace、`generate-monitor-html.py` 的 publication 路径）。S0 的车道 TMPDIR 都在 `/private/tmp`
  之下，而同时运行的 `test_load_release_transaction`（独占一个车道）在每个 `ReleaseTransactionTests`
  用例中直接在 `/tmp` 增删 `http-rt-*.noindex`；可以从调用栈定位到层级的那一例，变化的正是
  `/private/tmp`，其余 8 例只能确定属于同一族检查；同一窗口内机器其他进程也在 `/private/tmp` 新建条目，
  因此证据与「套件自身的 `/tmp` 写入」这一原因一致，但不能排除机器写入的份额。串行中这些用例与该模块
  从不重叠。修法只改布局：车道私有 TMPDIR 与 `--sharded` 的 work 目录不得位于 `/tmp`、`/var/tmp` 之下
  （按 realpath，并按各级祖先的 dev/inode，使大小写不敏感卷上的另一种拼写同样被拒），否则在任何车道运行前
  失败；测试与产品门都不改。整机其他进程改动 TMPDIR 祖先仍可能让串行与分片同样偶发这类 HOLD（串行 armG
  出现过一次），这属于运行环境前提：TMPDIR 与 `--sharded` 目录应放在一个专用父目录之下，它不被任何进程当作
  TMPDIR，运行期间也没有其他作业在其中或其祖先中新建条目。`getconf DARWIN_USER_TEMP_DIR` 比
  `/private/tmp` 安静（复审 300 秒探针：前者 1 次变化，后者 92 次），但仍是本用户各进程共用的 TMPDIR；
  共用的证据目录 `runs/` 在同一探针中变化 5 次，也不宜作 `--sharded` 目录的父目录。
- 遗留语义：串行 `--all` 的 `run_selection` 在主 checkout 与操作员 TMPDIR 中运行，只按退出码判定，
  随后 `_one_cycle` 重新执行 `load_and_validate_manifest` 并复读 `make_snapshot` 与运行前比较；它从不
  检查被忽略文件与 TMPDIR 内容，这些文件留在主 checkout 与 TMPDIR 中，后续用例与后续运行都能看到。
  分片的车道之间看不到彼此的被忽略文件，所以「只记录、不阻断」只在同车道方向上与串行等价；跨车道方向上，
  串行中较晚的用例会读到较早用例留下的被忽略文件，分片中不会。S0 与串行 armG 的实测给出了这样的实例：
  两者都留下同样的 611 个被忽略文件（4 种形态），其中 `outputs/test-diagnostics/download-parent-red-*`
  含 300 个 `*.py`，`test_monitor_writer_quiesce_workflow` 的 `ROOT.rglob("*.py")` 会解析它们——串行中
  这 2 个 quiesce 用例因此 ERROR（ROOTCAUSE G4），分片中 quiesce 在另一车道、通过。分片据此规定：
  tracked 变化、未跟踪且未忽略的文件、clone 未通过同一串行运行后复核（tracked 未变时才在协调器中执行该
  clone 的部署选择器，执行前后恢复 `sys.path`）是门禁问题；车道 clone 的被忽略文件变化（新增或原有的消失）
  必须匹配计划 `leftover_allowlist` 中经审阅、写明理由的形态（`fnmatchcase`，`*` 可跨 `/`；首个路径
  组件必须是字面量），否则作为不签证明的非门禁问题（阶段 B 照常运行）；整树遍历或串行源码发现会读的
  形态（`*.py`、`*.sh`、`*.cgi`、`*.service`、`*.timer`、`02-AIR-devices_config.csv`）位于 runner 的
  非源码根（`NON_SOURCE_ROOTS`：`.git`、`outputs/`、`.codex`、`.agents`，以及 `.codex_tmp*`）之外时，即使在审阅过
  的目录下也永远不算审阅；位于这些根之内时，与其他形态一样只凭经审阅的模式放行（整合修订 F6：串行源码发现
  本来就跳过这些根，A 批之后测试侧的整树遍历改走 `governed_tree_paths`，也不进入它们）。匹配的变化与私有
  TMPDIR 内容只逐车道记入 `audit.json` 的
  `leftovers`（`ignored`、`ignored_removed`、`unreviewed`、`tmpdir`，各为排序后的路径、个数，以及以 NUL
  连接的文件系统字节的 sha256），成功时随 clone 与 TMPDIR 一并删除。当前计划审阅
  `outputs/test-diagnostics/` 下的两棵保留夹具树 `collector-prefix-feedback-*` 与 `download-parent-red-*`，
  依据是对 `test_cases/*.py` 全部 302 个文件的静态普查（没有测试列出或通配临时根目录；整树遍历只有 4 个
  模块——quiesce workflow 的 `*.py`、`test_test_case_repository` 的 `test_*.py`、`test_project_contracts`
  的 `02-AIR-devices_config.csv`、`test_ztp_monitor_watch_runtime_workflow` 的 `*.service`/`*.timer`——A 批
  之后都改走 `governed_tree_paths`，不进入 `outputs/`），以及整合修订 F6 对产品代码的静态普查（156 个文件）：
  会进入 `outputs/` 的只有打包的特殊节点检查（对普通文件、目录、符号链接不做任何记录）、打包打印的工作区
  大小、README 目录（`outputs/` 路径在读取前就被排除）和 finish-project 的容量普查（测试从不在真实 checkout
  上运行它），都观察不到这两棵树中的条目。A 批之前 quiesce 会解析 `download-parent-red-*` 中的 `*.py`
  （ROOTCAUSE G4），那时它不能审阅。`.deployment.lock` 与
  `monitor/.generate-monitor-html.lock` 不审阅：测试经产品打包代码遍历 checkout（例如
  `test_upload_package_contract` 断言 monitor 锁不被打包），串行在该用例之前已由别的用例建出锁，所在车道
  却可能没有，断言的检出力因此不同——用正确代码两臂都绿，排除规则回退时却会串行红、分片绿，专用会话
  对照发现不了。所以分片运行前主 checkout 必须已有这两个空的被忽略文件（正式 checkout 在真实 load 后本来
  就有），这样串行与每个车道从第一个用例起看到的相同，车道也不再「新增」它们；缺少时车道新建它们，按未审阅
  变化拒签。普查只覆盖测试源码直接列目录或整树遍历的口径，经产品代码间接遍历 checkout 或扫描临时根目录的
  情形没有穷尽（上面的打包即是一例）；就地改写已有被忽略文件（名字集合不变）也看不到。这两类是残余风险：
  审阅新形态时要先查产品代码中的遍历，专用会话对照只能发现两臂结果不同的情形，发现不了只影响检出力的差异。
- 阶段 B：串行有测试失败时仍跑完全部测试。分片只在阶段 A 出现 runner 能直接检出的隔离或门禁问题时
  跳过阶段 B；阶段 A 只有测试结果失败或未审阅的被忽略文件变化时阶段 B 照常运行，整次仍返回 1、不签证明。
  `audit.json` 的 `non_gate_problems` 只含非成功结果、class/module fixture 错误、记录一致（finished 为不
  成功且退出码为 1）时的退出码、被 setUpClass/setUpModule 错误挡住未运行的行（记为 `errored_ids`，与串行
  unittest 相同）以及未审阅的被忽略文件变化；其余全部问题都列入 `gate_problems`。任何一类问题都使整次失败。
  车道遗留门中的意外异常记为门禁问题，不会中断该阶段的残留门。
- 计时：审计 schema 改为 `http-full-shard-audit/2`。每车道保留 `started_epoch`、`ended_epoch`、
  `seconds`，新增同值的 `wall_seconds`、`prepare_seconds`（clone、clone 门与被忽略文件扫描）、
  `gate_seconds`（车道结束后的遗留与 snapshot 门），以及车道自报的 `lane_tests_started_epoch`（发现完成、
  开始运行用例）与 `lane_finished_epoch`；阶段级新增 `phase_a/b_started_epoch` 与 `phase_a/b_ended_epoch`；
  `chain_drift` 记录每阶段前后共享车道根（临时父目录与 work 目录）从 `/` 起各级 stat 的变化，只用于
  归因，不作门禁。

### 2026-10-09 再审与候选判定

> 合入 DEV 注（2026-10-25）：本小节原文是 http-test 树（TEST）上的判定记录，表中读数、日志与 SHA256 都是 http-test 的历史证据，DEV 没有运行这些测试。表中「已落地」指 TEST 树：在 DEV，「精确 proof 复用」与 pre-push 门没有随本批合入（随 11-load 批另行裁定），macOS load 仍按 AGENTS.md 现行合同执行全量测试；本批合入 DEV 的是 invocation-local catalog（M04）、Git 不可变对象批量读取（M03）与 collection worker 早退出唤醒（M02）。表中「纯编译结果缓存」一行的 module_loader 部分（`_compile_source` 的 `lru_cache(maxsize=8)` 与 `_ExactSourceLoader`）随 initial-setup 批合入，本合并树已含（`test_cases/module_loader.py`）。TEST 的 validation-only 逐案例计时接口（9ef98fa）没有合入 DEV，本表不列。

再次核对的执行链为：真实部署选择器/完整 manifest → 源码、测试与 support snapshot
→ 选测/环境/只读 Git 与 loopback preflight → 原 canonical unittest discovery
→ 成功后重读 manifest/snapshot → 环境复核 → 原子 ledger 发布及发布后复核/失败回滚。
每个重核边界有独立的漂移/失败合同，不能把同一次读取跨测试或提交边界复用。

| 候选 | 同工作量证据或边界 | 本轮决定 |
| --- | --- | --- |
| 单次 manifest 的测试目录发现 | 五轮交替；同一工作树的完整 manifest 和 snapshot 相同；184 次扫描变为 2 次，中位数 0.379906→0.115989 秒 | 落地 invocation-local catalog；每条引用仍实时检查 regular/non-symlink，结尾全目录重扫；不跨运行缓存 |
| Git 不可变对象批量读取 | 已提交最终字节的三轮交替：69 叶/68 OID，blob child 69→3；1.030374→0.060535 秒；路径/模式/OID/字节相同 | 已落地；不放大固定 32 对象上限、不改历史源码 |
| collection child 的早退出唤醒 | 已落地的 bounded wait；原取消、清理、总 deadline 保留 | 保留；不缩短真实超时或删除等待负例 |
| 精确 proof 复用 | load 先 check，只有 4/5 full；项目输入不进入代码 proof；sync/package 不重复 full | 已落地；保留操作末端逐字节检查，不把安全错误当 cache miss |
| 两个轻量模块并行 | 11 原案例/三轮交替；native 限制实验单进程 0.408341 秒，双 worker 0.395331 秒，双 worker 串行 0.683555 秒 | 不接入正式 runner；约 13ms 不证明 full 收益，不能用双启动的串行值夸大基线 |
| 单文件 SHA 缓冲区调整 | 462 条 regular 路径、七轮交替、每条摘要相同；1MiB/64KiB/16KiB 中位数 0.068527/0.070711/0.070280 秒 | 保持 1MiB；另外两种实测更慢 |
| mtime/stat 驱动哈希缓存、alias 合并 | proof 必须发现同 inode/mtime 的 ABA、链接及来源变化 | 不采用；不能用 metadata 替代原字节检查 |
| 复用已导入生产模块或修改导入路径 | module loader 保留 fresh module 与生产模块 lazy import 路径；当前 manifest profile 的三个 selector 加载合计约 0.040 秒 | 不缓存模块/namespace；下方纯编译结果缓存是独立方案，不复用运行对象 |
| 纯编译结果缓存 | 五轮交替，每轮真实 LOAD/SETUP 共 12 次 fresh import；完整函数 code 字段相同；0.595356→0.123089 秒 | 每次重读源字节，最多 8 项、单源 2MiB；只缓存 code，每次重新执行新模块；不读取或写入磁盘 pyc |
| 历史 P replay 合并、删掉重复 case ID | 固定历史 SHA、原 fixture/进程边界和 discovery 出现次数是被测合同 | 不采用；不以优化改写历史合同或去重真实执行次数 |
| 移除 fsync、批间身份校验或发布末端重核 | 冷恢复、unknown-object 保留、held-FD/权限和可回滚证明依赖这些边界 | 不采用；不削弱恢复能力换速度 |
| 并行 SHA、扩大有状态 suite 并发 | 当前普通 SHA 阶段约 0.1 秒；固定历史回放、共享锁/项目与真实 loopback 的完整隔离尚未证实 | 不引入线程/进程池；小工作量不抵启动/调度成本，重型 suite 不因名字而获隔离资格。2026-10-23 起唯一例外是上文「opt-in 两阶段分片全量」小节的 `--all --sharded`：受管计划、私有 clone、覆盖等价与全部门禁，候选状态，默认串行不变 |

这不是对 full 总耗时的同比承诺。最近普通正式基线为 5,578 tests / 8,816.975 秒 /
OK (skipped=5)，而新候选增加独立测试；整体比较须列出版本、工作量与运行条件变化，
不能把不同测试数的墙钟差归因到 manifest 微基准。当前 runner 变化按既有 path rule
要求 canonical full；执行显式 `--all -v` 会同时覆盖受影响 direct/workflow 并由 runner
自动签发精确 full ledger，不再先为同一候选重复跑一轮隐式 full。

新 catalog 的原字节 RED 两项均为 2 != 184；原失败输出保留于
`outputs/test-diagnostics/catalog-original-red.log`，SHA256
`7e4e71ff962fff50f29976335d09b8318548c947c78a981a4c5a074245f60c05`。
direct、真实 sync/image/archive 三个选择器的 CLI workflow、陈旧叶子拒绝和末端
inventory 漂移拒绝均保留；三个治理模块共 102 tests / OK / exit0，日志
`catalog-modules-green.log` SHA256
`36e3e440faf3d37013efc83ff877f924184ee8707dd77108142c7c46180b85e6`。
五轮 catalog 微基准 `catalog-paired-benchmark.log` SHA256
`4f23b546c3b2479142c7ff08188a74600d6b3d409a54e7924427aa5128754780`；
SHA 缓冲区诊断 `hash-buffer-benchmark.log` SHA256
`24684c280451447d2f223241da75031632c4177745d110c4c3d3a3bda5e83c63`。
这些是诊断证据，不签发批准；正式状态只看最终源码提交、自动 ledger 和当前 full/check。
AIR simulation 必须验证最终同版 receipt/源码和项目身份，不能用本机 fixture 或历史跳板
示例代替当前目标确认，也不因本次优化批准生产部署、服务切换或网络写入。

### 2026-10-09 当前源码执行与纯编译缓存

> 合入 DEV 注（2026-10-25）：本小节取自 TEST b92f554，只保留 (a) 当前源码执行修复（runner 与 `test_runner_preflight`，本批合入）与 (b) 纯编译缓存（`module_loader` 与 `test_module_loader_contract`，M05 性能部分随 initial-setup 批合入）的合同正文；M06 私有 HTTP fixture 退出轮询没有合入（随 XC-1A 组）。

实测发现 `-B` 只阻止 pyc 写入，并不阻止读取时间戳有效的旧 pyc。同长度源码改写后
恢复 mtime，原 loader、canonical discovery、测试的生产依赖、部署 selector、clean
authority 及 runner 启动的 project contract 都能执行旧值。先保留独立字面预期的 RED，
再修实现；不能以 source snapshot 正确推断执行的代码也正确。

共享 loader 每次通过 SourceFileLoader 读取当前源字节，以完整 bytes、实际 filename 和
optimization 为 key；有界 LRU 只保留不可变 code，超过 2MiB 的源仍正常编译但不缓存。
每次保持原 ModuleSpec、package 信息、fresh module/globals/classes，以及生产模块声明的
lazy import 路径。删源、同 metadata 改源、坏语法、编码/future flags、路径差异、驱逐及
大源不缓存都有独立 direct；不缓存已导入模块、执行结果、文件 metadata 或可变对象。

runner 的 selector/clean authority 直接编译当前 bytes。同步治理依赖导入使用一次性私有
字节码 namespace 并恢复原 sys.pycache_prefix；ordinary 与 validation-only 测试子进程
各获唯一、空、0700 缓存目录，原 argv/discovery/环境版本闸门、stdin 隔离及精确例外不变。
原 operator cache 和环境变量不删除、不覆盖；正常结束及 child 创建异常均清理自有目录。
这不承诺任意同 UID 恶意写者隔离或在长驻进程中热重载所有已加载依赖；正式 proof 仍用
当前提交的新 CLI/测试进程，保留每个原字节与环境重核、fsync 和 ledger 回滚边界。

以下为 http-test 的历史证据（TEST 树上的 RED/GREEN 与基准；DEV 没有运行这些测试，不能当作 DEV 的证明）：

原 loader RED：`exact-source-loader-red.log`，9 tests / 2 FAIL / exit1，SHA256
`cc224cbdb06ba0cabcc2cd7f60ad1bf7260fb8ceee024a3f0fd41ff5e29fcd91`。
runner RED：`proof-source-bytecode-red.log`，4 methods / 6 FAIL（含 subtests）/ exit1，
SHA256 `70132719bba43a376ae3faa7427926fd4fa50d9aef69c4d22c10b44308dd7774`；
依赖补充 RED：`proof-source-dependency-red.log`，7 methods / 2 FAIL / exit1，SHA256
`030fef8ab5a4e619e85570db5667a4f420e5adb4660e21dcac5e26e2319fe625`。
治理、发布门禁、loader 与真实 R22/REQ23 workflow 六模块最终诊断回归为 402 tests /
2707.341 秒 / OK / exit0，完整日志 `proof-source-dependency-green.log`，SHA256
`e04072889aa448e1071a948ad96e95df6063383166f8b881dd74efda546737d7`。
此局部回归不签发整树 proof。

纯编译五轮基准 `exact-source-loader-paired-benchmark2.log`，SHA256
`f9c469f1d6f670b3499a6e368ec73cc93c9f13265a067c6de73069e56d647001`；
每轮含两个 cold compile 和十个 hit，同一空 pyc namespace、先预热两侧依赖、每次新模块，
源码/ledger 不变。首次诊断使用 marshal 序列化当 code canonical oracle 而失败；完整
`exact-source-loader-paired-benchmark.log` 原样保留，SHA256
`86b1157e4455d4a2a015bfadda2763f83cefc913ea898d0a351228d75f1d5cd4`。
调查确认序列化的 interning/reference 编码不同，而所有非 callable co_* 字段及嵌套 code
相同；最终比较全部这些字段，不删除或放松受管测试断言。

### 2026-10-08 当前 source guard 的不可变对象批量读取

> 合入 DEV 注（2026-10-25）：本小节原文是 http-test 树（TEST）上的记录；RED/GREEN 日志、模块回归计数、微基准与 SHA256 都是 http-test 的历史证据，DEV 没有运行这些测试。DEV 只合入 source guard 的批量读取实现与其 direct/workflow 测试，没有合入 TEST 本节前文对「Full proof 性能诊断记录」引言段的改写。

独立 direct 与真实 Warden→source guard→export/manifest→held export 流程先 RED：
69 个叶子/68 个唯一对象的字面夹具在旧实现触发 69 次 blob 子进程。
新实现最多每批 32 个唯一完整 OID，闭合 stdin 后执行有限 `cat-file --batch`；
只合并对象读取，保留全部路径、模式和 symlink。空树不启动 blob 子进程。
逐帧校验 OID、blob 类型、规范长度、分隔符、完整消费和原 SHA-1/SHA-256 Git 摘要，
拒绝重复/额外/错序/损坏/截断帧。真实 SHA-256 私有仓库也保留全部路径与对象身份。
可信 Git held FD、封闭环境、repo/Git 名称前后身份校验、原 30 秒 child deadline 不变；
批间改绑也在下一 child 启动前拒绝。所有对象验证在创建 destination 前完成，
第二批损坏、child 非零和身份漂移不能发布部分 export。

RED 完整日志 `outputs/test-diagnostics/git-batch-red.log` 的 SHA256 为
`63a6292bb42b423114de84b049ee9dad30e0a3a7fae1754ca03fdf49cd8612c6`。
三个相关模块诊断回归 124 tests / OK (skipped=1) / exit0，日志
`git-batch-modules-green.log` SHA256
`7d51b16d6c165b465bfc45c85e4ea46409b771e25342e32a15c20813591c0e83`；
这不代表正式 related/full，也不证明 Linux/root 真机流程。
同树三轮交替微基准绑定基线 HEAD `2a7e046d05c3cc5e8d5321f19666eb75a04e8048`，
读取 blob child 69→3（全部 Git child 70→4），独立核对路径/模式/OID/字节摘要相等。
当次中位数 1.118547→0.066909 秒；完整诊断日志
`outputs/test-diagnostics/git-batch-paired-benchmark.log` SHA256
`988407d57dcc4f5a805fe8cab7b98540d77eb641c03d148359f90734b4f6f354`。
只报告这个操作的微基准，不推算 canonical full 的总收益。补充 SHA-256/child 拒绝
测试最初有语法笔误，原失败日志保留为 `git-batch-sha256-refusal.log`，
修正语法而不改预期后通过；正式证明须覆盖最终完整测试字节。
补充后的三个模块与文档回归 174 tests / OK (skipped=2) / exit0，日志
`outputs/test-diagnostics/git-batch-final-modules-docs.log` SHA256
`8734b620c497614f80e348c5fd5bf7668ec56c7c54e724ee15a6a90776bd13e1`。
正式批准状态仍以最终 committed bytes、runner 自动 ledger 和 full/check 为准。

批量读取尚不授权 root 流程执行或部署：同版 Linux/root held-FD/namespace 场景仍需
按 REAL_ENVIRONMENT 原卡代表性验证。并行 suite 仍未启用；必须先证明实际独立资源、
完整出现次数/fixture 顺序与故障收敛，并在空闲同版环境测到收益，不能把逻辑 suite
分类或临时目录名称当作隔离证明。（2026-10-23 修订：opt-in `--all --sharded` 以覆盖等价、
fixture 拆分门、阶段 A 失败不进阶段 B 与遗留/残留/清理门实现前三项，收益与原超时余量由
`TC-REAL-FULL-SHARD-001` 的专用会话同版对照闭合；闭合前只作候选。）

隔离并行的诊断试验仅选已读取的两个轻量模块（snippet 8 案例、normalizer 3 案例），
独立保留全部 11 个字面 case ID、原断言、private cwd/TMPDIR；Python audit 拒绝文件
写入、子进程、网络及信号副作用，但不能宣称覆盖 native syscall 或完整 OS 隔离。
初次封闭 worker 缺少原运行时 PyYAML，原错误日志保留；明确绑定父进程的绝对 import
paths 后才比较同环境工作量，未更改测试预期或安装依赖。三轮交替测得单进程端到端
中位数 0.388255 秒、双 worker 并行 0.376937 秒、双 worker 串行 0.649919 秒，
而这些案例的纯执行仅约 0.006 秒。并行对单进程的约 0.011 秒差异不证明 full 收益，
更不能用人为双 worker 串行的启动开销作夸大基线。完整诊断
`outputs/test-diagnostics/parallel-gate-same-runtime.log` SHA256
`e08621640d23ba68ca522bf6849d4e6d2e23ba87ab3358d428933841234acb6f`。
据此本轮不把 `--jobs` 接入治理 runner；并行实现仍未落地，后续若识别可观的可隔离
重型 workload，必须先闭合传递来源、资源/原超时、canonical 重复出现次数、fixture
顺序及 worker 崩溃/报告缺失/清理失败门禁，再 tests-first 实现和同版 full/check。
（2026-10-23 修订：`--jobs` 仍不接入；opt-in `--all --sharded` 已按上述门禁 tests-first 实现，
见上文同名日期小节；引入它的提交由串行 `--all` 签发证明。）
此诊断既不产生批准，也不改变既有串行套件、历史 P 或外部验收。

### 2026-09-29 第二轮：collection worker 的结束唤醒

> 合入 DEV 注（2026-10-25）：本小节的计时文件、耗时与收益都是 http-test 的历史证据，DEV 没有运行这些测试；DEV 上的验证见合并窗口记录。

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

## 2026-10-23 HO-7：handoff run_workflow 每次 run 私有的 stdlib pyc 命名空间

> 合入 DEV 注（2026-10-25）：本节原文是 http-test 树（TEST）上的记录；所列 RED/GREEN、计时与收益都是 http-test 的历史证据，DEV 没有运行这些测试。DEV 合入时 run_workflow 保留 DEV 的 `run_workflow_process` 抽取与 `_fixture_environment`（darwin 上另含 `PYTHONEXECUTABLE`），外层套 `private_stdlib_pycache()`，并带入 cb40cfa 的 `_temporary_environment` 与 fixture-tmp；DEV 上的验证见合并窗口记录。

范围只在 `test_collection_cycle_handoff_workflow.run_workflow` 启动 BOOTSTRAP 时传入的
fixture env；`test_eth_activity_cycle_handoff_workflow` 经同一 helper 同样使用。生产脚本、
runner、`module_loader`、manifest 与任何既有断言都不变。fixture env 没有 HOME，macOS CLT
Python 因而没有可读的 pyc namespace，链路里每个 Python 进程都会把同一批 stdlib 从源码重新
编译一遍；HO-7 只消除这部分重复编译。

每次 `run_workflow` 调用新建一个 `tempfile.TemporaryDirectory(prefix="handoff-stdlib-pyc-")`：
属主为当前用户、0700、新建时为空，位于 TMPDIR，不在 fixture root、仓库或 runner 私有缓存之内。
随后由一个 `sys.executable -I -B` warm 子进程（env 只有 PATH：不读 PYTHON* 环境、没有 HOME、
不读取任何既有 pyc namespace）导入 35 个字面 stdlib 顶层模块，并且只为源码位于本解释器 stdlib
目录、不在 site-packages 下的已导入模块，从当前源字节编译 CHECKED_HASH pyc。父进程再逐项
校验：每一项必须是真实目录，或常规、无优化标记的 `.pyc`；映射回的源必须是 stdlib 内的常规
文件；magic 等于本解释器；flags 恰为 0b11（基于哈希、每次导入都校验）；头部源哈希等于当前源
字节的 `importlib.util.source_hash`。校验通过的清单（目录及每个文件的 SHA-256）绑定本次 run。
BOOTSTRAP env 只多 `PYTHONPYCACHEPREFIX` 一个键；`PYTHONDONTWRITEBYTECODE=1` 保留，HOME 仍不提供。

失效方式不依赖 mtime/size：链路子进程导入时，CPython 按 PEP 552 读取当前源字节重算源哈希并
与 pyc 头比较，不一致即从源码编译且不写回。仓库与 fixture 副本从不进入前缀（子进程只读不写，
任何新增文件都会使本次 run 失败），所以始终按当前字节编译。正常返回后重算清单，与运行前不同
（新增、删除或改写任一文件）即 AssertionError，fail closed；返回或抛出（含超时）时都删除前缀。
run 之间不共享、不复用、不持久化。

与既有条款的关系：上文「纯编译结果缓存……不读取或写入磁盘 pyc」约束的是共享 loader 与 runner
selector/clean authority 的进程内 code 缓存，HO-7 不改动它们；runner 给测试进程的「唯一、空、
0700」私有缓存也不变，HO-7 不写入它（新测试断言前缀在其外）。与已否决的「共享 checked-hash
stdlib pyc 预热（可伪造缓存 code）」及「磁盘 pyc 预热暂不采用」的区别：不共享、不跨 run 持久化，
没有可预埋的长期位置；pyc 只来自本 run 刚从当前源编译的字节，warm 不读取任何既有 pyc；父进程
逐项校验并绑定清单，run 中的任何改动都会让该 run 失败；只覆盖解释器 stdlib，不缓存任何仓库
代码。残余风险如实记录：CHECKED_HASH 只绑定源字节、不绑定 code 本体（新测试的已知为真对照
显示，哈希匹配的 pyc 会按原样执行）；同 UID 写者若在 run 期间改写 pyc 并在结束前恢复，事后
检测不到。这与上文「不承诺任意同 UID 恶意写者隔离」是同一威胁模型。

tests-first：同一模块新增 7 个 direct 用例（共享前缀且 stdlib 源码编译为 0、指向空私有前缀的
已知为真对照会编译；超时时删除前缀；每次 run 一个新前缀且不跨 run 存活；run 中新增文件或改写 pyc 时
fail closed；fixture 源同尺寸改写并恢复 mtime 后仍读到新值，可写 timestamp namespace 对照读到
旧值；stdlib 旧哈希 pyc 被忽略，哈希匹配的伪造 code 会被执行（对照）；前缀校验器拒绝空前缀、
timestamp、unchecked、旧哈希、非 stdlib、非 pyc 与 symlink）。
RED 在只含测试的提交 `9c7fd30` 上运行：7 个新用例单独运行 Ran 7、`FAILED (failures=8)`（其中
一个用例有 2 个子测试）、0 ERROR，8 个 FAIL 块都含 `HO7-RED-MARKER`；日志
`p1c-red-green/00-red-new7-treeR.log`，SHA256 `61a8b6c8d9b404e7d149c8697dc9111d829fd5b84de5dfc8dcc593301e2e913f`。
同一提交的整模块 Ran 35，原 28 个用例 ok，非成功的恰为这 8 个 FAIL；日志
`p1c-red-green/01-kbase-handoff-module-treeR.log`，SHA256
`d13c6e6ec6a6ca625da36b07fbf632bd9400d59e4f30990e6298d341a4fba59f`。GREEN 在实现提交 `dde76f7` 上运行：
整模块 Ran 35 / OK，日志 `p1d-green/00-green-handoff-module-treeB.log`，SHA256
`dacaff478500bf25aa385f0b79364ecb117e73adac07be74ee64835b8978ba78`；`test_eth_activity_cycle_handoff_workflow`
Ran 1 / OK，日志 `p1d-green/01-green-eth-activity-treeB.log`，SHA256
`34c462953f466637f0378e8651e861224498bb85b53f7deb88d3525baca4c918`。日志位于 `<http-test HO-7 evidence directory devHO7-evidence>`（仓库外）。这些运行使用
CLT Python 3.9.6、`-B -m unittest -b -v`、私有 TMPDIR 和每步新建的空 0700 `PYTHONPYCACHEPREFIX`；
运行期间另一个 full 在跑（load 6–16），所以只作正确性证据，不作计时。收益量值目前只有 lab 读数
（PROP-04：确认复跑 E2 = 1.032 s/run，n=24，已扣 warm；原读数 0.819 s/run，n=12；按每次 full
约 47 次 run 推算约 48.5 s/full），这不是本树的 full 证明。本树在 lab 版之上新增的父进程逐项
校验与结束复核未计入该推算；在负载下单独测得校验约 0.02–0.2 s/run，取决于新写的 pyc 是否
已被打开过（本机首次打开新写文件明显更慢，校验把这部分成本从链路子进程移到了父进程）。
收益还要求 `sys.executable` 与链路经 PATH 找到的 `python3` 是同一个解释器（本机 CLT 3.9 满足）；
如果测试解释器换成自带 stdlib `__pycache__` 的其他 Python（例如 3.12 venv），链路子进程不会
受益，而 warm 与前缀会使 BOOTSTRAP 变慢，正确性不受影响。

runner 选测：只改该测试模块时，runner 选 baseline 4 个模块加本模块；runner 不追踪测试模块之间
的 import，所以 `test_eth_activity_cycle_handoff_workflow` 要另行加跑。本文件的改动在 runner 中
属于未知路径，按规则要求 canonical full。以上运行都是诊断，不签发批准、不改 ledger；正式状态
只看集成后的 full/check。

## 全量计时诊断：`--timings`（2026-11-06，v3.1.0 从 TEST 合入）

> 来源：TEST `99445b4`（`validation_unittest.py` 的逐测试计时）和 `9ef98fa`（runner 透传）。TEST 原文写在本文件另一处的段落和 `FULL_PROOF_PERFORMANCE.md` 里，DEV 的本文件结构不同，合在这一节。它只增加测量能力，**不是提速**。

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
不得因计时输出修改已知 FAIL 判定或 proof 的输入输出。

在没有并行 full proof、且当前 checkout 可供测试创建临时制品时，也可以单独运行一次诊断
（不执行正式 runner 的 preflight/approval 流程，不更新 ledger）：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B -m test_cases.validation_unittest \
  /tmp/http-full-result-UNIQUE.json -v \
  --timings /tmp/http-full-timings-UNIQUE.jsonl
jq -s 'sort_by(.duration_seconds) | reverse | .[:20]' /tmp/http-full-timings-UNIQUE.jsonl
```

两个路径都不能预先存在。诊断命令的非零退出码和结果 JSON 中的 FAIL/ERROR/SKIP 必须如实保存。
记录诊断时同时保存命令、UTC 时间、当前 HEAD、Python/平台身份、结果 JSON、计时 JSONL、
`Ran ... in ...` 摘要，以及是否有其他重型进程；先核对 JSON 的 `tests_run` 等于计时行数且
测试 ID 无重复，否则不能形成新基线。

性能优化的判定（原 TEST `FULL_PROOF_PERFORMANCE.md`，该文件已并入本节）：

1. 先按逐测试与阶段耗时确定当前可修改的热点；固定历史重放（`@_historical_p_method`）
   不会因当前源码的小改动变快，不得为提速改写历史锚点、跳过重放或弱化断言。
2. 对候选热点做小范围前后微基准，确认确实降低总墙钟；不根据文件行数、`sleep` 计数或
   CPU 核数推算收益；记录同一机器、解释器和负载条件。
3. 实现前独立写好正反测试；保留完整测试集合、身份与内容核验、恶意改写/竞态负例、
   异常处理和相同的 FAIL/SKIP 语义；任何新 ERROR、额外 SKIP 或映射缺口都阻断采用。
4. 批准账本始终只有一个写者；不得以多个 runner 并发写 ledger 来「加速证明」。
   分片全量（`--all --sharded`）是 runner 自己的单写者模式，见本文件的分片章节。
