# IBSW Upgrade 开发测试交接

交出方：codex dev。接收方：由 owner 指定的 codex test 会话。
日期：2026-10-19。源码基准：`9bf7abc84ec66001f6a51af104b23df56a7b7e64`。

上述是原始集成基准，不包含全部后续修复。固定布局、缓存模板／runner 门及
固定 registry 的 imported-object 身份修复已于 2026-10-20 随 `f7456dd` 进入主树。
接收方须按该提交、后续工作列表及下列闭包逐文件核对，不能仅 checkout 原始基准
便当作已经继承；这些修复不启用 SCP，也不构成设备或发布验收。精确 SHA、命令和本地证据登记在主树
`outputs/req19-local-evidence-20261007/ROOT-IBSW-FIXED-LAYOUT-MAIN-LANDED-20261020.json`；
下列旧收据各自保留其原始代码与测试 epoch，不追认为当前整树证明。
此前逐步修复的历史记录见
`outputs/req19-local-evidence-20261007/ROOT-H-CONTAINMENT-MEMO-IB-LAYOUT-V4-20261019.json`。
随后 cached executor 原 runner 绑定修复及本轮证据另见
`outputs/req19-local-evidence-20261007/ROOT-H-LITERAL-FORMS-IB-CACHED-RUNNER-20261019.json`。
固定 registry 的 transitive cached-object 身份修复另见
`outputs/req19-local-evidence-20261007/ROOT-H-EXPRESSION-IB-TRANSITIVE-CACHE-20261020.json`；
包含真实 canonical/flat alias 正控、混合来源初始 RED 和原组件工作流回归。
范围选择／known-hosts 及三个历史流程的 IO 夹具一致性修复另见
`outputs/req19-local-evidence-20261007/ROOT-H-COMPREHENSION-IB-IO-COHERENCE-20261020.json`。
NVOS 历史观察／派发前失败的 IO 夹具接线，以及新增测试的精确 discovery 登记见
`outputs/req19-local-evidence-20261007/ROOT-H-OWNED-BOUNDARIES-IB-LEGACY-COMPAT-20261020.json`。
当前入口下三组件／金丝雀／未选状态隔离，以及 OS 链与固件 OS 前置的五项原流程证据见
`outputs/req19-local-evidence-20261007/ROOT-IBSW-CURRENT-COMPONENT-WORKFLOWS-PY312-20261020.json`。

IBSW 2.25 的运行代码、HTTP-only 入口、共享运行锁和本地测试已集成进 http 主树。
本交接供 codex test 继承到自己的代码目录并继续独立验证；不是发布许可或真机验收结论。
本功能不依赖 REQ7 初始化完成，但使用共享 tools 模块，不能只复制 `upgrade.sh`。

## 继承范围和目录布局

当前主树为 `/Users/joeyyang/Desktop/http`。先阅读本仓 `AGENTS.md`、本目录
`README.md` 顶部“当前入口”部分及本交接；README 分隔线以下是旧 shell 历史，
其中 SCP/local/HTTPS 菜单和旧参数不是当前合同。

优先在接收方的新目录保留完整仓库布局和上述提交，再对照自己的修改逐项整合。
不要把开发主树整体覆盖到已有脏目录，不要用旧 `ib-upgrade2` 原件倒盖当前修复。
本轮没有创建或覆盖 codex test 的目录；接收目标由 owner 与该会话确定。

运行闭包是原 17 个成员加共享 guard，共 18 个文件：

```text
infiniband/bringup/xdr-upgrade/
  upgrade.py
  upgrade.sh
  upgrade-component.sh
  upgrade-owned-runner.sh
  requirements.txt
tools/
  ibsw_upgrade_contract.py
  ibsw_upgrade_inputs.py
  ibsw_upgrade_schedule.py
  ibsw_upgrade_component.py
  ibsw_upgrade_driver.py
  ibsw_upgrade_executor.py
  ibsw_upgrade_observer.py
  ibsw_upgrade_access.py
  ibsw_upgrade_pipeline.py
  project_contract.py
  _package_common.py
  ssh_key_preparation.py
  ib_bringup_runtime_guard.py
```

上表是运行源清单，不是完整开发测试包清单。测试继承还须保留：

- 全部 `test_cases/test_ibsw225_*.py`，不要只拿本交接列出的抽样模块。
- 整个 `test_cases/ibsw225_fixture_support/`、其导入的测试辅助模块与所需 fixtures。
- `test_cases/script_test_manifest.json`、`REAL_ENVIRONMENT.md`、测试治理说明及必要的
  共享测试。批准 ledger 可以作为历史材料保留，但不能手改或当作新目录的有效证明。
- 初始化入口 `infiniband/bringup/xdr-initial-setup/initial-setup.py` 及共享接线测试。
  若验证生成、包装或部署接线，也必须继承相应生产者及生命周期代码，不能只验证升级子目录。

入口支持 canonical 仓库布局和完整 flat siblings 布局；选定布局缺依赖必须拒绝，
不能到另一棵树兜底导入。首次接收建议保留仓库布局。若另做 flat 制品，须重新核完整闭包、
真实导入来源和相应测试，不把这份目录清单当成已经制作并验收的 flat 制品。

### 固定布局与模板 ABI 增量

完整 flat 目录名可以是 `tools`；不能仅靠目录 basename 判断模板位置。
当前 `ibsw_upgrade_contract._fixed_layout` 供 component、executor 和入口共享。
继承时须逐项整合同一版本的 `upgrade.py`、contract、component、executor；
不能只拿新 component 配旧 contract。入口每次返回 driver 前重核布局，component 每次
读模板前核它与初次选择一致；executor 同样固定导入时的原 `_RUNNER`，每次读取前
重核完整布局仍与原路径一致，不能缓存后静默切到另一套完整布局。
这补上 V4 仅重算当前 runner 布局的缺口；严格源码 inverse 同时覆盖初始绑定与读取门，
原 13 项冻结哈希不变，不能将旧 V4 executor 形态作为另一种通过条件。
固定 canonical 入口与其 `tools/upgrade.py` 同时存在属于歧义，两个入口在加载运行包或渲染时都 HOLD；
原 sole `--help` / `--version` 仍仅作本地信息查询，不构成操作放行。
缺件或缓存后的布局变化也 HOLD，不自动删入口、补文件、切树或取备用模板。
入口另核固定 runtime registry 的消费者保留的 module/function/class 对象身份，
拒绝跨布局或重导入遗留的 stale bindings；真实 alias/re-export 必须仍是 provider 的
同一原对象（`is`），不凭同名通过。该有限审计不等于任意 Python 对象或闭包安全证明。
测试继承时，模拟 IO 须在明确的 provider／consumer 接缝共享同一对象；单边替换可能
在真实入口前触发身份 HOLD，不能为恢复测试而给 mocks 加生产豁免。范围选择、
known-hosts 和历史只读／连接失败／已达目标流程的原安全断言均保留。
派发前失败流程仍须保留“观察会话成功、执行会话失败”的区别；只共享本来相同的
SDK／读取模拟，不能为了身份一致而合并不同故障阶段。NVOS 历史观察也保留原始
解析失败、命令失败和输出脱敏断言。fixture helper 不是正常 discovery suite；
对 helper 的定向实际执行与仅发现正常测试身份必须分开记录，不混算验收数量。

独立离线证据见 `test_cases/test_ibsw225_flat_tools_layout.py`；包含冷解释器真实
entry→driver→executor 渲染、双入口、缺模板、缓存后冲突和布局变化，不调用 operational main。
源码继承还须保留 runtime source contract 的严格 literal-hunk 逆变换：原 13 项
`FROZEN_SHA256` 与 access inverse 未改，不接受增加新 hash、跳过文件或隐藏 hunk 外漂移。
这些局部测试不是完整设备升级、远程安装或发布证明。

## 共享 ABI 增量迁移补充

接收方报告的 `SETUP_CORE_IDENTITY_LINKS` ImportError 表明共享 ABI 尚未接齐；
不表示 DEV 全局失败，也不表示 TEST 已验证通过。本节只依据 DEV 当前源码。
保留 TEST 已有 REQ23、BRINGUP、private-guard 修复及独立断言，不整体覆盖
`tools/project_contract.py` / `tools/_package_common.py`，不以空 tuple 或忽略 import 兜底。

`ibsw_upgrade_inputs.py` 需要共享 exports：
`SETUP_CORE_IDENTITY_LINKS`、`parse_setup_manifest_layout`、
`require_project_eligible`、`runtime_link_specs`；
并导入 `_package_common._package_project_identity` / `_source_identity`。
四个 core anchors 首列相对于 `workspace/ztp/`，第二列相对于同一直接项目：

```python
SETUP_CORE_IDENTITY_LINKS = (
    ("config/cumulus/template/01-global.yaml", "01-global.yaml", "global", False),
    ("config/cumulus/template/02-devices_config.csv", "02-devices_config.csv", "inventory", False),
    ("config/isc-dhcp-server/02-subnet_config.csv", "02-dhcp-subnet_config.csv", "DHCP subnet", False),
    ("status", "99-output-ztp", "status", True),
)
```

`parse_setup_manifest_layout` 保留原 proj 首行、规范绝对链接与拒空行/重复名合同。
managed reader 必须核真实 manifest、项目资格及这四项精确 lexical symlink 关系，
不能只凭 resolve 后同字节、外置 CSV 或两个输入 aliases 取代 core identity。

生产者与读者要一起接齐：`SETUP_WORKSPACE_INPUT_MAPPINGS` 保留
`infiniband/01-global.yaml → 01-global.yaml`，增加
`infiniband/bringup/xdr-upgrade/01-global.yaml → 01-global.yaml` 的 file 项。
reader 同时保留历史 `xdr-upgrade/01-global.yaml → ../../01-global.yaml` 的两段绑定。
`NETWORK_CSV_MAPPINGS` 保留 `infiniband/ib.csv → 02-devices_config.csv`；
`NETWORK_INVENTORY_LINKS` 增加 `xdr-upgrade/ib.csv → infiniband/ib.csv`
（完整键是 `infiniband/bringup/xdr-upgrade/ib.csv`，生成的本地 symlink target 为 `../../ib.csv`）。
保留 xdr-upgrade-logs 的 `BRINGUP_OUTPUT_SPECS`；让 published/runtime specs 从原早期表
派生，不能 EOF 重赋；非 monitor workspace global 不因此自动成为 published input。

contract 继续用共享 safe YAML/schema、`normalize_redundancy_mac`、
`validate_service_endpoint`、`parse_device_csv_layout` / `require_device_csv_row_width`。
CSV 必须是完整 schema 1/2 positional 表，先验表头/行宽再过滤 IB；
不接受只有 hostname/type/IP/MAC 的 reduced CSV。
`config_method` 可选但唯一，位于业务列末端、完整的三列 source metadata 之前；
schema 2 行宽严格一致，schema 1 保留原末尾空单元格容忍，不修改接收方 schema 修复。

IB 增量包括 `validate_optional_ib_upgrade` 及
`_ibsw_mapping/_ibsw_version/_ibsw_version_key/_ibsw_ssd_version/_ibsw_file/`
`_ibsw_root/_ibsw_subdir/_ibsw_ib/_ibsw_cpld_targets/_ibsw_validate_upgrade`。
无声明 global 保留旧合同；显式 null/空/非法 upgrade block 拒绝。
`ibsw_upgrade_contract.load_global_text` 与包装的真实 `_validate_package_project_inputs` 都接该校验。
包装 static managed 集纳入升级 local CSV/global，保留已有 initial/UFM 项；
reserved upgrade global 存在却非 symlink 时拒绝，不把它作为普通代码打包。
保留原归档、held-input、私钥排除与 private-guard；消除 ImportError 后仍须在 TEST 精确树
独立重跑 ABI/alias/core anchors/完整 CSV/非法 block/包装回归，不能继承 PASS 标签。

## 已确认的运行合同

OS-only 的最小 global 字段、独立版本链与 HTTP URL 示例见
[README：最小 os-only global 声明](README.md#最小-os-only-global-声明离线输入检查)。
模板中只有 `ib.version` 不等于已声明升级 policy；该示例必须配
`--os-only --diagnose-inputs`，无组件选择时仍要求 OS/BIOS/CPLD 三份 policy。
HTTP 禁用时返回 `HTTP_POLICY`，只能检查并启用经批准的项目 HTTP 配置；
HTTPS、SCP、local 均不是当前入口的备用传输。相关离线测试同时核验零外部调用。
新增样例仅覆盖本地离线输入诊断，不是包可达、设备健康或升级验收证据。

- 仅 HTTP 包来源；HTTPS、SCP、local 明确拒绝，不静默降级。
- 可用 `--project ABS_PROJECT` 读取明确项目的 `02-devices_config.csv` 和
  `01-global.yaml`，不要求先 load/setup；不覆盖用户的 CSV/global。
- OS 当前版本必须位于 global 的有序文件链；按链逐步升级到 final。
  已达目标不刷，较新版本不自动降级。
- OS、BIOS、CPLD 维护独立的 `os-status.json`、`bios-status.json`、`cpld-status.json`。
  某组件金丝雀 FAIL/UNKNOWN 只阻止该组件其余目标，不撤销其他组件已取得的放行。
  普通设备失败停止本台后续写入并保留人工检查事实，不无条件停止其他正常设备。
- 每台进入固件步骤前均须现场确认实际最终 OS；`--bios-only` / `--cpld-only`
  也不能用旧状态文件代替该前置条件。仅选某组件时不读写未选组件状态列表。
- 默认顺序 OS→BIOS→CPLD，使用固定受支持 registry；未知、重复或非法顺序拒绝。
  不接受任意模块导入或调用者命令，不新增 BIOS/CPLD 硬件或源版本兼容预检查。
- 状态文件是事实与人工检查记录，不是调用者 PASS 授权。FAIL/UNKNOWN 不自动重试、
  清除或重置；共用来源安全异常、归属不明或可靠记录失败仍需停止。
- 初始化和升级使用同一 host-local 内核运行锁，忙时退出 75。它不是跨主机分布式锁；
  不得用另一台服务器并发写相同目标，也不得删除锁文件“解除”冲突。
- 密码不进入 argv/env/脚本/公开日志；身份、known_hosts、包来源、原配置备份和
  真实最终健康验证仍是必要条件。单个命令 exit 0 不等于组件升级成功。

### 重启观察与安装退出记录的区别

当前合作式重启观察路径不把 `owned-exit.record` 当作完成授权。记录缺失或不可信时，
不得猜测安装退出码、补造记录或重新派发；只有实际新 boot、身份、目标版本、配置、
健康及其余原安全门禁均通过，才可按现场观察完成组件，安装退出码仍为 `None`。
这不是所有执行路径都可以忽略原安装退出码的通用豁免。未观察到重启或最终条件不足时，
仍须在原期限内收尾并保留 `UNKNOWN`；退出码 0 也不能替代这些验证。

本机保留三个原工作流的定向证据：未重启保持 UNKNOWN、退出记录缺失后真实验证、
不可信退出记录不作为验证依据；后两项仍断言仅安装一次，缺失记录案例另断言零配置 patch。
收据为 `outputs/req19-local-evidence-20261007/ROOT-IBSW-OWNED-EXIT-UNCERTAINTY-20261020.json`。
设备 IO 与 boot 变化由原夹具模拟，不是实际设备重启、真实 SSH、断电、完整模块或 full 证明；
接收方仍须在自己的精确代码和环境上验证。三个案例也不证明可选退出文件探测分支已执行。

原延迟退出案例另有夹具可达性修正：仅在显式 `delayed_exit>0` 时，将本次模拟重启
延后到原 `lstat` 真正消耗指定缺失次数；不改生产探测间隔、期限或原 19 个工作流断言。
新增 `test_ibsw225_delayed_owned_exit_witness.py` 被动委托原 IO，独立要求两次缺失及
前后均无全局请求 lease，之后仍须完整 live 验证、仅安装一次，不要求成功读取退出文件。
它不提供真实 boot 字节见证或设备证明；本地初始失败、夹具修正与定向复验另见
`outputs/req19-local-evidence-20261007/ROOT-IBSW-DELAYED-PROBE-REACHABILITY-20261020.json`。

九目标并发原工作流另有本地定向收据
`outputs/req19-local-evidence-20261007/ROOT-IBSW-NINE-TARGET-OWNED-CHILD-20261020.json`。
原案例在该收据绑定的夹具及 585 项源码／监督脚本快照上单独运行，1 项 PASS，27.581 秒；
生产时钟、期限及原断言未改，外层 60 秒诊断预算未触发超时或强制终止。
原断言确认配置 5 个 in-flight、9 个模拟目标 COMPLETE 及 canary 先派发，
不证明实际 5 线程峰值或 5 个设备安装进程；也不证明超时终止后的安全收尾。
设备 IO 仍由原夹具模拟，不是真机或 full 证明；延迟探测可达性证据仍归属上一收据。
本段只是维护交接说明，没有重跑案例或把此前通过追认为修改后整树的测试证明。

`--help` / `--version` 是本地信息查询。`--diagnose-inputs` 是本地输入检查；
`--inspect-only` 和 `--dry-run` 会访问设备并写本地检查结果，不能当成离线测试。
`--scripts-only` 只生成脚本，结果仍是 NOT_EXECUTED。实际安装必须显式选择
`--upgrade --yes` 并另有现场授权；本交接不授予该权限。

## 开发环境

用独立 Python 3.12 环境安装本目录 `requirements.txt`，不要改系统 Python：

```bash
python3.12 -m venv /absolute/ibsw-test-venv
/absolute/ibsw-test-venv/bin/python -m pip install -r /absolute/http/infiniband/bringup/xdr-upgrade/requirements.txt
```

该 requirements 固定八个 SSH 依赖版本，PyYAML 没有锁版本。记录实际 Python、平台、
依赖版本和来源；不要宣称九包全部锁定。Paramiko 版本涉及受检查的内部接口，不随意升级。
验证整个 http 测试库还需要其他开发依赖，单独的 SSH 环境不等于完整测试环境。

交出方可复核的既有 SSH 环境为
`/Users/joeyyang/Desktop/http/outputs/req19-local-evidence-20261007/f01-env-recovery-20261017.niMetv/venv/bin/python3.12`。
这只是本机历史路径，不是接收方运行前提。不要复制 venv 后声称解释器/二进制依赖可移植。
不要让裸 `python3` 静默选中系统 Python 3.9：现有未选状态哨兵使用
`Path.stat(follow_symlinks=False)`。本轮 3.9 在该夹具行即 TypeError；保留失败原件，
确认解释器前置后，源码／测试／原断言不变地在上述 3.12.14 环境完成定向复验。
这不追认旧日志的解释器身份，也不表示 3.12 下已执行整个仓库或完成设备验收。

## 已保留的本地证据

核心集成提交为 `4693d8d`；当前操作说明为 `c06d456`；SFTP 中断收尾修复为
`935788c`，正常/普通错误/期限控制为 `f9fd7e1`；精确上游源组合 oracle 为 `5e11135`。
组件选择、受管外层成功/失败和共享 guard 等接线也已进入上述交接基准。

交出方历史定向记录包括：受管成功/失败流程、仅选 CPLD 对其他状态零访问、
SFTP 新增八项及原相关八项测试。完整收据在主树
`outputs/req19-local-evidence-20261007/`：

- `ROOT-CONTINUOUS-PARALLEL-LOCAL-CLOSURE-20261019.json`
- `ROOT-IBSW-SFTP-OWNED-CLIENT-INTERRUPTION-LANDED-20261019.json`
- `ROOT-IBSW-SFTP-EXACT-UPSTREAM-COMPOSITION-ORACLE-20261019.json`
- `ROOT-IBSW-CURRENT-OPERATOR-HANDOFF-20261019.json`

这些输出不一定随 Git 克隆继承。需要历史证据时向 owner 请求精确收据及其完整日志，
不要复制整个 outputs，其中可能混有其他任务、项目输入或私有材料。

2026-10-19，在交接源码基准上实际执行以下三个完整模块，共 **13 项 PASS，exit 0**：

```bash
cd /absolute/http
/absolute/ibsw-test-venv/bin/python -B -m unittest \
  test_cases.test_ibsw225_runtime_source_manifest_contract \
  test_cases.test_ibsw225_runtime_bootstrap_identity \
  test_cases.test_ibsw225_http_initializer_guard_protocol -v
```

范围是源码/manifest 闭包、精确两 hunk 组合、真实来源 bootstrap、私有共享锁互斥和
sole-help 合同；不是整个 IBSW 回归，更不是设备升级验证。测试未访问真实 SSH/设备。
接收方必须在自己的精确代码和环境上重跑，不能继承 PASS 标签。

`test_ibsw225_runtime_source_manifest_contract.py` 中十三份冻结上游 SHA 保留不变，
包括 access 原始 `aa05…`。access 仅通过反向还原两处明确批准的修复再核完整上游文件。
不要为了通过而重算全部预期哈希、删除 access 条目或放宽成任意源码白名单。

## codex test 接收顺序

1. 记录接收仓 HEAD/tree、dirty/diff、源清单 SHA、Python/平台与依赖；先审已有修改，
   不覆盖冲突，不使用开发机旧临时目录作唯一原件。
2. 先跑上述三个模块，按接收代码的实际测试数记录结果，确认真实模块来自接收目录，不混入旧树、外来 sys.modules 对象或同名模块。历史 13 项 PASS 不代表新增案例已执行。
3. 按风险分批跑原 IBSW 测试，至少覆盖三组件真实多脚本流程、两次 OS hop、
   金丝雀隔离、普通设备失败、仅选组件、来源/身份/主机密钥拒绝、备份先于替换、
   SFTP 中断及清理、报告写失败、共享 guard 的失败与成功路径。
   重点模块为 `test_ibsw225_three_component_workflow`、`test_ibsw225_access_recovery`、
   `test_ibsw225_known_hosts`、`test_ibsw225_genuine_fixture_discovery_contract`、
   `test_ibsw225_runtime_guard_exception_priority`、`test_ibsw225_managed_outer_guard_workflow`。
   期限辅助原件是 `ibsw225_fixture_support/_fixture_test_runtime_budgets.py`，
   不是名为 `test_ibsw225_runtime_budgets` 的独立顶层模块；保留固定 helper 及真实消费者。
4. 把夹具模拟设备 IO、真实本地脚本/子进程、实际 SSH/设备分开报告。UNKNOWN 或未收尾日志
   不写成 PASS，不凭单项复跑通过追认原失败已解决。
5. 保存命令、完整日志/END/退出码、前后源码及日志身份、测试数量和失败阶段。
   缺依赖或隔离/清理错误如实单列；不删、跳、弱化断言，不手改批准 ledger。
6. owner 目前明确“不跑 full”，本次不运行 full/check。若未来 owner 重新要求正式证明，
   必须在接收方当前精确树按原治理流程取得，不能绕过普通 load/sync/package 门禁。

真实设备验收状态为 **NOT RUN**。现场授权、目标及包/配置/known_hosts 原件、
维护窗口和故障清理方案须由 owner 单独确认。真实断电不以 SIGKILL 或正常重启代替。

## 回传开发窗口的内容

请回传接收提交/变更清单、环境身份、完整测试结果与日志位置、每个缺陷的独立复现及
最小 diff、真实环境已验/未验项和残余风险。修改仅在接收方目录进行；主树最终整合由
codex dev 审阅，不能自动跨树覆盖或反向同步。

可向 codex test 转交：

> 继承本交接基准到你自己的代码目录，先核完整 IBSW 运行及测试闭包，再做独立本地验证。
> 保持 HTTP-only、独立组件金丝雀/状态和全部失败安全合同。不要访问设备、修改生产、
> 跑 full/check、手改 ledger 或覆盖开发主树。把真实失败与完整日志、最小修复回传给我审阅。
