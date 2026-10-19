# IBSW Upgrade 开发测试交接

交出方：codex dev。接收方：由 owner 指定的 codex test 会话。
日期：2026-10-19。源码基准：`9bf7abc84ec66001f6a51af104b23df56a7b7e64`。

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

## 已确认的运行合同

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
2. 先跑上述 13 项，确认真实模块来自接收目录，不混入旧树、外来 sys.modules 对象或同名模块。
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
