# 验证与验收

不同证据层不能互相冒充。报告结论时应明确写出证据类型、运行平台、源码/制品身份和未覆盖项。

| 证据层 | 能证明 | 不能证明 |
|---|---|---|
| 静态/contract | 参数、路径、事务和 fail-closed 分支 | Docker daemon、真实服务或网络可用 |
| mock/workflow | 多脚本协议与错误恢复 | 宿主内核、真实进程和报文行为 |
| Ubuntu VM | 架构、Docker load、Supervisor、HTTP、重启恢复 | 真实交换机和物理 DHCP 广播路径 |
| 物理环境 | host-network DHCP/HTTP、设备 ZTP 与身份闭环 | 未执行的平台或未保留的证据 |

## 本地发布门禁

开发时先运行变更感知 direct/workflow 测试。正式同步、打包或部署前固定顺序是：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --all -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --check
```

分类 suite 和原始 unittest discovery 只用于定位，不能替代上述批准门禁。完整规则见
[`test_cases/README.md`](../../test_cases/README.md)。

## Docker VM 验收边界

至少记录 upload/tar SHA-256、build manifest、immutable image ID、容器 ID/labels/binds/platform、
动态 DHCP listener 接口、Supervisor 五个业务 program、Apache 精确 listener、公开/拒绝 HTTP
矩阵、activation generation 和重启前后日志增量。重启恢复必须验证是同一受管身份和持久状态，
不能只看容器名称或一个 HTTP 200。

VM 只读验证器及其复制边界见 [`test_cases/README.md`](../../test_cases/README.md)。未实际跑过的
Docker/VM 项不得写成 PASS；失败后也不能用后续观察补写成上一 checkpoint 成功。

## 物理 ZTP 验收边界

物理验收还要证明 DHCP DORA 经过预期宿主逻辑接口、Cumulus/NVOS 平台 option 分流、MAC/hostname/
scope 身份绑定、bootstrap/YAML 公钥下载、apply receipt、设备重启和最终监控状态。真实环境步骤、
风险、清理与证据要求登记在 [`REAL_ENVIRONMENT.md`](../../test_cases/REAL_ENVIRONMENT.md)；自动化
测试不连接或重置真实交换机。

## V3.2 合并记录

以下项目源自 `codex/v3.1-validation-export`，V3.2 合并时必须同时移植实现、direct 测试和
workflow/scenario 覆盖，并重新执行目标分支的治理测试。

### V32-001：P2P 辅助 sheet 误报

- 状态：已修复，提交 `f44decc`。
- 问题：`TAN Fabric`、`OOB Fabric`、`OOB Plan` 等辅助 sheet 没有链路表头时，生成器误报为
  损坏的拓扑 sheet。
- 实现：只在表头检测失败后跳过精确审核过的辅助 sheet 名；同名但含有效链路表头的 sheet
  仍然解析，未知的非空错误 sheet 继续 fail closed。
- 文件：`ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py`。
- 测试：`test_xlsx_zero_row_fail_closed.py`、`test_xlsx_zero_row_workflow.py`；真实 GB300
  workbook 成功读取 12,322 条链路记录。

### V32-002：BCM/UFM 错误继承 ZTP appliance 身份

- 状态：已修复，业务提交 `77c76e6`；`6e73de0` 仅为该组改动通过后的治理批准
  ledger 提交，不应作为业务修复提交移植。
- 问题：生产 AIR 模板没有独立 BCM/UFM 原型，节点回退到 `ztp-server` 后继承
  `model=oob-mgmt-server`，其 `eth0,eth1-9` 严格端口清单拒绝 `BF3-BMC/P1/P2` 等源端口。
- 实现：AIR DOT 继续保留独立 BCM/UFM 节点及合格链路；所有名称含 `BMC` 的端口均过滤，
  其余端口按每台服务器独立、稳定地映射为 `eth0..ethN`。BCM/UFM 输出为 8 CPU、8192 MB、
  80 GB、`os=generic/ubuntu2204`、`oob=false`，JSON 不含 `labels`。ZTP server 仍为
  `oob-mgmt-server` 并沿用独立的 eth1-based 映射。
- 文件：`ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py`。
- 测试：`test_air_retained_servers_contract.py` 覆盖生产模板回退、节点身份隔离、全 BMC 过滤、
  DOT/JSON 一致映射和模型校验。真实 GB300 LLDPQ 成功生成 548 个 AIR 节点、3129 条连接，
  原 BCM 端口错误未复现。

### V32-003：正式 load 复用精确 full proof，并把 proof 绑定到 push

- 状态：实现与聚焦回归已完成；尚未提交，尚未为当前合并状态执行 full suite 或生成最终
  proof，提交号与 full-proof 证据待补。
- 需求：同一台 Mac 或同一执行环境的 fresh clone，在受管源码、测试、manifest、依赖锁和
  Python/平台身份完全不变、仅修改 `DAY0-Prepare/<项目>` 输入或运行输出时，不应重复执行耗时的
  full suite；Git push 必须携带已经提交且与待推送字节精确匹配的 proof。
- 合同：正式 macOS load 先执行 `--check --require-full`。返回 0 时复用 proof；只有返回 4
  （受管字节未批准）或 5（proof 缺失、过期或环境不匹配）才回退执行一次 `--all` 并复核；
  返回 2 或其他治理/安全错误直接阻断。项目输入仍在每次 load 中完整执行合法性、生成与发布
  门禁，不因代码 proof 命中而缓存。
- Push 门禁：正式 load 配置仓库跟踪的 `.githooks/pre-push`，由
  `tools/pre-push-proof.py` 要求待推送非删除 ref 全部指向当前 checkout HEAD、approval ledger
  已被 Git 跟踪且其工作树字节已提交到该 HEAD，并用 load 绑定的精确 Python 再运行 proof
  检查。默认只接受 release proof；owner 授权的 AIR/prod 验证 push 必须显式设置
  `HTTP_VALIDATION_ONLY=1`，且只接受意图匹配的 validation-only proof，不能冒充最终发布证明。
- 文件：`DAY0-Prepare/11-load.py`、`.githooks/pre-push`、`tools/pre-push-proof.py`、
  `test_cases/script_test_manifest.json`、`test_cases/test_predeploy_test_gate.py`、
  `test_cases/test_upload_package_contract.py`、`AGENTS.md`、`test_cases/README.md`、
  `test_cases/CHANGE_AWARE_TESTING.md`。
- 测试：覆盖 proof 命中、退出码 4/5 回退、退出码 2 阻断、DAY0 项目输入不改变 governed
  snapshot、fresh clone 仅修改项目输入、未提交或 stale ledger、非 HEAD tip、删除 ref，以及
  release/validation wrong-intent。两个修复窗口合并后的聚焦回归最终 `115/115 PASS`；首次有
  3 项仅因 sandbox `PermissionError` 失败，授权环境重跑对应 3 项为 `3/3 PASS`，不是产品缺陷。
- 合并注意：应先提交已审阅的实现、测试和文档候选，再运行 full suite 生成 ledger，最后单独
  提交 ledger；当前“聚焦测试通过”不能写成已有 full proof，也不能据此 push。

### V32-004：REQ10C crontab 更新前检测非协作同 UID 写者

- 状态：实现与聚焦回归已完成；尚未提交，尚未执行当前合并状态的 full suite，提交号和
  full-proof 证据待补。
- 根因：REQ10C 的 watch 安装、自动移除和项目 unsetup 都以“读取整个当前用户 crontab、修改
  本项目行、整体写回”的方式工作。项目锁只能串行化本项目写者；其他不使用该锁的同 UID
  写者若在读取后插入任务，旧实现可能用旧快照覆盖其任务。
- 实现：`initial-setup.py` 的安装/移除路径和 `02-unsetup.py` 的清理路径都在项目锁内连续读取
  两次 crontab；两次字节不一致立即 fail closed，并保证在任何 crontab 写入前退出。原三条
  并发反例及断言没有删除或弱化，修复后已转为通过。
- 文件：`infiniband/bringup/xdr-initial-setup/initial-setup.py`、
  `DAY0-Prepare/02-unsetup.py`、`infiniband/bringup/xdr-initial-setup/README.md`、
  `test_cases/test_req10c_auto_contract.py`、`test_cases/test_req10c_auto_workflow.py`。
- 测试：原三条并发反例及相关检查 `5/5 PASS`；REQ10C direct + workflow `33/33 PASS`；与
  V32-003 合并后的聚焦回归包含在最终 `115/115 PASS` 中。
- 限制：双读是活跃写者检测，不是 compare-and-swap。第二次读取与整体写回之间仍存在窄竞态，
  因此 `REAL_ENVIRONMENT.md` 中“其他同 UID crontab 写者在完整读—改—写窗口保持静默”的真实
  环境前置条件继续有效；不得把本地测试描述成任意并发安全证明。

### 非代码事项

- P2P workbook 的 `OOB-for-OOB  LF` 曾包含
  `h05-oobofoob-leaf10:eth0 -- h05-oobofoob-leaf10:32` 自连接；这是输入数据问题，严格拒绝逻辑
  不应弱化。
- 单分支 clone 若缺少 `refs/remotes/origin/v2`，发布 authority 测试会按设计失败；这是验证环境
  前置条件，不是产品代码修复。
