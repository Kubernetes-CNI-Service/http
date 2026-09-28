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

- 状态：已在本地修复，提交号待补。
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

### 非代码事项

- P2P workbook 的 `OOB-for-OOB  LF` 曾包含
  `h05-oobofoob-leaf10:eth0 -- h05-oobofoob-leaf10:32` 自连接；这是输入数据问题，严格拒绝逻辑
  不应弱化。
- 单分支 clone 若缺少 `refs/remotes/origin/v2`，发布 authority 测试会按设计失败；这是验证环境
  前置条件，不是产品代码修复。
