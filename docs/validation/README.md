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
