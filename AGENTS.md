# Repository test governance

本文件适用于整个仓库。凡是修改受管生产脚本、对外行为、模块间流程或受支持场景，都必须遵守以下测试合同。

## 变更合同

1. 在修改实现之前或同时，先在 `test_cases/` 增加或更新能够独立表达预期行为的测试。预期值不得从被测实现反向生成，也不得为了让当前实现通过而自动重写断言。
2. 单脚本行为必须有 direct 测试；涉及两个或更多真实脚本的流程、事务或场景必须有 workflow/scenario 测试。修改跨模块边界时，不能只更新单元测试。
3. 检查 `test_cases/script_test_manifest.json`：每个生产脚本路径必须命中 direct `test_rule`，并属于至少一个覆盖多个真实脚本的 `workflow`。软链接发布入口按独立路径登记，并指向正确 canonical target。
4. 新增生产脚本时，必须同时登记脚本、direct 测试和 workflow/scenario。无映射、映射陈旧、canonical target 改变或测试模块缺失都必须 fail closed，不能以忽略路径的方式绕过。
5. 不能在本机安全自动化的真机、AIR、Docker、服务切换或破坏性场景，必须按 `test_cases/CASE_TEMPLATE.md` 登记到 `test_cases/REAL_ENVIRONMENT.md`，写明前置条件、证据、清理步骤和风险。

## 必须执行的验证

开发时运行变更感知测试；runner 会选择已有 direct 与 workflow/scenario 测试，只会在成功后更新批准哈希，不会创建或改写测试断言：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py -v
```

持续开发可以使用：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --watch --interval 2 -v
```

正式同步、打包或部署前必须先全量执行，再确认当前源码、测试、manifest 与批准状态逐字节一致：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --all -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --check
```

任何失败、未批准变更或 runner 安全检查错误都必须阻断发布。禁止通过删除、跳过、弱化测试，手工编辑批准 ledger，或让测试从当前实现复制结果来绕过失败。若需求确实改变，应先独立确认新合同并更新相应预期，再修正实现并重新运行测试。

详细规则见 `test_cases/README.md` 和 `test_cases/CHANGE_AWARE_TESTING.md`。`test_cases/` 只属于开发与验证，不进入生产 upload/sync 包。
