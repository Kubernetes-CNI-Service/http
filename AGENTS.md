# Repository test governance

本文件适用于整个仓库。凡是修改受管生产脚本、对外行为、模块间流程或受支持场景，都必须遵守以下测试合同。

## 变更合同

1. 在修改实现之前或同时，先在 `test_cases/` 增加或更新能够独立表达预期行为的测试。预期值不得从被测实现反向生成，也不得为了让当前实现通过而自动重写断言。
2. 单脚本行为必须有 direct 测试；涉及两个或更多真实脚本的流程、事务或场景必须有 workflow/scenario 测试。修改跨模块边界时，不能只更新单元测试。
3. 检查 `test_cases/script_test_manifest.json`：每个生产脚本路径必须命中 direct `test_rule`，并属于至少一个覆盖多个真实脚本的 `workflow`。软链接发布入口按独立路径登记，并指向正确 canonical target。
4. 新增生产脚本时，必须同时登记脚本、direct 测试和 workflow/scenario。无映射、映射陈旧、canonical target 改变或测试模块缺失都必须 fail closed，不能以忽略路径的方式绕过。
5. 不能在本机安全自动化的真机、AIR、Docker、服务切换或破坏性场景，必须按 `test_cases/CASE_TEMPLATE.md` 登记到 `test_cases/REAL_ENVIRONMENT.md`，写明前置条件、证据、清理步骤和风险。

## 辅助脚本的窄例外（owner 2026-11-11，04 Q-046 / R-020）

文件名以 `helper-` 开头、由人手工运行做准备或网络功能验证的小脚本，只有同时满足以下三条才适用本例外：

1. 不被仓库其他脚本调用或导入，自己也不导入仓库模块。
2. `--help` 在任何动作之前返回，没有副作用。
3. 只做人工准备或验证，不写仓库或项目里其他脚本要读的文件（项目文件、锁、台账、配置）。

符合条件的辅助脚本不写行为测试，也不按变更合同第 5 条登记真机卡；仍按第 3、4 条逐个登记 manifest scripts，命中共用 test_rule `helper_scripts_direct` 和共用 workflow `helper_scripts_with_initial_setup`（路径模式 `*/helper-*`，workflow 另含真实流程入口）。两者指向 `test_cases.test_all_script_entrypoints`，普查语法、安全 `--help` 和其他生产脚本不引用辅助脚本。`helper-` 前缀不能让不满足三条件的脚本规避正常测试与登记。

owner 原话（2026-11-11）：

- 16:12:03：「你在3.1.4版本的计划表里新增一个需求，把这个脚本放到xdr-initial-setup/下，它只是一个不会被其他脚本调用的小脚本，只是帮助用户准备eth_jump的环境，我们不用给它做任何测试，保证会跟踪版本和upload/sync 一起走」。上述普查和登记仍按随后确定的辅助脚本规则执行。
- 16:24:30：「我们统一给这类脚本加一个前缀名字吧」。
- 16:28:07：「helper-（推荐）可以」。

## 必须执行的验证

开发时运行变更感知测试；runner 会选择已有 direct 与 workflow/scenario 测试，只会在成功后更新批准哈希，不会创建或改写测试断言：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py -v
```

持续开发可以使用：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --watch --interval 2 -v
```

正式同步、打包或部署前必须具备绑定当前源码、测试、manifest 以及 Python/平台身份的全量测试
证明。本机 macOS 上的正式 `DAY0-Prepare/11-load.py` 会先执行只读的
`--check --require-full`：当前精确证明有效时直接复用；只有返回 4（受管字节变化）或
5（证明缺失、过期或执行环境不一致）才执行一次全量测试并复核，其他错误 fail closed。
普通 `DAY0-Prepare/<项目>` 输入和运行输出不属于代码治理快照；同一环境的 fresh clone
只修改这些项目文件时也复用仓库随 commit 携带的有效证明，但每次 load 仍完整执行项目输入、
生成和发布门禁。成功完成 load 后再次确认当前状态仍逐字节一致。开发者也可以显式执行以下治理命令：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --all -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --check --require-full
```

`sync-code.py` 与 `tar-for-upload.py` 只验证这份精确证明，绝不自行执行全量测试。证明缺失、
过期、源码发生变化或执行环境不一致时，它们必须在任何打包、网络或远端写入前停止，并要求
操作员先在当前工作树重新完成本机正式 load。Linux 管理服务器 load 与 macOS `--dry-run`
不运行开发测试。不得提供或使用无条件跳过证明检查的发布参数。

任何失败、未批准变更或 runner 安全检查错误都必须阻断发布。禁止通过删除、跳过、弱化测试，手工编辑批准 ledger，或让测试从当前实现复制结果来绕过失败。若需求确实改变，应先独立确认新合同并更新相应预期，再修正实现并重新运行测试。

2026-09-28 的 REQ10C 窄例外已随 `--auto` 退役（v3.1.3）。`--validation-only` 仍只产生与普通发布证明严格区分的验证证明，要求全部通过、跳过集合不变，不授权最终生产发布。

详细规则见 `test_cases/README.md` 和 `test_cases/CHANGE_AWARE_TESTING.md`。`test_cases/` 只属于开发与验证，不进入生产 upload/sync 包。
