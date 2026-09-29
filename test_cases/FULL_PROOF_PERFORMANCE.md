# Full proof 性能记录与诊断

本文件只记录性能证据和优化判定，不改变 `AGENTS.md` 的治理门禁。正式 full proof 仍须由
`test_cases/run_related_tests.py --all`（或明确授权的 `--all --validation-only`）执行；
诊断命令不能生成、替代或延长证明，不能跳过任何测试、修改断言或手工更新批准账本。

## 已知历史数据

| 数据 | 来源与可信度 | 用途 |
| --- | --- | --- |
| 3,785 tests，2,897.740 秒 | 本会话先前 `http-test` 全量运行的工具输出摘要；原始逐测试日志未保存到仓库，也未在此复核 | 仅作历史参考，**不是可审计计时基线** |
| `test_formal_children_share_one_isolated_dependency_capsule` 约 12–13 分钟 | 同次工作中的人工进程时间观察 | 用于确定诊断优先级，不能据此推算补丁收益 |

当前 V3 的上述慢测试经 `@_historical_p_method` 在私有 clone 中重放固定 SHA 的
`origin/v2` 历史测试源码。只修改当前
`test_cases/test_public_publication_workflow.py` 的依赖快照解包或逐文件 `fsync`，
**不会**加速该历史重放；不得为了提速改写历史锚点、跳过重放或弱化其断言。

## Opt-in 逐测试计时

`validation_unittest.py` 的默认调用、canonical discovery、原有结果 JSON 字段和
ISSUE-0016 精确判定保持不变。只有显式提供 `--timings` 时，才额外写入一个诊断 JSONL
文件；路径必须是已存在目录中的绝对路径，文件名此前不能存在。文件以独占创建方式写入，
权限为 `0600`。每个已完成的 `unittest.TestCase` 记录一行 `id` 与
`duration_seconds`；包含 setup、test、tearDown 和子测试总时长。中断时可能缺少未完成
的记录，不能将不完整 JSONL 视为全量证据。

在没有并行 full proof、且当前 checkout 可供测试创建临时制品时，可单独运行一次诊断：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B -m test_cases.validation_unittest \
  /tmp/http-full-result-UNIQUE.json -v \
  --timings /tmp/http-full-timings-UNIQUE.jsonl
```

将 `UNIQUE` 换成此次运行的唯一标识，两个路径均不能预先存在。诊断命令的非零退出码
和结果 JSON 中的 FAIL/ERROR/SKIP 必须如实保存；它不会更新 ledger。排序查看最慢测试：

```bash
jq -s 'sort_by(.duration_seconds) | reverse | .[:20]' \
  /tmp/http-full-timings-UNIQUE.jsonl
```

记录诊断时同时保存命令、UTC 时间、当前 HEAD、Python/平台身份、结果 JSON、计时
JSONL、`Ran ... in ...` 摘要，以及是否有其他重型进程。先核对 JSON 的 `tests_run`
等于计时行数且测试 ID 无重复；未达到这些条件时不能形成新基线。诊断运行不自动等价于
正式 runner 的 preflight/approval 流程；正式同步、打包、部署仍需有效的独立 full proof。

## 下轮优化判定

1. 先按逐测试与阶段耗时确定**当前 V3 可修改**的热点，不把固定历史重放误当作可由
   当前源码小改动解决的热点。
2. 对候选热点做小范围前后微基准，并确认它确实降低总 wall time；不根据文件行数、
   `sleep` 正则计数或 CPU 核数推算收益。记录同一机器、解释器和负载条件下的结果。
3. 实现前独立写好正反测试。必须保留完整测试集合、单对象/单文件身份与内容核验、
   恶意改写/竞态负例、异常处理和相同 FAIL/SKIP 语义。任何新 ERROR、额外 SKIP 或
   测试映射缺口都阻断采用。
4. 先跑相关 direct/workflow 与负例，再由主窗口安排完整治理运行。批准账本始终只有
   一个写者；不得以十个 `--suite` runner 并发写 ledger 来“加速证明”。

十个逻辑 suite 是模块分区，不是隔离证明：现有测试会在仓库下创建临时项目及 monitor
锁文件，部分测试使用 loopback sshd 和真实 Git 检出。因此在逐项解决共享写入、端口、
克隆 Git 引用和结果合并的安全边界前，不启用 suite 并行。
