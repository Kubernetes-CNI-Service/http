# 在线 Issue Tracker 同步（REQ7）

把最近一次采集到的 IB 与 ETH 链路结果同步到项目的在线 Issue Tracker（Google Sheets）。

- 同步引擎 `cabletracker/` 是参考工具 CableTracker 的**逐字节复制**，不在本仓库修改。
  `test_cases/test_issue_tracker_sync.py` 钉住这四个文件的 sha256：
  - `cabletracker_runner.py`
  - `mapping_v4.json`
  - `ibdiagnet/__init__.py`
  - `ibdiagnet/generate_report.py`
- `format_precheck.py` 是写表前的只读格式关卡，详见下文「兼容引擎与文档的变化」。没有跳过它的参数。
- `update-engine.py` 用于把新版引擎原样换进来；`engine.lock.json` 记录当前副本每个文件的 sha256。
- `issue-tracker-sync.py` 是我们写的包装层。它只负责两件事：把我们自己的采集结果转换成引擎能读的两种格式，然后每个域各运行一次引擎。

| 域 | 输入（项目目录内） | 转换 | 交给引擎 |
|---|---|---|---|
| IB | `99-output-monitor/infiniband/ufm-ibdiagnet/` 里最新的 `<run-id>_<node>_ibdiagnet2.tgz`，以及 `99-output-p2p/*-cvt.xlsx` | `cabletracker/ibdiagnet/generate_report.py` | `ib-cvt.json`，`--source-type cvt` |
| ETH | `99-output-monitor/ethernet/eth-info/` 里最新的 `<YYYYMMDD-HHMM>-<env>.tar.gz`，以及 `99-output-p2p/*-lldpq.dot`（AIR 用 `*-air.dot`） | `tools/lldp-analyze-tool/analyze_lldp.py --payload-json`，再投影成 LLDPQ schema v1 | `eth-lldpq.json`，`--source-type lldpq` |

## 项目文件（只放在 `DAY0-Prepare/<项目>/`，不进 git、不进镜像）

- **`cre.json`**：Google 服务账号密钥。
  - 权限必须是 `600`，必须是普通文件，不能是链接。
  - 包装层只检查它的形状，并把路径交给引擎；不打印、不记录其中任何值。
  - 该服务账号必须是目标表格的编辑者。表格里如果有受保护范围，也要把它加进这些范围的编辑者，至少包括 `Whitelist` 和 `IB Cabling` 的 `Fault ID` 列。
- **`03-issue-tracker.json`**：

```json
{
  "schema": "issue-tracker-sync-v1",
  "spreadsheet_id": "<表格 URL 中 /d/ 与 /edit 之间的部分>",
  "timezone": "Asia/Shanghai",
  "ib":  {"enabled": true, "environment": "prod", "import_sheet": "CVT_Import_GS",   "cabling_sheet": "IB Cabling",  "include_warnings": false},
  "eth": {"enabled": true, "environment": "prod", "import_sheet": "LLDPQ_Import_GS", "cabling_sheet": "ETH Cabling", "include_warnings": false}
}
```

除 `schema` 和 `spreadsheet_id` 外，其余键都可省略，省略时取上面的值。上面的表名就是标准 Issue Tracker 模版里的表名。IB 与 ETH 必须导入不同的工作表。

**在线文档是统一的规范格式，同步只填数据，不改格式。** 换用新文档前，先用只读预检确认引擎期望的表头和文档完全一致：导入表、IB/ETH Cabling 的第 2 行、Whitelist 的版式。表名对不上时，引擎会自动新建工作表；表头对不上时，引擎会重写表头。这两种情况都算改格式，不得写入。

这两个文件不会被链接进 `monitor/`。Apache 会对外提供 `monitor/` 下的静态文件，所以包装层直接从项目目录读取它们：默认按 setup 建立的 `monitor/01-global.yaml` 链接找到项目目录，也可以用 `--project-dir` 指定。

## 运行

```bash
python3 monitor/issue-tracker/issue-tracker-sync.py                  # 两个域都转换并同步
python3 monitor/issue-tracker/issue-tracker-sync.py --only eth       # 只处理 ETH
python3 monitor/issue-tracker/issue-tracker-sync.py --convert-only   # 只生成 JSON，不联系 Google，不需要 cre.json
python3 monitor/issue-tracker/issue-tracker-sync.py --force          # 输入没变也重新同步
```

- 引擎在顶层就导入 Google 库和 openai、httpx。运行它的解释器必须装齐这些包；可以用 `--engine-python` 指定解释器。AI、BCM、Agent 功能都没有开启，引擎只访问 Google OAuth 和 Sheets。
- 某个域的最新输入（文件名加 sha256）、规划文件和目标表都与上次成功同步时相同，就跳过这个域。失败的运行不会被记成已同步，下次照常重试。
- 结果写在 `<项目>/99-output-p2p/issue-tracker/`：
  - `ib-cvt.json`、`ib-cvt.summary.json`、`eth-lldpq.json`：转换结果，每次覆盖；
  - `state.json`：上次成功同步的输入；
  - `issue-tracker-sync.log`：本脚本的日志，用 `tools/log_rotation.py` 轮转；
  - `.sync.lock`：同一项目同一时间只允许一个同步。
- 退出码：
  - 0：成功、输入未变，或没有输入；
  - 1：某个域的转换、引擎或 Google 出错；
  - 2：配置或输入错误，什么都没有发送；
  - 75：另一个同步正在运行。

## ETH 状态映射（analyze_lldp 结果映射到 LLDPQ）

每条 P2P 链路输出一行：交换机一端作为本端（A），规划的对端作为 Z。实际看到的 LLDP 邻居填进 `actual_device`/`actual_port`。

| analyze_lldp | LLDPQ status | `connection_health` 前缀 | 引擎归类 |
|---|---|---|---|
| CONFIRMED_BOTH_SIDE / CONFIRMED_SW_SIDE | SUCCESS | 空 | Pass |
| WRONG_PEER | FAILED | `wrong device:` 或 `port mismatch:` | Mis-wiring |
| DOWN | FAILED | `Link Down:` | Link Down |
| MISSING_INTERFACE | FAILED | `Interface missing:` | Others |
| SW_LLDP_PRESENT | WARNING | `LLDP neighbor not confirmed:` | 只在 `include_warnings` 为真时建 Case |
| NO_LLDP | WARNING | `No LLDP neighbor:` | 同上 |
| MISSING_DEVICE | NO INFO | `Switch not collected:` | 不判失败，也不关闭已有 Case |

只存在于现网、不在 P2P 中的链路不输出，与 `generate_report.py` 只以 P2P 为范围的做法一致。

## 已知限制

- `generate_report.py` 要求 `-cvt.xlsx` 的 Server Profile 表至少有一行数据。我们的 `p2p-to-validation.py` 只在有 smc-b300 主机时才写这张表。没有这类主机时，IB 转换以退出码 1 报错，ETH 不受影响。
- iblinkinfo 降级采集得到的 `.log` 不是 tgz，引擎读不了，不会被选作输入。

## 兼容引擎与文档的变化

CableTracker 的代码和在线文档都会演进。我们只复制它的同步部分，并且只通过两个公开接口使用它：

- 命令行参数；
- 两种输入格式：IB 用引擎自带 `generate_report.py` 产出的 CVT JSON，ETH 用引擎 README 公布的 LLDPQ schema v1。

我们不调用引擎的内部函数。

**格式关卡（影子运行）**：每次运行引擎前，`format_precheck.py` 先用引擎自己的入口完整跑一遍：

- 读请求照常读真实文档；写请求全部拦截，不发出去。
- 服务账号凭据被强制改成只读权限范围，所以即使有写请求漏过拦截，Google 也会拒绝。
- 写请求只按它落在哪里判定：
  - 导入表、Cabling 表 A1 的「… at:」时间戳：放行；
  - 这两类表表头行以下的数据行：说明准备阶段已经结束，影子运行到此停止，判定通过；
  - 其他一律判为改格式，拒绝：新建标签页、写标题行或表头行、增删列、写其他标签页、无法识别的请求。
- 真正同步完成后，再把各标签页和表头行与同步前的快照比对。一旦发现被改，就报错并提示从文档的版本历史恢复。

**更新引擎**：owner 把新版 CableTracker 项目放在 `tools/cabletracker/`（仅作参考，不进 git、不进镜像），然后执行：

```bash
python3 monitor/issue-tracker/update-engine.py --engine-python <装有引擎依赖的 python>
python3 monitor/issue-tracker/issue-tracker-sync.py --precheck-only     # 只做转换和格式预检，不写表
```

`update-engine.py` 依次做三件事：

1. 把同步需要的文件原样复制到暂存目录；
2. 确认新版引擎的 `--help` 能运行，并且仍然接受我们用到的全部参数；
3. 通过后才替换副本，并重写 `engine.lock.json`。

如果新版拆出了新的本地模块，或者改了参数名，第 2 步就会拒绝，副本保持不变。测试按 `engine.lock.json` 校验副本，并用 `test_cases/issue_tracker_template.py` 中的标准模版，对真引擎做离线影子运行。

## 时间说明

`IB/ETH Cabling` 的 `Opened At` 由引擎在新建 Case 时按当前时间填写，不是数据的采集时间。采集时间写在导入表的 `Last Update (UTC)` 列，只精确到日期。所以同步应紧跟每次采集自动执行；补同步旧数据时，`Opened At` 会是补同步的时刻。

## 设备状态（ETH&IB Switch）

当前版本的 CableTracker 只会填写 Cabling 两张表。Switch status 里有问题的设备，会按在线文档 `ETH&IB Switch` 表的列和取值规范（BasicData 的状态、Fabric，以及 Priority 下拉值）提前整理成数据文件；等 CableTracker 支持同步设备状态后，直接交给它同步。我们不自己写这张表。
