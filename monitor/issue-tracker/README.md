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

## 启用（项目 `01-global.yaml`，owner 2026-10-23）

```yaml
common:
  mgmt:
    issue-tracker:
      status: enabled             # 默认 disabled：采集后不整理也不同步
      spreadsheet_id: <表格 URL 中 /d/ 与 /edit 之间的部分>
      credentials: cre.json       # 服务账号 JSON 的文件名，放在同一项目目录（缺省 cre.json）
```

- setup 和 load 用 `tools/project_contract.py` 里的同一套规则校验这个配置块：
  - `spreadsheet_id` 必须匹配 `[A-Za-z0-9_-]{20,}`；
  - `credentials` 只能是一个 `.json` 文件名，不能写成路径；
  - `disabled` 时不得出现这两个键。
- 服务账号文件（如 `cre.json`）放在 `DAY0-Prepare/<项目>/`，不进 git，不进镜像：
  - 权限必须是 `600`，必须是普通文件，不能是链接；
  - 包装层只检查它的形状，并把路径交给引擎，不打印、不记录其中任何值；
  - 该服务账号必须是目标表格的编辑者。
- 各工作表的名字固定使用标准 Issue Tracker 模版里的名字：`CVT_Import_GS`、`IB Cabling`、`LLDPQ_Import_GS`、`ETH Cabling`。

**在线文档是统一的规范格式，同步只填数据，不改格式。** 详见下文「兼容引擎与文档的变化」。

`01-global.yaml` 和服务账号文件都不会被链接进 `monitor/`。Apache 会对外提供 `monitor/` 下的静态文件，所以包装层直接从项目目录读取它们：默认按 setup 建立的 `monitor/01-global.yaml` 链接找到项目目录，也可以用 `--project-dir` 指定。

## 运行

`cron.sh` 在每次采集、分析、页面刷新之后自动调用；也可以单独执行：

```bash
python3 monitor/issue-tracker/issue-tracker-sync.py                  # 两个域都转换并同步（未启用时什么都不做）
python3 monitor/issue-tracker/issue-tracker-sync.py --only eth       # 只处理 ETH
python3 monitor/issue-tracker/issue-tracker-sync.py --convert-only   # 只整理数据，不联系 Google，不需要启用
python3 monitor/issue-tracker/issue-tracker-sync.py --precheck-only  # 整理数据并做格式预检，不写表
python3 monitor/issue-tracker/issue-tracker-sync.py --force          # 输入没变也重新同步
```

- 引擎在顶层就导入 Google 库和 openai、httpx。运行它的解释器必须装齐这些包；可以用 `--engine-python` 指定解释器。AI、BCM、Agent 功能都没有开启，引擎只访问 Google OAuth 和 Sheets。
- 引擎的依赖清单是 `infra/docker/requirements-issue-tracker-engine.txt`：36 个分发，带哈希，登记在 `infra/dependencies.json`。
  - 容器：镜像把它装进 `/opt/http-ztp/venv`。改动这份清单或 `activate.py` 后，每台 Docker 主机都要先重建镜像再 load，见 `infra/docker/README.md`「镜像内 Python 依赖」。
  - 原生服务器：`cron.sh` 由 `11-load.py` 启动的 switch-collection worker 运行（setup 和 load 不安装 crontab），所以由执行 11-load.py 的用户运行 `python3 infra/deps.py install --target venv-cabletracker`，建出该用户的 `~/.venvs/http/cabletracker`。
    - load 用 `sudo` 执行时，这个用户是 root：用普通 `sudo` 执行 install，venv 建在 root 自己的家目录；`sudo -E` 会保留别人的 HOME，install 拒绝执行。
  - `cron.sh` 按顺序选引擎解释器：容器 venv → 该用户的 `~/.venvs/http/cabletracker/bin/python` → `python3`。
    - 用户 venv 只在没有别人能改它时才用：从 `~/.venvs` 到 `bin`、再到解析后的解释器，每一级都属于当前用户或 root、不可被组或其他人写，目录不能是链接。否则改用 `python3`，并在 cronjob.log 记一次原因。
    - `python3` 缺包时引擎在导入阶段就失败，cronjob.log 记一条 WARNING。
- 某个域的最新输入（文件名加 sha256）、规划文件和目标表都与上次成功同步时相同，就跳过这个域。失败的运行不会被记成已同步，下次照常重试。
- 整理好的数据按网络放在项目的 `99-output-monitor/` 下（UFM 算 IB）：
  - `infiniband/issue-tracker/`：`ib-cvt.json`、`ib-cvt.summary.json`、`state.json`
  - `ethernet/issue-tracker/`：`eth-lldpq.json`、`state.json`
  - 设备状态数据 `<设备类型>-switch-status.json` 由 `switch-status.py` 生成，见下文「设备状态」。
  - `state.json` 记录上次成功同步的输入。
- 脚本日志写在 `99-output-monitor/issue-tracker-sync.log`，用 `tools/log_rotation.py` 轮转。同一项目同一时间只允许一个同步，锁文件是 `99-output-monitor/.issue-tracker-sync.lock`。
- 与本目录同级的 `monitor/99-output-monitor` 是 setup 建立的链接，指向 `DAY0-Prepare/<项目>/99-output-monitor`（登记在 `tools/project_contract.py` 的 `MONITOR_RUNTIME_MAPPINGS`）。同步脚本默认通过这个链接写数据和日志，并核对链接确实指向当前项目；用 `--project-dir` 指定项目时，直接写到该项目的 `99-output-monitor/`。
- 所有 Issue Tracker 相关脚本都在 `monitor/issue-tracker/`；CableTracker 原项目在 `tools/cabletracker/`，只作为 `update-engine.py` 的来源。
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

当前版本的 CableTracker 只会填写 Cabling 两张表。Switch status 里有问题的设备（生产环境的 ETH、IB、NVL 交换机，以及 UFM 服务器），由 `switch-status.py` 按在线文档 `ETH&IB Switch` 表的列和取值规范提前整理成数据文件；等 CableTracker 支持同步设备状态后，直接交给它同步。我们不自己写这张表，脚本也不联系 Google。

```bash
python3 monitor/issue-tracker/switch-status.py                  # 四类都按最新的生产归档整理
python3 monitor/issue-tracker/switch-status.py --type ufm       # 只整理 UFM
```

- 输出：`99-output-monitor/<网络>/issue-tracker/<设备类型>-switch-status.json`，设备类型为 `eth`（ethernet）、`ib` 与 `ufm`（infiniband）、`nvl`（nvlink）。只有有问题的设备才有行；本轮计划过的设备，其旧行整体替换。
- 问题判定沿用监控页面自己的解析函数（`monitor/generate-monitor-html.py`），每台设备一行，多个问题合并到 Issue Description，Priority 取最高的一项：

| 问题 | Priority |
|---|---|
| 温度传感器（ASIC、PSU）状态不是 ok/normal，或读数达到 Crit | Critical |
| 本轮应采集但没有返回设备信息（Not collected） | High |
| PSU 或 FAN 状态不是 ok | High |
| 温度读数达到 Max；没有阈值的传感器（UFM 的 HCA）达到 85°C，即页面标红的位置 | High |
| 交换机 system health 为 not ok | High |
| UFM：经 VIP 读到的 HA 状态为 error（如节点离线）；没有 HA 状态时，ufm-enterprise 为 failed | High |
| UFM：HA 状态为 warning（如在线 1/2、DRBD 断开）；没有 HA 状态时，ufm-enterprise 不是 active（只是 PSU/FAN 故障引起的 warning 不重复计） | Medium |

- 有阈值的传感器在 Max 以下不报；没有阈值的传感器在 85°C 以下不报（页面在 70–85°C 标黄，这一段不报）。
- 列与取值（来自标准模版第 2 行表头和数据验证）：Submitor 为 `CVT`，Status 为 `New`（BasicData「HW - NV Status」），Priority 取自 `Critical,High,Medium,Low`，Fabric 取自 BasicData 的 `OOB/Inband/Compute/Storage`。RU 和 Model 在模版里是按 Host Name 查 Inventory 表的公式，行里**不出现**这两列（文件的 `formula_columns` 列出它们），同步时不得覆盖。Rack 没有数据来源，留空；OOB IP 取 `02-devices_config.csv` 的 `eth0_ip`，SN 取本轮采集。Issue Description 用英文；Not collected 的采集时间写在 `devices[].issues[].collection`，不进描述。
- Fabric：类型为 ib、nvl、spx（独立 SPX 网络）、server_ufm 的是 Compute。eth 与 eth_spx 是 inband/OOB 交换机，按 Cumulus 模版族判断：`border`、`oob-*`、`oobofoob-*` 为 OOB，`tan-*` 为 Inband；模版不说明时再看 hostname 中以 oob/border、tan、storage 开头的词；都没有时留空。
- 主机名匹配：先按 CSV 主机名精确匹配；只有归档里的名字本身不是清单设备时，才接受带机架前缀的名字（且只能有一个），一台设备不会拿到另一台的数据。
- `cron.sh` 在页面刷新之后、REQ7 同步之前，对每种类型调用一次，传入本轮确切的归档（本轮没有该类型的归档时传 `--no-archive`），以及采集前计划的设备（`--planned`）。因此中途掉线的设备会被报为 Not collected；全部 UFM 在密钥准备阶段就失败时也一样。AIR 环境不整理；本轮没有计划某类设备时，不改动该类的文件；只采集了 Ethernet 某个子类型（`cron.sh --type eth_spx` 等）时，本轮没计划的同类设备保留上一份文件里的行，并在 `devices[].carried_from` 注明来自哪份归档。脚本的结果不影响采集结果。
- 单独运行时（不带 `--archive`），读取该类型最新的生产归档，`02-devices_config.csv` 里该类型的全部设备都算应采集。
- 退出码：0 表示已写入，或没有需要整理的内容；2 表示参数或输入错误，此时不写任何文件。
