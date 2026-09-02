# InfiniBand 交换机统一升级脚本

## 在整体架构中的位置

本目录是部署后的 IB 固件/系统专项维护模块，不参与 DHCP、配置生成或 ZTP 轮次。它读取明确
设备与升级包，逐设备记录可审计结果；项目级输出应进入 setup 管理的 bringup 结果目录并随
download/import 回收。整体实施顺序见根目录 `USER_MANUAL.md`。

本目录使用 `upgrade.sh` 统一完成 InfiniBand 交换机的 OS、BIOS 和 CPLD 升级。脚本支持四种升级包传输方式，共用同一套设备读取、版本判断、确认、并发、等待、日志和升级后验证逻辑。

## 1. 运行环境

管理服务器需要：

- Linux 和 Bash 4 或更高版本。
- Python 3，仅使用标准库 `csv` 和 `ipaddress` 解析、校验设备CSV，不需要安装 `openpyxl` 或其他pip包。
- `ssh`、`scp`、`awk`、`sed`、`sort`、`mktemp` 等常用命令。
- 能够通过管理网络 SSH 登录目标交换机。
- 使用 local 或 SCP 方式时，管理服务器上需要存在相应升级包。

交换机需要：

- 可以使用 `admin` 账号登录。
- `admin` 能执行脚本需要的 `sudo` 命令。
- 支持 NVUE `nv action fetch/install` 命令。
- 使用 SCP 方式时，交换机需要安装 OpenSSH `scp` 客户端和Python 3，并能回连管理服务器；Python PTY用于安全响应NVUE的交互密码提示。
- 使用 HTTPS 方式时，交换机上的 NVUE 必须能访问 HTTPS 服务。NVOS 的直接 HTTPS fetch 要求服务器使用交换机信任的有效 CA 证书。
- 使用 HTTP 方式时，交换机需要 `curl`，并能访问HTTP服务；文件下载到 `/home/admin` 后再由NVUE通过 `file://` fetch。

## 2. 快速开始

直接运行：

```bash
bash upgrade.sh
```

没有指定传输方式时会提示：

```text
Select package delivery method:
  1. scp    Switch pulls packages from management server [default]
  2. http   Switch downloads through HTTP, then uses local file fetch
  3. local  Uses local files [pre-stage packages in the user's home directory]
  4. https  Direct NVUE fetch [requires a valid CA certificate trusted by the switch]
Choice [1/2/3/4] (default: scp in 10s):
```

直接回车或等待10秒均选择默认的 `scp`。

建议先执行只读检查：

```bash
bash upgrade.sh --method scp --dry-run
```

确认结果后执行升级：

```bash
bash upgrade.sh --method scp --all
```

## 3. 四种传输方式

| 方式 | 传输方向 | 管理服务器源 | 交换机暂存目录 |
| --- | --- | --- | --- |
| `scp` | NVUE通过SCP URI直接从管理服务器fetch | `--scp-root`，默认与`upgrade.sh`同目录 | 不提前暂存 |
| `http` | 交换机通过curl下载，再由NVUE执行file fetch | HTTP `/image`、`/firmware` | `/home/admin` |
| `local` | 使用交换机用户家目录中的文件；缺失时可由管理服务器补推 | `--source-root`，默认脚本目录 | `/home/admin` |
| `https` | NVUE通过HTTPS URL直接fetch；服务器证书必须被交换机信任 | HTTPS `/image`、`/firmware` | 不提前暂存 |

### 3.1 SCP方式

```bash
bash upgrade.sh --method scp --all
```

默认升级包目录是 `upgrade.sh` 所在目录。脚本先查询所有目标交换机的实际版本，只检查本轮确实需要的包：

- OS 只检查每台交换机当前版本的下一步包。
- 当前 OS 为 `25.02.7002` 时只需要 `25.02.8008`，不会检查 `25.02.6077` 或 `25.02.7002`。
- 所有交换机 BIOS 已达标时不检查 CAB。
- 所有交换机 CPLD 已达标时不检查 BURN/REFRESH VME。
- 多种当前 OS 基线需要不同下一步包时，对实际需要的文件去重后统一检查。

需求发现对每台设备只建立一次SSH连接，在该连接中同时取得OS、BIOS和CPLD信息；不同设备按 `--parallel-limit` 并发查询，默认最多8台。相比原先逐设备串行执行三次SSH，24台设备从最多72次串行握手降为24次、8并发。

如果默认目录缺少实际需要的包，脚本会列出缺失文件并提示指定目录。显式使用 `--scp-root` 时，该目录缺包会直接报错。

管理服务器地址默认按设备探测：

1. 读取管理服务器非回环接口 IPv4 地址。
2. SSH 到目标交换机。
3. 通过交换机 `w` 输出取得当前 SSH 会话来源地址。
4. 确认该地址属于管理服务器本地接口。
5. 使用匹配地址供交换机回连 SCP。

可以显式指定地址、用户名和目录：

```bash
bash upgrade.sh --method scp --os \
  --mgmt-server 192.0.2.10 \
  --mgmt-user cumulus \
  --scp-root /srv/firmware
```

脚本通过 `id -un` 获取当前管理服务器用户名，并显示为默认值：

```text
Management-server SCP username [cumulus]:
```

直接回车使用该用户。随后输入一次管理服务器密码，供本次运行所有交换机使用。

生成的 SCP 子脚本不会先运行 `scp` 下载，也不会再通过交换机本地 `file://` 路径 fetch。NVUE 直接使用管理服务器 URI，fetch 成功后再按 basename install。假设 `upgrade.sh` 位于 `/root/IB_Packages`，示例为：

```bash
nv action fetch platform firmware BIOS scp://root@192.0.2.10/root/IB_Packages/0ACQF.cab
nv action install platform firmware BIOS files 0ACQF.cab force skip-version-check
```

URI 不包含密码。真实日志证明NVUE的交互包装器不会读取 `SSH_ASKPASS`，因此生成脚本使用Python PTY为NVUE提供控制终端：检测到 `Password:` 后才注入已经验证的管理服务器密码，并保持终端关闭回显。密码不进入URI、命令行或日志。OS、BIOS和CPLD均使用同一直接fetch模式。

真实SCP运行会在进入OS/BIOS/CPLD阶段前，从第一台交换机沿实际回连路径验证管理服务器凭据：

- 先确定该交换机应使用的管理服务器接口地址。
- 在交换机上发起只读的 `ssh -C <user>@<management-server> true`，不传输升级包。
- 密码错误时最多允许3次隐藏输入；全部失败后在升级阶段前退出。
- 路由、超时等连接问题不会反复提示密码，而是直接报告连接错误。
- 没有任何组件需要传输升级包时，不探测管理服务器地址、不询问管理服务器用户名或密码，并跳过回连验证。
- dry-run不提示或验证管理服务器密码。

### 3.2 local方式

```bash
bash upgrade.sh --method local --all
```

local 方式默认从脚本目录读取文件，并推送到交换机：

```text
/home/admin
```

使用该方式前，用户应先把升级包放入交换机用户家目录（默认 `/home/admin`）。若目标文件缺失，编排器仍可从管理服务器源目录补推。

处理规则：

1. 先确认该设备的组件确实需要升级。
2. 检查交换机对应文件是否存在且非空。
3. 文件有效时直接复用，不检查或推送管理服务器源文件。
4. 文件缺失或为空时，先在管理服务器日志中打印交换机、组件和完整缺失路径，再只检查当前组件实际需要的管理服务器源文件。
5. 通过 SCP 推送后再次执行非空检查。
6. BIN、CAB和VME均直接使用 `/home/admin` 下已经验证为非空的完整文件路径执行 NVUE fetch。
7. 不再复制到 `/host/fw-images`。

指定其他源目录或交换机暂存目录：

```bash
bash upgrade.sh --method local --os \
  --source-root /srv/firmware \
  --local-dir /home/admin
```

### 3.3 HTTPS方式

```bash
bash upgrade.sh --method https --all
```

正式命令行方法名为 `https`。默认不硬编码服务器地址，而是对每台交换机使用与 SCP 相同的地址探测：先读取管理服务器接口 IPv4，再通过该交换机当前 SSH 会话的 `w` 输出识别回源地址，并要求两者匹配。也可显式覆盖：

```bash
bash upgrade.sh --method https --all --http-server 192.0.2.10
```

文件映射：

```text
OS BIN  -> https://<server>/image/<file>.bin
CAB/VME -> https://<server>/firmware/<file>
```

生成脚本不再调用 `curl`，也不先下载到 `/home/admin`。OS、BIOS和CPLD均把完整HTTPS URL直接传给NVUE，fetch成功后再用basename执行install：

```bash
nv action fetch platform firmware BIOS https://<server>/firmware/0ACQF.cab
nv action install platform firmware BIOS files 0ACQF.cab force skip-version-check
```

NVOS没有为该命令记录“跳过HTTPS证书验证”的参数，因此服务器必须提供交换机信任的有效CA证书。若客户环境只能使用未受信任的自签名证书，应改用默认SCP方式，或先把签发CA加入交换机信任链。

生成脚本不包含固定服务器地址。编排器在部署时通过加密 SSH 标准输入传入每台设备应使用的 `HTTP_SERVER_IP`。

### 3.4 HTTP方式

```bash
bash upgrade.sh --method http --all
```

HTTP与HTTPS使用相同的服务器地址探测和URL路径映射，但处理方式不同：

1. 使用 `curl -fsSL --retry 3 --retry-delay 5` 下载到 `/home/admin/<file>.part.<pid>`。
2. 下载失败或临时文件为空时删除临时文件并停止，不执行NVUE。
3. 校验成功后原子移动为 `/home/admin/<file>`。
4. 执行 `nv action fetch ... file:///home/admin/<file>`。
5. fetch成功后以basename执行install。

BIOS示例：

```bash
curl -fsSL --retry 3 --retry-delay 5 http://<server>/firmware/0ACQF.cab -o /home/admin/0ACQF.cab.part.<pid>
mv /home/admin/0ACQF.cab.part.<pid> /home/admin/0ACQF.cab
nv action fetch platform firmware BIOS file:///home/admin/0ACQF.cab
nv action install platform firmware BIOS files 0ACQF.cab force skip-version-check
```

## 4. 设备清单

### 4.1 ib.csv

默认优先读取脚本目录中的 `ib.csv`。`type` 和 `eth0_ip` 是必需列；建议同时提供 `hostname` 用于一致性检查：

```csv
hostname,type,eth0_ip
IB-Leaf01,ib,198.51.100.11
IB-Leaf02,IB,198.51.100.12
OOB-Leaf01,eth,203.0.113.21
```

规则：

- `type` 忽略大小写和首尾空格。
- 只读取 `type=ib` 的设备。
- 使用 `eth0_ip` 登录，不使用 hostname。
- 登录后执行远端 `hostname`，并与 CSV 的 hostname 做大小写不敏感比较；结尾的 `.` 不影响比较。
- hostname 不一致、CSV hostname 为空或远端查询失败时会打印 ERROR，并统一提示是否继续；10秒超时和直接回车默认停止。
- 用户确认继续后，日志优先使用交换机实际 hostname，格式为 `[hostname eth0_ip]`。
- 当前只接受合法 IPv4。
- 重复地址去重，保留第一次出现顺序。
- 支持 UTF-8 BOM 和标准 CSV 引号。
- 任意 IB 行地址为空或非法时停止，不静默跳过。
- CSV 存在但格式错误时不会回退到 `ib.log`。

指定其他 CSV：

```bash
bash upgrade.sh --dry-run --ib-csv /path/devices.csv
```

### 4.2 ib.log兼容输入

只有 CSV 不存在时才读取 `ib.log`：

```text
# 每行一个目标
198.51.100.11
198.51.100.12
```

支持空行、整行注释、行尾注释和去重。`ib.log` 没有类型字段，因此其中所有有效目标都会进入处理范围。

使用 `ib.log` 时没有可比较的 CSV hostname。脚本仍会登录交换机执行 `hostname`，并把获取结果用于后续日志；查询失败时同样要求用户确认是否继续。

```bash
bash upgrade.sh --ib-csv /not/exist.csv --ib-log ./ib.log --dry-run
```

## 5. 升级阶段和目标版本

阶段执行顺序：

```text
OS -> 等待 -> BIOS -> 等待 -> CPLD -> 等待 -> dry-run验证
```

可以单独或组合选择：

```bash
bash upgrade.sh --os
bash upgrade.sh --bios --cpld
bash upgrade.sh --all
bash upgrade.sh --os-first
```

`--os-first` 会自动选择 OS、BIOS 和 CPLD，并使用 `TARGET_OS_FILES` 最后一个条目作为最终 OS 目标：

1. 每轮只把交换机推进一个配置的 OS 版本节点。
2. 等待交换机重启后重新查询版本。
3. 仍低于最终目标时继续下一轮 OS。
4. 所有交换机达到最终 OS 后才执行 BIOS 和 CPLD。
5. 任意 OS 查询/升级失败，或仍有设备低于目标但本轮没有部署时，阻止 BIOS/CPLD。
6. 最多运行与 `TARGET_OS_FILES` 数量相同的轮次；达到安全上限后版本仍未推进会报错并阻止 BIOS/CPLD，避免设备持续报告旧版本时无限循环。

例如当前版本为 `25.02.6077`，会先升级到 `25.02.7002`，等待并确认后再升级到 `25.02.8008`，最后才进入 BIOS/CPLD。

没有阶段参数时，交互运行会询问阶段；`--dry-run`、`--scripts-only` 或 `--yes` 默认选择全部阶段。

当前 OS 路径：

```text
25.02.6077 -> 25.02.7002 -> 25.02.8008
```

每次运行只推进到第一个高于当前版本的节点。例如当前版本是 `25.02.7002`，本轮目标是 `25.02.8008`。

当前 BIOS 目标：

```text
0ACQF_06.01.006 --[0ACQF.cab]--> 0ACQF_06.01.009
```

BIOS 不进行数值大小比较：当前版本精确为 `0ACQF_06.01.006` 时使用 `upgrade.sh` 所在目录下的 `0ACQF.cab`；精确为 `0ACQF_06.01.009` 时不升级；其他版本按不支持处理并报错跳过，避免对未知基线强制刷写。

CPLD 目标版本从 BURN 文件名解析，并逐项核对目标 CPLD ID。任意目标 ID 在设备查询结果中缺失时按查询失败处理，不会误报已达标。

## 6. 并发、确认和错峰

每个升级基线的第一台设备顺序执行并确认；确认后，其余同基线设备在显式子 shell 中并行处理。显式子 shell 用来避免 Bash 对后台函数末尾 SSH/SCP 命令做进程替换而跳过回调剩余逻辑。

默认并发上限为8，低于常见 OpenSSH `MaxStartups` 起始阈值，避免大量交换机同时通过 SCP 回连管理服务器时被随机断开。`--parallel-limit 0` 可显式取消限制，但仅建议在已经调高并验证管理服务器 SSH 容量后使用。

```bash
bash upgrade.sh --method local --all --parallel-limit 10
```

## 7. 逻辑架构

脚本由一个管理服务器编排器和按方式动态生成的交换机子脚本组成。

```text
命令行和静态目标配置
        |
        v
参数/配置安全校验
        |
        v
CSV优先、ib.log回退 -> hostname查询与一致性检查
        |
        v
当前OS/BIOS/CPLD发现 -> 计算本设备下一动作
        |
        +--> dry-run：记录需求、打印建议命令、默认不执行
        |
        +--> real run：准备实际需要的包 -> 生成/部署子脚本
                                      |
                   +------------------+------------------+
                   |                  |                  |
                  SCP               HTTPS              local              HTTP
             NVUE直接SCP fetch    NVUE直接HTTPS      管理服务器推送      curl后file fetch
                   +------------------+------------------+------------------+
                                      |
                                      v
                          NVUE fetch完整路径/install文件名
                                      |
                                      v
                              等待、汇总、dry-run验证
```

主要代码层次：

- 输入和配置层：参数解析、`validate_configuration`、设备清单解析及 hostname 校验。
- 发现和决策层：版本查询、版本比较、下一 OS 节点计算、CPLD 逐 ID 比较。
- 传输策略层：`method_prepare_package` 将 local/SCP/HTTPS/HTTP 差异隔离在统一入口。
- 生成层：四种 `generate_scripts_*` 生成共20个交换机子脚本。
- 调度层：代表设备顺序确认，其余设备显式子 shell 并发，`--parallel-limit` 分批回收。
- 执行层：`deploy_and_run` 只负责远端目录、子脚本部署、运行时秘密传递和退出码收集。
- 汇总和验证层：组件计数、部署计数、自动只读复查和可选二次升级。

逐分支执行流程、dry-run、参数、日志、等待和升级后验证均已合并在本 README 的
第 10–16 节中，避免维护另一份容易与 `upgrade.sh` 漂移的流程文档。

## 8. 验证测试记录

本轮测试在隔离 mock 环境中执行。`ssh`、`scp`、`ip` 和 `nv` 均被测试替身接管，没有连接或升级真实交换机。测试覆盖的是编排逻辑、命令构造、状态转换、错误传播和生成脚本行为；真实 NVOS 硬件兼容性仍应使用一台测试交换机做最终验收。

| 分类 | 场景 | 结果 |
| --- | --- | --- |
| 静态 | 主脚本 `bash -n` | 通过 |
| 生成 | SCP/HTTPS/local/HTTP各生成5个脚本，共20个 | 通过 |
| 生成 | 20个子脚本逐个 `bash -n` | 通过 |
| HTTP | curl临时下载、非空检查、原子移动、file fetch | 通过 |
| 配置 | OS路径严格递增、CAB格式、BURN/REFRESH FUI和CPLD目标一致 | 通过 |
| 输入 | 合法CSV、type大小写、非IB过滤、旧版日志回退 | 通过 |
| 输入异常 | 缺列、非法IPv4、无IB设备、危险旧日志目标 | 正确失败 |
| hostname | CSV一致、默认拒绝不一致、`--yes`确认继续 | 通过 |
| local E2E | OS 6077→7002→8008，再BIOS/CPLD，最后验证 | 通过 |
| 并行E2E | 两台设备并行执行OS/BIOS/CPLD，二次验证为零需求 | 通过 |
| OS-first异常 | 升级命令成功但版本不推进 | 3轮安全上限后正确失败 |
| SCP | 设备为7002时只要求8008包 | 通过 |
| SCP异常 | 需要8008但显式目录为空 | 正确失败 |
| SCP边界 | 所有设备达标且目录为空 | 不要求无关包，通过 |
| SCP自动化 | 用户名/密码已提供且无TTY | 通过 |
| SCP回连认证 | 从第一台交换机验证管理服务器密码，错误重试3次 | 通过 |
| 地址探测 | 本机接口IP与交换机`w`来源地址匹配 | SCP/HTTPS/HTTP均通过 |
| HTTPS | 默认生成`https://` URL，不指定服务器时逐设备自动注入地址 | 通过 |
| 子脚本 | SCP/HTTPS使用完整远端URL；local/HTTP使用`file:///home/admin/...`；install使用basename | OS/BIOS/CPLD均通过 |
| HTTPS直取 | 不调用curl、不预下载、不使用`file://` | 通过 |
| NVUE异常 | `nv`返回非零 | 正确失败 |
| SSH异常 | 版本查询失败 | 组件失败并返回非零 |
| 升级异常 | 远端子脚本返回非零 | 组件失败并返回非零 |
| dry-run | 需求计数、设备明细、建议命令、30秒默认否 | 通过 |
| dry-run确认 | 明确输入yes后执行相应组件并再次验证 | 通过 |
| 无TTY | dry-run检测出需求 | 打印提示并安全地不执行，无系统TTY报错 |

## 9. 代码审查结论和后续改进建议

本轮已经修复的高价值问题：

- 移除 HTTP 服务器地址硬编码，改为安全的逐设备自动探测或显式参数。
- 为静态目标文件和版本路径增加启动期一致性校验，错误配置在连接设备前失败。
- 加强 `ib.log` 目标校验，拒绝可能进入 SSH 参数或日志的危险内容。
- 修复后台函数的 Bash 尾部外部命令优化问题；否则第二台及后续设备可能只打印“自动升级”但不实际部署。
- 修复已有 SCP 环境凭据时仍强制要求 TTY 的问题。
- 修复无控制终端时 dry-run 直接操作 `/dev/tty` 的问题。
- 为 `--os-first` 增加最大轮次保护及查询/停滞错误计数。
- local方式统一使用 `/home/admin` 下的文件路径；HTTPS方式改为NVUE直接fetch远端URL。
- 修复NVUE直接SCP fetch在无TTY远端执行中调用`getpass()`并报`EOFError`：改由生成脚本的Python PTY安全响应密码提示。

仍可继续优化，但不影响本轮功能验收：

1. 生成器去重：SCP PTY helper和三类子脚本的日志骨架仍有部分重复。建议下一步继续使用小型模板函数输出公共段，组件函数只提供 NVUE 命令和文件列表。生成脚本属于高风险代码，重构时必须保留15脚本快照对比和黑盒回归。
2. 配置集中化：目标包文件名、交换机用户、远端脚本目录、local交换机包目录、SSH超时、OS错峰120秒和默认阶段等待480秒仍是代码顶部常量。它们是有意的部署默认值，不是隐藏地址硬编码；若多环境差异增大，建议迁移到只读配置文件并继续使用当前 `validate_configuration` 校验。
3. 完整性校验：当前只使用“文件非空”防止0字节包，无法发现非空但损坏的包。建议为每个发布包维护SHA-256清单；传输前后都校验，成功后才执行 NVUE。
4. SSH主机身份：当前为了新设备批量部署使用 `StrictHostKeyChecking=no`。安全要求较高的环境应预置 `known_hosts`，并改为 `StrictHostKeyChecking=yes` 或 `accept-new`。
5. HTTP预检：dry-run不会对每个URL做HEAD/GET探测，这是为了保持只读和避免传输。可以增加可选 `--verify-http-packages`，只检查实际需要的URL、Content-Length和摘要。
6. 测试可维护性：建议把本轮 mock 黑盒场景固化为仓库测试脚本，并在每次修改后自动运行语法、生成脚本快照、输入异常和双设备并行回归。
7. 统计语义：`--os-first` 的OS `ok` 是“设备轮次检查次数”，不是唯一设备数；日志已能正确表达过程，但可额外增加“唯一设备达标数”汇总减少误解。

当前没有发现会阻止这套流程上线试运行的已知逻辑缺陷。由于测试未在真实交换机上执行固件写入，生产前仍建议按第16节先完成单台硬件验收。

`--parallel-limit`：

- 默认值 `8`：每批最多并发8台，等待该批完成后继续。
- `0`：显式取消限制，其余设备一次并发执行。
- 其他大于0的值：每批最多并发指定数量，等待该批完成后继续。

OS 传输使用 `OS_DOWNLOAD_JITTER=120`：

- 每个 OS 基线用于顺序确认和验证的第一台交换机不等待，立即传输 BIN 并执行升级。
- 只有确认后的其余批量并行设备才应用错峰。
- 实际随机等待范围是 `0-119` 秒。
- local 在管理服务器推送缺失 OS 包前等待。
- SCP/HTTPS/HTTP 在交换机拉取或下载 OS 包前等待。
- local 发现交换机已有有效 OS 包时不等待。
- BIOS/CPLD 不应用 OS 错峰。

`-y` 会自动确认升级操作，但不会跳过必要的密码输入，也不会自动确认下述公钥安装。
它也会自动确认 hostname 不一致或查询失败；批量生产运行前建议先不带 `-y` 执行一次验证。

## 10. 密码和SSH处理

脚本以 `admin` 登录交换机；只有公钥不能覆盖全部设备时，才隐藏输入一次密码：

```text
Switch password for admin (attempt 1/3, used for all devices):
```

读取设备清单后，脚本先对所有目标逐台执行仅允许公钥认证的只读 SSH 登录预检：

- 全部设备均可免密登录时不提示输入交换机密码，后续 SSH/SCP 也保持批处理公钥认证。
- 只要有一台设备不能免密登录，就提示输入一次共享密码，并在第一台免密失败的设备上强制关闭公钥认证来验证密码，避免其他设备已有 key 时把错误密码误判为有效。
- 只有明确的认证拒绝才会触发密码提示。连接超时、路由不可达、端口拒绝和主机密钥错误会保留原始 SSH 错误，但不会中断清单扫描；脚本继续尝试其他设备。
- Phase 0 中发生上述非认证类 SSH 错误的设备会立即从活动目标列表移除，不再参与 key 安装、hostname、包需求发现、OS、BIOS、CPLD、部署或验证操作。
- 如果部分设备连接异常，但所有可连接设备均可免密登录，则不询问密码，也不提示部署 key。
- 只有清单内所有设备都无法建立 SSH 连接时，才在扫描结束后退出且不询问密码。
- 密码验证目标临时发生连接异常时，脚本会依次尝试其他预检时可连接的设备；验证命令会强制关闭公钥认证，因此已有 key 的设备也能安全用于验证密码。所有候选设备都无法连接时才退出。
- 进程退出前会通过统一清理流程单独打印 Phase 0 跳过设备汇总，即使后续中途报错也不会遗漏；汇总包含输入目标、CSV hostname（如有）和首次 SSH 错误原因。这些设备不计入各组件的 checked/failed 数量。
- 密码验证成功后，同一密码用于尚未部署 key 或公钥认证失败的设备。

- 密码认证失败时明确打印 `attempt N/3`，并提示重新隐藏输入。
- 最多允许3次密码尝试；全部失败后立即退出，不把认证失败误报为 hostname 异常。
- 连接超时、路由不可达和其他非认证故障不会反复询问密码，而是直接报告 SSH 连接问题。
密码处理：

- 不写入日志或生成脚本。
- 不作为 SSH/SCP 命令行参数。
- 交换机登录密码使用权限为 `700` 的管理服务器临时 `SSH_ASKPASS`。
- 管理服务器SCP密码经加密SSH标准输入传到子脚本环境，再由Python PTY在NVUE显示`Password:`后注入；不进入URI或命令行。
- 本次运行和升级后验证复用密码。
- 退出时删除临时文件并清除变量。
- 不依赖 `sshpass`。
- 如果 `MGMT_SCP_USER` 和 `MGMT_SCP_PASSWORD` 已由受控自动化环境提供，SCP 方式不要求 TTY；只有缺少凭据时才交互提示。
- 脚本会实际尝试打开 `/dev/tty`，而不是只检查设备节点权限，避免 cron/CI 中出现 `Device not configured`。

SSH/SCP 使用压缩参数 `-C`。默认连接超时10秒，每次连接最多提示一次密码。

### 可选公钥安装

如果至少一台设备不能免密登录，且共享密码已在该设备验证成功，脚本会询问是否把管理服务器当前账户的公钥安装到本次 `--ib-csv` 或 `--ib-log` 选中的全部交换机。若所有设备一开始就能免密登录，则不再提示安装：

```text
Install public key SHA256:... (ED25519) on all 8 selected switch(es)? [y/N] (default: no in 10s):
```

- 默认依次查找 `~/.ssh/id_ed25519.pub`、`id_rsa.pub`、`id_ecdsa.pub`；也可通过 `--public-key FILE` 明确指定。
- 只有输入 `y` 或 `yes` 才执行；直接回车、其他输入或等待10秒均跳过。`-y` 不改变这个默认行为。
- 脚本保留原有 `authorized_keys`，设置 `.ssh`/`authorized_keys` 权限为 `700`/`600`，同一完整公钥已存在时不重复追加。
- 每台写入后都会强制关闭密码和键盘交互认证，以纯公钥 SSH 再验证一次，并汇总安装、已存在和失败数量。
- 自动验证子运行以及 dry-run 确认后启动的真实升级子运行不会重复询问。
- 找不到默认公钥时只记录并跳过；显式指定的文件不存在、不可读或不是单个有效 OpenSSH 公钥时退出并报错。

## 11. NVUE文件参数规则

OS BIN统一遵循：

```text
/home/admin/<os-file>.bin
```

local方式先验证 `/home/admin/<file>` 非空；HTTP方式下载并验证后使用同一路径。两者都从本地完整路径执行fetch。HTTPS和SCP方式直接使用服务器URI。所有方式的install均使用导入后的basename：

```text
fetch   local/HTTP使用file:///home/admin/<file>；HTTPS使用https://服务器/路径/文件；SCP使用scp://用户@管理地址/脚本目录/文件
install 使用导入后的文件名 basename
```

BIOS 示例：

```bash
nv action fetch platform firmware BIOS file:///home/admin/0ACQF.cab
nv action install platform firmware BIOS files 0ACQF.cab force skip-version-check
```

这样可以避免 `fetch` 消耗或清空源文件后，`install` 继续引用原始完整路径导致失败。

## 12. dry-run和scripts-only

### dry-run

```bash
bash upgrade.sh --method local --dry-run
```

dry-run会：

- 读取设备并查询 OS、BIOS、CPLD 版本。
- 判断本轮需要升级的组件。
- 检查实际需要的本地/SCP源包。
- 输出设备级需求和组件计数。

dry-run不会：

- 生成、部署或执行子脚本。
- 下载、推送或复制升级包。
- 执行 `nv action fetch/install`。
- 提示管理服务器 SCP 密码。

固件和升级包检查在 dry-run 中保持只读。公钥安装是独立的可选准备操作，因此即使使用 `--dry-run`，在10秒提示中明确输入 `y` 仍会修改交换机的 `authorized_keys`；默认不执行。

如果 dry-run 检测到至少一个设备/组件需要升级，并且所有版本查询和升级包检查均成功，汇总后会提示：

```text
Dry-run found 3 device/component upgrade requirement(s).
Suggested command: bash upgrade.sh --method local ... --bios --yes
Start the real upgrade for all listed requirements now? [y/N] (default: no in 30s):
```

- 汇总会根据实际需要的组件生成并打印一条可复制的真实升级命令；例如只有 BIOS 需要升级时只包含 `--bios`。
- 输入 `y` 或 `yes`：执行显示的命令，保留传输方式、设备文件、目录、并发和等待参数，并自动确认刚才列出的升级计划。
- 直接回车、输入其他内容或等待30秒：不执行真实升级。
- dry-run 存在查询失败、hostname校验未确认或升级包检查失败时，不提供真实升级入口。
- 真实升级完成后的自动验证 dry-run 如果仍检测到升级需求，也会显示此提示；默认不执行下一轮。
- 只有用户明确输入 `y` 或 `yes` 才会按最新验证结果升级相应交换机仍然需要升级的组件。下一轮完成后会再次验证和询问，不会无人值守地自动递归。

除上述明确确认的公钥安装外，dry-run 的固件流程保持只读；只有用户在最终提示中明确输入 `y` 后，才会启动新的真实升级运行。

示例汇总：

```text
Dry-run upgrade requirements
Components requiring upgrade: OS=0  BIOS=1  CPLD=0
  [198.51.100.12] BIOS: 0ACQF_06.01.006 -> 0ACQF_06.01.009
```

### scripts-only

```bash
bash upgrade.sh --method scp --scripts-only --all
```

只在 `xdr-upgrade-logs/upgrade_scripts/<method>/` 生成子脚本，不读取设备、不检查版本、不连接交换机，也不检查升级包是否存在。

## 13. 等待和升级后验证

某阶段有实际部署时，默认等待：

```text
BIOS_PHASE_WAIT=600秒（10分钟）
OS/CPLD PHASE_WAIT=480秒
```

`--phase-wait` 会同时覆盖BIOS、OS和CPLD等待时间：

```bash
bash upgrade.sh --all --phase-wait 600
```

随机传输错峰发生在传输之前，并行任务结束后只执行对应组件的阶段等待，不会再次叠加120秒。

只要本次至少部署了一个组件，脚本最后会使用相同方式、设备输入和阶段参数自动执行一次 `--dry-run` 验证。

## 14. 完整参数

| 参数 | 说明 |
| --- | --- |
| `-h`, `--help` | 显示帮助。 |
| `--method scp\|http\|local\|https` | 选择传输方式；未提供时10秒默认 SCP。 |
| `-y`, `--yes` | 自动确认升级。 |
| `-A`, `--all` | 选择 OS、BIOS、CPLD。 |
| `--os` | 只选择 OS。 |
| `--bios` | 只选择 BIOS。 |
| `--cpld` | 只选择 CPLD。 |
| `--os-first` | 按配置路径把所有设备 OS 逐轮升级到最终目标，再执行 BIOS/CPLD。 |
| `--dry-run` | 只读版本和升级需求检查。 |
| `--scripts-only` | 只生成子脚本。 |
| `--ib-csv FILE` | 指定设备 CSV。 |
| `--ib-log FILE` | 指定 CSV 不存在时使用的旧清单。 |
| `--public-key FILE` | 指定在可选安装提示中使用的 OpenSSH 公钥。 |
| `--mgmt-server HOST` | SCP管理服务器地址；默认逐设备探测。 |
| `--mgmt-user USER` | SCP管理服务器用户；默认 `id -un`。 |
| `--scp-root DIR` | SCP源目录；默认脚本目录。 |
| `--source-root DIR` | local源目录；默认脚本目录。 |
| `--local-dir DIR` | local/HTTP交换机升级包目录；默认 `/home/admin`。 |
| `--http-server HOST` | HTTPS/HTTP服务地址；默认逐设备通过交换机 `w` 自动探测。 |
| `--http-scheme https\|http` | 兼容参数，用于在HTTPS/HTTP之间选择；新命令应优先使用 `--method`。 |
| `--parallel-limit N` | 并发上限；默认8，`0`表示显式不限制。 |
| `--phase-wait SEC` | 覆盖所有组件的部署后等待时间；默认BIOS为600秒，OS/CPLD为480秒。 |

## 15. 日志和生成文件

当前目录的 `xdr-upgrade-logs/` 由 DAY0 setup 链接到当前项目的
`99-output-ib_nvl/bringup/xdr-upgrade-logs/`；切换项目后，日志和生成脚本会随项目归档。

编排日志：

```text
xdr-upgrade-logs/upgrade-scp-YYYYMMDD-HHMM.log
xdr-upgrade-logs/upgrade-local-YYYYMMDD-HHMM.log
xdr-upgrade-logs/upgrade-https-YYYYMMDD-HHMM.log
xdr-upgrade-logs/upgrade-http-YYYYMMDD-HHMM.log
```

设备登录成功并取得 hostname 后，日志会同时打印交换机实际主机名和管理地址：

```text
[2026-08-08 15:01:37] Phase 1: OS Upgrade  (final target: 25.02.8008)
[2026-08-08 15:01:37]   [IB-Leaf01 198.51.100.11] Current OS: 25.02.7002
[2026-08-08 15:01:38]   [IB-Leaf01 198.51.100.11]   File fetched successfully
```

日志使用固定层级缩进：主标题、阶段标题、`Phase 1 round N` 和每个 `Phase N result` 最终汇总不缩进；每条 round/result 检查点后输出两个不带时间戳的空白行。主标题下的目标版本、传输方式和运行模式缩进两格；编排器在各阶段产生的设备查询、判断和传输日志同样缩进两格；交换机远端子脚本及NVUE输出在设备标签后再缩进一层。准备工作单列为 `Phase 0: Preparation`，因此任何单条业务日志都能从最近的顶层标题和缩进判断所属阶段。

并行设备的编排日志使用进程锁逐行写入终端和主日志，不再由多个 `tee` 进程竞争输出。远端输出进入主日志前会把回车进度更新拆成独立记录，并清除 ANSI/光标控制字符，避免出现大段前导空格、半行拼接或阶段汇总被挤偏。

SSH 始终使用 `eth0_ip`，主机名只用于一致性检查和提高日志可读性。如果交换机 hostname 查询失败且用户确认继续，则该设备回退为 CSV 标签或 `[目标地址]`。

生成脚本：

```text
xdr-upgrade-logs/upgrade_scripts/scp/
xdr-upgrade-logs/upgrade_scripts/http/
xdr-upgrade-logs/upgrade_scripts/local/
xdr-upgrade-logs/upgrade_scripts/https/
```

`upgrade.sh` 是生成脚本的唯一来源。每次修改它之后，必须在该目录重新生成并检查四套脚本：

```bash
bash upgrade.sh --method scp --scripts-only --all --scp-root /root/IB_Packages
bash upgrade.sh --method http --scripts-only --all
bash upgrade.sh --method local --scripts-only --all
bash upgrade.sh --method https --scripts-only --all
find xdr-upgrade-logs/upgrade_scripts -mindepth 2 -maxdepth 2 -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
```

交换机远端工作目录：

```text
/home/admin/upgrade
```

生成的远端脚本使用 `tee` 同时保留远端日志并把 NVUE 错误返回到管理服务器编排日志。

## 16. 推荐生产流程

1. 检查 `ib.csv` 中设备范围。
2. 确认目标文件名和目标版本配置。
3. 使用相同传输方式执行 `--dry-run`。
4. 确认最终汇总只包含预期组件和设备。
5. 先使用一台测试交换机执行真实升级。
6. 确认重启、版本和日志正常。
7. 设置合理的 `--parallel-limit` 后扩大范围。

示例：

```bash
bash upgrade.sh --method local --all --dry-run --parallel-limit 10
bash upgrade.sh --method local --all --parallel-limit 10
```
