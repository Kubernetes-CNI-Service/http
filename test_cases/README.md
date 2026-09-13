# Test Case 案例库

`test_cases/` 是仓库唯一的测试案例目录。这里集中保存全部自动化回归、案例模板和必须在
真实环境执行的验收案例；测试文件不得散落到其他源码目录，也不提供旧 `tests/` 别名，避免
同一个案例被 discovery 重复加载。

本目录中的自动化测试不连接设备、不修改项目运行数据，重点检查跨目录接口，而不是替代
真实交换机、Docker 或端到端部署测试。

## 变更感知测试治理

完整机制和退出码见 [CHANGE_AWARE_TESTING.md](CHANGE_AWARE_TESTING.md)。
受管脚本、canonical 目标和软链接 alias 的数量由当前 manifest 与工作树动态推导；使用
`run_related_tests.py --list` 查看当前值，不在文档中维护容易过期的快照。
runner 每次运行都会重新发现生产脚本，并实时校验每个路径都有 direct 测试
映射、至少一个覆盖多个真实脚本的 workflow/scenario，以及正确的 canonical target。新增脚本
没有完整映射时会 fail closed。

manifest 还把 Cumulus `03-templates-j2/*.yaml.j2` 与 Cumulus/NVOS 配置根的
`default*.yaml` 标为 complete tracked support authorities。runner 只接受正向、仓库相对的
POSIX 直接子项 glob，并通过 held descriptors 校验非链接目录和 single-link regular members；
磁盘新增但未 pinned、pinned 后缺失、特殊文件、symlink/hardlink 或 root/member rebinding
都会阻断证明。生成的 `99-output*` 不会因宽泛递归匹配误入 authority。模板闭包另由不可跳过的
Jinja 测试锁定静态 include/import/from-import/extends 引用及 cycle 拒绝，默认文件则由完整
literal semantic oracle 锁定。上述任一 authority byte 变化会使旧 full-suite attestation
过期；related 测试不会被提升为 eager full，也不能铸造或沿用 stale full proof。

开发期间建议持续观察；普通单次运行会根据已批准 SHA-256 自动选择受影响的 direct 与
workflow/scenario 测试，并且只有全部通过才更新批准哈希：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --watch --interval 2 -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py -v
```

全部 `test_*.py` 还在同一份 manifest 中归入 7 个互斥主测试域。先查看完整目录，再按域执行；
`--suite` 可重复，用于一次合并多个域：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --list-suites
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --suite deployment-runtime -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --suite packaging-sync --suite repository-governance -v
```

分类运行不会更新批准哈希，也不会替代发布前的全量门禁。新增测试模块若没有主分类、属于多个
主分类，或分类引用了不存在的模块，manifest 校验都会 fail closed。

正式发布需要一份绑定当前源码、测试、manifest 和 Python/平台身份的全量回归证明。本机
macOS 正式 `DAY0-Prepare/11-load.py` 先解析并拒绝互相冲突的纯命令行参数，再在生成项目文件前执行全量回归，并在成功后做只读逐字节
复核。也可以单独执行以下治理命令生成及检查证明：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --all -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py --check --require-full
```

发布前合同是：生产行为变更必须先或同时更新独立测试预期；确认
`script_test_manifest.json` 的 direct 与 workflow 映射；执行 `--all` 并全部通过；随后执行
`--check --require-full`，确认源码、测试、manifest、执行环境和批准状态仍是同一组精确身份。
`sync-code.py` 与 `tar-for-upload.py` 只复核并复用这份证明，不会运行全量测试；证明缺失、过期
或执行环境不匹配时必须要求重新完成本机正式 load，并在任何打包或远端连接前停止。Linux
管理服务器 load 与 macOS `--dry-run` 不运行开发测试。任一步失败都必须阻断
`sync-code`、`tar-for-upload --deploy` 和正式部署。runner 只负责选测、执行及成功后的批准哈希
更新，绝不会根据实现自动重写断言；禁止通过弱化、跳过或删除测试来接受失败。

manifest 校验还会直接加载并合并三份真实部署选择器：`sync-code.py` 的根目录同步选择、
`infra/docker/activate.py` 的镜像源码选择，以及 `_package_common.py` 的归档源码选择。任一选择器
缺失、无法加载或返回非法路径属于配置错误；成功选择出的路径若不在 `scripts` 与
`tracked_support` 的并集中，则属于未受管部署权威。两类错误都在读取或更新批准 ledger 之前
fail closed，`--check --require-full`、`--list` 与 `--list-suites` 也不能绕过。

## 新功能、流程和场景的补充规则

1. 功能或缺陷修复必须先在 `test_<area>.py` 中增加可稳定复现的案例，再修改实现。
2. 单函数行为写 unit/contract case；跨文件提交与回滚写 transaction case；跨 DHCP、Apache、
   monitor、worker 或设备身份边界的行为写 integration/scenario case。
3. 无法在本机安全执行的步骤不能省略，必须按 [CASE_TEMPLATE.md](CASE_TEMPLATE.md) 写入
   [REAL_ENVIRONMENT.md](REAL_ENVIRONMENT.md)，记录前置条件、证据、清理和是否具有破坏性。
4. 每个自动化文件必须有模块 docstring，并能被下面的统一 discovery 命令发现。
5. 测试数据只放本目录或运行时临时目录；案例库永远不进入 upload/sync 部署包。
6. 行为、流程、场景或文档合同变化时，要同时更新相应案例和本 README。
7. 每个受管脚本还必须在 `script_test_manifest.json` 中同时拥有 direct 和 workflow/scenario
   映射；新增脚本在映射和测试齐全前必须保持 fail closed。

## 在整体架构中的位置

本目录验证公共模块之间的静态合同和安全边界，适合每次代码同步前快速执行；它不替代
管理服务器 load、Docker infra、AIR simulation 或真实设备闭环。用户流程以
根目录 `USER_MANUAL.md` 为准，失败时再回到对应模块 README 定位接口。

`test_project_contracts.py` 是跨目录契约主入口，按功能契约分组加载各目录模块。
`test_load_release_transaction.py` 在隔离临时目录中验证 load 的统一 release：只有 DHCP 与
Cumulus/NVOS 子 manifest 的设备身份、真实 YAML hash、完整 MAC 链接集合、effective default
及 DHCP 输出都匹配当前输入时才发布 parent release；旧 `latest_yaml`、篡改 YAML/链接或
生成后被修改的 DHCP 文件必须被拒绝。测试还要求 infra 延迟服务激活，
`current-release.json` 只在 `/etc/dhcp` staging/事务安装成功之后原子提交；失败时恢复旧 DHCP
文件、旧 YAML latest 和进入启动阶段前的服务状态，不能把已验证但尚未安装的 parent 当作
current。由于 child manifest 尚无输入来源证明，非 dry-run `--skip-generate` 必须在任何状态
修改前失败。

同一模块还覆盖端到端 deployment scope：默认 `all` 同时生成 Production/AIR；`prod` 只发布
Production Cumulus/IB/NVL；`air` 只发布 AIR DHCP/YAML/release，并只临时渲染 AIR full profile
实际引用的 Production 来源；单独指定 `mini` 会自动选择 AIR scope 和 `eth`，显式 `prod+mini`
必须在本机全量测试启动前失败。scope 必须逐段写入 child/parent
manifest，monitor `auto` 仅继承明确的 `air`/`prod`，冲突组合在锁和任何项目写入前 fail closed。

`test_mlag_evpn_generation.py` 覆盖 Cumulus MLAG 与 EVPN-MH 的互斥边界：MLAG 设备只保留
EVPN 控制平面，非 MLAG 设备继续启用 EVPN multihoming；同设备混合两种冗余模式会在 CSV、
legacy/nested bond 预处理及跨 `set` 的最终 YAML 门禁中失败。跨模块案例通过真实 Border 父模板
和 `generate_all()` 验证 MLAG 输出，再经过发布规范化并与 `nv config show` 比较；MLAG 输入若
选到不能生成 MLAG 配置的模板也会在发布前失败。测试还确认 MLAG `peerlink` 只生成
成员和 `type: peerlink`，不显式配置 `bridge`/`vlan`；它依靠 VLAN-aware bridge 的默认行为
继承 `br_default` 的全部业务 VLAN，`peerlink.4094` 仍作为独立控制子接口生成。

`test_terminal_l2_stp_generation.py` 覆盖 schema v2 终端二层端口的 STP 防环策略：生成器自动为带
`bridge` 配置的独立二层 `swp` 或逻辑二层 `bond` 生成版本匹配的枚举；Cumulus 5.14 及以前为
`admin-edge: on`/`bpdu-guard: on`，5.15 及以后为
`admin-edge: enabled`/`bpdu-guard: enabled`，CSV 不增加策略字段。版本缺失或无法识别、跨 `set`
片段的 `stp` 非 mapping 覆盖均 fail closed。routed BGP 接口、peerlink 和 bond member 保持无
Edge/Guard；`oobofoob-leaf` 的 `bond49b51`、`oobofoob-spine` 的 `bond1` 到 `bond11`
作为普通 STP 交换机互联固定排除。冲突值、排除接口上的 Edge/Guard 和合格目标缺失配置
都会安全拒绝。workflow 覆盖真实 CSV→91-devices→配置生成、发布规范化、
`nv config show` 比较以及 Feedback 不向 CSV 回写派生策略字段。

`test_qos_evpn_uplink_generation.py` 覆盖 Border/TAN RoCE QoS 与 EVPN-MH BGP uplink：
Border 只选择普通父物理口，TAN（排除 `tan-cp-1gleaf`）只选择 breakout 子接口，逻辑
bond 不得配置 PFC watchdog；任何启用 EVPN-MH 的模板都必须为每个接口型 BGP neighbor
配置 uplink，并排除 `peerlink.4094`。该模块同时运行真实 Border generator → publisher →
manual runtime/latest 比较；`test_v2_generation_flow.py` 还覆盖真实 v2 TAN breakout 流程。

`test_v2_project_schema.py` 是 schema v2 的单模块合同：版本选择、零到多个普通/EVPN
重复字段组、严格行宽、全局 VRR 按 VRF+VLAN 推导与四位十进制 VLAN-to-MAC 编码、
locally-administered/低 16 bit 基址门禁、standalone SVI、
两种 SVI/VRR + DHCP relay 模式、
Border-only `/29` 高低三地址分区与 VRR±3 next-hop、`/native` 语义、local/MLAG/EVPN
bond 分组以及引用完整性都必须 fail closed；非 Border 模板不受 `/29` 半区策略约束。
`test_v2_generation_flow.py` 在临时项目中串联真实 setup、load、DHCP、Cumulus/NVOS 解析器、
全部具体 Jinja 模板与发布规范化，验证重复 VLAN 不被模板丢弃、单 native VLAN 仍为 trunk、
设备可以没有任何 VLAN 组，并要求等价 v1/v2 管理清单生成逐字节相同的 DHCP 运行文件。
该流程还锁定管理 Docker API 的版本化语法：只有 Cumulus 5.17.x 和 5.18.x 生成的
`system.docker` 只保留 `vrf: mgmt`，不得再生成 `state: enabled`；包括 5.16.x 在内的
其他版本继续保留原语法。
该流程还把真实生成 YAML 再送入 Feedback，验证重复组、native、bond 与派生 VRR 运行态证据
能够回环；Border 只把唯一 `/29` SVI 用于自动默认路由，非 `/29` SVI 不触发规则，
错误半区、多个 `/29` 候选或无效默认下一跳必须在发布目录创建前阻断，
maximum/minimum 两种方向必须分别渲染 N+3/N+4。setup 的 direct case 同时
覆盖未声明 bond 引用、`|` 对齐/MAC 规则和未使用声明 warning；若 `bond_ports` 为空，
遗留的 `bond_type`/`bond_mac` 只产生 warning 且生成器忽略它们，但 VLAN 对未声明 bond
的引用仍必须阻断。
同一 VRF/VLAN 混用共享 gateway 与其他 SVI 地址时，生成器必须在写入任何派生 VRR 字段前
按网段和策略指出共享 gateway、异常 hostname、CSV 行号、字段组及实际地址；该主错误不得被
后续“缺少 vrr_mac”的派生校验掩盖，失败时也不得留下部分 VLAN 已推导、部分未推导的模型。

版本化网页 User Manual 的合同由 `test_project_contracts.py`、upload 与 sync workflow 共同覆盖：
首页必须提供离线入口；V1、V2、V3-dev 均以 Release Notes 开篇，并按目录/文件、逐脚本使用说明、
总体流程、受支持场景、测试验收和故障恢复组织；每个操作入口必须独立写明用途、运行位置、
使用场景、典型用法和是否允许直接执行。场景名称和后端边界使用独立预期，不从页面实现反向
生成。`tools/update-user-manual.py` 的完整目录必须精确覆盖当前 Git tracked 与 untracked/nonignored
文件；每个文件独立说明类别、作用和维护/生成责任，被忽略的大型项目数据、镜像、缓存和运行态
按受控路径模式说明。全部 `.py`、`.sh`、`.cgi`（包括 operator、worker、CGI、内部库和测试）
必须逐项说明是否可直接运行、环境、场景、前置条件、语法、参数、输入输出、成功判据、失败恢复
和示例。V2 Native 主路径必须给出可复制的项目创建、本机 load/full proof、直连/relay 发布、
服务器 load、验收、sync、收集/backup、download/import 和 unload runbook；尚未取得成功真机证据的
Docker 必须标成未准入，不能出现可复制的生产部署命令。生成器 `--check`、真实 upload archive
与增量 sync 还必须证明发布的是同一份当前 `user-manual.html`。

覆盖内容：DAY0 模板输出骨架和 DHCP 唯一性、setup 管理的 monitor global 链接、项目时区、
ibdiagnet 报告发现、首页本地链接、upload/sync 人工备份过滤，以及 Ubuntu 24.04 双架构离线
仓库布局。

Docker operator 合同还覆盖参数化 init：它必须从显式 project/scope 生成 root 私有、single-link、
不可覆盖的 `infra-runtime.conf`，AIR mini 自动固定 Ethernet。`image-export`（兼容别名
`build-export`）必须在同架构联网构建端冻结 source manifest，两次验证 immutable generic image
identity，原子输出 image tar、`image-metadata.json` 与两项 `SHA256SUMS`，且不得读取项目/runtime、
启动、停止、load 或激活服务容器。项目 upload release 必须由 `tar-for-upload.py --relay-bundle`
独立生成，并与 matching installer、upload metadata 和摘要一起发布；shared artifact 与可选
bootstrap-only project image 也各自独立。目标端逐目录校验、由 installer 应用 release、一次
`docker load` 并使用完整 image ID 执行 `deploy-preloaded`。测试必须证明 upload/live release 可在
runtime contract 与 image-coupled 记录匹配时比 generic image 新，也必须证明 coupled drift、非法
compatibility JSON、Mac UID/GID 泄漏和私有 staging 残留都 fail closed。

部署场景测试按位置、后端和操作类型三条轴组合：Mac 只生成/测试；adapter 直通 Ubuntu VM 后与
远端 Ubuntu 共享 Native/Docker 合同；可直连目标区分 Native、Docker 在线 build 和 Docker
预构建；可信中转分别验证这三种后端入口。每一组合还要覆盖首次部署、source update、同一
Service IP 换接口、Service IP 地址值改变、重启和事务中断。中转不把 `sync-code.py` 当作离线
增量包，Native 离线 apps 与 Docker image bundle 也不能互相替代。自动化锁定命令和 fail-closed
边界，真实 adapter、DORA、重启、架构与物理设备证据登记在对应 `TC-REAL-*` 案例。

还覆盖 AIR 行在统一设备清单末尾的原子重建与幂等性、旧 AIR 清单退役，以及 ZTP 状态默认
同时处理 Production/AIR、显式 scope 才筛选单一环境，以及共享 IP 必须按实际 DHCP MAC
唯一归属环境的契约。

新身份/DHCP 契约覆盖：AIR JSON 的 hostname/eth0 MAC 为权威，AIR-only Cumulus 必须生成
“effective default + hostname”的 baseline YAML 与完整 12 位 MAC 链接；Production 未绑定
Cumulus/NVOS 依据 option 60/61/77 仍取得对应 bootstrap，真正 unknown 不取得 ZTP 指令；
ISC DHCP 输出必须直接使用受支持的 option 条件并明确禁止 Kea 风格 `member()`；生命周期日志
中的非零填充 MAC（例如 `2:b:...`）也必须归一化后关联 commit/release/expiry；
`identity_pending` 不生成 host declaration，`transit_dynamic` 不写 `fixed-address`，计划静态
IP 落入动态 range 必须失败。IB/NVL 的 eth0/eth1 MAC 都参与 lease 转正、发布和远端身份匹配。
`dhcp_runtime_inventory.py` 的日志/lease 合并保持只读，临时别名必须包含完整 12 位 MAC；正式
MAC 出现后，当前 hostname 覆盖旧别名并过滤旧 archive 成员。lease 文件先按地址取最后一个
状态块再按 MAC 合并，地址 release/free 或重分配后不会让旧 MAC 继续保留同一 live IP；
`test_dhcp_runtime_reassignment.py` 独立覆盖重分配、无 MAC free 块和 lease 过期。

P2P/AIR 契约还覆盖项目级 `03-air-topology-policy.json`：源 P2P 自连接默认失败关闭，只有
AIR policy 中唯一精确命中的 rewrite 可以替换 AIR edge；LLDPQ 仍保留原始设计链路，节点
allowlist、replacement 和端口集合都必须通过冲突检查。load 把 global 的 Cumulus 版本传入
AIR 生成器，并把 policy hash 纳入 parent release；manual-ZTP 会拒绝发布后新增、修改或删除
该 policy。inventory 中 PDU 的显式分类必须优先于交换机名称启发式，不能生成假 AIR 交换机。
P2P 历史空对端写法必须按完整“设备+端口”端点分类：双端真实才进入物理 LLDPQ DOT；一端
真实、一端为空只进入绑定该 DOT SHA-256 的 description-intent sidecar，并给存在于 YAML 的
接口写入固定 `P2P:----UNUSED-----NO-PEER` 描述；完全未出现在 P2P 的 breakout 补齐端口保持
无 description 的 INFO。部分填写、空意图与真实链路冲突、sidecar 漂移或 sidecar/YAML 不一致
必须独立失败或告警，不能伪造物理 edge。
`test_xlsx_zero_row_fail_closed.py` 与真实 `11-load.py` 配置生成 workflow 还约束 XLSX 提取门禁：
TAN/OOB sheet 的两行表头默认必须成功自动定位，只有显式且仅出现一次的 `--legacy-columns`
才允许使用历史固定列；未识别表头或所有已扫描 sheet 合计提取零行都返回 1，后者必须列出
扫描过的 sheet。开始提取前只删除当前解析后 workbook stem 对应的旧 `*-lldpq.dot` 与
`*-description-intent.json`，因此失败运行不会留下看似可用的旧拓扑，同时不影响其他 workbook
或 AIR 输出；workflow 必须证明 DHCP、交换机配置生成和发布均未继续执行。
AIR DOT 与最终 JSON 的普通、继承及 OOB 节点都必须至少分配 4096 MB 内存，原有更高值不得降低；
`ztp-server` 在两种模板和完整 load workflow 中都必须固定为 8 CPU、8192 MB 内存和 80 GB 存储，
且不能把该专用规格误用到普通交换机。
AIR JSON `positioning` 还必须复用 Ethernet Diagram 的角色、TAN/OOB/OOBofOOB 分区和上游端口排序
语义，在 275 像素网格上稳定生成无重叠的多行坐标；节点或链路输入顺序不得改变结果。

`11-load.py --switch eth|ib|nvl` 的 direct 与 release workflow 必须证明选择器贯穿 devices CSV
平台字段校验、镜像、DHCP、Cumulus/NVOS 生成发布及 parent/child `switch_scope`。默认值为全部
平台；AIR 未显式指定时默认选择 `eth`，AIR+IB/NVL 必须在加锁前失败。单平台成功会退役未选
平台旧 `latest`，后续事务失败必须从快照恢复；不得用未选平台的旧 child release 补齐本轮 parent。
`test_dhcp_switch_scope_preservation.py` 与对应 workflow 进一步约束 DHCP 子事务：显式单平台或
AIR 隐式 Ethernet 只重写所属 `dhcpd_*.hosts`，其余平台文件的字节、inode、mode 和 mtime
保持不变；release manifest 同时记录三族实际声明数与四个输出 SHA-256。候选生成或 manifest
发布失败时，`dhcpd.conf`、所属 host、保留 host 和旧 manifest 必须全部回滚，不能留下跨族半成品。
`tar-for-upload.py` 的首选上传接口为 `PROJECT HOST`，并保留互斥的 `--host` 兼容路径；两种写法
必须生成同一套固定 SSH argv、身份检查、SHA 和远端锁行为。

今日监控回归还覆盖：ZTP 多轮次与 30 秒持续间隔、同网段静态 SVI fallback 的轻量身份探测
（主采集地址绿色，hostname+管理 MAC 双重匹配的备用地址淡绿色，身份错配红色，且完整日志
只采集一次）、
独立 ZTP/Switch 按钮和 worker、Switch Status Auto-Refresh 默认关闭，以及信息收集、配置备份、
持续收集、持续备份四个控制；收集与备份使用独立执行 lane、周期和状态，可以同时运行，跨类型
不会互相阻塞。同类型手工/持续任务共用 10 分钟冷却；启用持续模式时只禁用同类型手工按钮，
两个手工按钮均按“单次执行；开始后不可中断”保持运行中且禁用至终态；两个持续按钮均按
“周期执行；停止只取消后续轮次”排空当前轮。
停止后也不得绕过该类型冷却。停止持续模式只取消后续调度；若当前轮已开始，状态必须保持
“停止中，等待当前任务完成”、不得设置该 lane 的取消事件，同类型手工按钮继续禁用，任务自然
收口后才发布 stopped；worker/Supervisor 整体关闭的有界终止路径除外。持续备份密码只经匿名 FD 和短生命 `SSH_ASKPASS` 子进程环境传递；
单设备不可达或步骤失败必须保留成功设备发布并返回“完成但有警告”及失败设备汇总；全部设备
失败或全局事务错误才返回整体失败。
其他页签保持独立 Auto-Refresh，AIR scope 保留 Ethernet
Diagram、VX/CPU/Disk 解析，以及 optimize 的 AIR/Production 边界和实际 hostname 漂移。
统一页面排序合同还覆盖 ZTP 首个显示 IPv4、完整状态等级、自然名称与缺失值，SPX/IB/NVLink
设备组和端口、十进制/科学计数/温度，以及各表独立 ARIA/刷新持久化状态；真实浏览器验收见
`TC-REAL-MONITOR-SORT-001`。
`test_ztp_group_handoff.py` 独立覆盖 ZTP→Switch 的四组交接：部分类型先完成即先采集、同组
设备全部完成门禁、AIR `pending_eth` 的环境归类、unknown/`pending_nvos` 隔离、单组命令边界、
schema 2 分组签名持久去重与 schema 1 安全重采、单组失败不阻塞兄弟组，以及自动单键和手工
AIR/Production/All 多键冷却语义；所有组仍通过共享锁串行执行。
`test_ztp_group_handoff_display.py` 补充覆盖 `scope=all` 下未归类设备不会被误标为 Production、
自动新完成签名不受页面 30 分钟冷却吞并、各组 `collected_at` 审计时间保持独立，以及刷新
`monitor.html` 时仍保留原始 AIR/Production/All 展示范围。

setup/upload 的监控清单合同还要求部署包继续排除运行态 CSV 链接，而管理服务器正式 load
必须在 fresh HTTP root 中重建三条固定别名：`ethernet/monitor/eth.csv -> ../eth.csv`、
`infiniband/monitor/ib.csv -> ../ib.csv` 和 `nvlink/monitor/nvsw.csv -> ../nvsw.csv`。
三条别名必须纳入 setup 的冲突检查、整批回滚和 manifest，并最终解析到当前项目唯一的
`02-devices_config.csv`；采集器由该 canonical 链定位项目 `mgmt-server.pub`，不得在 monitor
目录复制公钥或用环境变量绕过活动项目身份。三个发布入口必须按自身 lexical area 精确绑定：
Ethernet 只读 `eth.csv`、InfiniBand 只读 `ib.csv`、NVLink 只读 `nvsw.csv`；即使同目录存在
指向其他项目且完全有效的异类 inventory，也不得用“第一个存在文件”替代。`MGMT_PUBKEY_FILE`
环境值不受信，公钥只能从该精确 inventory 的项目目录推导。

手工 ZTP 契约覆盖具体 hostname/多个通配符的展开与去重、类型和环境边界、任一未匹配即
整次拒绝、GUI `preview → diff → confirm` 两阶段协议、精确 `operation_id`/`trigger_id`、
服务端发布/配置指纹复检、CGI 固定请求、worker 固定 argv、逐设备按钮准确携带 hostname，
以及 Cumulus 零参数固定 URL helper 与最小 sudoers 权限。还覆盖触发前轮次基线、旧轮 100%
不得完成、新轮执行中、仅新轮 100%/complete success 才结束、每设备独立状态、不同设备并发
排队和同设备去重；同时验证自动/Web/CLI 共用单调 `ztp_round`、独立 `trigger_source`、CLI
operation 发现、DHCP 预期下一轮、Bootstrap 后逐栏重置、失败不增轮次且完成时间不复用、
跨刷新待执行状态、上一轮 success index 不得显示为本轮成功，以及客户端时区转换入口。
`preview_ready` 与 future 完成之间到达的 confirm 必须留在 durable queue，不能静默丢弃；
Production host-key mismatch 默认 fail closed，只有单台完整 hostname 的交互 CLI 显式
`--refresh-host-key` 才允许替换，AIR 公钥模式兼容 rebuild，GUI/密码隐式刷新均禁止。
`trigger`、Cumulus factory reset、NVOS ZTP force 与 `renew` recovery intent 分别验证；测试必须
确认 renew 不会写 ISC lease，服务端 lease release 也不会被当成客户端已重新 DHCP 的证据。
测试不会连接或触发真实交换机。

`test_ztp_applied_receipt.py` 覆盖 bootstrap 的 root-owned `/run` 独立工作区、原子
`latest-log` 指针、未来 mtime 旧日志反例、apply/save receipt、原始 YAML 字节/hash、失败后
默认回退和固定只读 helper。`test_manual_applied_config.py` 覆盖手工操作始终把 selector-normalized
的当前 `nv config show` 与 current latest 比较，包括 breakout `swp1s0-3`/组合 selector；receipt
只用于审计和 preview/confirm TOCTOU 指纹，可信 receipt 也不能掩盖后续运行态漂移。该套件还
覆盖 `system.aaa.user.<用户名>.hashed-password` 在 show 中缺失/显示 `*` 时不产生假 diff，
同时验证其他同名路径、其他配置漂移及完整发布哈希仍严格生效。
`test_bootstrap_config_fetch_contract.py` 与真实 `11-load.py` 渲染 workflow 约束两份 Cumulus
bootstrap 的专属 MAC YAML 获取：固定为 5 次重试、3 秒间隔、5 秒连接超时、120 秒单次总时限，
只重试连接失败和 5xx。明确 404 才允许使用 default 并标记 degraded/source_kind=default；
401/403、空 200、连接或 5xx 耗尽必须终止，且不能产生 NV 配置写入、成功回执、last-success
或 authorized_keys。
`test_ztp_http_identity_binding.py` 覆盖 OOB Leaf 通过前面板 transit
端口取得 DHCP、再用 eth0 MAC 下载专属 YAML 时的 canonical 身份归属；404、歧义 MAC 和匿名
别名不能冒充受管设备；已有 eth0 IP 时禁止 transit 回退，eth0 IP 为空时只有 canonical eth0
MAC 与实际 DHCP holder 接口 MAC 都唯一匹配，才允许用黄色 transit IP 临时采集。主契约测试
还验证 reset 日志中途改变时区时以 log mtime/boot ID 和实际
marker 晋级阶段、macOS 空管理-key 占位仍保留固定下载 URL，以及重启窗口的瞬态 SSH failure
不会提前终止同一操作。

`test_diagnostic_bundle.py` 覆盖只读支持包的独立安全边界：结构化配置必须递归脱敏，坏
YAML/JSON 只能写 omission metadata；命令使用固定 argv、净化环境、超时和输出上限；输出不能
位于 DocumentRoot、软链接或不安全目录；tar 只能含单一安全顶层和普通文件。测试还验证历史
项目不得执行 live SSH但仍生成 partial 包、运行态项目只能从固定 inventory link 识别、远端
hostname/MAC 任一不符时不保存设备状态/配置，以及诊断脚本确实进入 tools upload/sync 部署合同。
新版诊断还必须按严格 `latest-log` pointer 选择设备日志；pointer 非法只记录错误，不回退 mtime。

`test_deployment_writer_lock.py` 覆盖 sync 与 `tar-for-upload --deploy` 从第一次远端写入到最终
marker promotion 全程共用 `.deployment.lock`，失败保留 marker，dry-run/普通上传不取锁；
只上传后的 `--deploy-uploaded <ARCHIVE>` 必须复用同一份本地/远端 SHA-256 已验证归档，不能
重新打包或传输，并继续使用归档内 source manifest 绑定的 guard；
同步结束必须按 runtime 提示恢复入口：Native 重新 load；Docker 写入先 stop 并标记
rebuild-required，随后重新 deploy，避免 resident worker 继续执行旧代码或旧镜像。

`test_deploy_upload_archive.py` 覆盖可信中转后的服务器本地安装入口：installer/archive 的
root owner、single-link、NOFOLLOW 与稳定读取，安全 tar member、唯一项目、source manifest 和
embedded guard 哈希绑定，`--verify-only` 零 live 写入，以及 Native/Docker 后续提示。归档内
相对软链接只允许规范解析到同一归档中已验证的普通文件或目录（包括 P2P 的
`lldp-analyze-tool` 目录入口），逃逸、缺失、循环和特殊文件仍拒绝；source manifest 可精确绑定
设计上的 0 字节普通占位，但 installer、guard 和 manifest 权威文件本身必须非空。真实临时
workflow 会执行归档内 guard，但不接触 SSH、Docker、NIC 或宿主服务。成员校验不得把 8 GiB
全局安全上限当成单次内存申请：小型权威文件只按声明大小读取，manifest payload 使用有界分块
SHA-256，因此包含多 GiB switch image 的合法归档也不会要求把整个成员载入内存；内存分配异常
必须转成明确的 installer fail-closed 错误，不能泄漏裸 `MemoryError` traceback。

`test_apache_publication_boundary.py` 覆盖 infra 托管的 Apache 静态发布边界：项目输入、
DHCP/manifest、运行状态、日志和源码必须拒绝静态读取，bootstrap、公钥、
`latest_yaml`、镜像和 APT 仓库仍可访问；自定义 `ztp_url_prefix` 不得绕过规则，
load 在启动 Apache 前还必须核对 infra 签发策略的精确 SHA-256。根 README 汇编测试
同时自动发现非项目输出目录中的源 README，防止新模块文档未被嵌入。

`test_all_script_entrypoints.py` 对源树中的每一个 Python、CGI 和 Shell 脚本做分类及语法检查，
并执行所有 argparse 入口、明确列出的手写 Python 入口和操作员 Shell 入口的只读 `--help`；
两份运行时 bootstrap 还必须与唯一模板逐字一致（仅允许声明的运行参数不同）。
`test_ztp_release_core_review.py` 对 ZTP/release 核心逐模块检查模板渲染、authorized_keys 原子去重、
过期动态 AIR lease、CSV/hostname/path 注入、manual deployment lock、归档/latest 路径逃逸和
P2P 资源上限。`test_monitor_stack_review.py` 覆盖 monitor/collector/CGI/worker/IB-NVL 工具的
身份、队列、并发、原子发布、时间同步独立性与高延迟不确定度门禁、密码来源和危险升级确认门禁。
`test_ops_deployment_review.py` 覆盖 setup/load/unsetup/unload、upload/sync/download/import 和
infra 的共享 deployment lock 安全继承、归档边界、私有权限、事务回滚及输入一致性。

`test_docker_destructive_confirmation.py` 与
`test_docker_destructive_confirmation_workflow.py` 约束 Docker `unload/down` 的破坏性确认边界：
项目、scope、immutable container ID 以及精确删除/保留范围必须在提示或 `--yes` 触发的首个写入前
完整打印；交互只接受逐字节小写 `yes`，EOF、大小写或空格变体均零写入取消。`down` 把提示时捕获的
container ID 传入 hostlock，并在同一 deployment lock 内再次核对；确认期间 A 被替换为 B 或消失时，
不得 stop/rm 新容器，也不得清除 activation。Native `13-unload.py` 使用同一 literal-confirmation 语义，
而容器内部 `hostctl unload` 仍只在外层确认完成后精确传递一次 `--yes`。

`test_monitor_writer_quiesce.py` 与 `test_monitor_writer_quiesce_workflow.py` 从 Monitor 每轮实际
读取的四项 authority（`current-release.json`、项目 `01-global.yaml`、项目
`02-devices_config.csv`、active `p2p-air.json`）反向发现受支持 writer。Native setup、unsetup、
load、unload、DHCP/P2P generator、密码更新、feedback writeback 和 deployment prewrite guard
必须在共享 deployment lock 内、首次相关写入前停止并确认同项目 detached Monitor 已退出；load
子流程复用继承 lock/quiesce，不得重复停止。`import-from-download.py` 只允许 merge-new 且不得覆盖
任一既有 authority，因此是精确豁免而非通用写入豁免。测试以真实多脚本 workflow、失败零写入、
反向 sink/caller 闭包和写入顺序 hostile mutation 共同约束该集合。

`test_ztp_monitor_watch_resilience.py` 与 `test_ztp_monitor_watch_runtime_workflow.py` 约束持续
Monitor 的故障恢复合同。只有明确命名的 runtime transport 与报告发布边界属于可重试故障；每次
失败必须先原子刷新 unhealthy sidecar，再用最后一次成功报告重建带告警的 `monitor.html`，不得
改写 `latest` 或报告。第五次连续失败、输入身份漂移和边界外异常均永久退出；成功轮次重置预算。
同一进程固定 project/scope、setup manifest、active inventory、current release，以及 Monitor
实际读取的四项 authority 字节身份，任何同路径替换都在下一轮工作前拒绝。重复日志抑制与摘要
周期 `max(300, 10 * max(watch, 5))` 仅存在于当前进程内，重启不会继承抑制状态。Native load、
Docker activation 与 Monitor cleanup 还必须通过持久 sibling `.ztp-monitor.pid.lock` 串行化 PID
发布/清理；该锁只保护参与协议的受支持 writer/remover，不声称阻止可绕过锁的并发 root。

`test_full_flow_integration.py` 使用真实 ISC structured event、普通 DORA 和 Apache access-log 格式
串起跨模块状态机：OOB Leaf 的前面板 transit lease 只有在当前 lease epoch 内出现精确
`GET 200` 专属 eth0-MAC YAML 时才归属 canonical 身份，transit IP 永不成为 SSH 地址；真正
未知平台即使取得 lease、甚至伪造相同 HTTP 请求，也不能获得受管身份或触发 SSH 采集。

`test_upload_package_contract.py` 覆盖 upload 的项目消费清单和 P2P XLSX 清理：包中只允许三份
固定配置、当前选中 P2P、公钥和镜像；其他规划工作簿、项目说明及 setup 管理的 `p2p.xlsx`
链接必须排除。选中 P2P 只在临时副本中删除 `xl/media`、图片 relationship 和对应 drawing
anchor，非图片 drawing 保留；测试同时验证源 XLSX SHA-256 不变、归档内工作簿仍是有效 ZIP。

`test_ztp_service_runtime.py` 覆盖 Ubuntu host-network 容器的动态 DHCP 监听边界：监听逻辑接口
由 subnet CSV 和同一份 `ip -j` 快照按精确地址、前缀和 ifindex 推导，数量为 0..N，relay
网段不会平白增加 NIC，allowlist 只收窄候选而不能扩大监听；同一 ifindex 的任一 secondary IP
命中多个 `shared_network` 时必须在服务变更前失败。DHCPD 始终使用显式 argv，空接口列表和
option-like 名称均被拒绝。容器明确选择 Supervisor 后端，不能调用 systemd/journald；load、
monitor、unload 与容器入口必须共用同一 runtime 模块。真实 DORA、host-network 抓包和容器重建
验收登记在 `TC-REAL-DOCKER-ZTP-001`。

`test_ztp_container_runtime.py` 把 Docker 发布选择贯穿到真实 load parser：
`HTTP_ZTP_SCOPE`、`HTTP_ZTP_SWITCH_SCOPE`、`HTTP_ZTP_MINI` 先由 wrapper/Compose 规范化，再由
`hostctl.py` 转成 `11-load.py --deployment-scope/--switch/--mini`。AIR 默认 Ethernet，mini 只允许
AIR + Ethernet；Production 默认全部平台，也可显式只选 eth/ib/nvl。parent release、runtime
plan、activation marker 和 health-check 必须精确绑定同一选择，旧范围的 release 或运行中容器
不能被复用。workflow 使用真实 `container.env.example`、Settings、hostctl argv 与真实
`11-load.py` parser 串联验证，而不是复制参数解释逻辑。

`test_ztp_release_core_review.py` 与 `test_load_release_transaction.py` 共同锁定 AIR mini 的项目策略
authority：`03-air-topology-policy.json` 必须提供严格 `mini_sampling`，未知角色动作只能显式为
`keep|exclude|error`；`anchors` 只在需要 anchor 选择时显式声明，也可省略或为空列表。角色/anchor
歧义、非法 regex、重复键、symlink、越界和超限输入均失败关闭。
direct 测试验证异构角色抽样、04 显式选择优先级及逐设备原因；真实 11-load→拓扑生成 workflow
验证旧 canonical 可由已校验客户源刷新，而策略/客户源漂移不会留下部分输出，也不会在 policy
缺失时先计算 release basis。parent release 必须同时绑定 policy 与最终 04 的 SHA-256。

同一 Docker 合同把“宿主发行版”与“容器发行版”分开验证：宿主只接受 Ubuntu 22.04 或
24.04 的 `amd64`/`arm64` 本机 rootful Docker，其他发行版或版本在任何 Docker mutation 前
fail closed；Dockerfile、image label、preloaded verifier 和容器内 `/etc/os-release` 始终固定
Ubuntu 24.04。测试不得为了支持 22.04 宿主而把容器 base image、镜像身份或容器运行态降级。

同一模块还覆盖管理服务器的动态网络恢复：没有 source write 时，Service IP 从一个合格接口移动
到另一个合格接口后，真实 runtime planner 必须选择新的接口名、ifindex 和 fingerprint；
`hostctl.transactional_reload_network()` 必须在共享锁内先核对既有 image/source、release、DHCP、
runtime plan 与 committed activation，只允许 listener identity 和观察摘要变化，再撤销 authority、
停止旧服务、发布新 plan/precommit、由 Supervisor 收敛并完成两阶段 health，最后提交 activation。
该事务不得运行 `11-load.py`、重置 worker control、清除 rebuild/quarantine 或改写项目生成制品；
NOOP 不得停止服务，失败则撤销 authority 并让五个业务服务保持停止。宿主 systemd 或直接
`supervisorctl restart dhcpd` 不能替代该事务。

`test_ztp_container_runtime.py` 还独立验证 activation 的双快照稳定性 projection：只允许 Linux
bridge 精确路径 `linkinfo.info_data.gc_timer` 的有限非负数值变化，以及 DHCP 地址
`valid_life_time`/`preferred_life_time` 在 Linux uint32 有限范围 `1..4294967294` 内保持或自然
递减。`0`、字符串 `forever` 与数值 forever sentinel `4294967295` 均不归一化，跨类别变化、
增长和超界值必须 fail closed。第一次原始完整 link/address 快照继续交给 planner 并保留诊断
hash；projection 不得原地修改输入。ifindex/name、MAC、flags、operstate、link type/kind/parent、
VLAN ID、地址/prefix/scope、tentative/dadfailed/deprecated 仍严格比较；全表 IPv4 route 也必须
连续采集两次并逐字段保持不变，非规范 timer/lifetime 及非对象 route 记录必须 fail closed。Ubuntu 24.04
风格的跨脚本场景还证明两个 listener 的 fingerprint 不因上述倒计时漂移，真实拓扑或路由变化则
在发布 runtime plan、Apache listener、activation/precommit 或启动服务前失败。真机复现与证据要求登记在
`TC-REAL-NETWORK-SNAPSHOT-001`。

`run_vm_validation.py` 是 upload/load 完成后的 Ubuntu 24.04 管理 VM 只读验收器。它核对
parent/child release 与输入/制品 hash、DHCP shared-network 到 vNIC 的唯一映射、服务、worker、
AIR scope 和 mini 清单绑定，但不会运行 load、更新密码、重启服务或修改项目。`test_cases/`
不进入生产 upload/sync 包，须按 `TC-REAL-VM-ZTP-001` 单独复制到 VM，并把 JSON 报告带回审核。

原生 systemd 的完整验收使用 `--full-systemd --worker-scope prod|air`。完整模式在上述检查之外，
还会只读编译部署树中的 Python/CGI、对 Shell 执行 `bash -n`，核对 systemd enable/MainPID、
DHCP `INTERFACESv4` 策略（空值代表自动发现；显式值须与实际 cmdline 一致）、Apache 发布边界、
已安装控制 CGI、worker 状态与最新报告，
并主动 GET bootstrap、ztp.json、SSH 公钥、monitor.html 和 parent-bound MAC YAML，HEAD 已发布镜像，
同时证明内部路径返回 403、三个控制 CGI 返回存活 JSON。它不会修改项目、NIC、Netplan、服务或
配置，但主动 HTTP 请求会正常写入 Apache access log。`--expect-mini` 只用于确实生成 mini AIR
清单的项目，不能为了“全量”盲目添加。

直接 unittest discovery 只用于开发定位，不更新批准哈希，也不替代上面的发布门禁：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -m unittest discover -s test_cases -t . -p 'test_*.py' -v
```

该测试套件只做快速契约检查。发布前还应执行 Python/Bash 语法检查、setup/load dry-run、
临时目录生成/发布流程，以及 `ubuntu:24.04` 容器中的 infra setup/teardown。
