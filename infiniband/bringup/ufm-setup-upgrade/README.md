# UFM 初始化与升级

`ufm-setup-upgrade.py` 只读取本目录下的输入，除公共模块 `infra/ubuntu24_host.py` 外不依赖仓库其它文件，
也不依赖 load、git 或 load 生成的锁文件；输入文件正确即可运行：

```text
ufm-setup-upgrade/
  ufm-setup-upgrade.py
  01-global.yaml -> ../../01-global.yaml      servers: - ufm: 段（仓库跟踪的链接）
  publickey -> ../../publickey               部署服务器公钥（仓库跟踪的链接）
  ib.csv -> ../../ib.csv                     setup 创建；server_ufm 行及 OOB Leaf/Spine 的 eth_jump 行
  p2p.xlsx -> ../../p2p.xlsx                 setup 创建；UFM 各接口接在哪台设备的哪个口
  ufm-setup-upgrade-logs -> ../../../DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/ufm-setup-upgrade-logs   setup 创建
```

`ib.csv`、`p2p.xlsx` 和日志目录与 xdr-initial-setup 一样由 setup 按当前项目创建，unsetup 时移除；
不运行 setup 时也可以手工建立同样的链接，或用 `--input-dir` 指向放有这些文件的目录。

运行环境：Python 3.9+、PyYAML、系统 `ssh`。

## 需要预先准备的链接（2026-10-22 起由 setup 建立）

脚本运行前，本目录下要有以下 6 个链接。前 2 个随代码提交；后 4 个依赖当前项目或管理服务器，由 setup
创建、unsetup 移除（`image` 只有 ha-post-config 用到；`http/image/` 不存在时 setup 跳过它）。除 `image` 外，
所有链接最终都指向 `DAY0-Prepare/<项目>/` 下的文件：

| 本目录下的链接 | 链接内容 | 最终指向 | 谁来建 |
|---|---|---|---|
| `01-global.yaml` | `../../01-global.yaml` | `infiniband/01-global.yaml` → `DAY0-Prepare/<项目>/01-global.yaml` | 本链接随代码提交（git 跟踪的 symlink）；`infiniband/01-global.yaml` 由 setup 建（已有） |
| `publickey` | `../../publickey` | `infiniband/publickey/`（`mgmt-server.pub`、`laptop.pub`） | 本链接随代码提交；`infiniband/publickey` 由 setup 准备（已有） |
| `ib.csv` | `../../ib.csv` | `infiniband/ib.csv` → `DAY0-Prepare/<项目>/02-devices_config.csv` | **setup 新增**（`infiniband/ib.csv` 已有） |
| `p2p.xlsx` | `../../p2p.xlsx` | `infiniband/p2p.xlsx` → `DAY0-Prepare/<项目>/p2p.xlsx` | **setup 新增**（`infiniband/p2p.xlsx` 已有） |
| `ufm-setup-upgrade-logs` | `../../../DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/ufm-setup-upgrade-logs` | 项目输出目录 | **setup 新增**；目标目录不存在时脚本只创建最后一级 |
| `image` | `../../../image` | 管理服务器 http 树的 `image/`（`{common.mgmt.http}/image/` 对外提供的目录） | **setup 新增**（owner 2026-10-22）；`ha-post-config` 在这里找 `*.lic`，没有链接或没有 `.lic` 时跳过 license，只在最后提示 |

脚本还依赖公共模块 `infra/ubuntu24_host.py`（按 `../../../infra/` 相对路径导入），
打包或同步时必须一起带上。

setup 中的实现（2026-10-22 合入 http）：
- `tools/project_contract.py`：
  - `BRINGUP_OUTPUT_SPECS` 含 `("ufm-setup-upgrade", "ufm-setup-upgrade-logs")`；
  - `BRINGUP_INPUT_SPECS` 含 `ib.csv`、`p2p.xlsx`（链接到 `infiniband/` 下的当前别名）；
  - `BRINGUP_IMAGE_LINKS` 含 `image`。
- `DAY0-Prepare/01-a-setup.py`：`_process_bringup_links`、`_process_bringup_input_links`、`_process_bringup_image_links`。
- `DAY0-Prepare/02-unsetup.py::_known_workspace_links` 列出这 4 个 setup 链接。
- `tools/_package_common.py::STATIC_SETUP_MANAGED_LINKS` 含全部 6 个。
- `test_cases/audit_public_tree.py::SETUP_RUNTIME_BRIDGES` 登记 `01-global.yaml`、`publickey` 两个仓库桥接。
- `.gitignore` 与三份 dockerignore 已同步。
- 测试：`test_setup_ufm_links_workflow`、`test_ufm_setup_upgrade_workflow`。

所有读取 CSV `type` 列的脚本都已兼容下面「CSV 新增 type」一节的两个类型：setup 校验 `server_ufm` 的格式，
其余脚本跳过服务器行，`server_mgmt` 按 `server` 处理（`test_server_device_types`、`test_server_device_types_workflow`）。

## CSV 新增 type（所有脚本都要兼容）

`02-devices_config.csv` 的 `type` 列新增两个服务器类型：

| type | 设备 | 使用的列 | 处理方 |
|---|---|---|---|
| `server_ufm` | UFM 设备 | 只用前 7 列：`hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac`，其余列留空 | `infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade.py` |
| `server_mgmt` | 其他 Ubuntu 管理服务器（原来写作 `server`） | 与 `server` 相同 | `infra/` 的部署脚本 |

列的写法：
- `hostname` 为 FQDN（如 `ufm01.site01.example.test`）。
- `eth0_ip` 为不带前缀的 IPv4。
- `netmask` 写前缀长度（如 `23`，也接受 `/23`）。
- `server_ufm` 的 `eth0_gw`、`eth0_mac` 必填。

兼容规则：**所有读取 CSV `type` 列的脚本都必须接受这两个类型**。不处理该类型的脚本直接跳过这些行：
- 不报错；
- 不当成交换机或其他设备去生成配置、DHCP 条目、监控对象或打包内容；
- 也不因为这些行只填了前 7 列而报列数或字段错误。

setup 的输入校验只需按上表核对这些行的格式（地址、掩码、MAC 合法，`eth0_ip`/`eth0_mac` 不与其他行重复）。
行宽仍要与表头一致：schema v2 的整行宽度检查先于 type 过滤，所以后面的列留空，但逗号不能省。

需要改的地方（2026-10-19 只读排查，共 33 个文件、40 条路径；其余 27 条路径是白名单过滤，已经安全）。
2026-10-22 合入 http 时第 1、2、3、5 条已全部完成，另外修了排查时漏掉的 `90-c2-generate_configs.py`（CSV 带
`config_method` 列时先跳过 `server_ufm`）和 `tools/project_contract.py` 的配置方法表（`server_mgmt` 绑定
`deploy_infra`）；第 4 条（`tools/ufm_input_contract.py` 的旧 type `ufm`）属于 codex 早先的 F01 准备代码，保持原样：

1. 遇到新 type 会报错，整次运行失败。把两个 type 加入跳过集合或允许集合：
   - `DAY0-Prepare/01-a-setup.py` 的 `_SUPPORTED_TYPES` / `_SERVER_TYPES`。
   - `DAY0-Prepare/11-load.py` 的 `VALID_TYPES`，以及 `_release_inventory` 中跳过 `server` 的地方。
   - `ztp/config/cumulus/d-hostname2mac.py::load_csv`。
   - `ztp/config/isc-dhcp-server/c1-generate_dhcp.py::load_csv`。
   - `ztp/backup/yaml-collect.py::load_devices_csv`。
   - `ztp/manual-ztp.py::read_devices`。
2. **会被当成交换机，危险**：`DAY0-Prepare/12-ztp-monitor.py::read_devices` 目前只跳过 `server`/`eth_jump`。
   一旦上面的校验放开，它会以 `cumulus@` 去 SSH UFM 和管理服务器。必须与第 1 条同时修改。
   建议 `monitor/generate-monitor-html.py` 的 ZTP 报告和 `tools/collect-ztp-diagnostics.py::select_devices` 也排除服务器类型。
3. `infra/deploy_infra.py::load_servers`（`check_infra.py` 共用）只选 `type == "server"`。
   `server_mgmt` 要按 `server` 部署；`server_ufm` 不能进入 infra 部署。
4. `tools/ufm_input_contract.py` 认的是旧 type `ufm`（f01 遗留）。需要改为认 `server_ufm`，或者下线。
5. `DAY0-Prepare/template/README.txt` 仍写着「infra 只选择 type=server 行」。

## 输入格式

`ib.csv` 中 UFM 只使用前 7 列，`netmask` 写前缀长度：

```csv
hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac
ufm01.site01.example.test,server_ufm,NA,198.51.101.130,23,198.51.101.254,02:00:00:00:01:01
ufm02.site01.example.test,server_ufm,NA,198.51.101.132,23,198.51.101.254,02:00:00:00:02:01
```

`01-global.yaml`：

```yaml
servers:
  - ufm:
      version: "2.6.1-5"
      vip: "198.51.101.133"
      interfaces:
        alias:
          eth0: eno8303            # 逻辑管理接口 -> 实际接口
        primary:
          ipmi:
            address: "198.51.101.129/23"
            # gateway: "198.51.101.254"   # 可选，见下
          eno8403: "192.0.2.1/30"
          ib0: "100.126.255.1/16"
          ib1: "100.126.255.2/16"
        secondary:
          ipmi:
            address: "198.51.101.131/23"
          eno8403: "192.0.2.2/30"
          ib0: "100.126.255.3/16"
          ib1: "100.126.255.4/16"
```

- `ipmi` 只接受 `address`/`gateway` 写法（owner 2026-10-21），`gateway` 可选：
  - 不写 `gateway`：IPMI 地址与 eno8303 同网段时，网关用 ib.csv 的 `eth0_gw`；不同网段时报错，提示 ipmi 没有提供 gateway。
  - 写了 `gateway`：IPMI 可以在自己的网段，网关必须是该网段内的可用地址，且不能等于 IPMI 地址本身。
  - 旧的字符串写法 `ipmi: "x.x.x.x/nn"` 会报错，并提示改写成 `address` 写法。
- 另外使用 global 的 `common.switch.system`（DNS/NTP/时区）和 `common.mgmt.http`（address/port，升级镜像下载地址）。
- 主机名第一段以 `ufm01` 结尾的是安装期 primary，另一台是 secondary；不看 CSV 行序。
- primary 与 secondary 的接口集合必须相同，同名接口必须在同一网段；所有地址不得重复。
- P2P 中 UFM 名称按去掉 `-`/`_` 后的第一段匹配（`ufm-01` 对应 `ufm01.site01...`）。
- P2P 中 UFM 一侧的端口写法统一换算成设备上的接口：`8303`、`eno8303`、`eth0` 都是 eno8303；
  `8403`、`eno8403`、`eth1` 都是 eno8403。规则：先按实际接口名，再按 alias 逻辑名，
  纯数字按以太网接口名结尾的数字唯一匹配（不会匹配 ib0/ib1）。
- `eth1` 是 HA 直连接口：alias 中写了 `eth1` 以 alias 为准；没写时取 primary/secondary 中唯一的
  非 IPMI、非 IB 接口（这里是 eno8403），不唯一则提示在 alias 中声明。
- `check` 会核对 P2P 中两台 UFM 的 eno8403 是否互相直连；交换机侧的数字端口在 Leaf 上对应 `swpN`。

## 使用：三个流程（owner 2026-10-20）

```bash
python3 ufm-setup-upgrade.py                              # = check：检查输入文件和设备状态（只读）
python3 ufm-setup-upgrade.py check --inputs-only          # 只检查输入文件，不登录设备
python3 ufm-setup-upgrade.py config-upgrade --apply       # 部署基本配置，然后升级 UFM
python3 ufm-setup-upgrade.py ha-setup --apply             # 没有 HA 时做 HA 部署（含互信），完成后自动 ha-post-config
python3 ufm-setup-upgrade.py ha-post-config --apply       # 在已有且正常的 HA 上做 HA 之后的配置
```

- `--input-dir` 默认是脚本所在目录；`--node` 默认是 ib.csv 中全部 `server_ufm`。
  `ha-setup` 总是同时处理两台，不能用 `--node` 只选一台。
- `config-upgrade` 和 `ha-setup` 必须带 `--apply` 才执行；不带时是用法错误（退出码 2），
  并提示改用 `check`。只查看状态一律用 `check`。

| 命令 | 对应需求文档 | 做什么 |
|---|---|---|
| `check` | 输入合法性 + 设备状态 | 输入检查 → 地址占用检查 → 每台只读登录核验；新设备到此为止，已改过密码的设备做全部只读检查 |
| `config-upgrade --apply` | 阶段一 + 步骤 1 + 步骤 3 | 先做与 check 相同的检查，列出改动计划，确认一次；新设备先改密；每一步只改不符合或缺少的项；最后升级 UFM |
| `ha-setup --apply` | 步骤 2 + 步骤 4 | 先读两台的 `ufm_ha_cluster status`：已有 HA 配置就不做任何事并提示（清除后重跑，或直接 ha-post-config）；没有集群时检查 HA 五项前提，确认一次后做互信、配置 standby 和 master、等 DRBD 同步、启动，以 status 判定，再自动做 ha-post-config |
| `ha-post-config --apply` | HA 之后的配置 | 只在已有且正常的 HA 上运行：经 VIP 安装 license、改 gv.cfg 的 [Server] 三项、按 ibswitches 写 root_guid.conf；任何一项有改动就 failover 一次，再核对 |

### check（默认，只读）

1. **输入文件合法性**：
   - 格式、主备角色、子网一致；
   - 地址和 MAC 互不冲突；
   - UFM 的地址和 MAC 不能已在 ib.csv 中分配给其它设备；
   - VIP 不能与任何地址重复。
   有错误时不登录任何设备。
2. **地址占用检查**：在 OOB Leaf/Spine 上检查输入地址是否被现网设备占用，只读。
   - 检查对象：每台的管理 IPv4、IPMI 地址和 VIP。
   - 选一台在该网段有自有 IPv4 SVI 的交换机：先选 P2P 中该 UFM 管理口/BMC 所接的 Leaf，再选 Leaf 的 LLDP 显示的 Spine。在它上面 `ip vrf exec <vrf> ping -I <svi>` 让交换机去 ARP，再读邻居表。
   - 结果：
     - 无应答：`FREE`。
     - 由本机应答：管理口 MAC 与 CSV 相同，或 IPMI 的 MAC 出现在 P2P 中该 UFM BMC 口的 FDB 里，记为 `SELF`。
     - VIP 由 UFM 之一应答：`IN_USE_BY_UFM`，表示 HA 可能已配置。
     - 其它设备应答：`CONFLICT`，状态记为 `ADDRESS_CONFLICT`，按失败处理。
   - 只有已确认的邻居记录（REACHABLE）才算占用，残留的 STALE/FAILED 缓存不算。
   - 该网段没有带 IPv4 的 SVI 时报 `UNCHECKED`（只提示）。
   - P2P 没有 BMC 连线时，IPMI 地址有应答报 `UNVERIFIED`（只提示）。
3. **P2P 连线核对**（规则同 ib-initial-setup v15，owner 2026-10-20）：在 P2P 中该 UFM 管理口（eno8303）所接的 OOB Leaf 端口上，重新读取 `bridge fdb show`，学到的动态 MAC 必须是 CSV 的 `eth0_mac`。bond 成员按 bond 主接口查。
   - `MATCH`：一致，继续。
   - `MAC_MISMATCH`：学到的是别的 MAC；或者端口没学到 MAC，而 CSV 的 MAC 出现在这台 Leaf 的别的端口上（写明实际端口）。
   - `LINK_DOWN`：端口不是 up。`MAC_NOT_LEARNED`：端口 up 但没有学到动态 MAC。
   - 不从 CSV 的 MAC 推导地址去尝试登录。IPv6 link-local 只在经 OOB 登录时使用：邻居表中有这个 MAC 的 IPv6 就用它；没有时，用 FDB 学到、且已核对等于 CSV 的 MAC 推导（EUI-64），与 ib-initial-setup v15 相同。
   - 以上三种情况：
     - 列出 P2P 连线、CSV MAC、端口实际学到的 MAC 和可能原因，然后询问是否继续处理这台 UFM：`[y/N]`，**默认不继续，15 秒无输入按不继续处理**，没有交互终端也按不继续处理。
     - 不继续：这台 UFM 本次不登录、不改动，状态即上述结果，按失败处理。
     - 继续：照常检查和配置，汇总里保留一行「P2P 连线核对 …，用户选择继续」。
   - 读不到交换机时记为 `UNCHECKED`，只提示，不阻止。
   - BMC 口 down 不检查，BMC 只在地址占用检查里用 FDB 核对应答 MAC。
4. **登录每台 UFM**：先试部署服务器公钥，再试新密码，最后试出厂密码。
   - **需要改出厂密码说明是新设备**：状态 `NEW_DEVICE`，到此为止，下一步执行 `config-upgrade --apply`。
   - 能用公钥或新密码登录的，**做全部只读检查**：
     - 基本配置各项是否符合：netplan、公钥、hostname、IPMI、DNS/搜索域、NTP、时区、`/etc/hosts`；
     - 版本是否已是 global 的目标版本；
     - 两台都能检查时，再查互信，并在 master 上读 `ufm_ha_cluster status`（结果记在 `ha_config`）：
       - `OK`：已是这两台、这个 VIP，状态正常；此时不再检查 HA 前提（`ha_preconditions` 为 `SKIPPED`，因为 HA 运行时 ufm-enterprise 在运行、VIP 已被占用）。
       - `WOULD_CHANGE`：两台都没有集群（同时检查 HA 五项前提）。
       - `UNHEALTHY`：是这两台，但状态不正常（含已配置未启动）；`MISMATCH`：集群节点或 VIP 与输入不符。这两种都需要人工处理，`ha-setup` 不处理已有的 HA 配置。
       - `UNKNOWN`：读不到 status（例如设备上没有 `ufm_ha_cluster`）。
       - 已有 HA（`OK`、`UNHEALTHY`、`MISMATCH`）时，互信只作提示：`ha-setup` 不改动已有 HA，也就不会建互信，
         所以缺少的 root 密钥对、对端公钥记为 `NOT_NEEDED`，不计入需要改动（owner 2026-10-23；实验环境手工部署的 HA 即如此）。
5. 结果：
   - 全部符合为 `COMPLIANT`，退出码 0。
   - 有需要改动的为 `NEEDS_CONFIGURATION`，或者有新设备 `NEW_DEVICE`，退出码 3。
   - 失败（含地址冲突和不继续的 P2P 连线问题）退出码 1。

### config-upgrade --apply

1. 先做与 check 相同的只读检查，包括地址占用。任何输入地址被其它设备占用时，本次不改动任何设备。
2. 列出改动计划，例如「新设备——先改密再全部配置并升级」「需要改动 netplan, dns, upgrade」，然后**只确认一次**。`--yes` 跳过确认。
3. 逐台执行：
   - 新设备先把出厂密码改为新密码，并用新密码重新登录确认。
   - 经 OOB 进来的先写 netplan 配好 IPv4。
   - 然后依次处理 netplan、公钥、公钥直连验证、hostname、IPMI LAN、IPMI 用户、IPMI 电源测试、DNS、搜索域、NTP、时区、`/etc/hosts`。**每一步执行前再检查一次，只改不符合或缺少的项**。
   - IPMI LAN、IPMI 用户、IPMI 电源测试这三步失败时（例如 BMC 拒绝主机侧写入），记下失败并继续后面的步骤和升级；整台最后仍标为失败，汇总里逐条列出 IPMI 的错误（owner 2026-10-20）。其它步骤失败时，这台立即停止。
4. 最后升级（只针对 UFM）：`/etc/ufm-release` 中 `UFM_APPLIANCE` 已是目标版本就跳过。
5. 升级重启后：重新登录，确认 `UFM_APPLIANCE` 已是目标版本，再把全部配置步骤检查一遍。
   升级改动过的配置会列出来，并当场重新配置（步骤名前缀 `post_upgrade_`；被重新配置的项记在 `result.json` 的 `post_upgrade_reconfigured`）。
6. 结果：
   - `STEP_FAILED_IPMI_LAN` / `STEP_FAILED_IPMI_USER`：其余步骤（含升级）都已完成，只有 IPMI 失败；修好 BMC 后重跑，已完成的步骤不会重复改动。
   - `UPGRADED`：已升级，升级后的复查也通过。
   - `CONFIGURED`：有配置改动，版本本来就是目标版本或 global 未声明版本。
   - `UP_TO_DATE`：什么都没改。

### ha-setup --apply

两台都要能登录，否则停止。以下「master」指安装期的 primary（hostname 以 ufm01 结尾的那台），「standby」指另一台。

1. **先判断是否已有 HA 配置**（owner 2026-10-22）：在两台上各读一次 `ufm_ha_cluster status`。
   - 任何一台读到 HA 集群（有节点列表或节点数），不论状态正常与否、节点和 VIP 是否与输入相同：**不做任何 HA 配置**，结果 `HA_EXISTS`（退出码 1）。
   - 本次运行的最后一行之后提示：「当前 UFM 已有 HA 配置（在哪台上读到、节点、VIRTUAL_IP、status 是否正常或前几项问题）。本次没有做任何 HA 配置。要重新部署 HA，请先清除现有的 HA 配置，再运行 ha-setup --apply；如果确认当前 HA 正常，可直接运行 ha-post-config --apply 完成 HA 之后的配置」。
   - 清除 HA 配置的命令不在提示里给出：情况各不相同，由用户自己操作（owner 2026-10-22）。
   - 两台都读不到集群：继续第 2 步。读 status 本身失败（例如没有 `ufm_ha_cluster`）：`HA_NOT_READY`。
2. 查 HA 五项前提：
   - ① ufm-enterprise 未运行
   - ② eth0（eno8303）互通
   - ③ eth1（eno8403）互通
   - ④ VIP 未被占用
   - ⑤ 每台至少一个 IB 口 LinkUp

   除 ①（ufm-enterprise 在运行）以外的任何一项不满足时停止（`HA_NOT_READY`），不做改动。
3. **确认一次**：列出全部要做的事，包括要停止 ufm-enterprise 的设备、互信、standby 和 master 的完整 `ufm_ha_cluster config` 命令。
   - 确认内容里写明代价：两台的 `/opt/ha_data` 备份到 `/ha_backup/<时间>/` 后清空并交给 DRBD，在 master 上格式化 `/dev/drbd0`，并销毁两台上原有的集群配置。
   - 这一次确认覆盖本次运行的全部改动；回答 N 则什么都不改（`NOT_AUTHORIZED`）。
4. 停止 ufm-enterprise（如在运行），做互信，再查一次全部前提。
   - 互信：两端各自确保有 ed25519 密钥对，交换公钥，再从两端按 IP 登录对端，核对对端接口上确实有这个地址。
5. **配置**：先 standby，再 master（带 `--virtual-ip`），命令见下一节。
   - 两条命令的全部输出都写进设备上的日志 `/root/.setup/<运行目录名>/ha-config-standby.log`、`ha-config-master.log`，只把退出码、是否出现 `[*] Configuring HA cluster done.` 和日志末尾 15 行（去掉含 password 的行）带回来。
   - 原因：`ufm_ha_cluster` 自己给 hacluster 设密码，会打印 `passwd` 的两个提示（New password、Retype new password）。如果这些提示回到本工具的会话里，应答器会把它当成强制改密提示并中止会话，配置就会断在中途。
   - 命令用 `nohup` 运行，SSH 会话意外断开时配置会继续完成。
   - standby 失败：`HA_CONFIG_FAILED`，master 不动（`INCOMPLETE`）。master 失败：`HA_CONFIG_FAILED`，standby 记 `INCOMPLETE`。排除问题后重跑；如果重跑提示已有 HA 配置，需先清除。
6. **等 DRBD 同步**：在 master 上每 100 秒执行一次 `drbdadm status`，每次打印一行带时间戳的进度（含 `done:` 百分比），最长 2 小时。
   - 同步完成的判据：`disk:UpToDate`，且 `replication:Established peer-disk:UpToDate`。
   - 超时：`HA_SYNC_TIMEOUT`，不启动。此时 HA 已配置，重跑 `ha-setup` 会按第 1 步判为已有 HA 配置而不做任何操作；同步完成后在 master 上手工执行 `ufm_ha_cluster start`，再用 `ufm_ha_cluster status` 确认。
7. **启动**：在 master 上 `ufm_ha_cluster start`，输出同样写进 `ha-start.log`。退出码非 0 为 `HA_START_FAILED`。
8. **判定**：每 15 秒读一次 `ufm_ha_cluster status`，最长 15 分钟，直到满足下面全部条件（owner 2026-10-22）：
   - master 在 Promoted 中，两台都在线，集群有 quorum；
   - 每个资源都是 Started，且都在 master 上，其中必须有 ufm-enterprise；
   - corosync、pacemaker、pcsd 都是 active；
   - `DRBD_CONNECTIVITY` 为 Connected，`DISK_STATE` 和 `PEER_DISK_STATE` 都是 UpToDate，`VIRTUAL_IP` 等于 global 的 VIP。
   - 读不到的字段算不满足，不当作正常。
   - 全部满足为 `HA_CONFIGURED`；到时间仍不满足为 `HA_UNHEALTHY`，列出最后一次的问题，需要人工处理（重跑同样会判为已有 HA 配置）。
9. **最后在 Promoted 的那台上执行 `ufm_enterprise_sanity.sh`**（限时 60 秒）。未通过、没有输出或没有这个命令都**只提示**：写进 `result.json` 的 `notes`，并在本次运行输出的最后一行之后以「提示:」列出，不影响结果和退出码。

8'. **接着自动做 ha-post-config**（owner 2026-10-22：确实新做了 HA 之后自动调用），见下一节。失败为 `HA_POST_CONFIG_FAILED`。sanity 在 ha-post-config 之后、在当时 Promoted 的那台上执行（failover 后就是另一台）。

完成状态（退出码 0）只有 `HA_CONFIGURED`（本次配置并启动，ha-post-config 也已完成）。`HA_EXISTS`（已有 HA 配置，未做任何改动）和 `HA_READY`（只满足了前提）都不是完成状态。

### ha-post-config --apply（owner 2026-10-22，ufm-manual.log 第 1143–2088 行）

HA 的操作分成两块：`ha-setup` 只负责部署 HA；`ha-post-config` 负责 HA 之后的配置。`ha-setup` 新部署完 HA 会自动调用 `ha-post-config`；已有 HA 时，确认 HA 正常后可以单独运行它。

1. **前提**：两台都能登录，`ufm_ha_cluster status` 显示是这两台、这个 VIP，并且状态正常（不要求 Promoted 是哪一台）。否则 `HA_NOT_READY`，不做任何事。
2. **登录 VIP**：全部操作都经 VIP 在当时的主机上执行。
   - failover 后 VIP 的主机密钥会变（ufm-manual.log 第 2014–2028 行）。所以先经两台各自的地址读出它们的 SSH 主机密钥（`/etc/ssh/ssh_host_*_key.pub`），写进本次运行目录下的 `vip-known-hosts`。
   - 登录 VIP 时用 `StrictHostKeyChecking=yes` 加这个文件：只接受这两台的密钥，不读也不改 `~/.ssh/known_hosts`。
   - 再按管理口 MAC 认出 VIP 当时在哪台上。
3. **license**：
   - 在本工具目录下 `image` 链接（setup 建，指向管理服务器的 `image/`）里找 `*.lic`；
   - 让主机从 `{common.mgmt.http}/image/<文件名>` 下载到 `/opt/ufm/files/licenses/`，核对 sha256 与本地文件相同；
   - 全部复制，同名覆盖，覆盖前备份；内容已相同的不算改动。
   - 没有 `.lic` 就跳过这一步，只在最后提示，并带上当前评估 license 的到期日。
4. **gv.cfg**（`/opt/ufm/files/conf/gv.cfg`）：
   - 只改 `[Server]` 段的三个键：`fabric_interface = ib0`、`multi_port_sm = ha_enabled`、`additional_fabric_interfaces = ib1`，所有项目相同；
   - 其它内容一个字节都不动，键不存在就加在 `[Server]` 段末尾；
   - 改前备份到 `/root/ufm-setup-upgrade-backup/<运行目录>/post-ha/`。
5. **root_guid.conf**（`opensm.conf` 的 `root_guid_file` 必须是 `/opt/ufm/files/conf/opensm/root_guid.conf`，否则不自动改）：
   - 在容器里运行 `ibswitches`，只解析以 `Switch` 开头的行；
   - 描述 `"MF0;<主机名>:<型号>/U<n>"` 里的主机名与 ib.csv 中 `type=ib` 的设备比对：
     - 有主机名含 `core` 的设备时，只写 core；
     - 否则写 spine，判断规则与监控页面相同；
   - 每台写入它的全部 ASIC GUID，按描述自然排序，与你的 `sort -t'"' -k2,2V` 相同；
   - 清单里有、但 ibswitches 里没有的设备，只在最后提示，已发现的照样写入；
   - 内容相同不改；一个也没发现不改。
6. **failover**：
   - 3–5 步任何一项有改动，就只做一次 `ufm_ha_cluster failover`；都没改动就不做；
   - 经 VIP 的会话会被切断，这是预期的；
   - 之后经新主机自己的地址读 `ufm_ha_cluster status`，等它正常，且 Promoted 是另一台；
   - 不切回，不清除 move constraint（owner 2026-10-22）。
7. **核对**（经 VIP，在新主机上）：
   - `grep smi /opt/ufm/files/log/opensm-smdb.dump` 有 2 行，说明 gv.cfg 已生效；未配置时只有 1 行；
   - 装了 license 时，`ufmlicense` 里新主机 eno8303 MAC 的那一行为 Valid（owner 2026-10-22；输出样本待 owner 提供后再核对格式）；
   - root_guid.conf 不核对生效。
8. **结果**：
   - `HA_POST_CONFIGURED`：有改动，已 failover 并核对通过；
   - `HA_POST_UP_TO_DATE`：都已符合，没有改动；
   - `HA_POST_CONFIG_FAILED`：失败，原因写在 detail 里。

#### HA 配置命令（owner 2026-10-22 在 ufm02/ufm01 上实测，已实现）
owner 在对话中给出了实测命令和输出，下面用文档地址段示意。`ufm-manual.log` 是 owner 的工作记录，不改动它。

| 参数 | 含义 | 在我们输入里的来源 |
|---|---|---|
| `-r standby` / `-r master` | 本机在 HA 中的角色 | master = 工具里的 primary（hostname 第一段以 ufm01 结尾的那台）；standby = secondary |
| `--local-primary-ip` / `--peer-primary-ip` | HA 直连口 `eno8403`（别名 eth1）的地址，不带掩码 | global `servers.ufm.interfaces.<primary/secondary>.eno8403` |
| `--local-secondary-ip` / `--peer-secondary-ip` | 管理口 `eno8303`（别名 eth0）的地址 | CSV 中两台的 `eth0_ip` |
| `--virtual-ip` | VIP，只在 master 上给 | global `servers.ufm.vip` |

**注意**：`ufm_ha_cluster` 里的 primary/secondary 指的是两条链路（直连口和管理口），和本工具里「安装期 primary/secondary 两台机器」不是一回事。

顺序（实测）：
1. **standby（ufm02）**：

   ```bash
   systemctl stop ufm-enterprise.service
   ufm_ha_cluster config -r standby --local-primary-ip 192.0.2.2 --peer-primary-ip 192.0.2.1 --local-secondary-ip 198.51.100.132 --peer-secondary-ip 198.51.100.130
   ```

   - 成功标志：输出 `[*] Configuring HA cluster done.`
   - 副作用：
     - `/opt/ha_data` 备份到 `/ha_backup/<时间>/` 后清空、卸载，交给 DRBD（`/dev/md0p1` → `/dev/drbd0`）。
     - pcsd、pacemaker、corosync 设为开机自启。
     - `ufm-enterprise`、`ufm-ha-watcher`、`ha-monitor` 从 systemd 开机自启中去掉，改由 pacemaker 控制。
2. **master（ufm01）**：

   ```bash
   systemctl stop ufm-enterprise
   ufm_ha_cluster config -r master --local-primary-ip 192.0.2.1 --peer-primary-ip 192.0.2.2 --local-secondary-ip 198.51.100.130 --peer-secondary-ip 198.51.100.132 --virtual-ip 198.51.100.133
   ```

   - 先检查 VIP 是否合法，以及四个地址上的 pcsd 端口 2224。
   - 用 `mke2fs` 格式化 `/dev/drbd0`，再挂载到 `/opt/ha_data`。
   - **先销毁两台上原有的集群**，再分发密钥并启动两台的集群服务，等两台都上线（最长 120 秒）。
   - 创建 DRBD、文件系统、VIP、`ha-monitor`、`ufm-ha-watcher`、`ufm-enterprise` 等 pacemaker 资源，优先放在 master 上。
   - 成功标志：`[*] Configuring HA cluster done.`，并提示：`Once DRBD sync is completed, you can start HA cluster using: ufm_ha_cluster start`。
3. **等 DRBD 同步完成**（owner 2026-10-22 用 `drbdadm status` 确认）。同步完成时 master 上显示：

   ```
   ha_data role:Primary
     disk:UpToDate
     peer role:Secondary
       replication:Established peer-disk:UpToDate
   ```

   这次实测：master config 在 04:57 完成，05:30 前后已同步并启动，同步大约在 30 分钟以内（推断，没有单独计时）。
4. **在 master 上执行 `ufm_ha_cluster start`**，之后用 `ufm_ha_cluster status` 验收。ufm01 实测（Pacemaker 2 格式）：
   - `* Online: [ ufm01 ufm02 ]`；
   - `Promoted: [ ufm01 ]`、`Unpromoted: [ ufm02 ]`；
   - `ha_data_file_system`、`cluster_virtual_ip_0`、`ufm-ha-watcher`、`ufm-enterprise`、`ha-monitor` 都是 `Started ufm01`；
   - corosync、pacemaker、pcsd 都是 `active/enabled`；
   - DRBD 段缩进两格、值带方括号：`DRBD_CONNECTIVITY: [Connected]`、`DISK_STATE` 和 `PEER_DISK_STATE` 都是 `[UpToDate]`；`VIRTUAL_IP: [<vip>]`。
5. **在 master 上执行 `ufm_enterprise_sanity.sh`**，正常时最后一行为 `Sanity tests completed successfully!`。

**判定规则（owner 2026-10-22）**：
- **HA 是否成功只看 `ufm_ha_cluster status` 的结果**：master 在 Promoted 中、两台都在线、资源都是 Started、DRBD 两端都是 UpToDate 且 Connected。
- **`ufm_enterprise_sanity.sh` 失败不算失败**，只在本次运行的最后提示，不影响结果和退出码。
- 监控页面用的也是同一条规则。

监控页面的 HA 判定（`monitor/generate-monitor-html.py::parse_ufm_ha_status`）已按这份新格式修正，新旧两种格式都能读。
本工具有自己的一份解析（`parse_ha_status`）。两边各自独立运行，监控不依赖本工具的公共模块。`test_cases/test_ufm_ha_status_parity.py` 用全部已记录的格式（启动后、failover 后、未启动、没有集群、Pacemaker 1）核对两边读出的字段完全相同；改任一边都会触发这个测试。

**failover 之后**（ufm-manual.log 第 2001–2084 行）：Promoted 变成 ufm02，status 开头多一段 `WARNINGS:`（move constraint 仍在）。工具读这份输出时：
- 这段 WARNINGS 不影响解析；
- 不要求必须是 master Promoted（只有本次刚启动时才要求），只要求所有资源都在 Promoted 的那台上；
- 所以 failover 后 `check` 仍是 `OK`；`ha-setup` 按第 1 步判为已有 HA 配置。

集群（hacluster）密码由 `ufm_ha_cluster` 自己设置默认值，本工具不处理（owner 2026-10-22）。输出里 `passwd` 的两个提示（New password、Retype new password）是它自己应答的，不需要人工输入。

master 的 config 会销毁旧集群并格式化 DRBD，代价很大，所以 `ha-setup` 先读两台的 `ufm_ha_cluster status`，已有 HA 配置就什么都不做（见上面第 1 步）；需要配置时只在确认后执行。

`ufm_ha_cluster status` 在没有集群的设备上输出什么，目前没有实测；工具按「读不到节点列表和节点数」判为没有集群。这样判断是安全的：集群在运行时 VIP 在线，第 2 步的 VIP 检查会拦下来。未启动状态下 status 的样子同样是推断（资源为 Stopped (disabled)），它同样算已有 HA 配置。

### 连通测试与验证只用地址

所有连通测试（ping、ssh）的目标都是 IP/IPv6 字面地址；所有身份核验都比对地址或 MAC，从不比对主机名：
- UFM：核对管理口 MAC，以及 IPv4 地址在管理口上。
- OOB Leaf/Spine：登录用的 IP 必须在它自己的接口上。
- 互信：对端接口上要有我们连接的那个地址。
- 地址占用：应答的 MAC 与 CSV 或 BMC 口的 FDB 比对。

主机名只作为配置项（hostnamectl、/etc/hosts）写入。

### 确认、退出码与设备上的痕迹

- check 不改密码，不做任何配置：
  - 设备上只留下执行过的检查脚本副本（见下表 `/root/.setup/`），不改任何配置；
  - 不记录主机密钥。
  - 只清除一条邻居缓存：HA 前提检查 VIP 时，没有 arping 才会这样做。
- `--apply` 在**第一次改动设备之前**询问一次 `[y/N]`，授权对本次运行的后续设备同样有效。
  - 回答 N 则不做任何改动：设备为 `NOT_AUTHORIZED`，其余为 `NOT_ATTEMPTED`。
  - 没有交互终端时必须加 `--yes`。
- 生成的脚本放在 UFM 上的位置：

  | 内容 | 位置 |
  |---|---|
  | 在 UFM 上执行过的全部 sh 脚本（check、config-upgrade、ha-setup 都包括） | `/root/.setup/<运行目录名>/<序号>-<步骤>.sh` |
  | 改动前备份的原文件 | `/root/ufm-setup-upgrade-backup/<运行目录名>/` |

  - owner 2026-10-20：真正在 UFM 上执行过的 sh 脚本都保留在 `/root/.setup/`，方便在设备上手工操作，脚本名前加执行顺序的序号。
    - 序号由 UFM 在脚本落盘时分配（目录中最大序号 + 1），每台从 001 起连续编号。
    - 同一步骤在只读检查、正式执行和升级后复查中各执行一次，三份互不覆盖。
    - 没连上设备的尝试（例如升级重启期间的状态探测）和 sha256 校验失败的传送不占序号，设备上也不留文件。
  - 运行目录名与部署服务器 `ufm-setup-upgrade-logs/` 下的日志目录同名，格式为 `年月日-时分秒-命令`。
  - 脚本在本地生成，base64 传送，在 UFM 上核对 sha256 后才执行；脚本里没有密码，ipmitool/SSH 的密码提示由本地 pty 应答。
  - 本地日志目录里（已脱敏）：
    - 在 UFM 上执行过的脚本存为 `<主机名>-<序号>-<步骤>.sh`，输出存为同名 `.out.txt`，序号与设备上一致。
    - 没有在 UFM 上执行的尝试存为 `<本次运行顺序号>-<主机名>-<步骤>-not-run.sh` / `.out.txt`，输出里有原因。
- 退出码：
  - 0：全部已是目标状态。
  - 3：check 发现需要改动。
  - 1：失败或未完成。
  - 2：命令行用法错误。

### 密码

**每次运行只需要输入一个密码**（owner 2026-10-21）：UFM root 的新密码。
- 在输入检查通过后、连接任何设备之前询问一次。密码不接受命令行参数或环境变量，日志中做脱敏。
- **BMC 的 IPMI 用户**（`--ipmi-user`，默认 `admin`）用同一个密码。ipmitool 交互设置只支持 16 字节，超过时 `config-upgrade` 在连接设备前就报错。
- **出厂默认密码 `UFMappliance`** 只在首次登录时使用：`check` 和 `config-upgrade` 在新密码被拒绝后才会用它。出厂密码不是默认值时，加 `--ask-factory-password` 交互输入。`ha-setup` 不用出厂密码。
  - 它写在代码里（owner 2026-10-22）：各类设备的出厂默认用户名和密码都是厂商公开的默认值，种类太多，没有必要让用户输入。这条取代 REQ-F01 D-66 §二「出厂默认凭据不得作为字面量」。
- **新设备强制改密时再确认一次**：只有在真正把某台设备的出厂密码改成新密码之前，才要求再输入一次新密码，必须与开始时一致，否则不改任何设备的密码（`NOT_AUTHORIZED`）。每次运行最多问一次，平时运行不会出现。
- **OOB Leaf/Spine 先用部署服务器公钥登录**，公钥被拒时才询问交换机密码（owner 2026-10-21），每次运行最多问一次，之后的交换机都用这个密码。直接回车则不登录交换机，地址占用检查和 P2P 连线核对记为 `UNCHECKED`。

### 各步骤的细节

- **hostname**：/etc/hosts 中没有本机 FQDN 时追加 127.0.1.1。按 /etc/hosts 文件本身判断，不走 DNS 解析。原因是改名后 systemd-resolved 会合成解析结果，而 DNS 不可达时 getent 会卡住约一分钟。
- **netplan**：
  - 用 routes 写法，`gateway4` 会被改写。
  - apply 延后 3 秒执行（定时器精度 100ms），apply 的退出码写入备份目录；核验时要先看到这个退出码，再看网络状态。
  - 经 OOB 配好 IPv4 后，用新会话核验；部署服务器到 IPv4 不通时，经 OOB 新会话核验。
- **公钥**：把 `publickey/*.pub`（mgmt-server.pub、laptop.pub）追加到 root 的 `authorized_keys`。之后试一次部署服务器公钥直连，不通只给警告。
- **IPMI 用户**：核对用户槽位、权限和启用状态，再用 `ipmitool user test <id> 16` 核对密码是否就是 root 新密码。密码在 ipmitool 提示时由终端应答输入，不进命令行参数。三项都符合就不改动；否则重设。
  - 设置后再读回权限、启用状态，并用 `user test` 校验密码。ufm01 上实测过：新建用户后第一次设置的密码没有生效。所以校验不通过时会再设一次密码并重新校验，仍不通过则这一步失败（按 IPMI 失败处理：不阻断后续步骤，最后整台标为失败）。
- **IPMI LAN**：设置时每条 `ipmitool lan set` 都执行并记录退出码和输出，成败按 `lan print` 的读回判定；失败时报错里列出每条命令的结果。
  - 同时检查 IPMI over LAN（owner 2026-10-21）：`ipmitool channel info 1` 中 volatile 与 non-volatile 的 `Access Mode` 都必须是 `always available`；不是时执行 `ipmitool lan set 1 access on` 并读回。ufm01 实测：Access Mode 为 disabled 时，admin 和 root 都无法经网络（lanplus）建立会话。
- **IPMI 电源测试**（`ipmi_power`，只读，owner 2026-10-21）：admin 用户用于查看和管理电源。在 UFM 上执行 `ipmitool -I lanplus -H <BMC 地址> -U admin -a chassis power status`，必须返回 `Chassis Power is on/off`。
  - 密码与 OS 的 root 新密码相同，在 `-a` 的提示下由终端应答，不进命令行参数。
  - IPMI LAN 或用户还需要改动、或者已经失败时，记为 `NOT_TESTED`；`--apply` 没有提供 IPMI 密码时记为 `SKIPPED`。
  - 测试失败按 IPMI 失败处理：不阻断后续步骤，最后整台标为失败。
- **DNS/NTP/时区**：取自 global 的 `common.switch.system`，与 infra 相同。DNS 搜索域 `Domains=` 取 CSV 主机名后缀，没有后缀则跳过。
- **`/etc/hosts`**（步骤 `hosts`，owner 2026-10-22，照 `ufm-manual.log` 中 ufm02 的做法）：
  - 两台 UFM 都写进 `/etc/hosts`：`<HA 直连口 eno8403 地址>    <FQDN>  <短名>`，primary（ufm01）在前。地址取自 global 的 `interfaces.<primary/secondary>.eno8403`（别名 eth1），去掉掩码。
  - **只追加缺少的条目，文件里其它行一律不动**（owner：「只需要新增后面两条，前面的不用管」）。判断一个条目已存在的标准：有一行未被注释、第一列是这个地址、并且这一行里有这个 FQDN。
  - 改之前备份到本次运行的备份目录；检查模式只报告。单台部署、或 global 没有给出两台的直连口地址时，这一步为 SKIPPED。
  - 实现：公共模块 `infra/ubuntu24_host.py::hosts_entries_script`。
- **升级**：
  - 镜像来自 `common.mgmt.http`：`http://<address>:<port>/image/ufm-appliance-<version>-omu.x86_64.tar`，不做镜像校验。
  - `/root/` 下已有的同名文件，只有大小与服务器 Content-Length 一致才复用，否则重新下载。
  - 停止 `ufm-enterprise` 后确认它不再运行；停不下来就不升级。
  - 以 systemd 临时单元在后台执行 `ufm-os-upgrade.sh --appliance-sw-upgrade -r -y`，输出写入设备的 `/var/log/ufm-setup-upgrade-os-upgrade.log`。这样做是因为升级结束设备会自动重启。
  - 先等 `--wait-initial`（默认 600s），再每 `--wait-interval`（30s）探测一次，最长 `--wait-max`（默认 2400s；手工升级约 23 分钟）。
  - 判定规则：
    - 重启期间连不上视为正常。
    - 只有本次开始之后的状态日志行才算数。
    - `UFM_APPLIANCE` 等于目标版本、且本次的 `UFM-OS-FIRSTBOOT` 为 PASSED 才算完成。
    - 出现 `[FAILED]` 立即停止。
    - 超时则停止并提示登录设备查看日志，不会重复启动升级。
- **互信**：验证登录时先不记录主机密钥（StrictHostKeyChecking=yes）；失败后才以 accept-new 记录对端主机密钥再重试。
- **HA 的 VIP 检查**：
  - 先清掉该地址的邻居缓存；
  - 有 arping 时以 ARP 重复地址检测为准；
  - 没有 arping 时用 ping 加邻居表，屏蔽 ICMP 的设备也能发现。
  - `ibstat` 按物理状态 `Physical state: LinkUp` 判断，因为 SM 未运行时 State 不会是 Active。
- **远端执行方式**：每一步在部署服务器上生成一个小 bash 脚本，经 base64 传到设备，在设备上用 sha256 校验后再用 bash 执行。
  - 口令从不写进脚本。
  - 脚本副本、每次会话输出和 `result.json`（含输入文件摘要）保存在 `ufm-setup-upgrade-logs/<时间>-<命令>/`。
- **出错处理**：认证拒绝不会切换访问路径；主机密钥冲突、MAC 不符、输出无法识别都会停止，不重试。
- 与 Ubuntu 24.04 主机相关的配置脚本在公共模块 `infra/ubuntu24_host.py`。check 和 config 计划进一步做成模块，供 `server_mgmt` 复用。

## 为什么没有复用 f01 的 UFM 工具（2026-10-20 记录）

f01 分支（`http-f01-ufm-validation`）有一套 UFM 工具：
- `tools/ufm_initial_setup.py`：入口。
- `ufm_bootstrap_auth_adapter.py`：首次登录与认证观察。
- `ufm_project_key_install.py`：公钥安装。
- `ufm_deployment_script_builder/_syntax/_staging_owner/_staging_sftp.py`：生成、检查、暂存并经 SFTP 上传只读探测脚本。
- `f01_ssh_dependency_identity.py`：核对 SSH 依赖版本。

本工具没有复用它们，而是另写。原因如下，均为 2026-10-20 在本沙箱对 f01 原件实测：

1. **不做实际部署**：`ufm_initial_setup.py` 的说明写明只给出计划和只读探测，不执行任何厂商写入步骤。
   要求是按 `ufm-manual.log` 真正完成四阶段七步，这部分 f01 没有。
2. **违反独立运行**：`ufm_initial_setup.py` 要求项目必须是 setup 当前激活的项目，否则停止。
   本工具只凭本目录的输入文件运行，不依赖 setup/load/git/锁文件。
3. **输入格式不同**：`tools/ufm_input_contract.py` 只认旧的 `type=ufm`，不接受 `/23` 写法的掩码。
   当前格式是 `type=server_ufm`、只用前 7 列，global 为 `servers: - ufm:` 的 primary/secondary 结构。
4. **依赖的模块不存在**：`ufm_project_key_install.py`、`ufm_deployment_script_syntax.py`、`ufm_deployment_staging_owner.py`
   会在运行中途导入 `ufm_managed_output_binding`、`ufm_deployment_access`、`ufm_oob_relay`，这三个模块在任何分支都不存在。
   公钥安装、OOB 暂存等路径一执行就会报错。
5. **技术路线不同**：f01 用 paramiko，并要求精确的依赖版本。owner 指定参考 `ib-initial-setup` v15，与手工流程一致：
   系统 `ssh` 加 pty 应答密码，OOB 经 Leaf/Spine 的 `ip vrf exec … ssh -6` 嵌套登录；现场只需 Python 与 PyYAML。

另外，这些 f01 文件在沙箱里既没有在 `script_test_manifest.json` 登记，也没有被任何生产代码使用，
却让变更感知测试、CLI 帮助合同和公开审计都不通过。经 owner 同意，2026-10-20 已从沙箱删除以下 13 个文件。
它们与 `~/Desktop/http-f01-ufm-validation` 中的原件逐字节一致，需要时可从那里取回：
- 上面 8 个工具；
- `test_cases/test_f01_initial_setup_entry.py`、`test_f01_initial_setup_live_gate.py`、`test_f01_ssh_dependency_identity.py`；
- `UFM-AUTH-KEY-EXTENSION.md`、`UFM-INITIAL-SETUP-README.md`。

f01 改过的 6 个已跟踪文件（`tools/ufm_input_contract.py`、`tools/ufm_identity_binding.py`、`tools/ufm-discover.py`、
`infra/ufm_jump_transport.py` 及其两个测试）保留未动。

## OOB 跳板选择（移植自 ib-initial-setup v15）

IPv4 不可达时，先只读登录 P2P 指定的 Leaf，读取 `nv show interface`、`ip -d link show`、
`bridge fdb show`、`ip neighbor`、`ip -j address show`（每台交换机每次运行只读一次）：

1. 接入口 Oper Status 必须为 up；FDB 中该口必须学到 CSV 管理 MAC，并给出唯一 VLAN/bridge。
2. Leaf 上该 VLAN 有唯一真实 SVI 且该 SVI 有 IPv4：从 Leaf 跳（`reason=LEAF`）。
3. SVI 不存在（`LEAF_SVI_MISSING`）或没有 IPv4（`LEAF_SVI_HAS_NO_IPV4`）：改走 Spine。
   - 候选只取 Leaf `nv show interface` 中 Oper Status=up 的 LLDP Remote Host，并且必须与
     ib.csv 中的 Spine 库存唯一对应；默认库存是短名以 `oob-spine` 开头的 eth_jump，
     也可用 `--oob-spines a,b` 指定。只在 CSV 中登记但 LLDP 中没有的 Spine 不会登录。
   - 候选 Spine 的身份按地址核对：登录用的 IP 必须出现在它的 `ip -j address show` 里；该 VLAN 上有唯一真实 SVI（`vlan1000-v0` 这类 VRR
     macvlan 不算），SVI 为 UP 且有自有 IPv4 和 link-local，能查到 VRF，并且邻居表有该 MAC
     的 link-local 或可由 MAC 推导（推导地址与邻居表冲突则拒绝）。
   - 合格候选中随机选一台，同一 Leaf 下的两台 UFM 使用同一台 Spine；不合格原因写入结果。
   - Spine 的登录地址取 eth0_ip；没有时取该行唯一一组 vlan_id/svi_ip。Leaf/Spine 使用同一个
     OOB 密码（或密钥）。
4. 从选定的跳板执行 `ip vrf exec <vrf> ssh -6 -B <svi> root@<link-local>`，登录后照常核对 MAC。

Leaf、Spine 只做只读查询，不修改任何交换机配置。
- 密码不接受命令行参数或环境变量，日志中做脱敏。每次运行的报告、各次 SSH 会话输出和
  `result.json` 保存在 `ufm-setup-upgrade-logs/<时间>-<命令>/`。

HA 配置（config、DRBD 同步、start、status 判定）和 HA 之后的配置（license、gv.cfg、root_guid.conf、failover、核对）都已按 owner 2026-10-22 在 `ufm-manual.log` 中的实测记录实现，见「ha-setup」「ha-post-config」两节。`ufmlicense` 的实际输出样本还在等 owner 提供，届时再核对 license 判定的格式。
