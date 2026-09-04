DAY0 项目完整目录模板说明
========================

整体架构与使用入口
------------------

本文件说明“一个项目目录里每个输入、输出和可能连接的固定路径”。整个工作区的模块架构、
公开仓库的边界和验证入口见 `.github/README.md`；私有工作区如保留根目录
`USER_MANUAL.md`，其中说明管理服务器 load、ZTP 波次、监控、结果回传和 unload 场景。
各公共代码目录的 README 说明生成器和采集器内部逻辑。

项目目录只保存项目输入和项目结果：公共代码位于 ztp/、monitor/、infra/、tools/ 等目录，
共享镜像/离线包位于 image/ 和 apps/。setup 在 staging 中验证本文件描述的运行链接后原子
激活项目；load 再负责生成、发布、服务和 worker。不要手工修改 setup 管理的公共链接。

本目录是所有 DAY0 真实项目的完整模板。

公开仓库中的本目录只包含不可直接上线的脱敏骨架：192.0.2.0/24、
198.51.100.0/24 和 203.0.113.0/24 是文档地址，02:00 开头的 MAC 是本地管理
示例；laptop.pub、mgmt-server.pub、镜像和 p2p.xlsx 都是空占位。所有密码值
均为锁定值 `*`。其中 Cumulus global 输入写成 `"'*'"` 是有意的：Jinja 渲染
后生成 YAML 才会得到安全的 `hashed-password: '*'`，不能简化成裸星号。
创建项目后必须先替换地址、MAC、凭据、公钥和所需制品；strict setup/load 会
拒绝尚未准备完成的占位输入。

执行：

  python3 DAY0-Prepare/01-a-setup.py <项目文件夹>

时，setup 会递归遍历本目录：

  1. 在真实项目中创建这里出现的全部目录，包括空目录。
  2. 把这里的全部缺失文件复制到真实项目。
  3. 真实项目中已经存在的同名文件或目录不会被覆盖。
  4. template 后续增加的文件或目录，会在项目下次 setup 时自动补齐。

本目录中的空 `.bin` 文件是镜像名称占位符，setup/load 会像其他模板文件一样把它们
复制到真实项目，用来提醒用户应准备哪些版本。真实 Cumulus/NVOS 镜像是所有项目
共用的制品，统一放在：

  http/image/

setup 会把它们链接到 ztp/image/cumulus/ 和 ztp/image/nvos/。
可能创建的连接：
  ztp/image/cumulus/<Cumulus镜像名>.bin -----> http/image/<Cumulus镜像名>.bin
  ztp/image/nvos/<NVOS镜像名>.bin       -----> http/image/<NVOS镜像名>.bin
镜像归属由文件名识别；无法识别为 Cumulus 或 NVOS 的 .bin 文件只告警，不创建链接。


一、项目输入文件
----------------

01-global.yaml
  作用：Cumulus 和 NVOS 配置生成器共用的全局参数，包括 DNS、NTP、BGP、
        VLAN、VRF、MLAG 等项目级配置。
  新项目固定使用 schema_version: 2。缺少该字段或写 1 的历史项目仍按 v1 兼容；
  声明 v2 后，02-devices_config.csv 必须采用下面的 v2 列布局，不能混入 v1 的
  vrf_default/vrr_ip/vrr_mac 列。
  公开模板中的 DNS/NTP、relay、VRL、MLAG 地址及 MAC 均为脱敏示例，必须按
  项目替换；`*` 表示锁定登录，不是可用的默认密码。
  load 前必须补充：
    common.mgmt.http.status/http_root
    common.mgmt.ztp.status/ztp_url_prefix；service_ip 从 DHCP subnet 的 URL 推导，
    不需要在 global 中重复填写
    switches.eth.version、switches.ib.version、switches.nvl.version
  只有 devices CSV 实际包含相应设备类型时，load 才要求该类型的版本镜像；
  eth/eth_spx 使用 Cumulus 镜像，ib/nvl 分别使用其 global version 对应的 NVOS 镜像。
  DHCP subnet 中的 provision URL 必须使用相应网络角色的服务地址和脚本：
    prod_oob      -> ztp-bootstrap_oob.sh
    prod_oobofoob -> ztp-bootstrap_oobofoob.sh
    air_oob       -> ztp-bootstrap_oob.sh
    air_oobofoob  -> ztp-bootstrap_oobofoob.sh
  AIR 与 Production 按网络类别共用上述两份 bootstrap，不再使用单独的
  ztp-bootstrap_air.sh。
  可能创建的连接：
    ztp/config/cumulus/template/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    ztp/config/nvos/template/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    infra/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    monitor/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
  monitor 从 common.switch.system.date-time.timezone 读取页面显示时区；
  也可临时使用 MONITOR_TIMEZONE 环境变量覆盖。

02-devices_config.csv
  作用：统一保存 eth、eth_spx、spx、ib、nvl、server、air 设备及其 hostname、类型、管理IP、MAC、模板和网络参数。
  非 AIR 行由用户维护；DHCP 生成器每次原子重建全部 type=air 行并放在文件末尾。
  AIR 名称先精确匹配 Production；带站点/机柜前缀时只采用最长、最具体且唯一的
  Production hostname 后缀，最长候选并列时停止生成，避免相似短名称错误继承地址。
  schema v2 的列顺序为：
    1) 固定 12 列 hostname..lo_ip；
    2) 零到多个 vlan_id,svi_ip,netmask,vlan_ports 普通 VLAN 组；
    3) 固定 7 列 bgp_asn,bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl；
    4) 可选安全策略列 terminal_l2_ports（公开模板默认包含）；
    5) 零到多个 evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,evpn_l2vni,
       evpn_l2vlan,svi_ip,netmask,vlan_ports EVPN 组。
  v2 每行列数必须与表头完全一致；普通 VLAN 组可以完全没有，也可重复任意次。
  范围 VLAN 只做二层成员，带单值 SVI 的 VLAN 必须拆成自己的组。
  terminal_l2_ports 只列预期连接服务器/PDU/CDU 等终端的独立二层 swp 或逻辑
  二层 bond，以 / 分隔；bond member、peerlink、routed 接口和交换机互联 bond 不得填写。
  只有显式列出的接口才生成 admin-edge 与 bpdu-guard。缺列或单元格为空都不会自动
  选择接口；缺列项目会收到迁移 warning。

  VRR 是项目级策略，不再逐设备填写：
    switches.eth.vrr.base_mac: 02:00:5e:01:00:00
    switches.eth.vrr.gateway_ip: subnet_maximum
  gateway_ip 可为 subnet_maximum/subnet_minimum/YAML null/省略；null 和省略默认
  subnet_maximum，字符串 none 会被拒绝。base_mac 必须是低 16 bit 为零的非零
  locally-administered unicast MAC。VLAN ID 补足为四位十进制数字，并将四个数字编码到
  MAC 的最后四个十六进制半字节；Fabric 1 下 VLAN 110 得到 02:00:5e:01:01:10，
  VLAN 4094 得到 02:00:5e:01:40:94。Fabric 2 可使用 02:00:5e:02:00:00。
  schema v2 不再使用 mlag.pairs，也不生成 system.global.system-mac；设备使用自身
  唯一的系统 MAC。MLAG 成员关系由 devices CSV 中规范化后的 bond_mac 建立，两个
  MLAG peer 必须使用同一个值。所有 MLAG 设备都把 bond_mac 用作
  mlag.mac-address；只有同时承载 VNI/VXLAN 时，才额外生成
  system.global.anycast-mac 和 nve.vxlan.mlag.shared-address。普通二层 MLAG
  不生成 global anycast 或 shared-address。
  shared-address 默认取两个 peer loopback 中较大地址的下一个 IPv4。自动值冲突时可在
  switches.eth.mlag.shared-addresses 中按 bond-mac 显式覆盖：
    shared-addresses:
    - bond-mac: '02:00:00:ff:01:ff'
      anycast-ip: 192.0.2.201
  bond-mac 匹配不区分大小写，anycast-ip 不带 CIDR。重复 bond-mac/IP、找不到对应
  MLAG pair、地址冲突或给非 MLAG+VNI pair 配置 override 都会停止生成。schema v1
  历史项目仍按原 mlag.pairs 合同兼容读取；不能在 schema v2 中混用旧结构。
  同 VRF + VLAN 的 SVI 网段必须相同。所有设备 SVI 地址互异且不占 gateway 时，gateway
  作为共同 vrr_ip、MAC 写在 ipv4.vrr 下，DHCP relay 用 giaddress；所有 SVI 都等于
  gateway 时不生成 vrr_ip：Cumulus 5.18 及以上把 MAC 写入该 SVI 的 link.mac-address，
  更早版本写入该 vlan 的 ifupdown2_eni snippet；DHCP relay 使用设备 loopback 的
  gateway-interface，输入字段名仍为 vrr_mac。只在一台设备出现且 SVI 不是 gateway
  时视为 standalone 普通 SVI，不派生 VRR IP/MAC；其他混合输入拒绝生成。
  Border 模板的 /29 SVI 另采用严格三地址分区。subnet_maximum 时本端物理地址为
  N+4/N+5、VRR 为 N+6、对端 next-hop 为 N+3（VRR-3）；subnet_minimum 时
  本端物理地址为 N+2/N+3、VRR 为 N+1、对端 next-hop 为 N+4（VRR+3）。
  该规则只用于 Border 的 /29 SVI；其他交换机及 Border 上的其他掩码
  均不触发此地址策略。一个 Border VRF 最多只能有一个 /29 transit
  VLAN，否则默认路由来源不明确并拒绝生成；没有 /29 时不自动生成该默认路由。

  单 VLAN 可写 100/native；它同时保留在 trunk vlan 列表并配置为 untagged。
  vlan_id 与 evpn_l2vlan 都支持该后缀，范围或组合 selector 不允许 /native，同一接口
  不能从不同 VLAN 组获得多个 native VLAN。

  bond_ports、bond_type、bond_mac 可用 | 表示对齐的多组 bond。v2 类型别名为
  local、mlag、evpn；local 名称 bond49b51b53 表示一个本地 bond，成员为
  swp49/swp51/swp53。bond_mac 按类型解释：local 必须为空或 NA；MLAG 必须填写，
  同一设备的全部 MLAG bond 及两个 peer 必须使用相同值，该值也用来识别 pair；EVPN-MH
  必须填写并生成 segment.mac-address，同一冗余组的不同 bond 可以复用该值，由各 bond
  的 local-id 形成不同 ESI。EVPN-MH 不从 bond_mac 生成 system.global.anycast-mac。
  例如 local|mlag 对应的 bond_mac 应写成 NA|02:00:00:ff:01:ff。MLAG 与 EVPN-MH
  不能在同一设备共存。vlan_ports 中引用的每个 bond 都必须已在 bond_ports 声明，
  仅声明但未引用的 bond 不会被隐式配置，setup 会输出 warning 要求确认它是预留项还是
  迁移时漏写了 vlan_ports 引用。
  可能创建的连接：
    ztp/config/cumulus/template/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ztp/config/nvos/template/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ztp/config/isc-dhcp-server/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ztp/backup/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ethernet/eth.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    infiniband/ib.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    nvlink/nvsw.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    monitor/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    infra/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
  监控、ZTP、backup、Feedback 统一读取本文件并按 type 过滤；infra 只选择 type=server 行。

02-dhcp-subnet_config.csv
  作用：ISC DHCP 的 shared-network、subnet、地址池、网关和 ZTP URL 配置。
  可能创建的连接：
    ztp/config/isc-dhcp-server/02-subnet_config.csv -----> DAY0-Prepare/<项目>/02-dhcp-subnet_config.csv

p2p.xlsx
  作用：P2P 拓扑 Excel 的固定入口，供 AIR、LLDPq 和 CVT 相关流程使用。
        可把多个客户版本保存在 p2p/ 下，文件名须包含 p2p（忽略大小写）；setup/load
        默认选择修改时间最新的非空版本，并把根目录空占位替换为相对软链接：
        p2p.xlsx -----> p2p/<最新客户文件名>.xlsx
        IP Assignment 等其他 XLSX 不参与选择。也可用
        --p2p-file=p2p/<文件名>.xlsx 明确选择；脚本不会删除旧版本。
        若不使用 p2p/，根目录仍须只有一个文件名含 p2p 的非空 XLSX。
  可能创建的连接：
    ztp/config/cumulus/template/P2P/p2p.xlsx -----> DAY0-Prepare/<项目>/p2p.xlsx
    ztp/config/nvos/template/P2P/p2p.xlsx    -----> DAY0-Prepare/<项目>/p2p.xlsx
    ethernet/p2p.xlsx                        -----> DAY0-Prepare/<项目>/p2p.xlsx
    infiniband/p2p.xlsx                      -----> DAY0-Prepare/<项目>/p2p.xlsx
    nvlink/p2p.xlsx                          -----> DAY0-Prepare/<项目>/p2p.xlsx
    ztp/config/cumulus/template/P2P/output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p/
    ztp/config/nvos/template/P2P/output-p2p    -----> DAY0-Prepare/<项目>/99-output-p2p/
  P2P 派生结果统一写入项目的 99-output-p2p/。

03-air-topology-policy.json（可选）
  作用：只调整由 P2P 派生的 AIR 拓扑，不改写原始 P2P、LLDPQ DOT 或生产设备配置。
        当前支持按 inventory 类型精确限制 AIR 节点，以及用完整的设备名和端口匹配一条
        已知错误链路后替换为获准链路。规则必须唯一命中；零命中、多命中、未知字段、
        自连接或端口冲突都会 fail closed。没有该文件时维持严格默认行为。
  load 会把 01-global.yaml 的 Cumulus 版本显式传给 AIR 转换器；例如版本 5.18 会生成
  cumulus-vx-5.18 节点。策略文件存在时，其 SHA-256 也进入统一 release，manual-ztp
  preflight 会检查新增、删除或内容漂移，防止发布后静默改变 AIR 拓扑。

laptop.pub
  作用：项目电脑 SSH Ed25519 公钥。setup 会复制到真实项目，并作为 ZTP/bootstrap 安装到交换机 authorized_keys 的公钥。
  可能创建的连接：
    ztp/config/publickey/laptop.pub   -----> DAY0-Prepare/<项目>/laptop.pub
  使用要求：创建项目后应替换为项目电脑的真实公钥。0 字节公钥只作为准备占位，setup 不会发布；Linux 正式 load 的 strict 门禁会拒绝必需的空公钥。

mgmt-server.pub 和 .management-pubkeys
  作用：`mgmt-server.pub` 为空时是管理服务器公钥占位文件；非空时保存管理服务器的真实公钥。
  `.management-pubkeys` 明确记录该路径由 load 流程管理。
  macOS 配置准备会保留这个计划路径但不发布空文件；Linux 管理服务器正式 load 时使用
  当前执行用户的 `~/.ssh/id_ed25519.pub` 注入它，再发布到 ZTP。
  不要手工复制项目电脑公钥到这个文件，两把 key 必须不同。

其他 *.pub（可选约定）
  作用：项目可以增加其他 SSH 公钥，setup 会逐个建立同名 ZTP 链接。
  可能创建的连接：
    ztp/config/publickey/<原文件名>.pub -----> DAY0-Prepare/<项目>/<原文件名>.pub
  只有非空且格式合法的公钥才会成为运行时发布文件。

README.txt
  作用：本说明文件。它也会被复制到每个真实项目，但不会创建运行时软链接。


二、项目输出目录
----------------

99-output-eth/
  作用：Cumulus 配置生成结果、带 description 的配置和 AIR 仿真配置。
  可能创建的连接：
    ztp/config/cumulus/template/99-output       -----> DAY0-Prepare/<项目>/99-output-eth
    ztp/config/cumulus/template/91-devices.yaml -----> DAY0-Prepare/<项目>/99-output-eth/91-devices.yaml
    DAY0-Prepare/<项目>/99-output-eth/latest -----> <最新完整发布目录>
    ztp/config/cumulus/latest_yaml -----> ztp/config/cumulus/template/99-output/latest
  latest_yaml 是固定 HTTP 入口；项目内 latest 仅指向带 .published-complete 的发布目录。

99-output-ib_nvl/
  作用：NVOS 的 <时间戳>-ib、<时间戳>-nvl、校验完成后的 -combine 发布目录，
        以及 InfiniBand bringup 工具按项目归档的日志与生成文件。
  可能创建的连接：
    ztp/config/nvos/template/99-output-ib_nvl -----> DAY0-Prepare/<项目>/99-output-ib_nvl
    DAY0-Prepare/<项目>/99-output-ib_nvl/latest -----> <最新完整发布目录>
    ztp/config/nvos/latest_yaml -----> ztp/config/nvos/template/99-output-ib_nvl/latest
    infiniband/bringup/ndr/ndr-upgrade-logs -----> DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/ndr-upgrade-logs
    infiniband/bringup/xdr-initial-setup/xdr-initial-setup-logs -----> DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/xdr-initial-setup-logs
    infiniband/bringup/xdr-upgrade/xdr-upgrade-logs -----> DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/xdr-upgrade-logs
  latest_yaml 是固定 HTTP 入口；项目内 latest 优先指向同一时间戳的 -combine 目录。

99-output-dhcp/
  作用：保存 c1-generate_dhcp.py 生成的 DHCP 主配置和设备 hosts 文件。
  可能创建的连接：
    ztp/config/isc-dhcp-server/dhcpd.conf -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd.conf
    ztp/config/isc-dhcp-server/dhcpd_eth.hosts -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd_eth.hosts
    ztp/config/isc-dhcp-server/dhcpd_ib.hosts -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd_ib.hosts
    ztp/config/isc-dhcp-server/dhcpd_nvl.hosts -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd_nvl.hosts

99-output-backup/
  作用：保存 yaml-collect.py 拉取的设备配置、采集日志和差异报告。
  可能创建的连接：
    ztp/backup/yaml-backup -----> DAY0-Prepare/<项目>/99-output-backup

99-output-p2p/
  作用：保存 P2P 转换产生的 *-lldpq.dot、*-air.dot、上传 NVIDIA AIR 的 *-air.json、
       HTML 或其他拓扑派生文件。
  可能创建的连接：
    ztp/config/cumulus/template/P2P/output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    ztp/config/nvos/template/P2P/output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    monitor/99-output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
  90-c2-generate_configs.py 直接扫描上述 output-p2p 目录，不再创建单文件 DOT 软链接。

99-output-monitor/
  作用：保存 Ethernet/SPX、InfiniBand、NVLink 的采集结果、链路结果和 cron 日志。
  setup 会创建以下项目子目录：
    99-output-monitor/ethernet/eth-info/
      保存 Ethernet 设备信息采集结果。
    99-output-monitor/ethernet/spx-link/
      保存 SPX 链路采集和检查结果。
    99-output-monitor/ethernet/cronjob.log
      保存 Ethernet/SPX 定时采集任务日志。
    99-output-monitor/infiniband/ib-info/
      保存 InfiniBand 设备信息采集结果。
    99-output-monitor/infiniband/ib-link/
      保存 InfiniBand 链路采集和检查结果。
    99-output-monitor/infiniband/cronjob.log
      保存 InfiniBand 定时采集任务日志。
    99-output-monitor/nvlink/nvsw-info/
      保存 NVLink Switch 设备信息采集结果。
    99-output-monitor/nvlink/nvsw-link/
      保存 NVLink 链路采集和检查结果。
    99-output-monitor/nvlink/cronjob.log
      保存 NVLink 定时采集任务日志。

  可能创建的连接包括：
    ethernet/monitor/eth-info -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/eth-info
    ztp/config/cumulus/template/P2P/eth-info -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/eth-info
    ethernet/monitor/spx-link -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/spx-link
    ethernet/monitor/cronjob.log -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/cronjob.log
    monitor/ethernet -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet

    infiniband/monitor/ib-info -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ib-info
    ztp/config/nvos/template/P2P/ib-info -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ib-info
    infiniband/monitor/ib-link -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ib-link
    infiniband/monitor/cronjob.log -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/cronjob.log
    monitor/infiniband -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband

    nvlink/monitor/nvsw-info -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink/nvsw-info
    nvlink/monitor/nvsw-link -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink/nvsw-link
    nvlink/monitor/cronjob.log -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink/cronjob.log
    monitor/nvlink -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink

  各网络目录下的 monitor 链接供采集脚本写入当前项目；http/monitor/ 下的三个
  类型目录链接供 HTML 汇总页面读取相同数据。设备清单不再复制或链接到上述项目
  输出子目录，而是统一使用：
    monitor/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv

99-output-ztp/
  作用：保存 12-ztp-monitor.py 按次生成的 ZTP 状态快照、report.json 和
        latest 发布链接。目录作为完整项目模板的空骨架保留，运行数据
        由 ZTP 监控流程写入，不在 upload/sync 部署时传输。
  可能创建的连接：
    DAY0-Prepare/<项目>/99-output-ztp/latest -----> <最新完整 ZTP 状态目录>


三、维护约束
------------

1. template 中不要放项目生成结果、真实监控数据或设备备份。
2. 修改 template 不会覆盖既有项目的同名文件，只会补齐缺失项。
3. 空的 .xlsx、*.pub 或 http/image/*.bin 在 --strict 校验下会阻止 setup。
4. template 和项目根目录只保留空 `.bin` 名称占位符；真实镜像只放在 http/image/ 中。
5. 新增模板文件时，应在本 README 中补充用途、维护责任和可能的软链接。
