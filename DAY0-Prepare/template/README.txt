DAY0 项目完整目录模板说明
========================

整体架构与使用入口
------------------

本文件说明“一个项目目录里每个输入、输出和可能连接的固定路径”。整个工作区的模块架构、
公开仓库的边界和验证入口见 `.github/README.md`；私有工作区如保留根目录
`USER_MANUAL.md`，其中说明管理服务器 load、ZTP 波次、监控、结果回传和 unload 场景。
各公共代码目录的 README 说明生成器和采集器内部逻辑。

项目目录只保存项目输入和项目结果：公共代码位于 ztp/、monitor/、infra/、tools/ 等目录，
共享镜像/离线包位于 image/ 和 apps/。setup 校验项目、补齐本文件描述的目录和文件后，
让 DAY0-Prepare/activate-project 指向它来激活项目（见下文「激活项目」）；load 再负责生成、
发布、服务和 worker。不要手工修改 setup 管理的公共链接。

本目录是所有 DAY0 真实项目的完整模板。

公开仓库中的本目录只包含不可直接上线的脱敏骨架：192.0.2.0/24、
198.51.100.0/24 和 203.0.113.0/24 是文档地址，02:00 开头的 MAC 是本地管理
示例；仓库模板中的 laptop.pub、mgmt-server.pub、镜像和 p2p.xlsx 都是空骨架，
setup 不从模板复制 laptop.pub。所有密码值
均为锁定值 `*`。其中 Cumulus global 输入写成 `"'*'"` 是有意的：Jinja 渲染
后生成 YAML 才会得到安全的 `hashed-password: '*'`，不能简化成裸星号。
创建项目后必须准备真实地址、MAC、凭据和所需制品；本机 setup 从本机 ~/.ssh
选择或必要时生成项目电脑公钥，Linux 管理服务器正式 load 使用独立的管理公钥。
未准备完成的部署输入不得进入正式发布。

执行：

  python3 DAY0-Prepare/01-a-setup.py <项目文件夹>

时，setup 会递归遍历本目录：

  1. 在真实项目中创建这里出现的全部目录，包括空目录。
  2. 除 laptop.pub 外，把这里的缺失文件复制到真实项目。
  3. 真实项目中已经存在的同名文件或目录不会被覆盖。
  4. template 后续增加的文件或目录，会在项目下次 setup 时自动补齐。

激活项目（R-016）
----------------

DAY0-Prepare/activate-project 是唯一随项目变化的链接，原文是项目的一级名字（例如
activate-project -> 2026-09-example）。树里所有用到项目文件的链接都经过它，原文固定为
relpath("DAY0-Prepare/activate-project/<固定名>", 链接所在目录)，例如
ethernet/eth.csv 的原文是 ../DAY0-Prepare/activate-project/02-devices_config.csv；
4 个公钥目录里逐把公钥的链接也一样。切换项目只换这一个指针，别的链接都不动。
下文「可能创建的连接」箭头右边写的是链接最终到达的项目文件。

setup 激活项目分 6 步，每一步都能重复执行；不回滚、不加切换标记，出了问题就再跑一次 setup：
  1. 校验目标项目，什么都不写。项目参数只接受 DAY0-Prepare 的直接子目录（真实目录，不能是
     template、链接或以 . 开头的名字）；global、CSV、P2P、公钥按现有规则校验。不通过以 2 退出。
     加 --force 时，输入校验的错误降为警告，照样准备和切换。
  2. 准备目标项目，只写这个项目：按本模板补齐、准备 laptop.pub、选 P2P 并建 p2p.xlsx 指针、
     建 99-output-* 目录和预先存在的输出文件。出错以 1 退出，不切换，原来的项目照常可用。
  3. 核对链接规格表（tools/project_contract.py 的 SETUP_LINK_SPECS）：不存在就建，原文不对就
     原子替换并打印旧目标 → 新目标，同名真实文件或目录只报错、不删。错误只计数。
  4. 切换 activate-project：已指向目标就跳过；原来指向另一个项目时询问一次，要完整输入 yes；
     -y/--yes（--confirm-project-switch 同义，load 使用）不再询问。之后按目标项目刷新逐把公钥链接、
     latest_yaml、共享镜像、optimize sample，清理旧版 setup 留下的链接，绑定 infra/logs。
  5. 写派生记录 ztp/.setup_manifest。它只是记录，判断当前项目一律看指针。
  6. 第 3 步以后有错误以 1 退出，但已经切换；处理后重跑 setup。
切换那一刻正在运行的工具（采集、升级、手工脚本），结果不保证；ZTP/DHCP 服务正在运行时，
请用 load 切换项目，只跑 setup 会让发布内容混用两个项目（setup 只提示，不阻止）。
--csv-dir 已经退役：清单放在项目外时，在项目里建 02-devices_config.csv -> 外部文件 的链接
（见下文「用户链接输入」）。

本目录中的空 `.bin` 文件是镜像名称占位符，setup/load 会像其他模板文件一样把它们
复制到真实项目，用来提醒用户应准备哪些版本。真实 Cumulus/NVOS 镜像是所有项目
共用的制品，统一放在：

  http/image/

setup 会把它们链接到 ztp/image/cumulus/ 和 ztp/image/nvos/。这些共享链接与项目无关：
可能创建的连接：
  ztp/image/cumulus/<Cumulus镜像名>.bin -----> http/image/<Cumulus镜像名>.bin
  ztp/image/nvos/<NVOS镜像名>.bin       -----> http/image/<NVOS镜像名>.bin
  infiniband/bringup/ufm-setup-upgrade/image -----> ../../../image（UFM license *.lic 也放在 http/image/；
                                                    该目录不存在时 setup 跳过此链接）
NVOS 镜像精确支持 `nvos-amd64-<A.B.C>.bin` 和
`nvosv<A-B-C>amd64.bin` 两种名称；同版本两种名称内容不同时 load 会拒绝，内容相同时
固定优先前一种新名称。镜像归属由文件名识别；无法识别为 Cumulus 或 NVOS 的 .bin
文件只告警，不创建链接。

下文每个文件或目录下的「可能创建的连接」合起来，与 tools/project_contract.py 的链接
规格表（SETUP_LINK_SPECS）逐条一致；箭头右边写的是链接最终到达的项目文件，或仓库内的
另一个链接（写成相对路径或仓库路径）。


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
    common.mgmt.http.status/address/port/http_root
      address 是本机独立的 HTTP 服务 IPv4。status 为 enabled 时必须填写，setup 和
      load 都会拒绝缺少 address 的 global。DHCP 下发给设备的 URL（Cumulus 的
      provision URL、NVOS 的 ztp.json）由 address、port 和 ztp_url_prefix 拼成，
      bootstrap 里的 ZTP_SERVER 也取 address 和 port；都不从 DHCP subnet 的
      ztp_service_ip 推导。
    common.mgmt.ztp.status/ztp_url_prefix
    switches.eth.version、switches.ib.version、switches.nvl.version
  只有 devices CSV 实际包含相应设备类型时，load 才要求该类型的版本镜像；
  eth/eth_spx 使用 Cumulus 镜像，ib/nvl 分别使用其 global version 对应的 NVOS 镜像。
  ZTP 服务地址（service_ip）和每个网段使用哪份 bootstrap，写在
  02-dhcp-subnet_config.csv 里，见下文。
  文件末尾有一段注释掉的 servers: 示例（UFM 的 VIP、IPMI 和各接口地址）。使用 UFM
  的项目取消注释并替换地址；不用 UFM 的项目保持注释即可。格式见
  infiniband/bringup/ufm-setup-upgrade/README.md；监控的 UFM 采集读取 servers.ufm.vip。
  可能创建的连接：
    ztp/config/cumulus/template/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    ztp/config/nvos/template/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    ztp/config/isc-dhcp-server/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    infra/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    monitor/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    ethernet/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    infiniband/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    nvlink/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    infiniband/bringup/xdr-upgrade/01-global.yaml -----> DAY0-Prepare/<项目>/01-global.yaml
    ethernet/monitor/01-global.yaml -----> ../01-global.yaml
    infiniband/monitor/01-global.yaml -----> ../01-global.yaml（UFM 采集读取 servers.ufm.vip）
    nvlink/monitor/01-global.yaml -----> ../01-global.yaml
    infiniband/bringup/xdr-initial-setup/01-global.yaml -----> ../../01-global.yaml（仓库内固定桥接，不由 setup 创建）
    infiniband/bringup/ufm-setup-upgrade/01-global.yaml -----> ../../01-global.yaml（仓库内固定桥接，不由 setup 创建）
  monitor 从 common.switch.system.date-time.timezone 读取页面显示时区；
  也可临时使用 MONITOR_TIMEZONE 环境变量覆盖。

02-devices_config.csv
  作用：统一保存 eth、eth_spx、spx、ib、nvl、server、server_mgmt、server_ufm、air 设备及其 hostname、类型、管理IP、MAC、模板和网络参数。
  server_mgmt 是 server 的新写法；server_ufm 是 UFM 设备，只填前 7 列
  （hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac，netmask 写 23 或 /23），
  其余列留空但逗号不能省，eth0_gw、eth0_mac 必填。
  非 AIR 行由用户维护；DHCP 生成器每次原子重建全部 type=air 行并放在文件末尾。
  AIR 名称先精确匹配 Production；带站点/机柜前缀时只采用最长、最具体且唯一的
  Production hostname 后缀，最长候选并列时停止生成，避免相似短名称错误继承地址。
  schema v2 的列顺序为：
    1) 固定 12 列 hostname..lo_ip；
    2) 零到多个 vlan_id,svi_ip,netmask,vlan_ports 普通 VLAN 组；
    3) 固定 7 列 bgp_asn,bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl；
    4) 零到多个 evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,evpn_l2vni,
       evpn_l2vlan,svi_ip,netmask,vlan_ports EVPN 组。
  v2 每行列数必须与表头完全一致；普通 VLAN 组可以完全没有，也可重复任意次。
  范围 VLAN 只做二层成员，带单值 SVI 的 VLAN 必须拆成自己的组。
  终端二层 STP 防护不占用 CSV 字段。生成器自动为带 bridge 配置的独立二层 swp
  和逻辑二层 bond 生成与 Cumulus 版本匹配的枚举：5.14 及以前为
  admin-edge=on 与 bpdu-guard=on，5.15 及以后为 admin-edge=enabled 与
  bpdu-guard=enabled；bond member、peerlink、routed BGP
  接口不会生成这两个参数。固定的 OOBofOOB 交换机互联例外也保持普通 STP：
  oobofoob-leaf 的 bond49b51，以及 oobofoob-spine 的 bond1..bond11 均不生成
  admin-edge/bpdu-guard；同设备的其他合格独立二层接口仍自动启用防护。

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
  迁移时漏写了 vlan_ports 引用。bond_ports 为空时，遗留的 bond_type/bond_mac 仅告警
  并被生成器忽略；vlan_ports 引用了未声明 bond 时仍会停止 load。
  可能创建的连接：
    ztp/config/cumulus/template/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ztp/config/nvos/template/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ztp/config/nvos/template/P2P/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ztp/config/isc-dhcp-server/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ztp/backup/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    monitor/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    infra/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ethernet/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    infiniband/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    nvlink/02-devices_config.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ethernet/eth.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    infiniband/ib.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    nvlink/nvsw.csv -----> DAY0-Prepare/<项目>/02-devices_config.csv
    ethernet/monitor/eth.csv -----> ../eth.csv
    infiniband/monitor/ib.csv -----> ../ib.csv
    nvlink/monitor/nvsw.csv -----> ../nvsw.csv
    infiniband/bringup/xdr-upgrade/ib.csv -----> ../../ib.csv
    infiniband/bringup/xdr-initial-setup/ib.csv -----> ../../ib.csv
    infiniband/bringup/ufm-setup-upgrade/ib.csv -----> ../../ib.csv
  p2p-to-validation.py 用 P2P 目录下这份清单的设备名选出 P2P 的名称列。
  监控、ZTP、backup、Feedback 统一读取本文件并按 type 过滤；infra 只选择 type=server 或
  type=server_mgmt 行；type=server_ufm 不进入 infra 部署，只由
  infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade.py 和监控处理，其余脚本直接跳过服务器行。

02-dhcp-subnet_config.csv
  作用：ISC DHCP 的 shared-network、subnet、地址池、网关，以及每个网段的 ZTP 声明。
  ZTP 声明是每行的三列：
    ztp_service_ip   本网段使用的 ZTP 服务地址，即管理服务器在这个网络上的地址。load 从
                     启用 ZTP 的各行推导 service_ip，用它判断本机是否具备这些地址（不具备
                     时只生成制品），并按地址和网段选择 DHCP 监听接口；设备拿到的 URL 不用
                     它拼，见 01-global.yaml 的 common.mgmt.http.address。
    cumulus_profile  oob、oobofoob 或 none：oob 下发 ztp-bootstrap_oob.sh，oobofoob 下发
                     ztp-bootstrap_oobofoob.sh，none 不给 Cumulus 下发 bootstrap。
    nvos_ztp         yes 或 no：yes 时给 NVOS 下发 ztp.json。
  启用了 cumulus_profile 或 nvos_ztp 的行必须填写 ztp_service_ip；两者都不启用时
  ztp_service_ip 必须为空。同一个 cumulus_profile 只能对应一个 ztp_service_ip，NVOS 的
  ztp.json 也只能有一个服务地址。旧的 URL 列 bootfile_name、cumulus_provision_url
  已经废弃，表头里出现就会被拒绝。
  AIR 与 Production 按网络类别共用上述两份 bootstrap，不再使用单独的
  ztp-bootstrap_air.sh。
  可能创建的连接：
    ztp/config/isc-dhcp-server/02-subnet_config.csv -----> DAY0-Prepare/<项目>/02-dhcp-subnet_config.csv

p2p.xlsx
  作用：P2P 拓扑 Excel 的固定入口，供 AIR、LLDPq 和 CVT 相关流程使用。
        客户版本只放项目根目录。自动选择候选须为非空普通 XLSX，文件名含 p2p
        （忽略大小写）；显式 --p2p-file 可钉选项目根目录内任意非空普通 XLSX，
        文件名无需包含 p2p。
        p2p.xlsx 是上次选定版本的相对软链接，不是参与比较的候选。
        唯一候选无需版本号；多候选各须有恰好一个 vX.Y 类版本号，再按数字版本、
        可选有效日期、最后 mtime 排序；平局拒绝猜测。
        无 --p2p-file 时调和到最新；--p2p-file=<根目录文件名> 可刻意钉选旧版，
        命令会提示最新文件和改名建议。IP Assignment 不参与自动选择。
        原有非空普通 p2p.xlsx 会先无覆盖归档为 p2p-original-时间戳[-N].xlsx；
        无原子无覆盖移动能力时停止，绝不覆盖客户字节。
        项目下的 p2p/ 子目录不是 P2P 候选位置：自动选择和 --p2p-file 都只看项目根目录
        （见 p2p/README.txt）；p2p/ 可以用来存放 P2P 相关资料。
        例外：用户自己建的 p2p.xlsx -> p2p/<工作簿>.xlsx 链接优先，setup 不改写它
        （见下文「用户链接输入」）。
        升级后旧版 current-release 即使 schema_version=1 也缺少真实来源绑定；
        须对当前项目重新正式 load，生成同时绑定真实文件名与摘要的新记录后才能手工部署。
  可能创建的连接：
    ztp/config/cumulus/template/P2P/p2p.xlsx -----> DAY0-Prepare/<项目>/p2p.xlsx
    ztp/config/nvos/template/P2P/p2p.xlsx    -----> DAY0-Prepare/<项目>/p2p.xlsx
    ethernet/p2p.xlsx                        -----> DAY0-Prepare/<项目>/p2p.xlsx
    infiniband/p2p.xlsx                      -----> DAY0-Prepare/<项目>/p2p.xlsx
    nvlink/p2p.xlsx                          -----> DAY0-Prepare/<项目>/p2p.xlsx
    infiniband/bringup/xdr-initial-setup/p2p.xlsx -----> ../../p2p.xlsx
    infiniband/bringup/ufm-setup-upgrade/p2p.xlsx -----> ../../p2p.xlsx
  P2P 派生结果统一写入项目的 99-output-p2p/，链接见下文 99-output-p2p/。

03-air-topology-policy.json（可选）
  作用：只调整由 P2P 派生的 AIR 拓扑，不改写原始 P2P、LLDPQ DOT 或生产设备配置。
        当前支持按 inventory 类型精确限制 AIR 节点，以及用完整的设备名和端口匹配一条
        已知错误链路后替换为获准链路。规则必须唯一命中；零命中、多命中、未知字段、
        自连接或端口冲突都会 fail closed。没有该文件时维持严格默认行为。
  load 会把 01-global.yaml 的 Cumulus 版本显式传给 AIR 转换器；例如版本 5.18 会生成
  cumulus-vx-5.18 节点。策略文件存在时，其 SHA-256 也进入统一 release，manual-ztp
  preflight 会检查新增、删除或内容漂移，防止发布后静默改变 AIR 拓扑。
  模板不放这个文件：放了空文件就会被当成输入读取。不创建运行时软链接。

04-air-mini-devices.txt（可选）
  作用：AIR 小拓扑（load --mini）的客户设备清单，只影响 AIR 的 DOT/JSON，不影响
        Production。每行一个设备名，# 开头的行是注释。文件可以不存在，这时只保留
        生成器选出的最小代表集。
  load --mini 不带值时读这个固定名；也可以用 --mini=<文件名>.txt 指定项目根目录下的
  其他 .txt，生成后那个文件会被换成指向本文件的相对链接。--mini 只用于 AIR/eth，并要求
  03-air-topology-policy.json 里有 mini_sampling。生成器把本文件改写成
  [minimum-required] 和 [customer-provided] 两段，客户写的设备保留在后一段；选择报告逐台
  写明入选原因。文件内容的 SHA-256 进入统一 release。
  模板不放这个文件，理由同 03。不创建运行时软链接。

04-device-aliases.csv（可选）
  作用：设备别名表（G14-1）。文件可以不存在，也可以只有表头；有错误的行只报错并被过滤，
        后面的程序继续使用合法的数据（owner 2026-11-04）。
  setup 先把三个网络的 monitor 目录链接好；链接悬空不算错误。
  可能创建的连接：
    ethernet/monitor/04-device-aliases.csv -----> DAY0-Prepare/<项目>/04-device-aliases.csv
    infiniband/monitor/04-device-aliases.csv -----> DAY0-Prepare/<项目>/04-device-aliases.csv
    nvlink/monitor/04-device-aliases.csv -----> DAY0-Prepare/<项目>/04-device-aliases.csv

laptop.pub
  作用：项目电脑 SSH 公钥。本机 setup 从本机 ~/.ssh 选取或必要时生成公钥，
        安全准备真实项目的 laptop.pub；server-delegated setup 不读取服务器 HOME，
        而是校验项目中已有的两把不同、非空的电脑和管理服务器公钥。
  setup 在 4 个公钥目录里各建一条同名链接；这 4 个目录都是真实目录，不是链接：
  可能创建的连接：
    ztp/config/publickey/laptop.pub   -----> DAY0-Prepare/<项目>/laptop.pub
    ethernet/publickey/laptop.pub     -----> DAY0-Prepare/<项目>/laptop.pub
    infiniband/publickey/laptop.pub   -----> DAY0-Prepare/<项目>/laptop.pub
    nvlink/publickey/laptop.pub       -----> DAY0-Prepare/<项目>/laptop.pub
  使用要求：不可将仓库模板中的 0 字节 laptop.pub 当作项目电脑身份或发布文件；
        管理服务器 load 不得以服务器自己的 HOME 公钥覆盖电脑身份。
  bringup 工具经仓库内固定桥接 infiniband/bringup/xdr-initial-setup/publickey、
  infiniband/bringup/ufm-setup-upgrade/publickey（都指向 ../../publickey）读取
  infiniband/publickey/。

mgmt-server.pub 和 .management-pubkeys
  作用：`mgmt-server.pub` 为空时是管理服务器公钥占位文件；非空时保存管理服务器的真实公钥。
  `.management-pubkeys` 明确记录该路径由 load 流程管理。
  macOS 配置准备会保留这个计划路径但不发布空文件；Linux 管理服务器正式 load 时使用
  管理服务器端准备并校验公私一致的独立 Ed25519 公钥注入它，再发布到 ZTP。
  不要手工复制项目电脑公钥到这个文件，两把 key 必须不同。
  非空时与 laptop.pub 一样，在 4 个公钥目录里各有一条同名链接（见下一条）。

其他 *.pub（可选约定）
  作用：项目可以增加其他 SSH 公钥，setup 会在 4 个公钥目录里逐个建立同名链接。
  可能创建的连接：
    ztp/config/publickey/<原文件名>.pub -----> DAY0-Prepare/<项目>/<原文件名>.pub
    ethernet/publickey/<原文件名>.pub   -----> DAY0-Prepare/<项目>/<原文件名>.pub
    infiniband/publickey/<原文件名>.pub -----> DAY0-Prepare/<项目>/<原文件名>.pub
    nvlink/publickey/<原文件名>.pub     -----> DAY0-Prepare/<项目>/<原文件名>.pub
  只有非空且格式合法的公钥才会成为运行时发布文件。

README.txt
  作用：本说明文件。它也会被复制到每个真实项目，但不会创建运行时软链接。

用户链接输入
  02-devices_config.csv、*.pub 可以是指向项目外文件的链接（例如 laptop.pub -> 自己的
  公钥）；P2P 用 p2p.xlsx -> p2p/<工作簿>.xlsx，p2p/ 本身可以链到外部资料目录。
  setup、tar-for-upload、sync-code 各在入口跟随链接一次，按真实文件校验：目标不存在或
  不是非空普通文件时报错停止，setup 不顺着链接往项目外写。tar-for-upload 把链接内容作为
  同名普通文件带进上传包（P2P 为去图后的根目录工作簿），并在
  03-linked-inputs.json 里记下每个链接、真实路径和 sha256；sync-code 用单文件
  --copy-links 推送这些内容，不推送指向项目外的 p2p.xlsx、p2p/ 链接（P2P 用
  tar-for-upload 带走）。
  01-global.yaml 和 02-dhcp-subnet_config.csv 仍必须是普通文件，不接受链接。
  02-devices_config.csv 的链接代替已退役的 setup --csv-dir。


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
  模板自带 bringup/ 下的日志目录：ndr-upgrade-logs/、xdr-initial-setup-logs/、
  xdr-upgrade-logs/、ufm-setup-upgrade-logs/，以及 xdr-upgrade-v2-logs/。
  xdr-upgrade-v2-logs/ 是 upgrade2.py 按项目运行时的证据目录，setup 不为它建链接；
  日志统一改用 xdr-upgrade-logs/ 以后（A6）去掉。
  只有用到相应 bringup 工具的项目才会往这些日志目录写东西，链接悬空不算错误。
  可能创建的连接：
    ztp/config/nvos/template/99-output-ib_nvl -----> DAY0-Prepare/<项目>/99-output-ib_nvl
    DAY0-Prepare/<项目>/99-output-ib_nvl/latest -----> <最新完整发布目录>
    ztp/config/nvos/latest_yaml -----> ztp/config/nvos/template/99-output-ib_nvl/latest
    infiniband/bringup/ndr/ndr-upgrade-logs -----> DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/ndr-upgrade-logs
    infiniband/bringup/xdr-initial-setup/xdr-initial-setup-logs -----> DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/xdr-initial-setup-logs
    infiniband/bringup/xdr-upgrade/xdr-upgrade-logs -----> DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/xdr-upgrade-logs
    infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade-logs -----> DAY0-Prepare/<项目>/99-output-ib_nvl/bringup/ufm-setup-upgrade-logs
  latest_yaml 是固定 HTTP 入口；项目内 latest 优先指向同一时间戳的 -combine 目录。

99-output-dhcp/
  作用：保存 c1-generate_dhcp.py 生成的 DHCP 主配置、设备 hosts 文件和发布清单。
  可能创建的连接：
    ztp/config/isc-dhcp-server/dhcpd.conf -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd.conf
    ztp/config/isc-dhcp-server/dhcpd_eth.hosts -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd_eth.hosts
    ztp/config/isc-dhcp-server/dhcpd_ib.hosts -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd_ib.hosts
    ztp/config/isc-dhcp-server/dhcpd_nvl.hosts -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcpd_nvl.hosts
    ztp/config/isc-dhcp-server/dhcp-release-manifest.json -----> DAY0-Prepare/<项目>/99-output-dhcp/dhcp-release-manifest.json

99-output-backup/
  作用：保存 yaml-collect.py 拉取的设备配置、采集日志和差异报告。
  可能创建的连接：
    ztp/backup/yaml-backup -----> DAY0-Prepare/<项目>/99-output-backup

99-output-p2p/
  作用：保存 P2P 转换产生的 *-lldpq.dot、*-air.dot、上传 NVIDIA AIR 的 p2p-air.json（固定名）、
       HTML 或其他拓扑派生文件，以及拓扑分析器的报告。
  可能创建的连接：
    ztp/config/cumulus/template/P2P/output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    ztp/config/nvos/template/P2P/output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    ztp/config/isc-dhcp-server/p2p-air.json -----> DAY0-Prepare/<项目>/99-output-p2p/p2p-air.json（只有 AIR 项目有，悬空不算错误）
    monitor/99-output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    ethernet/monitor/99-output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    infiniband/monitor/99-output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p（IB 链路校验读 CVT、写报告）
    nvlink/monitor/99-output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    tools/lldp-analyze-tool/99-output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
    tools/ibdiagnet-analyze-tool/99-output-p2p -----> DAY0-Prepare/<项目>/99-output-p2p
  90-c2-generate_configs.py 直接扫描上述 output-p2p 目录，不再创建单文件 DOT 软链接。

99-output-monitor/
  作用：保存 Ethernet/SPX、InfiniBand、NVLink 的采集结果、链路结果和 cron 日志，
        以及 issue tracker 的准备数据和日志。
  模板自带 ethernet/、infiniband/、nvlink/，以及 infiniband/ufm-info/、
  infiniband/ufm-ibdiagnet/，每个目录只有一个 .gitkeep。setup 补建其余项目子目录：
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
    99-output-monitor/infiniband/ufm-info/
      保存 UFM 的设备状态和 HA 状态快照。
    99-output-monitor/infiniband/ufm-ibdiagnet/
      保存经 UFM 采集的 ibdiagnet（降级时为 iblinkinfo）结果和运行记录。
    99-output-monitor/infiniband/cronjob.log
      保存 InfiniBand 定时采集任务日志。
    99-output-monitor/nvlink/nvsw-info/
      保存 NVLink Switch 设备信息采集结果。
    99-output-monitor/nvlink/nvsw-link/
      保存 NVLink 链路采集和检查结果。
    99-output-monitor/nvlink/cronjob.log
      保存 NVLink 定时采集任务日志。
    99-output-monitor/<网络>/<类型>-status/
      保存设备状态数据（G14-2），ethernet 下为 eth-status，infiniband 下为 ib-status
      和 ufm-status，nvlink 下为 nvsw-status。

  可能创建的连接包括：
    ethernet/monitor/eth-info -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/eth-info
    ztp/config/cumulus/template/P2P/eth-info -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/eth-info
    ethernet/monitor/spx-link -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/spx-link
    ethernet/monitor/eth-status -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/eth-status
    ethernet/monitor/cronjob.log -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet/cronjob.log
    monitor/ethernet -----> DAY0-Prepare/<项目>/99-output-monitor/ethernet

    infiniband/monitor/ib-info -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ib-info
    ztp/config/nvos/template/P2P/ib-info -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ib-info
    infiniband/monitor/ib-link -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ib-link
    infiniband/monitor/ufm-info -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ufm-info
    infiniband/monitor/ufm-ibdiagnet -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ufm-ibdiagnet
    infiniband/monitor/ib-status -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ib-status
    infiniband/monitor/ufm-status -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/ufm-status
    infiniband/monitor/cronjob.log -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband/cronjob.log
    monitor/infiniband -----> DAY0-Prepare/<项目>/99-output-monitor/infiniband

    nvlink/monitor/nvsw-info -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink/nvsw-info
    nvlink/monitor/nvsw-link -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink/nvsw-link
    nvlink/monitor/nvsw-status -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink/nvsw-status
    nvlink/monitor/cronjob.log -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink/cronjob.log
    monitor/nvlink -----> DAY0-Prepare/<项目>/99-output-monitor/nvlink

    monitor/99-output-monitor -----> DAY0-Prepare/<项目>/99-output-monitor（issue tracker 的准备数据和日志）
    tools/lldp-analyze-tool/99-output-monitor -----> DAY0-Prepare/<项目>/99-output-monitor

  各网络目录下的 monitor 链接供采集脚本写入当前项目；http/monitor/ 下的三个
  类型目录链接供 HTML 汇总页面读取相同数据。设备清单不再复制或链接到上述项目
  输出子目录，而是统一使用 monitor/02-devices_config.csv（见 02-devices_config.csv）。

99-output-ztp/
  作用：保存 12-ztp-monitor.py 按次生成的 ZTP 状态快照、report.json 和
        latest 发布链接。目录作为完整项目模板的空骨架保留，运行数据
        由 ZTP 监控流程写入，不在 upload/sync 部署时传输。
  可能创建的连接：
    ztp/status -----> DAY0-Prepare/<项目>/99-output-ztp
    monitor/ztp-status -----> ../ztp/status
    DAY0-Prepare/<项目>/99-output-ztp/latest -----> <最新完整 ZTP 状态目录>

99-output-infra/
  作用：保存 infra 部署（deploy_infra.py、infra-setup.py）按项目归档的日志。
  可能创建的连接：
    infra/logs -----> DAY0-Prepare/<项目>/99-output-infra

99-output-bringup/
  作用：一站式 bringup 的状态目录（R-012 BU0.5）。模板里还没有这个目录，R-012 落地时补；
        setup 先把链接建好。
  可能创建的连接：
    infiniband/bringup/99-output-bringup -----> DAY0-Prepare/<项目>/99-output-bringup

已不再使用的输出目录：
  99-output-ufm/ 原来对应已退役的 D-70 UFM 采集链。v3.1.1 起 setup 不再建这个目录和
  monitor/99-output-ufm 链接（R-013）；UFM 数据写在 99-output-monitor/infiniband/ufm-info/、
  ufm-ibdiagnet/。已有项目里的旧 99-output-ufm/ 不会被改动。


三、维护约束
------------

1. template 中不要放项目生成结果、真实监控数据或设备备份。
2. 修改 template 不会覆盖既有项目的同名文件，只会补齐缺失项。
3. 严格校验会拒绝未准备的 P2P 工作簿和所需镜像；公钥按本机 setup 与 Linux load
   的双身份流程准备、校验，不能把模板空公钥发布为运行时身份。
4. template 和项目根目录只保留空 `.bin` 名称占位符；真实镜像只放在 http/image/ 中。
5. 新增模板文件时，应在本 README 中补充用途、维护责任和可能的软链接。
6. 本 README 的「可能创建的连接」与 tools/project_contract.py 的链接规格表逐条一致，
   由 test_cases/test_setup_link_spec_contract.py 核对；规格表增删行时同步修改本文件。
