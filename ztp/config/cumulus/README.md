# Cumulus 配置发布

## 在整体架构中的位置

本目录位于 Cumulus 生成器与设备 HTTP 下载之间：template 生成 hostname YAML，发布脚本完成
结构校验、Production/AIR 配对、MAC 映射和 latest 原子切换，bootstrap 只消费已发布入口。
setup/load 是唯一推荐编排入口；完整场景见根目录 `USER_MANUAL.md`。

本目录负责保存 Cumulus 默认配置、生成设备 YAML 的工作模板，以及将主机名配置发布为
按 MAC 可访问的 `latest_yaml`。

## 目录与文件

- `default.yaml`：缺少设备专属配置时使用的最小默认配置。
- `default_5.16.5.yaml`：已有的 Cumulus 版本专属默认补丁配置。目标版本没有同名文件时，bootstrap 自动回退到 `default.yaml`。
- `ar_profile_custom.conf`：SPX 自适应路由配置。
- `template/`：配置生成器、Jinja 模板、设备 CSV 和输出链接。
- `d-hostname2mac.py`：校验输出 YAML、创建 MAC 链接并原子更新项目输出根的 `latest`。
- `latest_yaml`：固定指向 `template/99-output/latest` 的 ZTP HTTP 入口。

## 生成与发布

```bash
cd template
python3 90-c2-generate_configs.py -y

cd ..
python3 d-hostname2mac.py -y template/99-output/<时间戳>
```

发布时会校验目录中已有的主机 YAML，并确保每个已创建的 MAC 链接都指向正确配置。
CSV 中没有专属 YAML 的设备会明确告警，并在 ZTP 时回退到默认配置。

每次发布 Cumulus 配置前，`d-hostname2mac.py` 比较 `default*.yaml` 与
`template/01-global.yaml` 的修改时间。默认配置不比全局配置新时，脚本会保留默认配置
中的权限角色骨架，并同步合并后的 ETH `system` 设置；DNS/NTP server 列表会转换成
NVUE mapping。更新采用同目录临时文件原子替换，任一文件解析或写入失败都会中止发布。

同时间戳存在 `_with_desc` 时自动优先使用。脚本从统一 `02-devices_config.csv` 读取
Production 与 `type=air` 记录，校验每条 AIR 记录都能唯一匹配同名 Production 记录，
并在 `_combine` 中让两套 MAC 分别指向本环境 YAML。找不到 Production 对应项的 AIR 防火墙/服务器不创建专属 MAC
链接，设备通过 DHCP range 和 `default.yaml` 启动。发布前会对整个批次执行严格 YAML
重复-key、MAC 目标和完整性门禁，通过后才原子更新 `latest_yaml`。所有交互等待时间为
15 秒；采用 `_with_desc` 发布后，原始 `<时间戳>/` 目录直接删除且不打包。

NVOS 目录中的 `d-hostname2mac.py` 是此脚本的软链接，共享同一套发布实现。

### Schema v2 bond 与模板能力

Schema v2 会在写入 `91-devices.yaml` 和渲染 Jinja 之前，按设备模板检查已归一化的
`bond_type` 完整组合；不是分别检查每一个 mode。组合白名单如下（`{}` 表示没有 active
bond）：

- `border`：`{}`、`{localbond}`、`{evpn_multihoming}`、
  `{localbond,evpn_multihoming}`、`{mlag}`、`{localbond,mlag}`。
- `oob-core`、`oob-leaf`、`tan-cp-leaf`、`tan-hps-leaf`、`tan-leaf`、
  `tan-su-leaf`：`{}`、`{localbond}`、`{evpn_multihoming}`、
  `{localbond,evpn_multihoming}`。
- `oob-su-leaf`、`oob-rack-tor`、`oobofoob-leaf`、`tan-cp-1gleaf`：
  `{}` 或 `{localbond}`。
- `tan-spine`、`oob-su-spine`：只能是 `{}`。
- `oobofoob-spine`：只能是 `{mlag}` 或 `{localbond,mlag}`；MLAG 必须存在，
  EVPN-MH 不受支持。

MLAG 能力只从这张组合表推导，目前恰好是 `border` 和 `oobofoob-spine`。同一设备仍禁止
MLAG 与 EVPN-MH 共存。非 `NA` 的 `bond_ports` 不允许 `|` 两侧或中间出现空分组；每个声明
的 bond 都必须被有效 VLAN attachment 使用，否则在写入中间模型前失败。`bond_ports=NA`
时遗留的 `bond_type`/`bond_mac` 保持兼容告警并视为完全 inactive：不会生成 bond、全局
multihoming 或 uplink tracking。

渲染后、写入输出目录前还有逐 bond 语义门禁：local bond 必须保留完整成员和 bridge
attachment；MLAG 必须在同名 bond 上生成匹配 id/state，并同时具备 peerlink 与 top-level
MLAG；EVPN-MH 必须在同名 bond 上生成匹配 local-id、MAC、enabled state 和全局 policy。
任何 bond 缺失、成员/attachment 不符或冗余证据落在其他 bond 都会删除 staging 输出并
停止发布。不受支持的组合会报告 CSV 行号、hostname、template、归一化组合及允许组合。
Schema v2 生成文件还必须恰好包含一个 mapping-valued 顶层 `set` operation；任何
`set: null`、scalar/list 值、零个或多个 mapping `set` 都会在扫描冗余证据前失败并删除
staging。原因是 `nv config replace` 只消费生成文件中的第一个 `set`，后续 `set` 即使语法
可接受也可能被忽略，不能用后续块的证据证明实际应用的第一块。该限制只适用于生成器可推导
active-bond 描述符的 Schema v2 配置；legacy/source receipt 仍保留已有的多 `set` 聚合兼容。
不要通过复制其他角色的 Jinja 来绕过检查；新增模式前必须先确定成员形状、LACP、
MTU/FEC、Bridge/STP 与 EVPN 语义。

## 架构边界与用例

`template/90-c2-generate_configs.py` 负责“hostname → YAML”，本目录 `d-hostname2mac.py` 负责
“hostname YAML → HTTP 可按 MAC 获取的发布批次”。生成和发布刻意分离：前者可以产生待审核
目录，后者必须校验全批并原子更新 `latest`。bootstrap 只消费发布入口，不扫描历史目录。

常见用例包括首次生成、CSV/global 修改后的重生成、AIR simulation 与 Production 批次合并、
以及只更新 default 配置后的重新发布。故障时分别检查 generator log、批次 YAML、MAC 链接、
`.published-complete`、`latest` 目标和 HTTP 响应；不要直接修改 `latest_yaml` 内部文件。

P2P 设备类型由 `template/P2P/01-inventory.log` 的 section 顺序决定：第一个匹配 section
胜出，不按 glob 长度猜测优先级。共享解析器位于 `ztp/config/topology_rules.py`，Cumulus、
NVOS 和 LLDP 分析使用同一规则；PDU 必须保持早于 `Eth-SW`，`SMC-B300` 必须保持早于
`GB300-GPU`，因此同时含 `gpusrv` 与 `GPU` 的名称仍归类为 `SMC-B300`。
