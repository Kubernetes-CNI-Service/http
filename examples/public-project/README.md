# 脱敏项目输入示例

本目录只演示三个项目输入文件的结构。所有地址均来自 RFC 5737 文档保留网段，MAC 均使用
本地管理地址；这些值不对应真实站点，也不能用于生产部署。

文件以 `.example` 结尾，避免 setup/load 把它们误认为已完成的项目输入：

- `01-global.yaml.example`：管理服务、交换机 common 配置和版本字段；Cumulus 密码登录显式锁定，
  IB/NVL 不提供密码字段。
- `02-devices_config.csv.example`：一台 Cumulus 示例设备和一台 NVOS 示例设备；保留 canonical
  模板的完整 10 组 EVPN 扩展列和等长数据行。
- `02-dhcp-subnet_config.csv.example`：三个独立 DHCP subnet，以及 Cumulus profile/NVOS ZTP
  分流字段。

## 使用前检查表

复制到私有、被 Git 忽略的 `DAY0-Prepare/<project>/` 后，至少替换：

- DNS、NTP、timezone、软件版本和 HTTP/ZTP 服务参数；
- 每个 subnet、range、gateway 和 ZTP service IP；
- 每台设备的 hostname、type、template、管理 IP/MAC、loopback、VLAN、BGP、bond 和 EVPN 字段；
- 本地策略要求的账号配置。优先使用 SSH 公钥；如必须启用密码，哈希只能保存在私有输入中；
- P2P 工作簿、设备镜像、公钥及其他站点输入。它们不属于本公开示例。

保留 CSV 的列顺序。`02-devices_config.csv` 前 11 列有固定顺序，`vrl` 必须紧跟
`peerlink_ports`，每组 EVPN 扩展字段固定为 11 列。多个 EVPN 组按相同顺序重复追加。

这些文件只用于说明和本机测试。运行 setup/load 前，应使用项目校验器检查私有副本，并在隔离
环境验证生成配置、DHCP 配置、身份映射和回滚流程。

## 示例值的安全语义

- `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24` 是文档保留网段；
- `02:00:00:...` 是本地管理、单播 MAC 示例；
- global 示例中的 `hashed-password: "'*'"` 是供现有 Jinja 模板安全渲染的带引号标量：global
  解析后的字符串有意携带一对单引号，生成文件得到合法的 `hashed-password: '*'`，最终 YAML
  解析值严格等于 `*`，表示密码登录被锁定；它不是密码哈希。该行为已使用真实配置生成器验证；
- 示例 DNS/NTP 地址不会提供真实服务；
- 示例不包含私钥、公钥、口令、token 或可复用密码哈希。
