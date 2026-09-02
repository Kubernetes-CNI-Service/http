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

## 架构边界与用例

`template/90-c2-generate_configs.py` 负责“hostname → YAML”，本目录 `d-hostname2mac.py` 负责
“hostname YAML → HTTP 可按 MAC 获取的发布批次”。生成和发布刻意分离：前者可以产生待审核
目录，后者必须校验全批并原子更新 `latest`。bootstrap 只消费发布入口，不扫描历史目录。

常见用例包括首次生成、CSV/global 修改后的重生成、AIR simulation 与 Production 批次合并、
以及只更新 default 配置后的重新发布。故障时分别检查 generator log、批次 YAML、MAC 链接、
`.published-complete`、`latest` 目标和 HTTP 响应；不要直接修改 `latest_yaml` 内部文件。
