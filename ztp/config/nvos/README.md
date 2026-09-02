# NVOS 配置发布

## 在整体架构中的位置

本目录连接共享 NVOS 生成工作区与设备 HTTP 下载入口：生成器按 IB/NVL 分支写批次，发布脚本
校验后创建 MAC 链接并原子切换 latest，bootstrap 只读取已发布配置。setup/load 是推荐编排
入口；完整流程见根目录 `USER_MANUAL.md`。

本目录保存 NVOS 的默认 ZTP 配置和已发布设备配置入口。

- `default.yaml`：无设备专属配置时使用的默认配置。
- `disable-password-hardening.nv`：按需应用的 NVUE 命令片段。
- `d-hostname2mac.py`：复用 Cumulus 目录中的发布与完整性校验实现。
- `template/`：共享输入、生成器和项目输出目录链接。
- `template/99-output-ib_nvl/latest`：指向带 `.published-complete` 标记的最新发布目录。
- `latest_yaml`：固定指向 `template/99-output-ib_nvl/latest` 的 ZTP HTTP 入口。

```bash
cd template
python3 90-c2-generate_configs.py --branch ib -y
cd ..
python3 d-hostname2mac.py -y template/99-output-ib_nvl/<时间戳>-combine
```

发布器会校验 CSV 中预期的 IB/NVLink 主机配置和 MAC 链接；校验失败时不得更新
`latest_yaml`。

在标准 NVOS template 路径内可省略 `--branch ib`；`11-load.py` 会始终显式传入它。把共享
生成器复制到其他目录调试时不可依赖目录名推断分支。
