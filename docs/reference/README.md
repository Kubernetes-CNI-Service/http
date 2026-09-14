# 参考索引

## 稳定入口

| 工作 | 入口 |
|---|---|
| 项目创建/激活 | `DAY0-Prepare/01-a-setup.py` |
| Native/systemd 部署 | `DAY0-Prepare/11-load.py` / `13-unload.py` |
| Docker/Supervisor 部署 | `infra/docker/deploy.sh` |
| 初次受控发布 | `tools/tar-for-upload.py --deploy` |
| 增量更新 | `tools/sync-code.py` |
| 项目结果回收 | `tools/tar-for-download.py` / `import-from-download.py` |
| 只读诊断 | `tools/collect-ztp-diagnostics.py` |
| 本地测试治理 | `test_cases/run_related_tests.py` |
| VM 只读验收 | `test_cases/run_vm_validation.py` |

完整参数先运行 `<script> --help`，再读脚本所属模块 README。根 README 的自动表提供所有模块
文档入口，不重复保存模块正文。

## 支持平台

- 项目电脑配置准备：Python 3.9+；macOS 不运行 Apache、ISC DHCP 或 systemd。
- Native 管理服务器：实现支持的 Ubuntu 版本/架构以 `infra/README.md` 与脚本门禁为准。
- Docker 管理服务器宿主：Ubuntu 22.04 或 24.04 `amd64`/`arm64`，本机 rootful Linux Docker；
  容器镜像固定 Ubuntu 24.04。
- 离线 APT 仓库：OS 版本和 CPU 架构必须精确匹配，不跨平台复用。

## 制品身份合同

- upload：归档摘要、归档内 source manifest、受控 prewrite guard 和远端 owner 状态形成写入链。
- APT：同目录 `.deb`、`Packages`、`Packages.gz`、`repository.meta` 及依赖闭包共同构成可用仓库。
- Docker：source manifest、OCI tar 摘要、完整 immutable image ID、image metadata、live receipt 和
  container labels/binds 必须逐层一致。
- ZTP：parent/child release、输入 hash、DHCP staging、hostname/MAC YAML 和 published marker 必须
  属于同一代际。

缺少任一身份记录时应停止，不用文件名、tag、容器名或最近 mtime 猜测等价性。
