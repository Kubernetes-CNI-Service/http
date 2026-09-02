# Infra 离线 APT 仓库

## 在整体架构中的位置

`apps/` 是项目无关的共享制品层，不属于任何 `DAY0-Prepare/<project>/99-output-*`。管理服务器
执行 `infra/infra-setup.sh --mgmt --all` 时为本机 Ubuntu 版本和架构建立仓库；Client 由
`deploy_infra.py` 优先通过 HTTP 使用它，无 HTTP 时才回退 Internet。完整部署场景见
根目录 `USER_MANUAL.md`“场景八”。

本目录由管理服务器上的 `infra/infra-setup.sh --mgmt` 生成/更新，使无 Internet 的
client 可以通过 HTTP 安装 setup 所需包及完整依赖。仓库必须同时按 Ubuntu 版本和
CPU 架构隔离，不再在 `apps/` 根目录混放 deb：

```text
apps/
├── ubuntu-24.04/
│   ├── amd64/{*.deb,Packages,Packages.gz}
│   └── arm64/{*.deb,Packages,Packages.gz}
└── ubuntu-22.04/                 # 只在对应系统上构建后出现
    ├── amd64/{*.deb,Packages,Packages.gz}
    └── arm64/{*.deb,Packages,Packages.gz}
```

client 会探测：

```text
http://<mgmt>/apps/ubuntu-<VERSION_ID>/<amd64|arm64>/Packages.gz
```

当前 Ubuntu 24.04 的 amd64/arm64 仓库已分开生成，`Architecture: all` 包在两个目录
中均可用。`Packages` 与 `Packages.gz` 必须与同目录 deb 同步；手工增删包后不要只
复制 deb，应在对应系统/架构的管理服务器上重跑：

```bash
sudo ./infra/infra-setup.sh --mgmt --all
```

`tar-for-upload.py --include-apps` 可把现有仓库带到管理服务器；默认 upload/sync
不传输该大型目录。
