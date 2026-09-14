# 部署模式与受控发布

generic image、项目 upload release、共享大制品和可选 project image 的独立边界、真实 CLI 与
`2026-12-vb-gb300` 场景矩阵见[《四类交付制品与 2026-12 部署流程》](BUNDLE_WORKFLOWS.md)。

## 先选运行模式（CUX-01）

运行模式一经选择，同一轮部署不得混用。两种后端共享项目输入和 release 合同，但生命周期入口
不同：

| 模式 | 唯一生命周期入口 | 服务管理 | 宿主限制 |
|---|---|---|---|
| Native/systemd | `DAY0-Prepare/11-load.py`、`13-unload.py` | systemd/cron | 由 infra 管理宿主 Apache/DHCP |
| Docker/Supervisor | `infra/docker/deploy.sh` | 容器内 Supervisor | 不运行宿主 load/systemctl，不修改 NIC/Netplan |

Native/systemd 的详细操作见私有工作区中的 `DAY0-Prepare/README.md`；
Docker/Supervisor 的完整命令和限制见 [`infra/docker/README.md`](../../infra/docker/README.md)。

两种后端都默认保护 `/monitor/monitor.html`。首次打开时使用固定用户名 `nvis` 或 `cumulus`
认证；canonical 控制 URL 与页面同在 `/monitor/` protection path，支持的浏览器会复用凭据，
因此后续操作不再弹出登录框。Apache 仍认证每个控制请求，旧 `/cgi-bin/*-control` 只是受认证的
升级兼容入口。Basic over HTTP 仅限隔离、ACL 保护的可信管理网，不等于完成 TLS。

## 部署位置 × 运行后端 × 操作类型

部署说明先确定文件和网络所在的位置，再选择唯一服务后端，最后选择首次发布、更新或恢复动作。
macOS 只做配置准备和全量测试，不安装或启动 Apache/ISC DHCP；即使 Mac 已连接 USB/UTP
adapter，也不能把 macOS 本身当作受支持的管理服务器。需要在本机接真实交换机时，adapter
必须直通给 Ubuntu VM，Service IP 也配置在该 VM 的 Linux 接口上。

| 部署场景 | 源码进入运行主机 | 唯一生命周期 | 同一 Service IP 换接口 |
|---|---|---|---|
| Mac 本机开发（不连接交换机） | 不传输；正式本机 load 生成并测试 | 不启动服务 | 不适用 |
| 本机 Ubuntu VM（adapter 直通） | direct upload/sync 或 VM 内已有工作树 | 在 Native 与 Docker 中二选一 | Native 完整 load；Docker `reload-network` |
| 可直连管理服务器 Native | `tar-for-upload --runtime native --deploy`；更新用 `sync-code --runtime native` | `11-load.py` | 重新执行完整 load |
| 可直连管理服务器 Docker 在线 build | `tar-for-upload --runtime docker --deploy`；更新用 `sync-code --runtime docker` | `deploy` 在线 build | `reload-network → health → status` |
| 可直连管理服务器 Docker 预构建镜像 | 先受控应用独立 upload release，再核验并导入 generic image bundle | `deploy-preloaded <IMAGE_ID>` | `reload-network → health → status` |
| 可信中转 Native | upload archive + 同版本 installer，经最终服务器 `--verify-only` 后受控应用 | `11-load.py` | 重新执行完整 load |
| 可信中转 Docker 在线 build | upload archive + 同版本 installer，显式 `--runtime docker` | `deploy` 在线 build | `reload-network → health → status` |
| 可信中转 Docker 预构建镜像 | 独立 upload、generic image、可选 shared bundle 和外部批准摘要 | 一次 `docker load` 后 `deploy-preloaded <IMAGE_ID>` | `reload-network → health → status` |

本机 Ubuntu VM 与远端 Ubuntu 管理服务器使用相同 Native/Docker 合同；VM 的 NAT 管理口不得被
误选为 ZTP listener。Docker image 不能替代 Native 的离线 apps 仓库：Native 无 Internet 目标
仍需与宿主 OS/架构匹配的 `apps/`，Docker 预构建 bundle 只解决容器镜像运行闭包。

中转环境不使用 `sync-code.py` 向最终服务器做未受管的二次转发。代码或项目输入变化后，应先在
项目电脑重新完成正式 load，再重新生成并中转新的 upload archive。Docker 更新先用现有 immutable
image 执行 compatibility verifier：普通 live 代码/数据变化可复用；只有 image-coupled 字节变化或
runtime contract 不兼容时，才要求在线 build 或重新构建并传输预构建镜像。

上述位置和后端还要分别覆盖首次部署、源码/输入更新、同一 Service IP 换接口、Service IP 地址值
改变、宿主/容器重启、事务中断恢复、多 Service IP/VLAN/DHCP relay、amd64/arm64 制品以及最终
物理交换机验收。动作选择见 [`docs/operations/README.md`](../operations/README.md)。

## 固定发布顺序

Native/systemd 的首次发布固定为：**本机正式 load → tar-for-upload → 管理服务器正式 load**；
代码或项目输入变化后的更新固定为：**本机正式 load → sync-code → 管理服务器正式 load**。
本机 macOS 正式 load 在生成前运行全量测试，并在成功后签发、复核与当前源码、测试、manifest
和执行环境绑定的证明。`tar-for-upload.py` 和 `sync-code.py` 只复核该证明，绝不自行执行全量
测试；证明缺失或过期时在打包和联网前停止。Linux 管理服务器 load 不运行开发测试。

```bash
# 项目电脑：首次发布或每次代码/输入修改后都先完整生成和测试
python3 DAY0-Prepare/11-load.py DAY0-Prepare/<project>

# 首次发布
python3 tools/tar-for-upload.py <project> \
  <user>@<mgmt-host> --runtime native --deploy

# 后续更新（与上面的首次发布命令二选一）
python3 tools/sync-code.py <project> \
  --host <user>@<mgmt-host> --runtime native

# 管理服务器：接收首次包或增量更新后再执行生产 load
ssh -t <user>@<mgmt-host> \
  'cd /var/www/html && sudo python3 DAY0-Prepare/11-load.py --start-services DAY0-Prepare/<project>'
```

本机 `--dry-run` 不生成文件也不运行全量测试，不能替代正式本机 load。不得在正式本机 load
成功后继续修改源码、测试或 manifest；一旦发生变化，旧证明失效，必须从本机 load 重新开始。

Native load 不传范围参数时默认同时生成并发布 Production 与 AIR。本轮只部署一侧时使用
`--air` 或 `--prod`；`--mini` 进一步裁剪 AIR 拓扑和 AIR 设备配置，并自动推导 AIR + Ethernet，
不要求重复写 `--air --switch eth`。它与显式 `--prod` 或 `--switch ib|nvl` 冲突时会在锁前
拒绝。单一范围下 `--ztp-monitor-scope auto` 自动继承；默认双环境生成后若启动 monitor，仍需
明确选择管理服务器实际可达的 `air` 或 `prod`。

平台范围使用 `--switch eth|ib|nvl`。不指定时处理全部平台；`--air` 未指定本项时默认选择
`eth`，因为当前 AIR 只模拟 Ethernet/Cumulus。单平台 load 只校验、生成、发布所选平台，并
事务化退役未选平台旧 `latest`；任何后续失败都恢复原链接。它是完整的选择性 release，
不是在保留其他平台旧发布的同时只刷新部分文件。

## 受控写入 live 树（CUX-03）

禁止对 live `/var/www/html` 手工执行 `tar`，也不得把 upload 归档直接解压、rsync 或复制到正在
服务的源码树。首次部署和更新都应从项目电脑运行经过全量门禁的受控入口：

```bash
# Native/systemd
python3 tools/tar-for-upload.py <project> \
  <user>@<mgmt-host> --include-images --runtime native --deploy

# Docker/Supervisor
python3 tools/tar-for-upload.py <project> <user>@<mgmt-host> --include-images --runtime docker --deploy
```

`--deploy` 使用归档内经来源 manifest 绑定的 `tools/deployment_prewrite_guard.py`，在共享
deployment lock 内验证或停止精确受管容器、建立 pending marker、拒绝不可信旧源码，再安全应用
归档并提交 owner 状态。没有 `--deploy` 时仅上传并核验归档，不修改 live 树；随后使用脚本输出的
`--deploy-uploaded <ARCHIVE>` 可复用同一份本地和远端 SHA-256 已核验归档，
不会重新打包、不会重新传输。禁止在管理服务器手工执行 `tar`；复用入口仍从项目电脑发起并使用
归档内绑定的 guard。

若项目电脑不能直连最终服务器，可信中转只能携带 upload archive 与同一归档中的
`tools/deploy-upload-archive.py`。在最终服务器以 root 私有目录、installer `0500`、archive
`0600` 安装后，先运行 `--verify-only`，再以相同 `--runtime native|docker` 正式执行。该入口
自动绑定 archive SHA-256、source manifest 和 embedded guard，并继续使用共享 deployment lock；
禁止手工解压到 live 树。此处“可信中转”不是制品签名：installer 与 upload archive 一起被恶意替换
时，必须依赖组织批准的外部摘要/签名发现。
后续小范围源码/
输入更新也必须显式选择同一 runtime：

```bash
python3 tools/sync-code.py <project> --host <user>@<mgmt-host> --runtime native
python3 tools/sync-code.py <project> --host <user>@<mgmt-host> --runtime docker
```

省略 `--runtime` 会按 `native` 处理；Docker 更新因此不会建立 Docker owner 或执行容器 quiesce，
不能依赖默认值。两条路径都遵守同一 prewrite、锁和提交协议。

Docker tar/sync 成功写入会停止精确受管容器并提交 `stop + rebuild-required` 状态；下一步必须执行
`deploy` 重新 build/recreate。若已有与当前 live 源码身份链匹配且经验证的预加载镜像，则重新执行
`deploy-preloaded <IMAGE_ID>`。不得在 source write 后执行 `load`；单独的
`load → health/status` 仅用于没有 source write 且受管容器仍在运行，例如 `unload` 后重新激活、
失败或隔离恢复。同一 Service IP 在宿主接口间移动时使用
`reload-network → health → status`，不运行 load 或重新生成项目制品。

## Native/systemd

先用 `11-load.py --dry-run` 检查项目，再在明确允许时由同一 `11-load.py` 事务生成、发布并启动
宿主 Apache/DHCP/worker。独立生成器可用于开发预览，但不是生产激活入口。卸载使用
`13-unload.py`，不要手工删除 setup 链接或 DHCP 发布文件。

## Docker/Supervisor：在线构建

宿主必须是 Ubuntu 22.04 或 24.04、同架构 rootful Docker，且 ZTP service IP 已由既有网络管理
配置；容器镜像和容器内运行态仍固定 Ubuntu 24.04。
完成受控 upload 后只按 [`infra/docker/README.md`](../../infra/docker/README.md) 执行首次在线：
`init → doctor → deploy → status`。`deploy` 已包含 build/recreate、统一 load、激活和
health-check，不能再重复运行 load。宿主 TCP 80/UDP 67 冲突必须由管理员确认来源；wrapper
只报告，不会停用宿主服务。

Docker 将同一选择写入 `infra-runtime.conf`：AIR simulation 使用
`HTTP_ZTP_SCOPE=air`、`HTTP_ZTP_SWITCH_SCOPE=eth`、`HTTP_ZTP_MINI=enabled`；Production 默认
使用 `prod`、`all`、`disabled`。wrapper 会把它们转换成真实 load 的
`--deployment-scope/--switch/--mini` 参数，并要求 parent release、activation marker 与 health
检查保持同一身份；修改这些值后必须重新 `deploy`，不能在旧容器上直接 `load`。
首次 AIR mini 可直接执行
`sudo ./infra/docker/deploy.sh init --project <project> --scope air --mini` 原子生成该私有文件；已有
配置时命令拒绝覆盖。Production 使用 `--scope prod` 并按需追加 `--switch`。

## Docker/Supervisor：离线预加载

Docker generic image 是稳定的 Ubuntu 24.04 infra/control-plane 层；upload archive 是可独立演进的
live 代码与项目数据 release。联网同架构构建端使用
`deploy.sh image-export /root/<generic-bundle>`；`build-export` 只是兼容别名。generic bundle 只输出
`http-ztp-ubuntu-24.04.tar`、`image-metadata.json` 和 `SHA256SUMS`，不读取项目或 runtime 配置，也
不携带 upload、交换机镜像、apps 或 firmware。

项目电脑另用 `tar-for-upload.py --runtime docker --relay-bundle <directory>` 生成 upload archive、
matching installer、upload metadata 和摘要；按需再独立生成 shared-artifact bundle。目标端分别
执行各目录的 `sha256sum --check SHA256SUMS`，由 upload installer verify/apply release，再只运行
一次 `docker load --input http-ztp-ubuntu-24.04.tar`。`deploy-preloaded` 独立核对 live 全树自己的 manifest，并要求
live `runtime-contract.json` 兼容 image contract 且 image-coupled 控制器/template 字节匹配；普通
live 代码或项目数据更新可复用原 image，coupled 字节变化必须重建。导入后只把完整
`sha256:...` 传给 `deploy-preloaded`，不得用可重打标 tag 代替。
首次离线：`init → doctor → deploy-preloaded <IMAGE_ID> → status`；该动作同样已包含统一 load、
激活和 health-check。它成功后不得再追加一次 load。

一次成功导入后，后续失败应从已完成 checkpoint 继续诊断。不要为重试再次执行 `docker load`、
再次覆盖 upload、改变 NIC/Netplan，或删除身份不匹配的同名容器。只有镜像、live 来源和受管标签
全部通过，wrapper 才允许替换受管容器。
