# 四类交付制品与 2026-12 部署流程

本文是四类 bundle 的边界和操作入口清单。四类制品分别生成、分别校验、分别传输；除可选的
project image 外，不存在“一个 bundle 自动包含另外几个 bundle”的隐式关系。示例项目固定为
`2026-12-vb-gb300`，命令中的主机、端口、目录和完整 `sha256:` ID 需要替换为实际值。

## 四类 bundle 一览

| ID | 制品 | 生成入口 | 包含 | 明确不包含 |
|---|---|---|---|---|
| `BUNDLE-1-GENERIC-IMAGE` | 通用开发镜像 | `infra/docker/deploy.sh image-export` | Ubuntu 24.04 项目无关 Docker image、image metadata、摘要 | 项目输入、upload release、交换机镜像、apps、firmware |
| `BUNDLE-2-UPLOAD-RELEASE` | 用户/项目 release | `tools/tar-for-upload.py --relay-bundle` | 精确项目 upload archive、匹配 installer、upload metadata、摘要 | generic image、shared artifacts、project image |
| `BUNDLE-3-SHARED-ARTIFACTS` | 共享大制品 | `tools/package-shared-artifacts.py` | 按项目选择的交换机镜像，以及显式选择的离线 apps/firmware | 源码和项目 release、Docker image |
| `BUNDLE-4-PROJECT-IMAGE` | 可选项目镜像 | `tools/package-project-image.py build` | 精确 upload release；可选嵌入一份匹配的 shared-artifact bundle | 可复用 generic image 的角色、日常增量更新流程 |

每个输出目录都必须整体传输并先执行其中的 `SHA256SUMS`。摘要用于发现传输损坏，不能替代组织
批准的来源签名或外部摘要。

仓库治理要求正式打包前先执行 `run_related_tests.py --all -v`，再执行
`run_related_tests.py --check --require-full`。当前 `tar-for-upload.py` 的正式路径（包括 `--relay-bundle`）会在
自身流程中复核 full-suite attestation；generic image、shared artifacts 和 project image 的生成 CLI
只核验各自 source/metadata 合同，不会替操作员运行或复核全量测试。

## `BUNDLE-1-GENERIC-IMAGE`：项目无关的通用开发镜像

在联网、同 CPU 架构的 Ubuntu 22.04/24.04 rootful Docker 主机上，从已冻结
`deployment-source-manifest.json` 的源码树执行：

```bash
sudo ./infra/docker/deploy.sh image-export /root/http-ztp-generic-amd64
```

`build-export` 只是 `image-export` 的兼容别名。两者都不读取
`infra-runtime.conf`，不选择项目，不运行 load，也不创建、停止或激活服务容器。输出严格只有：

- `http-ztp-ubuntu-24.04.tar`
- `image-metadata.json`
- `SHA256SUMS`

因此 generic image 可以由开发者独立构建和复用；用户仍需用 `BUNDLE-2-UPLOAD-RELEASE` 单独发布
源码与项目输入。目标端必须先核对摘要并只导入一次：

```bash
cd /root/http-ztp-generic-amd64
sha256sum --check SHA256SUMS
sudo docker load --input http-ztp-ubuntu-24.04.tar
```

随后从 `image-metadata.json` 取得完整、小写 `sha256:<64-hex>`，在 upload release 已受控安装、
runtime 已 `init` 后使用 `deploy-preloaded <IMAGE_ID>`。不能用 tag 代替 immutable ID。

## `BUNDLE-2-UPLOAD-RELEASE`：独立用户/项目 release 与 installer

直连目标时可以继续使用 `tar-for-upload.py PROJECT HOST`。需要可信中转或要给 project image
提供精确输入时，先在项目电脑完成正式 load，再生成完全本地、无 SSH 的 release 目录：

```bash
python3 tools/tar-for-upload.py 2026-12-vb-gb300 \
  --runtime native \
  --relay-bundle /secure-transfer/2026-12-native-upload
```

Docker 目标把 `--runtime native` 改为 `--runtime docker`。`--relay-bundle` 固定外置
image/apps/firmware，且不能与 HOST、`--deploy`、`--dry-run` 或旧的 `--include-*` 选项组合。输出
严格只有项目 upload archive、匹配的 `deploy-upload-archive.py`、`upload-metadata.json` 和
`SHA256SUMS`。

最终服务器先核对整个目录，再用同一个 runtime 验证和应用，禁止手工解压 live HTTP root：

```bash
cd /root/2026-12-native-upload
sha256sum --check SHA256SUMS
sudo python3 ./deploy-upload-archive.py \
  ./2026-12-vb-gb300-upload.tar.gz --runtime native --verify-only
sudo python3 ./deploy-upload-archive.py \
  ./2026-12-vb-gb300-upload.tar.gz --runtime native
```

直连 Native 的等价受控入口是：

```bash
python3 tools/tar-for-upload.py 2026-12-vb-gb300 \
  ubuntu@mgmt.example --runtime native --deploy
```

直连 Docker 必须显式写 `--runtime docker`。upload 成功只写 live source；Native 随后运行统一
`11-load.py`，Docker 随后选择在线 `deploy` 或已验证 generic image 的 `deploy-preloaded`。

## `BUNDLE-3-SHARED-ARTIFACTS`：独立共享大制品

共享制品的默认来源不是手写文件名。生成器使用真实 `11-load.py` 解析项目 global、scope、平台和
mini 选择，自动从项目输入得到所需 Cumulus/NVOS 版本，再从 `image/` 选择精确交换机镜像：

```bash
python3 tools/package-shared-artifacts.py 2026-12-vb-gb300 \
  --deployment-scope all \
  --output /secure-transfer/2026-12-shared
```

附加选择遵守下面的 fail-closed 规则：

- `--apps-platform` 只在离线目标需要 APT 仓库时显式给出，可重复；联网目标不携带 apps。
- `--firmware` 必须显式指定 `firmware/` 下的单个文件，可重复；工具不会自动归档整个目录。
- `--no-upgrade` 不包含交换机镜像；它不阻止显式 apps 或 firmware。若最终没有任何 payload，工具
  报告成功但不会创建空 bundle。

例如离线 Ubuntu 24.04 amd64 目标需要 apps、一个显式固件，但本轮不升级交换机：

```bash
python3 tools/package-shared-artifacts.py 2026-12-vb-gb300 \
  --no-upgrade \
  --apps-platform ubuntu-24.04/amd64 \
  --firmware firmware/card/fw.bin \
  --output /secure-transfer/2026-12-shared-no-switch
```

生成成功的目录包含 `shared-artifacts.tar.gz`、匹配的 `deploy-shared-artifacts.py`、
`artifact-metadata.json` 和 `SHA256SUMS`。在目标端独立安装：

```bash
cd /root/2026-12-shared
sha256sum --check SHA256SUMS
sudo python3 ./deploy-shared-artifacts.py ./shared-artifacts.tar.gz --verify-only
sudo python3 ./deploy-shared-artifacts.py ./shared-artifacts.tar.gz
```

installer 只能写 `image/`、`apps/` 和 `firmware/` 命名空间。它不安装项目 release，也不启动服务。
firmware 在当前实现中只是运输/安装文件，不能写成会自动刷写设备；apps 安装完成后，Native 离线
主机仍需按 infra 合同显式执行 `infra-setup.sh --mgmt --offline --all`，统一 load 不会自动追加
`--offline`。

## `BUNDLE-4-PROJECT-IMAGE`：可选且仅用于 bootstrap 的项目镜像

project image 不是 generic image 的新默认形式。它在已加载并验证的 generic immutable ID 上，
离线嵌入一份 `BUNDLE-2-UPLOAD-RELEASE` 的精确 upload release；只有显式提供时才再嵌入一份与
同项目/scope/input hash 匹配的可选 shared-artifact bundle：

```bash
sudo python3 tools/package-project-image.py build \
  /root/2026-12-docker-upload \
  --base-image sha256:<64-lowercase-hex> \
  --shared-bundle /root/2026-12-shared \
  --output /root/2026-12-project-image
```

省略 `--shared-bundle` 即只嵌入精确 upload release。构建使用 `--network none --pull=false`，所以
generic base image 必须已经存在。输出严格只有项目 OCI tar、`project-image-metadata.json` 和
`SHA256SUMS`。

project image build 默认绑定升级策略 `enabled`。如果本项目镜像明确只用于保留交换机当前版本，
即使没有 shared bundle，也要在 build 命令追加 `--no-upgrade`；这会把策略绑定为 `disabled`。
提供 shared bundle 时，build 参数与 shared metadata 必须完全一致，否则在 Docker build 前拒绝。

这里的 upload bundle 必须由 `--runtime docker --relay-bundle` 生成；可选 shared-artifact bundle
必须与该精确 upload release 的项目、选择范围和输入 hash 一致。

在同架构最终服务器导入 OCI tar 后，先逐字执行 packager 打印的受限 `docker run ...
package-project-image.py install` 命令，把嵌入 release（以及可选 shared artifacts）安装进一个
fresh `/var/www/html`。这个安装是 bootstrap-only：非 fresh live root 会被拒绝，project image
不能替代 generic image，也不能作为日常覆盖/同步工具。随后执行：

```bash
sudo ./infra/docker/deploy.sh init \
  --project 2026-12-vb-gb300 --scope prod
sudo ./infra/docker/deploy.sh doctor
sudo ./infra/docker/deploy.sh deploy-project-preloaded \
  sha256:<64-lowercase-project-image-id>
sudo ./infra/docker/deploy.sh status
```

project image 自动绑定 shared metadata 中的 `upgrade_policy`。策略为 `enabled` 时只输出并接受
`deploy-project-preloaded <IMAGE_ID>`；策略为 `disabled` 时只输出并接受带 `--no-upgrade` 的部署命令。
这样不会要求操作员再次猜测或手工抄写策略，也不能用相反参数绕过 shared bundle 的镜像选择。

日常项目更新仍通过 `tar-for-upload.py` 或 `sync-code.py`；Docker source write 后按正常合同重新
`deploy`，或使用与新 live authority 匹配的预加载镜像，不能再次用 bootstrap installer 覆盖非
fresh root。

## 2026-12 场景矩阵

下面的“可信中转”只传递冻结目录；它不是新的运行后端，也不能用 `sync-code.py` 做离线二次转发。

| 场景 ID | 准备/传输 | 最终激活动作 | 关键边界 |
|---|---|---|---|
| `BWF-2026-12-MAC` | Mac 对 `2026-12-vb-gb300` 执行正式 `11-load.py` 和全量门禁；可生成 upload/shared bundle | 不启动服务 | Mac 无交换机时只证明配置与制品合同，不证明 DORA、bootstrap 或物理链路 |
| `BWF-2026-12-VM` | adapter 直通 Ubuntu VM；release 可由 direct upload 或 VM 内受控工作树取得 | VM 内只选 Native 或 Docker 一种生命周期 | Service IP 配在 VM Linux 接口；NAT 管理口不能成为 listener |
| `BWF-2026-12-DIRECT-NATIVE` | `tar-for-upload.py ... HOST --runtime native --deploy` | 服务器执行统一 `11-load.py --start-services` | 不运行 Docker lifecycle |
| `BWF-2026-12-DIRECT-DOCKER` | `tar-for-upload.py ... HOST --runtime docker --deploy` | `init → doctor → deploy → status` | `deploy` 已包含 load/health，成功后不再追加 load |
| `BWF-2026-12-GENERIC-PREBUILT` | upload release、generic image、可选 shared bundle 分别传输和安装 | `docker load` 一次后 `init → doctor → deploy-preloaded <IMAGE_ID> → status` | generic bundle 不含项目 release；所有制品分别核对摘要 |
| `BWF-2026-12-RELAY-NATIVE` | `--relay-bundle` 生成 Native upload bundle，经中转复制到最终服务器 | installer verify/apply 后统一 Native `11-load.py` | installer 与 archive 必须来自同一 bundle，禁止手工 tar |
| `BWF-2026-12-RELAY-DOCKER` | `--relay-bundle --runtime docker` 经中转；最终端 installer verify/apply | `init → doctor → deploy → status` | 最终端在线 build；中转端不运行 sync-code |
| `BWF-2026-12-RELAY-PREBUILT` | Docker upload、generic image、可选 shared 三个独立 bundle 经中转 | apply upload/shared、一次 `docker load`，再 `deploy-preloaded` | 不能把旧 build-export 当成包含 upload 的组合包 |
| `BWF-2026-12-PROJECT-IMAGE` | 精确 Docker upload + 可选 shared 嵌入 project image | fresh-root bootstrap 后 `deploy-project-preloaded` | 一次性 bootstrap；非 fresh root 和日常更新均不用该 installer |

Mac 和 VM 场景的正式命令、管理服务器 load 参数与物理设备证据仍以仓库根
`USER_MANUAL.md` 和真实环境登记为准。

## Service IP 漂移与变更

同一 Service IP 只从 Linux 接口 A 移到接口 B，且源码、项目输入、endpoint/subnet、runtime 配置
均未变化时：

- Native：重新执行统一 `11-load.py`，由 systemd 事务重新收敛。
- Docker：`reload-network → health → status`；它只重建动态 listener plan，不运行 load。

2026-12 Native 的完整收敛入口为：

```bash
sudo python3 DAY0-Prepare/11-load.py \
  --start-services DAY0-Prepare/2026-12-vb-gb300
```

Service IP 地址值改变属于项目输入变更。必须回到项目电脑修改 subnet 输入、正式 load/全量门禁，
再发布新的 upload release；Native 重新完整 load，Docker 执行 `deploy` 或使用与新 live authority
匹配的预加载镜像。不得用 `reload-network` 接受新的地址值。

## 发布前检查

1. 每个实际使用的 bundle 目录分别执行 `sha256sum --check SHA256SUMS`。
2. upload/shared/project image 的项目名、scope、switch scope、mini 和 source hash 必须匹配。
3. Docker image 使用完整 immutable ID，并与目标 CPU 架构一致。
4. 选择 Native 或 Docker 后，本轮只使用该后端的 lifecycle。
5. 真机、VM adapter、DHCP/DORA、网络隔离和 project-image fresh-root 证据按
   [`test_cases/REAL_ENVIRONMENT.md`](../../test_cases/REAL_ENVIRONMENT.md) 保存。
