# 配置反馈与多来源比较

本目录是正式 ZTP 代码的一部分，用于把生成配置、设备实际采集和配置备份转成统一表格，比较
AIR/Production 的期望状态与实际状态。upload/sync 会部署两个顶层 Python 文件，但排除
`*-sample/`、报告和 issue-tracker 等本地运行数据。

## 文件角色

- `feedback.py`：命令行入口。单来源模式把 YAML、INFO、目录或归档转换为 CSV；比较模式接受
  2–5 个来源，按设备和字段输出差异报告。项目/sample 模式默认分别运行 Production 与 AIR
  两组独立比较，输出到 `comparison/prod/` 和 `comparison/air/`；`--type prod`、
  `--type air|prod`、`--air`/`--prod` 只运行指定环境。`generated-latest` 同时保存 `X.yaml` 与
  `AIR-X.yaml`，每个环境严格按自己的 inventory 与真实 YAML 文件名筛选。CSV 的
  `hostname` 始终取 YAML 的 `set.system.hostname`，不会从文件名或另一个环境派生。
- `sample_links.py`：共享库，不是命令行入口。setup 调用其中的选择函数，为当前项目建立
  `monitor-{air,prod}-latest`、`config-backup-{air,prod}-latest`、`generated-latest` 和三份
  global/devices 输入链接；只选择时间戳有效且内容完整的最新来源，`latest` 目标必须仍在
  当前项目输出根内，候选批次中的 symlink 不会被当成可发布源。

`feedback.py` 解包 tar/zip 时只接受普通文件/目录，拒绝路径穿越、链接、超限的成员数/解压
字节以及 symlink 目标目录；归档验证失败时不生成比较输入。

global 反向回填只接受显式 `--global-config`、输入同目录的唯一
`01-global.yaml`/`global.yaml`，或 `sample_links.py` 建立的受管项目链接；不会再向任意祖先目录
猜测写入目标。一次命令在创建/刷新 sample、迁移旧输出或创建比较输出之前先持有 workspace
`deployment lock`；Production/AIR 递归复用同一把锁、同一份只读 discovery plan 和同一份
authority 快照，不再次刷新链接。受管链接的项目根和精确 sample 路径来自该 plan，绝不从
待验证链接的 `resolve()` 结果反推 authority。

加锁后的只读 mutation plan 会从 workspace held fd 开始，逐组件以
`O_DIRECTORY|O_NOFOLLOW` 绑定项目、`ztp/optimize`、sample、各输出根和 writeback state
父目录；每个现有目录都必须保持 dev/inode/type/mode/uid/gid，属于当前用户且不得 group/world
可写。所有路径验证完成后，缺失目录才相对已持有的父 fd 创建，legacy comparison 迁移和
sample 链接刷新也只用 dir-fd 相对操作。中间 symlink、错误 owner/mode 或 canonical name
重绑定会在第一次 mkdir/migration/unlink/symlink 前停止并保留完整 pre-tree；mutable-path
authority 不使用 `resolve()`。项目 authority 的 CAS 同样冻结 dev/inode/type/mode/uid/gid，
但故意排除会随合法 child 创建变化的 nlink/mtime/ctime。

authority 必须是 held-fd 的单链接 UTF-8 普通文件。所有来源都基于该快照生成 sidecar，只有
具备真实反推证据且原值缺失、`{}` 或 `- {}` 的 allowlist 路径会进入 staged patch，最后只
发布一次。候选以随机私有 `O_RDWR|O_EXCL|O_NOFOLLOW|O_NONBLOCK` 文件建立；名称、held fd、
完整字节、SHA-256、uid/gid/mode/size/nlink 在 CAS 前重复绑定校验，post-verify 继续使用同一
held fd，绝不通过不可信名称重新打开。补丁只改对应 YAML byte span，保留其他注释、顺序、
引用形式和字节；不会在源目录创建 `.bak`。

The implementation must not claim impossible compare-and-swap semantics from portable rename.

OPT-006 仍使用一个项目共享的 deterministic first-success baseline：Production 没有证据而
AIR 先有真实证据时，AIR 可以成为该字段的项目权威并用于后续 Production 生成。每个实际
commit 字段只输出一行 canonical compact JSON：JSON array `path`、枚举 `source_scope`、
不可逆 `source_ref_sha256`，以及整份 authority 的精确 `before_sha256`/`after_sha256`，绝不输出
反推值或 secret。序列化固定使用 `ensure_ascii=True`；C0/C1、DEL、NEL、LS/PS、bidi/isolate、
astral 和 surrogate 都只能以 JSON escape 出现，因此记录是 ASCII 且恰好一条物理行。每行在
完整 escaping 后连同换行最多 4096 bytes；双 hash 也计入同一上限，超限会在创建
候选/state/发布前 fail closed，绝不截断。所有 YAML
parse/edit/render 异常统一在一个结构边界转换为有界、无 source snippet 的错误。各环境的
source inventory、CSV 与报告仍独立；global sidecar
**不参与 comparison**，比较只读取各自生成的 CSV。

## writeback state 与人工恢复

发布前，`feedback.py` 在可信项目 `99-output-ztp/optimize` 下 durable 写入固定 0600 state：
`PREPARED` 表示 `published=false`；live `os.replace` 成功后立即推进为 `published=true`，然后才
执行 authority 父目录 fsync 和 held-fd final verification。全部成功才删除 state 并 fsync
state 目录。若在 live 已 durable 且 held-fd 验证完成后，state 已 unlink、但最后一次 state
目录 fsync 失败，publication 仍明确成功；命令输出与
`storage_health=state-directory-fsync-failed` 机器字段会同时说明文件系统健康告警和
`published=true` marker 可能在 crash 后重现。该告警绝不使用
`publication-indeterminate`。更早的 unlink/状态推进/live fsync/final verify 故障仍报告真正的
`publication-indeterminate`，保留 expected after-SHA 并禁止自动重试；下次自动 writeback
遇到任一残留 state 都会停止。

人工恢复必须先独立验证 live authority。仅当 state 为 `published=true` 且 live 文件 SHA-256
等于记录的 expected after-SHA，才可运行：

```bash
python3 ztp/optimize/feedback.py --recover-global-writeback-state \
  --global-config <project>/01-global.yaml
```

这表示发布成功而 state 清理失败，命令会验证并清除 state。`PREPARED`（即
`published=false`）或 after-SHA mismatch 仍属真正不确定状态，必须保留记录、人工调查，不能
清除或自动重试。state 只是事务标记，不含 YAML 值、secret、snippet 或 source preimage。

## schema v2 输出与比较

`feedback.py` 读取同一项目的 `01-global.yaml` 决定 schema。v2 输出使用清单中的严格布局：
12 个基础列、零到多个四列普通 VLAN 组、固定七列和零到多个九列 EVPN 组；当设备实际配置
需要更多组时只向右完整扩展重复组，不移动已有字段。反向解析保留单 VLAN 的 `/native`、
实际 bond interface 名称及 `local|mlag|evpn` 对齐关系。若一个 VLAN 在不同成员端口上的
native/tagged 状态不一致，单个 v2 VLAN 组无法无损表达，转换会 fail closed。

v2 不再输出逐设备 `vrr_ip`、`vrr_mac`。比较阶段仍从受保护的原始 NVUE YAML 提取按 VLAN
排序的 VRR IP/MAC 运行态签名，因此全局策略推导值在交换机上发生漂移时不会被忽略。
`source_yaml_b64/source_yaml_sha256/source_fields_sha256` 是只读审计元数据；生成器拒绝带原始
YAML 回环内容的 v2 行，防止它绕过规范字段、全局 VRR 推导和 native/bond 校验。

v2 反向解析会把设备全局 `mlag.mac-address` 写回该设备每个 MLAG profile 的
`bond_mac`，从而保留以 MAC 建立 peer 关系的新合同；EVPN-MH 仍从各 bond 的
`segment.mac-address` 回填。`system.global.system-mac` 是设备自身身份，不写回 global。
若运行配置含 `nve.vxlan.mlag.shared-address`，对应 sidecar/global 使用 MLAG MAC 作为键：

```yaml
mlag:
  shared-addresses:
  - bond-mac: 44:38:39:ff:00:12
    anycast-ip: 172.16.21.201
```

Feedback 不为普通二层 MLAG 伪造 shared-address override，也不把 EVPN-MH segment MAC
解释为 `system.global.anycast-mac`。schema v1 来源继续按旧 `mlag.pairs` 结构兼容输出；
schema v2 sidecar 不输出 `pairs`、`system-mac` 或旧的 `mac-address` 列表。

## 在整体流程中的位置

1. setup 在事务 staging 区调用 `sample_links.py`，为所选项目生成
   Production/AIR 各自的最新 monitor 和 backup 入口。
2. config generator 的 `_combine` 目录作为 generated 来源；其中可以同时存在
   `X.yaml` 和 `AIR-X.yaml`。
3. `feedback.py` 先按环境筛选 inventory 和 YAML，再转成统一 CSV，
   最后按设备+字段比较 generated、monitor 和 backup。
4. 默认 `all` 产生完全独立的 `comparison/prod/` 和 `comparison/air/`；
   单环境参数不会把另一环境配置带入比较。

设备管理 IP 可以在 AIR/Production 之间重复，因此不作为环境唯一键。
环境来自明确 scope 和来源元数据；配置中的 hostname 则始终以 YAML 真实值为准。
已标记环境的 `monitor-*-latest`/`config-backup-*-latest` 会保留设备实际 hostname；
即使它带有旧的站点前缀，也会通过管理 IP/MAC 与其他来源关联，并把
hostname 差异作为真实比较结果，而不是在转换前丢掉该设备。

## 使用

```bash
python3 ztp/optimize/feedback.py --help
python3 ztp/optimize/feedback.py <yaml-or-archive> -o result.csv
python3 ztp/optimize/feedback.py <project-or-sample>  # 默认分别生成 prod/air 报告
python3 ztp/optimize/feedback.py --compare --type prod <comparison-directory>
python3 ztp/optimize/feedback.py --compare --prod <comparison-directory>
python3 ztp/optimize/feedback.py --compare --type air <comparison-directory>
```

建议在 setup/load 之后先运行默认双环境比较，然后在当前管理服务器只可达
一个环境时用 `--air` 或 `--prod` 做定向复核。输出目录应保留用于差异审计，
但不进入 upload/sync 代码包。

项目激活时不要手工维护 `*-sample/` 内的链接；运行
`python3 DAY0-Prepare/01-a-setup.py <project>` 统一重建。切换项目失败时 setup 的事务回滚会
恢复旧链接，真实备份、采集归档和生成目录不会被删除。
