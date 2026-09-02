# HTTP 网络部署工具

这个仓库公开保存网络部署工作区的源码、脱敏示例、文档和测试。它不是任何站点的配置备份，
也不包含可直接部署到生产环境的凭据、拓扑、设备镜像或运行结果。

## 公开边界

公开版本可以包含：

- Python、Shell、CGI、Jinja2 等实现源码；
- 不含现场身份或凭据的通用模板；
- `test_cases/` 中可在本机安全执行的测试及合成 fixture；
- 面向公开使用者的架构、开发和安全说明；
- `examples/public-project/` 中只使用文档保留地址和本地管理 MAC 的示例输入。

以下内容必须一直留在私有环境，不能提交：

- `DAY0-Prepare/<真实项目>/` 中的 P2P、设备清单、站点 global 和全部 `99-output-*`；
- 密码、密码哈希、私钥、公钥、管理服务器身份文件及其他凭据；
- 真实 hostname、IP、MAC、客户名、项目名、拓扑、日志、诊断包和导入/下载快照；
- Cumulus/NVOS 镜像、固件、离线 APT/DOCA 包及其他第三方二进制；
- setup/load 在本机创建的运行态软链接、锁、状态、发布目录和生成页面；
- 含现场案例的内部汇编文档。公开版本以本文为入口，不能把内部工作区文档整体加入索引。

`.gitignore` 只是最后一道保护，不是脱敏工具。提交前仍需审查 staged 内容，并运行仓库的敏感
信息扫描和完整测试。

## 从脱敏示例开始

示例文件不会路由到真实设备，也没有可用密码。先在私有工作区创建一个被 Git 忽略的项目目录，
再复制并改名：

```bash
project=DAY0-Prepare/2099-my-private-site
mkdir -p "$project"
cp examples/public-project/01-global.yaml.example "$project/01-global.yaml"
cp examples/public-project/02-devices_config.csv.example "$project/02-devices_config.csv"
cp examples/public-project/02-dhcp-subnet_config.csv.example "$project/02-dhcp-subnet_config.csv"
chmod 600 "$project/01-global.yaml" "$project/02-devices_config.csv" \
  "$project/02-dhcp-subnet_config.csv"
```

然后按 [`examples/public-project/README.md`](../examples/public-project/README.md) 的检查表替换所有
示例值。不要在 Git 跟踪目录中填写真实值；不要直接部署示例。

设备 OS、固件和离线包需要从相应厂商或受授权的软件源单独取得。公开仓库不重新分发这些文件。

ZTP 的可版本化源文件位于 `ztp/templates/`。其中 `ztp-bootstrap.sh` 与 `ztp.json` 是
canonical 模板；`load` 会按当前项目渲染出被 Git 忽略的 `ztp/ztp-bootstrap_oob.sh`、
`ztp/ztp-bootstrap_oobofoob.sh` 和 `ztp/ztp.json`。不要把这些带现场地址的运行态产物提交回来。

## 开发与验证

仓库的测试合同由 [`AGENTS.md`](../AGENTS.md)、[`test_cases/README.md`](../test_cases/README.md)
和 [`test_cases/CHANGE_AWARE_TESTING.md`](../test_cases/CHANGE_AWARE_TESTING.md) 定义。修改脚本、
模块流程或受支持场景时，必须同时更新 direct 与 workflow/scenario 测试。提交或同步前运行：

```bash
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B \
  test_cases/run_related_tests.py --all -v
PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B \
  test_cases/run_related_tests.py --check
```

测试成功不代表示例适合某个真实网络。首次部署仍应在隔离实验环境完成配置审查、身份核验、
回滚和真机测试。

## 安全提交检查

每次提交至少确认：

1. `git status --short` 只列出预期的源码、公开文档、示例和测试；
2. `git diff --cached` 中没有真实地址、MAC、hostname、客户名、密钥或密码哈希；
3. 没有大文件、绝对路径软链接、运行日志、生成输出或第三方受限二进制；
4. 全量测试与批准状态检查均通过；
5. 在一个干净 clone 中重复测试，确认测试没有依赖本机的真实项目数据。

如果敏感信息曾经进入 commit，仅删除当前文件不够：应立即轮换凭据，并从完整 Git 历史中清除
该内容。公开 issue、测试日志和截图中也不要粘贴敏感数据。漏洞报告方式见
[`SECURITY.md`](../SECURITY.md)。

## 许可说明

公开可见不等同于获得开源许可。在仓库维护者明确添加 `LICENSE` 前，默认版权规则仍然适用；
不要假定可以复制、修改或再分发第三方组件。
