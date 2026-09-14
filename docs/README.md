# 文档中心

`docs/` 只保存项目无关、可公开审查的架构与操作导航。现场项目名、真实地址、设备身份、密钥、
运行日志和验收证据不得写入这里；它们继续留在被 `.gitignore` 隔离的项目或运行目录。

## 从哪里开始

- 私有实施工作区如包含根 `USER_MANUAL.md`，新实施人员先按其中场景选择入口。
- 选择管理服务器后端：读[部署模式与受控发布](deployment/README.md)。
- 理解数据和信任边界：读[架构与数据边界](architecture/README.md)。
- 日常 load、健康检查、恢复和回收：读[运行与恢复](operations/README.md)。
- 判断自动化证据、VM 证据和物理设备证据：读[验证与验收](validation/README.md)。
- 查找稳定入口、支持平台和制品合同：读[参考索引](reference/README.md)。

## 权威文档边界

私有工作区的根 `README.md` 是跨模块概览和生成的模块文档索引；根 `USER_MANUAL.md` 是场景化
操作入口。两者包含现场化说明，不属于公开仓库。模块 README 仍与实现放在同一目录，
负责该模块参数和内部合同。测试治理以 [`AGENTS.md`](../AGENTS.md) 和
[`test_cases/README.md`](../test_cases/README.md) 为准，公开发布边界以
[`PUBLIC_REPOSITORY.md`](../PUBLIC_REPOSITORY.md) 和 [`SECURITY.md`](../SECURITY.md) 为准。

不要复制模块 README 全文到根文档。`python3 tools/update-root-readme.py` 只生成去重链接索引；
软链接 README 以真实目标为一项并显示兼容别名，历史 issue 详情只从所属 tracker 索引进入。
