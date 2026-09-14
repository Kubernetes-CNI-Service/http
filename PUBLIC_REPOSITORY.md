# 公开仓库说明

本公开仓库的入口、发布边界、脱敏示例和验证说明见
[`.github/README.md`](.github/README.md)。

`docs/` 只保存无现场身份、地址、凭据或运行证据的通用文档，并从
[`docs/README.md`](docs/README.md) 导航；新增内容仍须通过公开树审计。

内部工作区的根 `README.md`/`USER_MANUAL.md` 包含现场化案例，不属于公开发布内容。

版本管理只覆盖公开源码边界；真实项目、运行输出和 `load` 渲染文件会继续保留在本地并被
`.gitignore` 排除。
