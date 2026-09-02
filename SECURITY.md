# 安全策略

## 私下报告漏洞

请不要在公开 issue、discussion、pull request、日志或截图中提交漏洞细节、凭据或现场数据。
优先通过仓库 GitHub 页面 **Security** 区域的私有漏洞报告入口或 GitHub Security Advisory 与
维护者联系：

- [本仓库 Security 页面](https://github.com/Kubernetes-CNI-Service/http/security)
- [GitHub 私有漏洞报告说明](https://docs.github.com/code-security/security-advisories/working-with-repository-security-advisories/privately-reporting-a-security-vulnerability)

如果仓库尚未启用私有报告入口，请不要改用公开 issue 粘贴敏感内容；先通过 GitHub 提供的私有
安全协作能力联系仓库维护者。本文不发布或杜撰维护者邮箱。

报告应尽量只包含复现所需的最小信息：受影响组件和版本/commit、影响、脱敏复现步骤、预期与
实际结果，以及建议的缓解方式。用合成 hostname、RFC 5737 文档地址和本地管理 MAC 替代现场值；
不要附带真实配置、P2P、密钥、token、密码哈希、设备日志或完整诊断包。

## 发现秘密或现场数据泄露

如果凭据、密钥、token、密码哈希或真实现场数据已经进入公开 commit：

1. 立即撤销或轮换受影响凭据；不要等待 Git 历史清理完成；
2. 记录受影响 commit 和暴露范围，但不要在公开渠道复制敏感值；
3. 通过上述私有渠道通知维护者；
4. 从完整 Git 历史、release、artifact、缓存和公开引用中清除内容；
5. 在干净 clone 中重新扫描，并检查 fork、CI 日志和下载制品是否仍保留副本。

仅从当前分支删除文件不能使已经公开的内容失效。Git 历史清理也不能替代凭据轮换。

## 仓库数据边界

本仓库只接收源码、脱敏模板、公开文档和合成测试。以下内容不属于可接受的漏洞附件或普通
贡献：真实项目目录、设备清单、P2P/拓扑、IP/MAC/hostname、客户或项目身份、管理公钥、私钥、
密码/哈希、现场日志、诊断包、设备镜像、固件及第三方离线包。

公开示例不能当作生产安全基线。真实部署还需要本地威胁模型、权限设计、网络隔离、供应链校验、
回滚和真机验证。

## 支持范围

仓库目前没有单独声明长期支持版本或响应时限。报告时请注明复现所用的 commit；维护者会以当前
源码和可安全复现的证据评估问题。第三方操作系统、固件、软件包和服务的漏洞应同时按其上游
安全流程报告。
