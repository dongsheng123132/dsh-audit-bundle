# dsh-audit-bundle

[![CI](https://github.com/dongsheng123132/dsh-audit-bundle/actions/workflows/check.yml/badge.svg)](https://github.com/dongsheng123132/dsh-audit-bundle/actions/workflows/check.yml)
[![MIT 许可证](https://img.shields.io/github/license/dongsheng123132/dsh-audit-bundle)](LICENSE)
[![Node.js 22+](https://img.shields.io/badge/Node.js-%E2%89%A522-339933?logo=nodedotjs&logoColor=white)](package.json)
[![Awesome DSH Plugins](https://img.shields.io/badge/Awesome_DSH-%E5%B7%B2%E9%AA%8C%E8%AF%81%E5%AE%9E%E9%AA%8C-0969da)](https://github.com/dongsheng123132/awesome-dsh-plugins/blob/main/README.zh-CN.md#2origin-%E6%8F%92%E4%BB%B6%E5%AE%9E%E9%AA%8C%E5%AE%A4)

跨多个独立 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 证据生产者的内容寻址审计索引。

它不是 SBOM 扫描器、签名器、审计日志、策略执行器或归档器。现有工具负责扫描，各 2Origin 插件负责产生发布、运行、恢复、血缘和策略证据；本插件只证明某个主体/revision 是否拥有足够的固定证据、允许的证据类型和相互独立的生产者来覆盖声明控制项。

Manifest 声明主体、revision、控制项最低证据数、最低独立生产者数、允许类型、每份证据 SHA-256、主体绑定 JSON Pointer 和仅用摘要表达的断言。缺失、陈旧、非法 JSON、主体错配、断言失败、类型不允许、证据不足或独立生产者不足都会失败闭合。

输出只含 ID、类型、生产者、JSON 路径、摘要、状态、覆盖情况和确定性 Merkle 根，不复制证据正文或断言原值。所有文件必须是工作区内普通相对路径；拒绝 symlink、目录逃逸、超大和过度复杂输入。不联网、不启动子进程，只向显式 `artifactDir` 写内容寻址索引并回读。

```sh
node bin/dsh-audit-bundle.mjs verify --workspace examples/basic --manifest audit.manifest.json --artifactDir artifacts
```

DSH 注册 `dsh_audit_bundle_inspect`、`dsh_audit_bundle_verify`；MCP 注册对应 inspect/verify。GitHub Actions 在 Ubuntu 与 Windows 运行。许可证：MIT。
