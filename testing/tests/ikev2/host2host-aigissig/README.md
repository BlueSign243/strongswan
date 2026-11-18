# moon/sun Aigis 复合签名实验

这是可人工执行的独立双机测试配置，不是已执行的 UML/VM 自动验收结果。地址为实际实验环境的 moon `192.168.199.131` 和 sun `192.168.199.130`；套用 strongSwan VM 平台时须替换地址、准备带签名插件的 guest，并按平台接入，不能直接按其他测试的 `192.168.0.1/2` 拓扑运行。

- `moon-m1.conf` / `sun-m1.conf`：复合 AUTH，传统 Ed25519 CA 签发复合叶子。
- `moon-m2.conf` / `sun-m2.conf`：复合 AUTH、复合签发链和显式复合 CA 约束。
- 文件包含完整 `connections` 块。两端仅加载选定阶段的对应文件。
- `start_action = none`：受控发起，避免旧连接的重叠 TS 掩盖结果。

先执行 [构建、生成混合证书及双机验收步骤](../../../../docs/aigis-sig-build-and-test.md)。必须检查新 IKE/Child SA 的身份和连接名、双方复合签名成功日志、IKE_AUTH 分片、双向 ESP 计数增长，以及 `--rekey --ike host-host-aigissig --reauth` 后再次出现完整复合认证。普通 IKE/Child rekey 不算签名证据。

M2 负向配置在实验副本中逐项测试：传统 CA 替代链、错误 CA、无 `remote.cacerts`、直接信任叶子/原始公钥替代链、仅传统 Ed25519 凭据。预期为配置拒绝或认证失败，无新成功 Child SA。不要用 `auth = pubkey` 替代本目录的强制策略。
