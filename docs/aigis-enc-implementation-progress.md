# Aigis-enc 实施记录

计划：`docs/pqmagic-aigis-ipsec-integration-plan.md`，2026-11-17。

- 用户已验证 ML-KEM；现有 Ed25519 认证保留，接入 mode 2 / SM3 的临时 KEM。
- PQMagic 提交：`42f5b6e6fe7e4951ffc9437ecd77c9a5af93ff08`，源目录 `/home/lxh/PQMagic`，不修改该外部仓库。
- 初始实现阶段在当前工作目录执行；当时不提交、不推送，也未替换系统正在运行的 daemon。
- 决策：当前没有 CMake，按 PQMagic std Makefile 的源文件集合用 GCC 构建独立依赖，提供可重复执行的脚本；产物隔离在 `.local-pqmagic/`。若今后依赖调整，需重新核对该文件集合。
- 基线：沙箱内 4 个 suite 的 socket 操作失败；沙箱外 `make -C src/libstrongswan/tests check` 全部 50 个 suite 通过。
- RED：新 KEM 对象 suite 的 10 次测试全部因 provider 缺失失败，符合预期。

- 依赖：PQMagic 自带测试的 1000 次 keypair/enc/dec 循环通过（同时检查成功输出，因上游 main 失败也返回 0）。
- GREEN：Aigis 对象、长度、缓存、隐式拒绝、RNG 失败恢复、proposal 混合协商/私有过滤/不兼容均通过。
- KAT：发现生成器标点错误导致最早一轮向量插件未重编，旧 `kat.log` / `active-transforms.txt` 作废。修正后通过 `nm` 确认新向量符号，临时翻转 shared 首字节，测试明确因 Aigis KAT 失败（`kat-mutation.log`）；恢复后 `kat-final.log` 通过。新文件 `active-transforms-final.txt` 确认 Aigis 与三个 ML-KEM 被验证。
- 决策：生产路径使用 PQMagic 的 internal coins 接口与 strongSwan RNG_STRONG，避免依赖 randombytes 的进程 abort 行为；测试通过对象级 DRBG 提供 coins，不替换全局 RNG。若 PQMagic 修改 coins 契约，必须更新向量/适配器。
- 决策：SM3/SHAKE 共享符号，插件启动执行固定输入自检，避免错误变体以同一私有编号协商。已构建 SHAKE 对照库并验证其被拒绝；改变算法变体需新增方法号/关键字。
- 协议：本地 libcharon 交换测试使用真实 OpenSSL ECDH、真实 PQMagic 和实际 IKE 编解码/加密；初建、双方 IKE rekey、双方 Child rekey 成功。同长篡改 ct 导致认证流程失败，未建立 Child SA。
- 限制：该协议框架模拟内核与报文传输，使用框架已有 PSK；不是 moon/sun 证书与真实 ESP ping 测试。新增 `testing/tests/ikev2/host2host-aigisenc/` 网络用例，尚未运行虚拟机测试平台。

- 关闭插件：`--disable-pqmagic` 且不提供任何 PQMagic flags，全项目构建成功，proposal/vectors 测试通过；随后恢复开启插件的本地构建。
- 缺失依赖：使用不存在的 PQMagic include/lib 路径，configure 退出 1 并明确提示缺少 `pqmagic_api.h`；随后恢复正确 flags。
- 完整回归：沙箱外仓库根目录 `make check` 退出 0：libstrongswan 51、libtls 5、VICI 4、kernel-netlink 1、libcharon 4、exchanges 8 个 suite 全通过，共 6 个测试程序。
- 独立只读复核未发现核心适配器阻断问题；发现网络 fixture 连续提交异步 rekey，旧 SA 可误满足断言。已补 `expect-rekey`，每轮等待新的有效 SA ID；3 个等待器测试通过。移除 ID 改变判断的 mutation 确认旧 SA 不变时测试失败，恢复后通过。
- 最终修复后复测：`make-check-final.log` 再次确认全部 6 个测试程序、73 个 suite 通过；`rekey-wait-final.log` 确认 3 个辅助测试通过，`git diff --check`、文档本地链接及命令语法检查通过。
- 未验收范围：真实双机/虚拟机网络、Ed25519 证书联调、XFRM/ESP、真实分片/丢包/并发连接；MONOLITHIC 仅复核构建登记，未独立构建。PQMagic 算法安全与侧信道审计不在本次范围，依赖内部栈临时量擦除仍由上游实现负责。

部署命令见 [pqmagic-aigis-build-and-test.md](pqmagic-aigis-build-and-test.md)。测试输出保存在仓库内忽略目录 `.local-pqmagic/`；不含运行会话秘密。

后续用户要求：moon 已由用户完成本地编译，当前改动通过新分支 `feature/aigis-enc-pqmagic` 提交到 `origin`，两端阶段测试通过前不合并到 `master`。sun 的拉取、依赖版本、编译和验收步骤见 [sun 部署说明](pqmagic-aigis-sun-deployment.md)。本助手未执行系统安装或两端网络联调。
