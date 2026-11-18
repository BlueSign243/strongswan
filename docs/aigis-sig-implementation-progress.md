# Aigis-sig 复合签名实施记录

本轮完成本地工程接入和测试，未执行真实 moon/sun 双机部署。部署与混合证书生成见 [构建及双机测试文档](aigis-sig-build-and-test.md)，固定 OID 见 [profile 清单](aigis-sig-profile.json)。本文记录的是实验实现的证据，不构成组合算法的安全证明。

## 1. 基线与决定

| 项目 | 本轮值 |
| --- | --- |
| strongSwan 基线 | `786cf22b60a482c2bb94bc7340575d32dc24653f`，6.1.0 |
| 开发分支 | `feature/aigis-sig-composite-pqmagic` |
| PQMagic 提交 | `42f5b6e6fe7e4951ffc9437ecd77c9a5af93ff08`，依赖工作区无修改 |
| 构建器 | GCC 13.3.0，Ubuntu 24.04 软件包 |
| OpenSSL | 3.0.13 |
| 运行环境 | Linux x86_64 |
| profile | `AigisSig2-SM3+Ed25519+SHA512-v1` |
| 签名依赖库 SHA-256 | `8ce6920d759825395a96732b65fa069d6d3ed933a34c30e9f97e9fc969bed795` |
| 固定向量头 SHA-256 | `5cc5dbca1cf769a611b55a175aab6adb95df1f4da079a2c59b5b3d7a856ea0e8` |

用户在本会话明确授权项目自行生成 OID，因此以 UUIDv4 按 ITU-T X.667 的 `2.25` 机制生成两项标识，未占用他人企业分支或标准算法 OID。此决定替代原设计中“等待用户提供授权分支”的外部输入；工程 profile 已冻结，独立密码分析仍未完成。UUID 对应关系和完整数字已保存，双机必须复用同一清单。

构建日志及最终本地证据位于忽略目录 `.local-pqmagic/evidence/`；库来源、编译器、符号表和上游正确性测试在 `.local-pqmagic/sign/`。`ldd` 确认当前 pqmagic 插件实际链接到该目录的 `libpqmagic_std.so`。这些是本工作区证据，不作为源码提交中的可移植二进制附件。

## 2. D0–D6 结果与边界

| 阶段 | 结果 |
| --- | --- |
| D0 规格与向量 | OID、字节标签、顺序、种子及 DER 已冻结；独立组合密码分析待完成 |
| D1 依赖与原语 | KEM-only 兼容构建、SM3 KAT、普通/internal context 等价、长度/溢出/分配/并发测试通过 |
| D2 对象与组合器 | 单 Aigis 与复合对象、既有 Ed25519 provider、SHA-512 transcript、双分量 AND、可选能力和失败清理已实现并测试 |
| D3 凭据与 PKI | 完整 SPKI/PKCS#8 v0、PEM、泛型/具体类型加载、完整指纹、CSR、M1/M2 签发及负向 DER 测试通过；运行中的 swanctl/daemon 凭据装载待双机确认 |
| D4 IKE AUTH | 真实 PQMagic + OpenSSL 的用户态交换通过；RFC 7427、IntAuth、严格 token、M2 链证据、拒绝降级及加密 AUTH 分片已测试 |
| D5 回归 | 最终完整回归、构建矩阵、独立辅助测试及限定范围 sanitizer 通过，详见下表 |
| D6 双机验收 | 未执行；已提供 M1/M2 完整配置和证书生成、分片、重新认证、ESP、负向及回滚步骤 |

实现组织与设计有三处工程调整：

- 单算法和复合对象共用密钥生命周期代码；三个独立测试 suite 共用 `test_aigis_sig.c`，仍分别报告执行结果。
- 内部 OID 常量使用 `OID_AIGIS_SIG2_ED25519_SHA512`，避免既有 `oid.pl` 对超长名称的格式限制；线上数字 OID 和对外 scheme 名不变。
- VICI 本地 M2 token 只选择复合 AUTH；远端 M2 才检查实际验证链和指定 CA。两端均配置 M2，以强制双向复合链。将远端证据约束用于本地认证轮次会导致重复 AUTH，已通过实际交换修正和验证。

## 3. 最终验证证据

最终代码的完整 `make check` 在沙箱外退出 0。沙箱中的 socket/线程扫描限制不作为产品测试失败，也未通过跳过目标 suite 来获得通过。

| 验证 | 结果 | 本地日志（相对 `.local-pqmagic/evidence/`） |
| --- | --- | --- |
| `make -j4` | 退出 0 | `build-final.log` |
| 完整 `make check` | 77 suites：libstrongswan 54、libtls 5、vici 4、kernel-netlink 1、libcharon 4、exchanges 9 | `make-check-final.log` |
| Python Aigis 脚本 | 4 tests，包含 PKI 子进程及既有 rekey 等待测试 | `python-final.log` |
| 依赖构建脚本 | 2 tests，真实 KEM-only/签名构建及未知参数拒绝 | `dependency-final.log` |
| 原语 ASan/UBSan/LSan | 退出 0，KAT/context/NULL/溢出/故障/四线程签验 | `primitive-sanitizers-final.log` |
| 对象 ASan/UBSan/LSan | 退出 0，对象、transcript、签名和 DER 拥有的分配故障/释放/seed 清理断言 | `alloc-sanitizers-final.log` |
| provider 降级隔离 | full/no-ed/no-sha512/bad-sig 全通过；错误同符号 SHAKE 库不发布签名，真实 KEM 仍工作 | `providers-final.log` |
| AND 变异 | 只验 Aigis、只验 Ed25519 的两种变异均被测试检出 | `mutations-final.log` |
| 实际 VICI 配置回调 | M1、本地 M2 通过；M2 无 CA、错误摘要、额外后缀、大写变体拒绝 | `vici-final.log` |
| 四种构建配置 | 关闭插件和旧 KEM-only 通过；缺 API 和矛盾开关按预期 configure 失败 | `matrix-final.log` 及 `.local-pqmagic/matrix/` |
| 文档 PKI 脚本 | 独立临时目录生成并验证 M1、M2 的 CA、两端密钥、CSR、证书和 SPKI | `deployment-pki-final.log` |

新增 suite 的实际名称为 `aigis_sig`、`composite_aigis_sig`、`pqmagic_credentials`、`aigis_sig_auth`；既有名称 `signature params` 含空格。完整回归确实执行这些 suite，未把零 suite 的成功退出计入覆盖。

协议测试使用真实 PQMagic/Ed25519 签验和 ECP-256 + Aigis-enc 密钥交换，传输和内核由既有 exchange 框架模拟。覆盖 M1、M2、预置完整原始公钥的 M1 正向，双分量篡改、错误身份/CA、传统链替代、直接信任叶子、缺 hash/扩展/provider、未知 OID、经典 AUTH、短签名和 IntAuth 绑定；加密 RFC 7383 AUTH 分片及重复首片也通过。这些结果不证明实际内核 ESP 转发或完整重新认证已验收。

固定向量来自锁定 PQMagic 的普通 context API，以及独立 Python RFC 8032 算术实现；后者先核对 RFC 8032 test 1，再生成组合期望值。种子只含专用公开测试值，不能用于部署。生成器和完整字节期望值均随源码保存。

代码审查发现的非最短证书/CSR signatureValue 长度、内层尾随对象、未检查自有分配及秘密编码中间量问题，均已修复并用负向/故障测试复核。复查未发现新的重要问题。codegraph 用于源码导航和变更影响检查；C 宏/方法接收者等静态解析限制意味着它不能替代编译和运行测试。

## 4. 秘密清理与仍待验证事项

新增代码显式检查自有分配，失败输出为空，使用清理函数擦除 seed、展开私钥、临时私钥 DER 和未完成签名。私钥导出副本由调用者负责清理。对象分配测试追踪自有缓冲区的释放并检查公开测试 seed 残留，不涵盖依赖库内部所有内存。

锁定 PQMagic 的 `sig/aigis-sig/std/sign.c` 在 internal 签名路径中普通 `free(buf)`，多项式/seed 等栈工作区没有全面显式擦除；ordinary API 也有额外缓冲区。插件使用受检 internal 包装并处理其长度加法和外部上下文，但没有复制或补丁化上游数学实现。后续加固应以可审查的版本化依赖补丁或升级交付，重跑 KAT，不能把插件对象销毁视为库内部秘密已全部清除。

分配 sanitizer 测试的隔离进程仅加载 OpenSSL default provider；默认 legacy provider 的现有生命周期曾产生依赖层泄漏报告，因此该测试显式禁用无关 legacy provider，并执行 OpenSSL 清理。该结果只证明记录范围内的新增代码和该隔离配置；没有声称整个 strongSwan/OpenSSL 的所有 provider 已通过泄漏审计。ASan/UBSan 也未对上游库所有源文件进行全覆盖插桩。

仍待单独完成：独立组合密码分析、PQMagic 内部清理加固、实际 daemon/swanctl 凭据装载、两端 M1/M2 初建与完整重新认证、双端 IKE/Child rekey、网络丢包与分片重传、实际 ESP 双向计数，以及在线吊销场景。本轮没有执行系统安装、服务重启、远程连接或现网配置替换。
