# Aigis-sig 复合签名：本地构建与 moon/sun 双机部署测试

实现 `AigisSig2-SM3+Ed25519+SHA512-v1`：Aigis-sig mode 2 / SM3 与 Pure Ed25519 同时签验，公钥 1344 bytes，签名 2509 bytes。沿用 ECP-256 + Aigis-enc mode 2 / SM3 混合密钥交换，不改变 ESP 算法。

本地实现、凭据、协议和回归测试已完成；**本文双机部署步骤尚未在真实 moon/sun 执行，不代表真实 ESP 验收通过**。实施证据、依赖边界和未验收项目见 [实施记录](aigis-sig-implementation-progress.md)。本轮未安装系统文件或替换现网凭据。

## 1. 固定 profile 与环境

| 项目 | 固定值 |
| --- | --- |
| strongSwan 基线 | `786cf22b60a482c2bb94bc7340575d32dc24653f`，6.1.0 |
| PQMagic | `42f5b6e6fe7e4951ffc9437ecd77c9a5af93ff08`，std / mode 2 / SM3 |
| 单 Aigis OID | `2.25.48040714654762008698679385395515984885` |
| 复合 OID | `2.25.189402091888940046385604693038199473194` |
| moon / sun | `192.168.199.131` / `192.168.199.130` |
| 身份 | `moon.strongswan.org` / `sun.strongswan.org` |

两个 OID 根据本会话授权，以 UUIDv4 在 `2.25` 下生成并冻结，详见 [profile 清单](aigis-sig-profile.json)。这是 [ITU-T X.667 的 UUID OID 分配方式](https://www.itu.int/en/ITU-T/asn1/pages/uuid/uuids.aspx)，没有借用任何标准签名 OID。不要在另一台机器重新生成 OID；两端使用同一份源码和清单。参数必须 absent，显式 NULL 也拒绝。

M1 仅强制复合 AUTH，允许传统 CA 签复合叶子，CA 信任仍依赖经典签名。M2 同时要求复合 AUTH、实际复合 X.509 链和显式指定的复合 CA。端点证书中的 SPKI、签发者的证书签名算法、IKE AUTH 算法是三项独立证据。

## 2. 本地编译，不安装系统

在两台主机各自的仓库中构建，不要复制包含另一台绝对 RUNPATH 的二进制插件。

```bash
cd /home/lxh/strongswan
sh scripts/build-pqmagic-aigis.sh /home/lxh/PQMagic "$PWD/.local-pqmagic/sign" --with-sign
./autogen.sh
PQMAGIC_PREFIX="$PWD/.local-pqmagic/sign"
./configure --prefix=/usr --sysconfdir=/etc \
  --enable-systemd --enable-swanctl --enable-vici --enable-pki \
  --enable-openssl --enable-ml --enable-sha3 \
  --enable-pqmagic --enable-pqmagic-sign --enable-test-vectors \
  --disable-charon --disable-stroke \
  PQMAGIC_CFLAGS="-I$PQMAGIC_PREFIX/include" \
  PQMAGIC_LIBS="-L$PQMAGIC_PREFIX/lib -Wl,-rpath,$PQMAGIC_PREFIX/lib -lpqmagic_std"
make -j4
```

原来的两参数构建调用仍为 KEM-only。开启签名而关闭 pqmagic、或链接缺签名 internal API 的旧库时，configure 必须失败。签名库 SM3 KAT 失败会停止发布签名能力，KEM 保留。复合能力依赖 Ed25519、SHA-512 和完整公钥指纹所需的 SHA-1 provider。

`.local-pqmagic/sign/build-manifest.txt` 保存编译器、依赖提交、库 SHA-256 与符号表；`correctness.log`、`signature-correctness.log` 保存上游正确性结果。确认实际依赖库：

```bash
ldd src/libstrongswan/plugins/pqmagic/.libs/libstrongswan-pqmagic.so
cat .local-pqmagic/sign/PQMAGIC_COMMIT
sha256sum .local-pqmagic/sign/lib/libpqmagic_std.so
```

## 3. 本地测试

suite 的实际名称是 `signature params`，包含空格。核对输出确实运行目标 suite，不能把零个 suite 的退出 0 当作通过。

```bash
TESTS_SUITES='aigis_sig,composite_aigis_sig,pqmagic_credentials,signature params,auth_cfg,pqmagic_kem' \
  make -C src/libstrongswan/tests check
TESTS_SUITES=aigis_sig_auth,aigis make -C src/libcharon/tests check
python3 scripts/tests/test_pqmagic_sign_build.py
python3 -m unittest discover -s scripts/tests -p 'test_aigis*.py'
sh scripts/tests/run_aigis_sig_primitive.sh
sh scripts/tests/run_aigis_sig_alloc.sh
sh scripts/tests/run_aigis_sig_provider_checks.sh
sh scripts/tests/run_aigis_sig_vici.sh
python3 scripts/tests/run_aigis_sig_mutations.py
sh scripts/tests/run_aigis_sig_matrix.sh
make check
```

矩阵脚本在 `.local-pqmagic/matrix/source` 建立本地副本，验证关闭插件、旧 KEM-only 库及两种预期失败配置；不改当前构建。变异测试在临时目录编译只检查一个分量的插件，要求现有向量/篡改测试将其检出，不改正常插件。

矩阵中的“关闭 pqmagic 却开启签名”和“开启签名却链接旧 KEM-only 库”必须被 configure 拒绝。脚本将这两项显示为 `[PASS] Expected configure rejection`，原始 `configure: error:` 保留在对应日志中；旧版脚本会直接打印这些预期错误。最终输出 `Build matrix: ... passed` 且退出码为 0 表示矩阵通过，无需为这两项错误修改配置。

可选内存检测：

```bash
PRIMITIVE_TEST_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  sh scripts/tests/run_aigis_sig_primitive.sh
ALLOC_TEST_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  sh scripts/tests/run_aigis_sig_alloc.sh
```

分配测试针对新增代码拥有的缓冲区做故障注入，并在释放时检查测试 seed 残留；隔离进程仅加载本算法需要的 OpenSSL default provider。它不等于 PQMagic 和整个 strongSwan 均已完成全面内存审计。受限沙箱可能禁止 socket 或 LeakSanitizer 的线程扫描；本次完整回归和 sanitizer 在沙箱外复核。

## 4. 生成后量子混合证书

### 4.1 一次性实验 PKI

以下脚本已经本地执行验证。每次使用不存在的新目录；不会覆盖旧私钥。生成的是新随机密钥，不使用固定向量中的公开测试 seed。

```bash
# 开发目录使用本仓库 pki 和插件，无需 make install
sh scripts/aigis-sig-create-test-pki.sh "$PWD/.local-pqmagic/lab-m1" m1
sh scripts/aigis-sig-create-test-pki.sh "$PWD/.local-pqmagic/lab-m2" m2
```

M1 输出 `aigisClassicalCa{Key,Cert}.pem`、`moonM1Composite{Key,Cert}.pem`、`sunM1Composite{Key,Cert}.pem`。M2 输出 `aigisCompositeCa{Key,Cert}.pem`、`moonComposite{Key,Cert}.pem`、`sunComposite{Key,Cert}.pem`，并保存 CSR、完整 SPKI DER、SHA-256 清单和证书验证结果。

此脚本将实验 CA 和两个端点私钥集中生成，仅用于封闭实验。真实双机密钥保管建议使用下一节：各端生成自己的私钥，只交换 CSR 和证书。CA 私钥不安装到 IPsec 端点的 `private/`，不提交 Git。

### 4.2 各端保留私钥，通过 CSR 发证

以下用已安装、包含新插件的 `pki`。未安装时将命令开头的 `pki` 替换成 `sh /home/lxh/strongswan/scripts/pki-local.sh`。

在离线 CA 工作目录生成新的 M2 CA：

```bash
umask 077
pki --gen --type aigissig2ed25519 --outform pem > aigisCompositeCaKey.pem
pki --self --type aigissig2ed25519 --in aigisCompositeCaKey.pem \
  --dn 'CN=Aigis Composite Test CA' --ca --lifetime 3650 \
  --digest sha512 --outform pem > aigisCompositeCaCert.pem
```

moon 在自己的安全工作目录执行：

```bash
umask 077
pki --gen --type aigissig2ed25519 --outform pem > moonCompositeKey.pem
pki --req --type aigissig2ed25519 --in moonCompositeKey.pem \
  --dn 'CN=moon.strongswan.org' --san moon.strongswan.org > moon.req.der
```

sun 同样生成独立密钥和 CSR：

```bash
umask 077
pki --gen --type aigissig2ed25519 --outform pem > sunCompositeKey.pem
pki --req --type aigissig2ed25519 --in sunCompositeKey.pem \
  --dn 'CN=sun.strongswan.org' --san sun.strongswan.org > sun.req.der
```

通过已认证渠道把两个 CSR 送给 CA。CA 对每份 CSR 验签后签发；以下循环在 CA 目录执行：

```bash
for node in moon sun; do
  pki --issue --type pkcs10 --in "$node.req.der" \
    --cacert aigisCompositeCaCert.pem --cakey aigisCompositeCaKey.pem \
    --lifetime 365 --digest sha512 --flag serverAuth --flag clientAuth \
    --outform pem > "${node}CompositeCert.pem"
  pki --verify --in "${node}CompositeCert.pem" --cacert aigisCompositeCaCert.pem
done
```

复合 CA 的 keyUsage 含 keyCertSign；新算法叶子明确含 digitalSignature。私钥导入接受固定 PKCS#8 v0 seed 编码；`--size` 缺省或 256，其他值拒绝。显式请求 `--digest sha256` 必须失败。M2 自签根不自动可信，必须预置信任锚并匹配 `remote.cacerts`。

若做 M1，可以用 `--gen --type ed25519` 生成独立实验传统 CA，或由现有受控 Ed25519 CA 对同样的复合 CSR 签发。使用 Ed25519 CA 时省略 `--digest sha512`，并按 M1 模板使用 `*M1Composite*` 文件名与 `aigisClassicalCaCert.pem`。不要复用旧端点的 Ed25519 私钥作为复合组件。

把各自的端点证书和同一 CA 证书返回对应主机。两端分别检查身份、有效期、用途及完整公钥匹配，例如 moon：

```bash
pki --print --in moonCompositeCert.pem
pki --verify --in moonCompositeCert.pem --cacert aigisCompositeCaCert.pem
pki --pub --type priv --in moonCompositeKey.pem > moon-key-public.der
pki --pub --type x509 --in moonCompositeCert.pem > moon-cert-public.der
cmp moon-key-public.der moon-cert-public.der
sha256sum moon-cert-public.der
```

sun 对应替换文件名。SHA-256 记录的是完整 SPKI，不只记录 Ed25519 分量。OpenSSL CLI 尚不认识实验 OID，不能用其验签结果替代本仓库 `pki`；它可辅助查看普通 X.509 扩展。

## 5. 两端安装与配置

先备份两端已有 strongSwan/swanctl 配置和凭据，并记录现有连接名。系统安装和重启会影响正在运行的隧道，选定实验维护窗口后再执行：

```bash
sudo make install
sudo ldconfig
sudo systemctl daemon-reload
```

保留原有配置 include。确认 daemon、`pki`、`swanctl` 实际加载 `pqmagic`、`openssl`、`random`、`pkcs1`、`pkcs8`、`pem`、`x509`；daemon 还需要已验证的网络、VICI、KDF 等插件。若使用显式 `load = ...` 列表，把新插件补入相应工具的列表。沿用 daemon 的 `accept_private_algs = yes`，不要移除已验收的其他插件。

M2 凭据安装示例（在各自持有文件的主机执行）：

```bash
# moon
sudo install -m 600 moonCompositeKey.pem /etc/swanctl/private/moonCompositeKey.pem
sudo install -m 644 moonCompositeCert.pem /etc/swanctl/x509/moonCompositeCert.pem
sudo install -m 644 aigisCompositeCaCert.pem /etc/swanctl/x509ca/aigisCompositeCaCert.pem
# sun 分别安装 sunCompositeKey.pem、sunCompositeCert.pem 和同一 CA 证书
```

两端完整连接配置见 [moon-m2.conf](../testing/tests/ikev2/host2host-aigissig/moon-m2.conf)、[sun-m2.conf](../testing/tests/ikev2/host2host-aigissig/sun-m2.conf)。M1 使用同目录 `moon-m1.conf`、`sun-m1.conf` 及对应凭据。只加载当前阶段的一套配置。

M1 两侧 `auth = ike:aigissig2ed25519-sha512`。M2 两侧 `auth = aigissig2ed25519-sha512`，远端块另有 `cacerts = aigisCompositeCaCert.pem`。本地 token 规范化为 IKE 算法选择，远端执行完整证书链证据检查；这是为了避免本地认证轮次判断误用远端验证结果、反复发送 AUTH。双方均配置 M2 才形成双向完整复合链要求。M2 不接受没有 CA 约束、仅原始公钥或直接信任叶子的替代配置。

先停用重叠 `/32` TS 的旧连接和 trap：终止旧 SA，存在 trap 时用 `swanctl --uninstall --child <旧Child名> --ike <旧连接名>`，并从当前加载配置移除旧自动启动项。备份后将所选完整模板作为实验配置加载；不要同时让旧连接承载相同流量。

先 sun 后 moon 重启、装载并检查：

```bash
sudo systemctl restart strongswan
sudo swanctl --load-all
sudo swanctl --list-conns
sudo swanctl --list-certs
sudo swanctl --list-algs
sudo journalctl -u strongswan -n 100 -l --no-pager
```

`--list-algs` 应有 `AIGIS_ENC_2_SM3[pqmagic]` 和 SHA-512；该接口没有公钥签名算法列表，不能要求它输出复合签名名称。复合能力证据来自完整凭据加载及真实 AUTH 成功日志，而不只是算法列表。缺 provider 或签名自检失败时停止本阶段。

## 6. 双机验收与证据

每个阶段使用新建 SA，记录两端新 IKE unique ID、SPIs、证书完整 SPKI SHA-256、连接名和 UTC 时间。先在独立终端抓包：

```bash
sudo tcpdump -ni any -s0 -w /tmp/aigissig-m2.pcap \
  'host 192.168.199.130 and host 192.168.199.131 and (udp port 500 or udp port 4500 or ip proto 50)'
```

在 moon：

```bash
sudo swanctl --initiate --child host-host-aigissig
sudo swanctl --list-sas --raw > /tmp/aigissig-before.txt
ping -I 192.168.199.131 -c 4 192.168.199.130
sudo swanctl --list-sas --raw > /tmp/aigissig-after.txt
sudo journalctl -u strongswan --since '-5 minutes' -l --no-pager
```

sun 反向执行 `ping -I 192.168.199.130 -c 4 192.168.199.131` 并保存前后计数。必须同时确认：

1. 连接为 `host-host-aigissig`，IKE `ESTABLISHED`、Child `INSTALLED`，TS 恰为双方 `/32`。
2. 两端日志分别出现自身和对端 `COMPOSITE_AIGIS_SIG2_ED25519_SHA512 successful`；KEM 为 ECP_256 + AIGIS_ENC_2_SM3。
3. IKE_AUTH 实际发生加密分片/重组，两个方向都有证据；不能拿旧 IKE_INTERMEDIATE 的小报文代替。
4. 两端 `--list-sas --raw` 中当前 ESP 的 bytes/packets 随双向 ping 增长，避免测到旧 SA。

AUTH 内容已加密，pcap 不能直接证明内层 OID；精确 AUTH_DS/OID/长度已由本地解码测试覆盖。保持正常日志级别，不为查看 AUTH 开启可能输出私钥/会话秘密的高等级调试。

分别从两端主动做 Child 与 IKE rekey，等待新 SA ID/计数稳定后再进行下一项；然后从两端分别发起**完整重新认证**：

```bash
sudo swanctl --rekey --child host-host-aigissig
sudo swanctl --rekey --ike host-host-aigissig
sudo swanctl --rekey --ike host-host-aigissig --reauth
sudo swanctl --list-sas --raw
```

每次完整重新认证须出现新 IKE_AUTH 和新的双向复合认证日志；普通 rekey 本身不能证明重新签验。重新认证后再做双向 ping/ESP 计数检查。封闭实验中还应在受控丢包条件下检查 AUTH 分片重传，并保存抓包与日志；本地用户态已测重复分片不触发重复认证，真实网络丢包行为仍待双机验证。

在配置副本逐项负向测试，失败后恢复当前阶段配置：旧 Ed25519 端点凭据、错误身份、错误 CA、M2 下传统 CA 替代链、无 CA、原始公钥/直接信任叶子替代链。预期配置拒绝或没有新的成功 SA；不得加 `pubkey`、经典备选 proposal 或 `ke1_none` 让强制连接自动降级。

## 7. 回滚

终止 `host-host-aigissig`，恢复两端备份的旧配置和凭据选择，重新加载/重启并新建原连接，确认原算法和 ESP 计数恢复。配置 reload 不会改变已有 SA 的算法。实验私钥留在受控目录中，不把 CA 私钥、端点私钥或会话密钥放入测试报告、抓包附注或 Git。

本版本属于实验接入。PQMagic 内部秘密工作区擦除、完整依赖加固、独立组合密码分析、在线吊销及真实双机重新认证/丢包/ESP 验收仍需分别记录，不能由本地工程测试替代。
