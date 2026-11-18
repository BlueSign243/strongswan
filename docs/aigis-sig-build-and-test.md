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

## 4. 生成后量子混合证书：各端保管私钥，moon 统一签发

本章只使用真实双机密钥保管方式：moon 是当前本机，兼任本次实验 CA；sun 是另一台 Ubuntu 虚拟机。两端分别生成自己的复合私钥，CA 私钥仅由 moon 保管。生成文件均放在各自的 `~/ipsec-lab`，安装目录仍为 `/etc/swanctl/*`。

“moon 生成 CA、签发 moon 证书、把 CA 证书交给 sun”可行；但 **sun 仅凭 CA 证书不能签发自己的证书**。签发需要 CA 私钥。合理流程是 sun 生成私钥和 CSR，把 CSR 送回 moon 签发，再取回签好的证书。CA 证书用于验证和建立信任，可以先送给 sun；不能代替 CA 私钥的签发能力。

| 顺序 | 操作端 | 操作或传输 | 私钥位置 |
| --- | --- | --- | --- |
| 1 | moon | 生成复合 CA、moon 私钥与 CSR，签发 moon 证书 | CA 和 moon 私钥留在 moon |
| 2 | moon → sun | 经 Windows 共享文件夹传输 CA 证书 | 不传私钥 |
| 3 | sun → moon | sun 本地生成独立私钥和 CSR，只传 CSR | sun 私钥留在 sun |
| 4 | moon → sun | moon 用 CA 私钥签发 sun 证书，只传签好的证书 | CA 私钥仍留在 moon |
| 5 | 两端 | 各自核验后安装自己的私钥、证书和同一 CA 证书 | 不安装 CA 私钥 |

此处选择 M2：CA、公钥、CSR、端点证书签名和 IKE AUTH 均使用复合算法。moon 同时承担 CA 与 VPN 端点，符合当前实验安排，但它不是离线 CA；后续若隔离 CA，应迁移 CA 私钥保管位置，签发流程仍通过 CSR 完成。

### 4.1 两端准备本地目录与工具

先完成两端的第 2、3 章构建和本地测试，确认 sun 使用同一签名实现与 profile，不能只安装此前的 KEM-only 版本。下面命令在 **moon、sun 各自的 Bash 终端**执行；`SIG_REPO` 改为该机实际源码目录，例如 sun 可能是 `$HOME/strongswan-aigis`：

```bash
SIG_REPO="$HOME/strongswan"
test -f "$SIG_REPO/scripts/pki-local.sh"
pki() { sh "$SIG_REPO/scripts/pki-local.sh" "$@"; }

umask 077
mkdir -p "$HOME/ipsec-lab"
chmod 700 "$HOME/ipsec-lab"
cd "$HOME/ipsec-lab"
# 拒绝用 > 覆盖已有密钥、CSR、证书和核验记录。
set -o noclobber
```

`pki` 是当前 shell 的函数，固定使用本仓库构建的程序与插件，无需先安装系统文件。新开终端后须重新设置 `SIG_REPO` 和该函数。`~/ipsec-lab` 必须是本机目录，不要把它建在共享目录或把它链接到共享目录。已有经典凭据可以保留；本章采用新的 `*Composite*` 文件名，不覆盖旧凭据。

以下按顺序逐条执行，任何命令失败就停止检查。遇到 `cannot overwrite existing file` 时，先确认是否已经完成该步；不要删除已有私钥重新生成，否则会使已有 CSR、证书失配。

### 4.2 moon：生成复合 CA 并签发 moon 证书

在 **moon** 的 `~/ipsec-lab` 执行：

```bash
cd "$HOME/ipsec-lab"
pki --gen --type aigissig2ed25519 --outform pem > aigisCompositeCaKey.pem
pki --self --type aigissig2ed25519 --in aigisCompositeCaKey.pem \
  --dn 'CN=Aigis Composite Test CA' --ca --lifetime 3650 \
  --digest sha512 --outform pem > aigisCompositeCaCert.pem
pki --print --in aigisCompositeCaCert.pem

pki --gen --type aigissig2ed25519 --outform pem > moonCompositeKey.pem
pki --req --type aigissig2ed25519 --in moonCompositeKey.pem \
  --dn 'CN=moon.strongswan.org' --san moon.strongswan.org > moon.req.der
pki --issue --type pkcs10 --in moon.req.der \
  --cacert aigisCompositeCaCert.pem --cakey aigisCompositeCaKey.pem \
  --lifetime 365 --digest sha512 --flag serverAuth --flag clientAuth \
  --outform pem > moonCompositeCert.pem

pki --verify --in moonCompositeCert.pem --cacert aigisCompositeCaCert.pem
pki --print --in moonCompositeCert.pem
pki --pub --type priv --in moonCompositeKey.pem > moon-key-public.der
pki --pub --type x509 --in moonCompositeCert.pem > moon-cert-public.der
cmp moon-key-public.der moon-cert-public.der
sha256sum moon-cert-public.der > moon-SPKI-SHA256.txt
chmod 600 aigisCompositeCaKey.pem moonCompositeKey.pem
```

确认 `--verify` 成功、`cmp` 无输出且退出 0，moon 证书含预期 SAN `moon.strongswan.org`、有效期及 digitalSignature 用途。复合 CA 的 keyUsage 含 keyCertSign。CA 和叶子的公钥类型应为 `COMPOSITE_AIGIS_SIG2_ED25519`，签名方案为 `COMPOSITE_AIGIS_SIG2_ED25519_SHA512`。

### 4.3 moon → sun：经共享文件夹传输 CA 证书

moon 已确认的 VMware 共享挂载为 `/mnt/hgfs/share`。以下约定 Windows 上同一个共享目录中的 `aigissig-m2` 作为本轮中转目录。sun 若挂载路径不同，只修改 sun 的 `SIG_SHARE`，确保仍指向 Windows 上同一个目录。不要把整个 `~/ipsec-lab` 复制到共享文件夹。

在 **moon** 执行：

```bash
SIG_SHARE=/mnt/hgfs/share/aigissig-m2
mkdir -p "$SIG_SHARE/moon-to-sun" "$SIG_SHARE/sun-to-moon"
cd "$HOME/ipsec-lab"
sha256sum aigisCompositeCaCert.pem > CA-CERT-SHA256.txt
cp -i aigisCompositeCaCert.pem CA-CERT-SHA256.txt "$SIG_SHARE/moon-to-sun/"
```

在 **sun** 执行（已完成 4.1）：

```bash
SIG_SHARE=/mnt/hgfs/share/aigissig-m2
cd "$HOME/ipsec-lab"
cp -i "$SIG_SHARE/moon-to-sun/aigisCompositeCaCert.pem" .
cp -i "$SIG_SHARE/moon-to-sun/CA-CERT-SHA256.txt" .
sha256sum -c CA-CERT-SHA256.txt
pki --print --in aigisCompositeCaCert.pem
sha256sum aigisCompositeCaCert.pem
```

还须把 sun 最后一条命令的 SHA-256 与 **moon 本地终端**的 `sha256sum "$HOME/ipsec-lab/aigisCompositeCaCert.pem"` 输出逐字核对。共享目录中的证书和校验清单可以同时被替换，单独执行 `sha256sum -c` 只能检查传输一致性，不能独立建立信任；本实验可通过本人控制的两台虚拟机控制台核对。这里记录的是 CA 证书 PEM 文件的 SHA-256。

若两个虚拟机没有同时挂载同一个 Windows 目录，可由 Windows 手工中转这些明确列出的文件，顺序和核验要求相同。不要用文本编辑器修改 PEM、DER 或校验清单。

### 4.4 sun：生成自己的私钥和 CSR，交给 moon

在 **sun** 的 `~/ipsec-lab` 执行：

```bash
cd "$HOME/ipsec-lab"
pki --gen --type aigissig2ed25519 --outform pem > sunCompositeKey.pem
pki --req --type aigissig2ed25519 --in sunCompositeKey.pem \
  --dn 'CN=sun.strongswan.org' --san sun.strongswan.org > sun.req.der
pki --pub --type priv --in sunCompositeKey.pem > sun-key-public.der
pki --pub --type pkcs10 --in sun.req.der > sun-request-public.der
cmp sun-key-public.der sun-request-public.der
sha256sum sun.req.der > SUN-CSR-SHA256.txt
sha256sum sun-key-public.der > sun-SPKI-SHA256.txt
chmod 600 sunCompositeKey.pem
cp -i sun.req.der SUN-CSR-SHA256.txt sun-SPKI-SHA256.txt "$SIG_SHARE/sun-to-moon/"
```

`sunCompositeKey.pem` 不离开 sun。`sun-key-public.der` 是完整复合 SPKI，其 SHA-256 包括两个公钥分量；这是后续比较对象，不是私钥。复制到共享目录的只有 CSR 和公开校验记录。

### 4.5 moon：核验 sun 的 CSR 并签发

在 **moon** 执行：

```bash
cd "$HOME/ipsec-lab"
cp -i "$SIG_SHARE/sun-to-moon/sun.req.der" .
cp -i "$SIG_SHARE/sun-to-moon/SUN-CSR-SHA256.txt" .
cp -i "$SIG_SHARE/sun-to-moon/sun-SPKI-SHA256.txt" .
sha256sum -c SUN-CSR-SHA256.txt
pki --pub --type pkcs10 --in sun.req.der > sun-request-public.der
sha256sum sun.req.der sun-request-public.der
```

把 CSR 的 SHA-256 与 sun 本地 `sha256sum sun.req.der` 对照，把 `sun-request-public.der` 的 SHA-256 与 sun 本地 `sun-SPKI-SHA256.txt` 中的值对照（文件名不同，比较摘要值）。与 CA 证书相同，应通过本人控制的 sun 控制台确认来源。`pki --pub --type pkcs10` 加载时会验证 CSR 的复合自签名，但 CSR 自签名不能独立证明提交者身份。

确认是本轮 sun 发来的申请后，在 **moon** 签发：

```bash
pki --issue --type pkcs10 --in sun.req.der \
  --cacert aigisCompositeCaCert.pem --cakey aigisCompositeCaKey.pem \
  --lifetime 365 --digest sha512 --flag serverAuth --flag clientAuth \
  --outform pem > sunCompositeCert.pem
pki --verify --in sunCompositeCert.pem --cacert aigisCompositeCaCert.pem
pki --print --in sunCompositeCert.pem
pki --pub --type x509 --in sunCompositeCert.pem > sun-cert-public.der
cmp sun-request-public.der sun-cert-public.der
sha256sum sunCompositeCert.pem > SUN-CERT-SHA256.txt
cp -i sunCompositeCert.pem SUN-CERT-SHA256.txt "$SIG_SHARE/moon-to-sun/"
```

检查证书 DN/SAN 为预期的 `sun.strongswan.org`、有效期和用途正确，`--verify` 成功且 `cmp` 无输出。moon 只有 sun 的 CSR、公钥和证书，始终没有 sun 私钥；签发使用的是 moon 保存的 `aigisCompositeCaKey.pem`。

### 4.6 sun：取回证书，核对自己的完整公钥

在 **sun** 执行：

```bash
cd "$HOME/ipsec-lab"
cp -i "$SIG_SHARE/moon-to-sun/sunCompositeCert.pem" .
cp -i "$SIG_SHARE/moon-to-sun/SUN-CERT-SHA256.txt" .
sha256sum -c SUN-CERT-SHA256.txt
pki --verify --in sunCompositeCert.pem --cacert aigisCompositeCaCert.pem
pki --print --in sunCompositeCert.pem
pki --pub --type x509 --in sunCompositeCert.pem > sun-cert-public.der
cmp sun-key-public.der sun-cert-public.der
sha256sum sun-cert-public.der
```

与 sun 自己的 `sun-SPKI-SHA256.txt` 核对，确认两分量完整公钥匹配。检查 SAN `sun.strongswan.org`、有效期和 digitalSignature 用途后再安装。

最终 moon 的 `~/ipsec-lab` 保存 CA 私钥/证书、moon 私钥/CSR/证书、sun CSR/证书及核验记录；sun 的 `~/ipsec-lab` 保存 CA 证书、sun 私钥/CSR/证书及核验记录。共享目录只包含 CA 证书、sun CSR、sun 证书和公开校验记录。`*Key.pem` 不进入共享目录、Windows 中转目录或 Git，CA 私钥不安装到 `/etc/swanctl/private/`。

私钥编码为固定 PKCS#8 v0 seed 格式；生成时 `--size` 缺省或 256，其他值拒绝。复合签名固定使用 SHA-512，显式请求 `--digest sha256` 必须失败。自签 CA 不会自动成为可信根，第 5 章须安装其证书并通过 `remote.cacerts` 绑定它。OpenSSL CLI 不支持本项目实验算法的验签，不能替代本仓库 `pki`。

如先做 M1，仍使用本章的分端私钥/CSR 流程，只将 CA 换成独立 Ed25519 CA、对应签发命令省略 `--digest sha512`，并采用 M1 模板的 `aigisClassicalCaCert.pem` 和 `*M1Composite*` 文件名。CA 私钥仍留在 moon；M1 不能作为完整复合证书链验收结果。

## 5. 两端安装与配置

先备份两端已有 strongSwan/swanctl 配置和凭据，并记录现有连接名。系统安装和重启会影响正在运行的隧道，选定实验维护窗口后再执行：

```bash
# 在各自的 strongSwan 源码目录执行，不是在 ~/ipsec-lab
cd "$SIG_REPO"
sudo make install
sudo ldconfig
sudo systemctl daemon-reload
```

保留原有配置 include。确认 daemon、`pki`、`swanctl` 实际加载 `pqmagic`、`openssl`、`random`、`pkcs1`、`pkcs8`、`pem`、`x509`；daemon 还需要已验证的网络、VICI、KDF 等插件。若使用显式 `load = ...` 列表，把新插件补入相应工具的列表。沿用 daemon 的 `accept_private_algs = yes`，不要移除已验收的其他插件。

M2 凭据从各自的 `~/ipsec-lab` 安装。先在 **moon** 执行：

```bash
sudo install -d -m 755 /etc/swanctl/x509 /etc/swanctl/x509ca
sudo install -d -m 700 /etc/swanctl/private
sudo install -m 600 "$HOME/ipsec-lab/moonCompositeKey.pem" /etc/swanctl/private/moonCompositeKey.pem
sudo install -m 644 "$HOME/ipsec-lab/moonCompositeCert.pem" /etc/swanctl/x509/moonCompositeCert.pem
sudo install -m 644 "$HOME/ipsec-lab/aigisCompositeCaCert.pem" /etc/swanctl/x509ca/aigisCompositeCaCert.pem
```

在 **sun** 执行：

```bash
sudo install -d -m 755 /etc/swanctl/x509 /etc/swanctl/x509ca
sudo install -d -m 700 /etc/swanctl/private
sudo install -m 600 "$HOME/ipsec-lab/sunCompositeKey.pem" /etc/swanctl/private/sunCompositeKey.pem
sudo install -m 644 "$HOME/ipsec-lab/sunCompositeCert.pem" /etc/swanctl/x509/sunCompositeCert.pem
sudo install -m 644 "$HOME/ipsec-lab/aigisCompositeCaCert.pem" /etc/swanctl/x509ca/aigisCompositeCaCert.pem
```

`$HOME` 由普通用户的 shell 在调用 sudo 前展开，指向该端登录用户的目录；不要切换到 root 后把它误当作 `/root/ipsec-lab`。两端只安装自己的端点私钥、证书和公共 CA 证书。

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
