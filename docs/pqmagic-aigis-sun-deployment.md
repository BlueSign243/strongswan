# sun 端拉取、构建与验证 Aigis-enc

本阶段开发分支为 **`feature/aigis-enc-pqmagic`**，远程仓库为 `https://github.com/BlueSign243/strongswan.git`。两端测试通过前不合并到 `master`。moon 已由用户完成编译；sun 需要相同分支、相同 PQMagic 提交与 SM3 变体。以下命令在 sun 执行；路径按 sun 的登录用户使用 `~`，不要求用户名与 moon 相同。

## 1. 获取开发分支

推荐新建源码目录，保留 sun 原有可用源码和构建环境：

```bash
git clone --branch feature/aigis-enc-pqmagic --single-branch \
  https://github.com/BlueSign243/strongswan.git ~/strongswan-aigis
cd ~/strongswan-aigis
git status --short --branch
git log -1 --oneline
```

如果 sun 已有这个远程仓库的干净 checkout，也可以在该目录首次切换分支：

```bash
cd ~/strongswan
git status --short
git remote -v
git fetch origin
git switch --track origin/feature/aigis-enc-pqmagic
git pull --ff-only
```

`origin` 应指向 `BlueSign243/strongswan`；若实际是上游仓库，使用前面的新目录克隆命令。有本地改动时先自行保存；不要用 `reset --hard` 覆盖。之后更新已切换的分支只需执行 `git fetch origin` 和 `git pull --ff-only`。下面以新目录 `~/strongswan-aigis` 为例。

## 2. 准备 PQMagic 和编译工具

已有 ML-KEM 编译环境时通常已安装这些依赖；若有缺项：

```bash
sudo apt update
sudo apt install git build-essential autoconf automake libtool pkg-config \
  perl python3 flex bison gperf libssl-dev libsystemd-dev libgmp-dev
```

PQMagic 源码不包含在本分支中。sun 尚无该依赖时，克隆并固定到与 moon 相同的版本：

```bash
git clone https://github.com/pqcrypto-cn/PQMagic.git ~/PQMagic-aigis
git -C ~/PQMagic-aigis checkout --detach 42f5b6e6fe7e4951ffc9437ecd77c9a5af93ff08
git -C ~/PQMagic-aigis rev-parse HEAD
```

如果已经有 PQMagic，可复用原目录，但先确认没有未提交改动，且 HEAD 为上述提交，并相应修改下面脚本的源目录参数。构建脚本适用于当前 Ubuntu/Linux x86-64 环境，固定选择 Aigis-enc mode 2 / SM3，不需要 CMake。

## 3. 编译 PQMagic 与 strongSwan

```bash
cd ~/strongswan-aigis
sh scripts/build-pqmagic-aigis.sh ~/PQMagic-aigis "$PWD/.local-pqmagic/install"
./autogen.sh
PQMAGIC_PREFIX="$PWD/.local-pqmagic/install"
./configure --prefix=/usr --sysconfdir=/etc \
  --enable-systemd --enable-swanctl --enable-vici \
  --enable-pki --enable-openssl --enable-ml --enable-sha3 \
  --enable-pqmagic --enable-test-vectors \
  --disable-charon --disable-stroke \
  PQMAGIC_CFLAGS="-I$PQMAGIC_PREFIX/include" \
  PQMAGIC_LIBS="-L$PQMAGIC_PREFIX/lib -Wl,-rpath,$PQMAGIC_PREFIX/lib -lpqmagic_std"
make -j4
```

PQMagic 脚本会编译独立依赖并运行 1000 次 keypair/enc/dec 正确性测试，应出现 `[+] Success.`。随后生成 `libstrongswan-pqmagic.so`。RUNPATH 指向 **sun 自己的** `.local-pqmagic/install/lib`，安装后不要移动或删除该目录；该实验部署沿用此路径。不能直接复制 moon 的二进制插件或它的构建缓存。

## 4. 先运行本地测试

```bash
cd ~/strongswan-aigis
TESTS_SUITES=pqmagic_kem,proposal make -C src/libstrongswan/tests check

# 此文件按追加模式写入，先截断，避免旧记录造成误判。
: > .local-pqmagic/sun-active-transforms.txt
TESTS_SUITES=vectors \
  TESTS_ACTIVE_TRANSFORMS="$PWD/.local-pqmagic/sun-active-transforms.txt" \
  make -C src/libstrongswan/tests check
grep -F 'AIGIS_ENC_2_SM3[pqmagic]' .local-pqmagic/sun-active-transforms.txt

TESTS_FUNCTIONS=test_regular_multi_ke,test_aigis_invalid_ciphertext \
  make -C src/libcharon/tests check
python3 scripts/tests/test_aigis_rekey_wait.py
make check
```

应实际看到 `pqmagic_kem`、`proposal`、`vectors` suite，Aigis 的 KAT 记录，以及 IKE/Child rekey 与错误密文测试。moon 本地已通过 6 个测试程序、共 73 个 suite，另有 3 个等待器测试；sun 使用相同配置时可作为对照。零个 suite 或没有 Aigis 记录不算验证成功。普通用户在正常终端执行测试即可，无需用 sudo 运行单元测试。

## 5. 安装与双机测试

本地测试通过后，在 sun 先备份配置，再安装。备份不输出私钥内容；目录仅 root 可读：

```bash
cd ~/strongswan-aigis
AIGIS_BACKUP_DIR="/root/strongswan-pre-aigis-$(date +%Y%m%d-%H%M%S)"
sudo install -d -m 700 "$AIGIS_BACKUP_DIR"
sudo cp -a /etc/swanctl /etc/strongswan.conf /etc/strongswan.d "$AIGIS_BACKUP_DIR/"
sudo make install
sudo ldconfig
sudo systemctl daemon-reload
```

两端都需要安装修改后的 libstrongswan 和新插件；moon 仅编译而尚未安装时，也要在 moon 自己的源码目录执行安装。使用原有 sun 证书、私钥及 CA，不需要重新生成凭据。

在两端 `/etc/swanctl/swanctl.conf` 的 `host-host` 连接修改以下三项，分别放在连接层和 Child 层：

```text
# connections.host-host
fragmentation = yes
proposals = aes256gcm16-prfsha384-ecp256-ke1_aigisenc2sm3

# connections.host-host.children.host-host
esp_proposals = aes256gcm16-ecp256-ke1_aigisenc2sm3
```

sun 的 `local_addrs`/`local_ts` 仍对应 `192.168.199.130`，远端为 moon `192.168.199.131`。在两端 `/etc/strongswan.conf` 现有 `charon` 节合并 `accept_private_algs = yes`，保留已有 include 与插件装载配置；确认 `/etc/strongswan.d/charon/pqmagic.conf` 中 `load = yes`。私有方法号为 65002，两端不得用其他算法或变体冒用该编号。

先 sun 后 moon 重启，并在两端检查：

```bash
sudo systemctl restart strongswan
sudo swanctl --list-algs
sudo swanctl --list-conns
sudo journalctl -u strongswan -n 80 -l --no-pager
```

两端均应包含 `AIGIS_ENC_2_SM3[pqmagic]`。在 sun 主动建立连接并验证流量：

```bash
sudo swanctl --initiate --child host-host
ping -I 192.168.199.130 -c 4 192.168.199.131
sudo swanctl --list-sas --raw
```

确认 IKE `ESTABLISHED`、`dh-group=ECP_256 ake1=AIGIS_ENC_2_SM3`、Child `INSTALLED`，且 ping 使 ESP 计数增加。再从 moon 反向 ping，并分别在两端主动验证 IKE/Child rekey。可复用带等待和新 SA ID 检查的测试辅助脚本：

```bash
sudo bash testing/hosts/default/usr/local/bin/expect-rekey child host-host
sudo bash testing/hosts/default/usr/local/bin/expect-rekey ike host-host
sudo swanctl --list-sas --raw
```

每轮必须输出 `Rekeyed ...: 旧ID -> 新ID`，再执行下一轮；该辅助脚本要求开始时对应名称只有一个有效 SA。`swanctl --rekey` 返回成功只表示请求已提交，不能单独证明交换完成。

**合并条件：** sun 本地构建/测试、两端 Aigis 实际协商、双向 ESP 流量和双方主动 rekey 均通过后，再评估合并到 `master`。当前分支保留测试中的实现，尚不能把模拟协议测试当作真实双机验收。
