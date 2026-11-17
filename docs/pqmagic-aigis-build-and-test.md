# Aigis-enc 本地构建、测试与 moon/sun 部署

远程开发分支为 `feature/aigis-enc-pqmagic`。sun 从仓库获取源码到编译、测试和双机验收的完整顺序见 [sun 部署说明](pqmagic-aigis-sun-deployment.md)；阶段测试通过前不合并到 `master`。

本实现提供 **ECP_256 + Aigis-enc mode 2 / SM3** 混合密钥交换，插件名 `pqmagic`，算法名 `AIGIS_ENC_2_SM3`，proposal 关键字 `aigisenc2sm3`。方法号 **65002 是私有实验值**，双方必须使用本实现及相同 PQMagic 变体。现有证书、Ed25519 认证和 ESP 算法保留；没有接入 Aigis-sig。

依赖源目录 `/home/lxh/PQMagic`，本次版本为 `42f5b6e6fe7e4951ffc9437ecd77c9a5af93ff08`。未把依赖源复制进 strongSwan；构建输出位于 `.local-pqmagic/`，未修改系统安装及正在运行的配置。实现依据见[接入计划](pqmagic-aigis-ipsec-integration-plan.md)，详细验证记录见[实施记录](aigis-enc-implementation-progress.md)。

## 1. 在源码目录构建

以下步骤不需要修改 `/etc`，也不需要停止原有服务。当前环境没有 CMake，辅助脚本按 PQMagic std 构建规则仅编译 Aigis-enc mode 2 与 SM3 所需文件，同时运行上游 1000 次正确性测试。该脚本的 SM3 实现路径适用于当前 Linux/x86-64 环境。

```bash
cd /home/lxh/strongswan
sh scripts/build-pqmagic-aigis.sh /home/lxh/PQMagic "$PWD/.local-pqmagic/install"
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

插件链接的库路径会写入 RUNPATH，方便本地测试。两台机器分别在各自源码目录构建，不能直接复制带 moon 本地路径的插件到 sun。正式安装可以把依赖放到统一安装前缀，并调整 `PQMAGIC_CFLAGS/LIBS`。开启插件但找不到头文件/五个 std API 时 configure 会报错；`--disable-pqmagic` 时不需要 PQMagic。

生产随机数由 strongSwan `RNG_STRONG` 提供，分别生成 64-byte keypair coins、32-byte encapsulation coins，再调用 PQMagic internal API；测试用对象级 DRBG。算法启动时用固定输入验证 SM3 结果，误链接 SHAKE 库会拒绝加载，不能只看三个函数符号是否存在。

## 2. 运行本地测试

```bash
# 算法对象和 proposal：这些 suite 必须实际出现在输出中
TESTS_SUITES=pqmagic_kem,proposal make -C src/libstrongswan/tests check

# KAT：记录实际验证过的算法，不能把未装载/跳过当作通过
TESTS_SUITES=vectors \
  TESTS_ACTIVE_TRANSFORMS="$PWD/.local-pqmagic/active-transforms.txt" \
  make -C src/libstrongswan/tests check
rg 'AIGIS_ENC_2_SM3|ML_KEM' .local-pqmagic/active-transforms.txt

# 双方 IKE/Child rekey 与错误密文负向测试
TESTS_FUNCTIONS=test_regular_multi_ke,test_aigis_invalid_ciphertext \
  make -C src/libcharon/tests check

# 全仓库默认检查
make check

# 网络用例异步 rekey 等待器的回归测试
python3 scripts/tests/test_aigis_rekey_wait.py
```

KAT 应包含 `AIGIS_ENC_2_SM3[pqmagic]`。算法对象测试覆盖缓冲区长度、未完成时读取秘密、getter 缓存与返回副本、重复 setter 拒绝、隐式拒绝和 RNG 失败。重复 setter 返回 FALSE 并保留原有成功结果；错误长度不生成秘密，允许在原对象上用正确输入重试。

`test_regular_multi_ke` 的循环 0/1 保留原有经典测试，2/3 使用真实 OpenSSL ECDH 与 PQMagic，覆盖初建及双方主动 rekey。`test_aigis_invalid_ciphertext` 在解密后注入等长错误密文，验证派生密钥不一致时无法完成认证。

这些本地协议测试沿用 strongSwan 测试框架的 PSK、模拟内核和报文队列；它们会执行 IKE 编解码与加密，但**不等于真实网络的证书认证、内核 XFRM 或 ESP ping 已通过**。socket 测试在受限沙箱内可能失败，本次基线已确认沙箱外能通过，完整结果见实施记录。

新增完整虚拟机网络用例：`testing/tests/ikev2/host2host-aigisenc/`，使用测试平台自带 moon/sun 地址 `192.168.0.1/2` 和证书，不能直接覆盖用户当前的 `192.168.199.131/130` 配置。用例通过 `expect-rekey` 等待每轮新 SA ID，避免把异步请求返回或旧 SA 当作 rekey 成功。需按 `testing/README` 准备带新插件与依赖的 guest 镜像后运行；本次未运行该虚拟机平台。

## 3. 在实际 moon/sun 环境安装并联调

本节命令供两端部署使用，本次没有执行系统安装、修改 `/etc` 或发起远端通信。sun 也必须安装新插件和修改后的 libstrongswan；只修改配置无法让原版识别新方法。先保留两端原有配置备份，再分别执行：

```bash
sudo make install
sudo ldconfig
sudo systemctl daemon-reload
```

确认 `/etc/strongswan.d/charon/pqmagic.conf` 中 `load = yes`，并在原有 `/etc/strongswan.conf` 的 `charon` 节合并设置：

```text
charon {
    accept_private_algs = yes
}
```

保留已有 `load_modular` 和 `plugins` include。两端 `/etc/swanctl/swanctl.conf` 的 `host-host` 连接只需把已经验证的 ML-KEM 附加交换替换为 Aigis，保留地址、身份、证书、TS 等其他设置：

```text
connections {
    host-host {
        fragmentation = yes
        proposals = aes256gcm16-prfsha384-ecp256-ke1_aigisenc2sm3
        children {
            host-host {
                esp_proposals = aes256gcm16-ecp256-ke1_aigisenc2sm3
            }
        }
    }
}
```

该片段是修改位置示意，不是替换整个文件。moon 地址仍为 `192.168.199.131`，sun 为 `192.168.199.130`；使用原有 moon/sun 证书及私钥，不需要创建 Aigis 凭据文件。两端均不要加入 `ke1_none` 或经典回退 proposal，以便验证实际协商结果。

先 sun 后 moon 重启并检查：

```bash
sudo systemctl restart strongswan
sudo swanctl --list-algs
sudo swanctl --list-conns
sudo journalctl -u strongswan -n 80 -l --no-pager
```

两端必须出现 `AIGIS_ENC_2_SM3[pqmagic]`。然后在 moon 执行：

```bash
sudo swanctl --initiate --child host-host
ping -I 192.168.199.131 -c 4 192.168.199.130
sudo swanctl --list-sas --raw
sudo swanctl --rekey --child host-host
sudo swanctl --list-sas --raw
sudo swanctl --rekey --ike host-host
sudo swanctl --list-sas --raw
```

等待每次 rekey 完成后再执行下一步。验收应确认 `dh-group=ECP_256 ake1=AIGIS_ENC_2_SM3`、IKE `ESTABLISHED`、Child `INSTALLED`、ESP 计数随 ping 增长，日志出现 IKE_INTERMEDIATE / IKE_FOLLOWUP_KE。首个 Child 继承混合 IKE 密钥；Child rekey 才实际执行独立的 ECDH + Aigis PFS。再由 sun 反向 ping 并主动执行两类 rekey。

回退时恢复两端已验证的 `ke1_mlkem768` 配置，重新加载并重建 IKE SA；只重新加载配置不会改变已建立 SA 的协商算法。
