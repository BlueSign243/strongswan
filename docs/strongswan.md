# strongSwan 6.1.0 双机 Host-to-Host 实验记录

本文记录本次在两台 Ubuntu 虚拟机上跑通 strongSwan IKEv2/IPsec 的可复现步骤。命令由使用者在对应虚拟机执行。编译使用 `--prefix=/usr --sysconfdir=/etc`；证书、配置和成功标志依据本次操作与日志记录。

| 角色 | 虚拟机     | IP                   | IKE 身份                                       |
| ---- | ---------- | -------------------- | ---------------------------------------------- |
| moon | Ubuntu64-1 | `192.168.199.131`  | `C=CH, O=strongSwan, CN=moon.strongswan.org` |
| sun  | Ubuntu64-2 |  `192.168.199.130` | `C=CH, O=strongSwan, CN=sun.strongswan.org`  |

两台虚拟机原本已能互相 ping 通。源码为 `strongswan-master`（`configure.ac` 标记 6.1.0），虚拟机中的源码目录为 `~/strongswan`。采用 `charon-systemd`、`swanctl`、X.509/Ed25519 证书认证和默认的 IPsec tunnel mode。参考本地 [README](../README.md)、[HACKING](../HACKING) 与 [Host-to-Host 测试](../testing/tests/ikev2/host2host-cert/)。

## 1. 两端安装依赖并编译源码

在 **moon 和 sun 各自**执行。确保两端使用同一份源码；如果系统还安装了发行版的 strongSwan，先检查它是否启动了另一套 `strongswan-starter` 服务，避免与源码安装的守护进程冲突。

```bash
dpkg -l 'strongswan*' 'charon*'
systemctl status strongswan-starter --no-pager

sudo apt update
sudo apt install build-essential autoconf automake libtool pkg-config \
  perl python3 flex bison gperf libssl-dev libsystemd-dev libgmp-dev

cd ~/strongswan
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc \
  --enable-systemd --enable-swanctl --enable-vici \
  --enable-pki --enable-openssl \
  --disable-charon --disable-stroke
make -j"$(nproc)"
sudo make install
sudo ldconfig
sudo systemctl daemon-reload

command -v swanctl
command -v pki
swanctl --version
```

这是开发源码快照，根目录尚无预生成的 `configure`，所以要先运行 `./autogen.sh`。`--prefix=/usr` 将程序安装到 `/usr` 下（`swanctl`、`charon-systemd` 通常位于 `/usr/sbin`），`--sysconfdir=/etc` 将配置和凭据放在 `/etc/swanctl`。可用 `command -v swanctl` 和 `systemctl cat strongswan` 核对实际路径。本次服务单元的 `ExecStartPost` 会运行 `swanctl --load-all --noprompt`，因此证书和配置应放好后再启动服务。

## 2. 生成 CA 与 moon 证书

在 **moon** 执行。`umask 077` 防止新生成的私钥被其他用户读取。已有的同一套 CA 不要重新生成，否则原先签发的证书将不再与它匹配。

```bash
mkdir -p ~/ipsec-lab
cd ~/ipsec-lab
umask 077

pki --gen --type ed25519 --outform pem > strongswanKey.pem
pki --self --ca --lifetime 3652 \
  --in strongswanKey.pem \
  --dn "C=CH, O=strongSwan, CN=strongSwan Root CA" \
  --outform pem > strongswanCert.pem

pki --gen --type ed25519 --outform pem > moonKey.pem
pki --req --type priv --in moonKey.pem \
  --dn "C=CH, O=strongSwan, CN=moon.strongswan.org" \
  --san moon.strongswan.org \
  --outform pem > moonReq.pem

pki --issue --cacert strongswanCert.pem --cakey strongswanKey.pem \
  --type pkcs10 --in moonReq.pem --lifetime 1826 \
  --outform pem > moonCert.pem

pki --print --in strongswanCert.pem
pki --print --in moonCert.pem
```

## 3. 生成并签发 sun 证书

先在 **sun** 生成自己的私钥和证书请求。`sunKey.pem` 留在 sun，不复制到其他机器。

```bash
mkdir -p ~/ipsec-lab
cd ~/ipsec-lab
umask 077

pki --gen --type ed25519 --outform pem > sunKey.pem
pki --req --type priv --in sunKey.pem \
  --dn "C=CH, O=strongSwan, CN=sun.strongswan.org" \
  --san sun.strongswan.org \
  --outform pem > sunReq.pem

cat sunReq.pem
```

在 sun 终端复制 `cat` 输出中从 `-----BEGIN CERTIFICATE REQUEST-----` 到 `-----END CERTIFICATE REQUEST-----` 的全部内容。在 **moon** 上运行 `mkdir -p ~/ipsec-lab` 和 `nano ~/ipsec-lab/sunReq.pem`，粘贴请求并保存。然后用第 2 步的 CA 签发：

```bash
cd ~/ipsec-lab
pki --issue --cacert strongswanCert.pem --cakey strongswanKey.pem \
  --type pkcs10 --in sunReq.pem --lifetime 1826 \
  --outform pem > sunCert.pem

pki --print --in sunCert.pem
cat sunCert.pem
cat strongswanCert.pem
```

在 moon 端分别复制 `sunCert.pem` 和 CA **公共证书** `strongswanCert.pem` 的完整 PEM 内容。在 **sun** 上使用 `nano ~/ipsec-lab/sunCert.pem` 和 `nano ~/ipsec-lab/strongswanCert.pem`，分别粘贴并保存，保留各自的 `BEGIN CERTIFICATE`、`END CERTIFICATE` 行及换行。CA 私钥 `strongswanKey.pem` 始终留在 moon。此次文件内容通过终端复制、粘贴，没有使用 `scp`。

## 4. 两端安装证书并配置 `swanctl.conf`

在 **moon** 执行：

```bash
cd ~/ipsec-lab
sudo install -D -m 644 strongswanCert.pem /etc/swanctl/x509ca/strongswanCert.pem
sudo install -D -m 644 moonCert.pem /etc/swanctl/x509/moonCert.pem
sudo install -D -m 600 moonKey.pem /etc/swanctl/private/moonKey.pem
sudo nano /etc/swanctl/swanctl.conf
```

moon 的 `/etc/swanctl/swanctl.conf`：

```text
connections {
    host-host {
        version = 2
        local_addrs = 192.168.199.131
        remote_addrs = 192.168.199.130

        local {
            auth = pubkey
            certs = moonCert.pem
            id = "C=CH, O=strongSwan, CN=moon.strongswan.org"
        }
        remote {
            auth = pubkey
            id = "C=CH, O=strongSwan, CN=sun.strongswan.org"
        }
        children {
            host-host {
                local_ts = 192.168.199.131/32
                remote_ts = 192.168.199.130/32
                start_action = trap
            }
        }
    }
}
```

在 **sun** 执行：

```bash
cd ~/ipsec-lab
sudo install -D -m 644 strongswanCert.pem /etc/swanctl/x509ca/strongswanCert.pem
sudo install -D -m 644 sunCert.pem /etc/swanctl/x509/sunCert.pem
sudo install -D -m 600 sunKey.pem /etc/swanctl/private/sunKey.pem
sudo nano /etc/swanctl/swanctl.conf
```

sun 的 `/etc/swanctl/swanctl.conf`：

```text
connections {
    host-host {
        version = 2
        local_addrs = 192.168.199.130
        remote_addrs = 192.168.199.131

        local {
            auth = pubkey
            certs = sunCert.pem
            id = "C=CH, O=strongSwan, CN=sun.strongswan.org"
        }
        remote {
            auth = pubkey
            id = "C=CH, O=strongSwan, CN=moon.strongswan.org"
        }
        children {
            host-host {
                local_ts = 192.168.199.130/32
                remote_ts = 192.168.199.131/32
                start_action = trap
            }
        }
    }
}
```

两端的 `local`/`remote` 地址、证书和身份互为镜像。`id` 使用证书的完整 DN；单独的 `moon.strongswan.org` 与该 DN 是不同类型的身份。`host-host` 在外层是 IKE 连接名，在 `children` 中是本地 CHILD_SA 名称；手动发起时使用后者。

## 5. 启动、建立连接和验收

**先 sun、后 moon**，在各自虚拟机执行：

```bash
sudo systemctl enable --now strongswan
systemctl status strongswan -l --no-pager
sudo swanctl --list-conns
sudo swanctl --list-certs
```

服务应显示 `active (running)`，`--list-conns` 应显示 `host-host`。接着在 **moon** 主动发起连接并发送测试流量：

```bash
sudo swanctl --initiate --child host-host
ping -c 4 192.168.199.130
sudo swanctl --list-sas
```

在 **sun** 同样检查：

```bash
sudo swanctl --list-sas
```

本次 moon 的实际成功输出含 `host-host ... ESTABLISHED, IKEv2` 和 `host-host ... INSTALLED, TUNNEL, ESP:AES_GCM_16-128`；流量选择器为 `192.168.199.131/32` ↔ `192.168.199.130/32`，`in`、`out` 各为 **4 packets / 336 bytes**，ping 也成功。IKE 使用了 `AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_256`。这构成传统算法基线；单独 ping 成功并不能证明流量经过 IPsec。再次 ping 后可复查两端 `--list-sas` 中的收发计数是否增加。

## 6. 修改配置或证书后如何重新加载

- **只改了 `swanctl.conf`：** 在改动的一端运行 `sudo swanctl --load-conns`，再用 `sudo swanctl --list-conns` 核对。已存在的 SA 不会仅因加载新配置就自动切换；需要在 moon 上执行 `sudo swanctl --terminate --ike host-host`，随后 `sudo swanctl --initiate --child host-host`。
- **更换了证书或私钥：** 先用 `install` 更新 `/etc/swanctl/x509ca`、`x509`、`private` 中对应文件，在改动的一端运行 `sudo swanctl --load-creds`；如配置也变了，再运行 `sudo swanctl --load-conns`。若要清除内存中此前加载的旧凭据，可用 `sudo swanctl --load-creds --clear` 重新加载当前目录下的全部凭据，或重启服务。之后终止旧 SA 并重新建立。两端必须信任签发对端证书的 CA；若重新生成 CA，需要重新签发并分发两端证书。参见 [凭据加载选项](https://docs.strongswan.org/docs/latest/swanctl/swanctlLoadCreds.html)。
- **希望完整重启服务：** 先在 sun、后在 moon 执行 `sudo systemctl restart strongswan`，再检查 `systemctl status strongswan -l --no-pager` 和 `sudo swanctl --list-conns`，最后由 moon 发起连接。服务启动时自动执行 `swanctl --load-all`，因此不必重复运行；也可在服务运行时手动执行 `sudo swanctl --load-all`。

排错时在出问题的端点查看完整日志：

```bash
sudo journalctl -u strongswan -n 100 -l --no-pager
```

本次遇到过两处具体错误：sun 的 `certs` 曾误写为 `moonCert.pem`，造成 `loaded 0 of 1 connections`；sun 的连接身份/地址与 moon 发来的请求不匹配时，日志出现 `no matching peer config found` 和 `AUTHENTICATION_FAILED`。此外，moon 的 CHILD_SA 曾命名为 `net-net`，此时运行 `--initiate --child host-host` 会报“not found”。以上问题均以**实际加载的** `/etc/swanctl/swanctl.conf` 和 `sudo swanctl --list-conns` 为准排查。

## 7. 更换密码算法

基线配置未显式写算法提案，strongSwan 从默认提案中协商出上文显示的算法。要控制实验变量，应在**两端**的 `host-host` 连接中写相同的提案。例如，将 IKE 改为 AES-256-GCM、SHA-384 PRF、P-384 密钥交换，将 ESP 改为 AES-256-GCM：

```text
connections {
    host-host {
        # 与 version、local_addrs、remote_addrs 同一级
        proposals = aes256gcm16-prfsha384-ecp384

        children {
            host-host {
                # 与 local_ts、remote_ts、start_action 同一级
                esp_proposals = aes256gcm16
            }
        }
    }
}
```

以上只是需要**加入现有配置的两行**，不要用此片段覆盖完整文件。`proposals` 控制 IKE SA，`esp_proposals` 控制 CHILD_SA 的 ESP。IKE 使用 GCM 等 AEAD 算法时须显式指定 PRF，不再另配完整性算法；ESP 的这个示例没有另列 DH 组，故未要求 CHILD_SA 重协商时进行独立密钥交换。若实验需要 ESP PFS，可在两端使用 `esp_proposals = aes256gcm16-ecp384`。算法关键词及组合规则见 [strongSwan 官方提案文档](https://docs.strongswan.org/docs/latest/config/proposals.html)。

更改后，在两端确认算法可用，并重新加载和建立 SA：

```bash
sudo swanctl --list-algs
sudo swanctl --load-conns
sudo swanctl --list-conns
```

然后在 **moon** 执行：

```bash
sudo swanctl --terminate --ike host-host
sudo swanctl --initiate --child host-host
sudo swanctl --list-sas
```

若修改后无法协商，检查两端是否支持并提供共同的提案，以及 `journalctl` 中是否出现 `NO_PROPOSAL_CHOSEN`。`--list-sas` 显示的是**实际协商结果**，应以它记录实验参数。更换 Ed25519 等**证书签名/身份认证算法**不能只改 `proposals`：还需生成相应类型的密钥和证书，并确认 strongSwan 编译、加载了所需插件。后量子密钥交换也需要对应实现和插件，不能仅填写一个提案名称就视为已启用。
