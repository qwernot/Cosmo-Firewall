# 🛡️ Cosmo Firewall

轻量级、零第三方依赖的独立全端口（`1–65535`）智能防扫描与 Linux 内核 `ipset / iptables` 防火墙控制台。

## ✨ 核心特性
- **全端口哨兵诱捕（可自定义）**：后台随时增删、启停探测诱捕端口，自动检测并避让宿主机已被占用的服务端口，实时展示监听状态与捕获次数。
- **IP / CIDR 白名单**：支持单 IP 与网段（如 `192.168.10.0/24`）最高优先级放行，加入白名单时自动从黑名单解封。
- **全端口 `conntrack` 横向扫段监控**：默认覆盖 `1–65535` 全部端口，自动豁免正常 `80 -> 443` 网页跳转与在线 `SSH / FRP / NPS` 会话。
- **SSHD / Nginx / Docker NPM 漏洞扫描联动**：同时支持标准 Nginx 与 Docker Nginx Proxy Manager 日志格式。
- **Linux 内核级毫秒丢包**：`root` 运行时自动启用 `ipset`（O(1) 哈希表）+ `iptables INPUT/DOCKER-USER` + `conntrack -D` 实时断连。

---

## 🚀 一键部署（Linux 生产环境）

### 方式一：GitHub 直连一键安装
```bash
curl -fsSL https://raw.githubusercontent.com/qwernot/Cosmo-Firewall/main/install.sh | sudo bash
```

### 方式二：国内服务器加速镜像一键安装
```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/qwernot/Cosmo-Firewall/main/install.sh | sudo bash
```

> 支持自定义端口与初始账密非交互安装：
> ```bash
> curl -fsSL https://raw.githubusercontent.com/qwernot/Cosmo-Firewall/main/install.sh | sudo NON_INTERACTIVE=1 PORT=8090 ADMIN_USER=admin ADMIN_PASS=admin bash
> ```

- 安装目录：`/opt/cosmo-firewall`
- 配置文件：`/etc/cosmo-firewall/cosmofirewall.conf`
- 控制台地址：`http://<服务器IP>:8090`
- 默认管理员账号：`admin` / `admin`（首次登录后请在面板「防护策略与日志」中修改密码）

---

## 🛠️ `cosmofirewall` 全局管理命令

一键部署完成后，可直接在终端任意目录执行 `cosmofirewall` 控制启停与运维：

| 命令 | 说明 |
| :--- | :--- |
| `cosmofirewall` | 打开交互式管理菜单 |
| `cosmofirewall start` | 启动 Cosmo Firewall 服务 |
| `cosmofirewall stop` | 停止 Cosmo Firewall 服务 |
| `cosmofirewall restart` | 重启 Cosmo Firewall 服务 |
| `cosmofirewall status` | 查看服务运行状态、面板端口与内核 `ipset` 拦截统计 |
| `cosmofirewall logs` | 实时查看服务运行与拦截日志 |
| `cosmofirewall port 8091` | 修改 Web 面板监听端口并重启生效 |
| `cosmofirewall reset-password` | 重置管理员登录密码 |
| `cosmofirewall update` | 在线拉取 GitHub 最新版本（自动保留数据库配置） |
| `cosmofirewall uninstall` | 彻底卸载服务并自动清理 `iptables` / `ipset` 规则 |

---

## 💻 本地开发与测试启动

```bash
git clone https://github.com/qwernot/Cosmo-Firewall.git
cd Cosmo-Firewall
chmod +x start.sh
PORT=8090 ./start.sh
```

运行自动化单元测试：
```bash
python3 -m unittest test_firewall.py -v
```
