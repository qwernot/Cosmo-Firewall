# Cosmo Firewall

轻量级、零第三方依赖的独立全端口（`1–65535`）智能防扫描与 Linux 内核 `ipset/iptables` 防火墙控制台。

## 核心特性
- **全端口哨兵诱捕（可自定义）**：后台随时增删、启停探测诱捕端口，自动检测并避让宿主机已被占用的服务端口，实时展示监听状态与捕获次数。
- **IP / CIDR 白名单**：支持单 IP 与网段（如 `192.168.10.0/24`）最高优先级放行，加入白名单时自动从黑名单解封。
- **全端口 `conntrack` 横向扫段监控**：默认覆盖 `1–65535` 全部端口，自动识别正常 `80->443` 跳转与在线 `SSH/FRP/NPS` 会话免误伤。
- **SSHD / Nginx / Docker NPM 漏洞扫描联动**：支持标准 Nginx 与 Docker Nginx Proxy Manager 日志格式。
- **Linux 内核级毫秒丢包**：root 运行时自动启用 `ipset`（O(1) 哈希表）+ `iptables INPUT/DOCKER-USER` + `conntrack -D` 实时断连；非 root 本地测试自动切换仿真模式。

## 本地启动
```bash
cd /home/dark/frpauto/firewall
chmod +x start.sh
PORT=8090 ./start.sh
```
- 控制台地址：`http://127.0.0.1:8090`
- 默认管理员账号：`dark` / `Aa666333`（可通过环境变量 `ADMIN_USER` / `ADMIN_PASS` 自定义，或在面板内修改）
