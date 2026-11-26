#!/usr/bin/env bash
# ==============================================================================
# Cosmo Firewall - 一键安装与系统服务部署脚本
# 仓库: https://github.com/qwernot/Cosmo-Firewall
# ==============================================================================
set -e

INSTALL_DIR="${INSTALL_DIR:-/opt/cosmo-firewall}"
CONF_DIR="/etc/cosmo-firewall"
CONF_FILE="${CONF_DIR}/cosmofirewall.conf"
SERVICE_FILE="/etc/systemd/system/cosmo-firewall.service"
CLI_BIN="/usr/local/bin/cosmofirewall"
REPO_URL="https://github.com/qwernot/Cosmo-Firewall.git"
MIRROR_REPO_URL="https://ghfast.top/https://github.com/qwernot/Cosmo-Firewall.git"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[Cosmo Firewall]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "请使用 root 权限运行安装脚本（例如: sudo bash install.sh）"
fi

echo "=========================================================="
echo "🛡️  Cosmo Firewall 一键部署安装程序"
echo "    全端口（1–65535）智能防扫描 · Linux 内核 ipset 防火墙"
echo "=========================================================="

# 1. 安装基础依赖 (python3, git, ipset, iptables, conntrack)
info "检查并安装系统依赖..."
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq python3 git curl ipset iptables conntrack iproute2 >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 git curl ipset iptables conntrack-tools iproute >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q python3 git curl ipset iptables conntrack-tools iproute >/dev/null 2>&1 || true
fi

command -v python3 >/dev/null 2>&1 || error "未找到 python3，请先安装 Python 3.8+"
ok "系统依赖就绪 (python3: $(python3 --version 2>&1))"

# 2. 获取/更新代码到 /opt/cosmo-firewall
if [ -d "${INSTALL_DIR}/.git" ]; then
    info "检测到已有安装目录 ${INSTALL_DIR}，正在拉取最新代码（保留数据库配置）..."
    git -C "${INSTALL_DIR}" fetch --all >/dev/null 2>&1 || true
    git -C "${INSTALL_DIR}" reset --hard origin/main >/dev/null 2>&1 || true
elif [ -f "$(dirname "$0")/server.py" ] && [ "$(cd "$(dirname "$0")" && pwd)" != "${INSTALL_DIR}" ]; then
    info "从当前本地目录部署至 ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}"
    cp -a "$(cd "$(dirname "$0")" && pwd)/." "${INSTALL_DIR}/"
else
    info "正在克隆 Cosmo-Firewall 仓库至 ${INSTALL_DIR}..."
    rm -rf "${INSTALL_DIR}"
    if ! git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}" 2>/dev/null; then
        warn "GitHub 直连较慢，尝试使用国内镜像加速克隆..."
        git clone --depth 1 "${MIRROR_REPO_URL}" "${INSTALL_DIR}" || error "仓库克隆失败，请检查网络连接"
    fi
fi

chmod +x "${INSTALL_DIR}/start.sh" "${INSTALL_DIR}/install.sh" "${INSTALL_DIR}/cosmofirewall" 2>/dev/null || true
mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"

# 3. 写入配置文件 (若不存在则创建)
mkdir -p "${CONF_DIR}"
if [ -f "${CONF_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${CONF_FILE}"
fi

WEB_PORT="${PORT:-${WEB_PORT:-8090}}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

if [ -t 0 ] && [ -z "${NON_INTERACTIVE:-}" ]; then
    read -r -p "请输入 Web 管理面板监听端口 [默认 ${WEB_PORT}]: " INPUT_PORT || true
    if [[ "${INPUT_PORT}" =~ ^[0-9]+$ ]] && [ "${INPUT_PORT}" -ge 1 ] && [ "${INPUT_PORT}" -le 65535 ]; then
        WEB_PORT="${INPUT_PORT}"
    fi
fi

cat > "${CONF_FILE}" <<EOF
# Cosmo Firewall 运行配置文件
PORT=${WEB_PORT}
HOST=0.0.0.0
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
EOF
chmod 600 "${CONF_FILE}"
ok "配置已写入 ${CONF_FILE}"

# 4. 安装全局命令 cosmofirewall
cp -f "${INSTALL_DIR}/cosmofirewall" "${CLI_BIN}"
chmod +x "${CLI_BIN}"
ok "全局管理命令已安装: cosmofirewall"

# 5. 注册并启动 systemd 守护服务
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Cosmo Firewall - Full-Port Anti-Scan & Kernel ipset Firewall
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-${CONF_FILE}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/bin/bash ${INSTALL_DIR}/start.sh
Restart=always
RestartSec=3s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cosmo-firewall >/dev/null 2>&1
systemctl restart cosmo-firewall
sleep 2

if systemctl is-active --quiet cosmo-firewall; then
    ok "cosmo-firewall 服务已成功启动！"
else
    warn "服务启动异常，请执行 cosmofirewall logs 查看日志"
fi

PUBLIC_IP="$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
echo ""
echo "=========================================================="
echo -e "${GREEN}🎉 Cosmo Firewall 部署完成！${NC}"
echo "🌐 控制台地址:  http://${PUBLIC_IP:-127.0.0.1}:${WEB_PORT}"
echo "👤 默认账号:    ${ADMIN_USER} / ${ADMIN_PASS}（登录后请尽快修改密码）"
echo "🛠️  管理命令:    cosmofirewall {start|stop|restart|status|logs|port|update|uninstall}"
echo "=========================================================="
