#!/bin/bash

# ====== 配置区 ======
# APP_NAME 不再写死：取脚本所在目录的目录名（见下方 cd 之后）
APP_ENTRY="server.js"
# ====================

cd "$(dirname "$0")" || exit 1

APP_NAME="$(basename "$PWD")"

# ---------- 检查依赖 ----------
check_deps() {
    echo "=== 检查依赖 ==="

    if ! command -v node > /dev/null 2>&1; then
        echo "[缺失] Node.js 未安装"
    else
        echo "[OK] Node.js 版本：$(node -v)"
    fi

    if ! command -v npm > /dev/null 2>&1; then
        echo "[缺失] npm 未安装"
    else
        echo "[OK] npm 版本：$(npm -v)"
    fi

    if ! command -v pm2 > /dev/null 2>&1; then
        echo "[缺失] PM2 未安装，可执行：npm install -g pm2"
    else
        echo "[OK] PM2 版本：$(pm2 -v)"
    fi

    if [ -d "node_modules" ]; then
        echo "[OK] node_modules 已存在"
    else
        echo "[缺失] node_modules 不存在，需要执行 npm install"
    fi

    if [ -f "$APP_ENTRY" ]; then
        echo "[OK] 入口文件存在：$APP_ENTRY"
    else
        echo "[缺失] 找不到入口文件：$APP_ENTRY"
    fi
}

# ---------- 运行项目 ----------
start_app() {
    echo "=== 运行项目 ==="

    if [ ! -f "$APP_ENTRY" ]; then
        echo "[失败] 找不到入口文件 $APP_ENTRY，请检查路径"
        return 1
    fi

    if [ ! -d "node_modules" ]; then
        echo "依赖未安装，先执行 npm install..."
        npm install || { echo "[失败] npm install 出错"; return 1; }
    fi

    if pm2 describe "$APP_NAME" > /dev/null 2>&1; then
        echo "检测到已有进程，重启中..."
        pm2 restart "$APP_NAME"
    else
        echo "首次启动..."
        pm2 start "$APP_ENTRY" --name "$APP_NAME"
    fi

    pm2 save
    echo ""
    echo "=== 完成 ==="
    echo "查看状态：pm2 list"
    echo "查看日志：pm2 logs $APP_NAME"
}

# ---------- 重启项目 ----------
restart_app() {
    echo "=== 重启项目 ==="

    if pm2 describe "$APP_NAME" > /dev/null 2>&1; then
        pm2 restart "$APP_NAME"
        pm2 save
        echo "[已重启] $APP_NAME"
    else
        echo "[提示] PM2 中没有找到 $APP_NAME，尝试启动..."
        start_app
    fi
}

# ---------- 关闭项目 ----------
stop_app() {
    echo "=== 关闭项目 ==="

    if pm2 describe "$APP_NAME" > /dev/null 2>&1; then
        pm2 stop "$APP_NAME"
        pm2 save
        echo "[已停止] $APP_NAME"
    else
        echo "[提示] PM2 中没有找到 $APP_NAME"
    fi

    echo ""
    echo "如需彻底删除：pm2 delete $APP_NAME && pm2 save"
    echo "如需取消开机自启：pm2 unstartup systemd && systemctl disable pm2-root"
}

# ---------- 菜单 ----------
while true; do
    echo ""
    echo "============================================"
    echo "          项目管理菜单"
    echo "============================================"
    echo "  1. 检查依赖"
    echo "  2. 运行项目"
    echo "  3. 重启项目"
    echo "  4. 关闭项目"
    echo "  0. 退出"
    echo "============================================"
    read -p "请选择 [0-4]: " choice

    case "$choice" in
        1) check_deps ;;
        2) start_app ;;
        3) restart_app ;;
        4) stop_app ;;
        0) echo "退出。"; exit 0 ;;
        *) echo "[无效] 请输入 0-4 之间的数字" ;;
    esac
done