@echo off
title Coolapk Web
cd /d %~dp0

where node >nul 2>nul
if errorlevel 1 (
    echo [错误] 未检测到 Node.js，请先安装 Node.js 再运行本脚本。
    pause
    exit /b 1
)

if not exist node_modules (
    echo 首次运行，正在安装依赖，请稍候...
    call npm install --no-audit --no-fund
    if errorlevel 1 (
        echo [错误] 依赖安装失败，请检查网络后重试。
        pause
        exit /b 1
    )
)

echo ========================================
echo   网页版酷安服务正在启动...
echo   关闭本窗口即可停止服务
echo ========================================
node server.js

echo.
echo 服务已停止。
pause
