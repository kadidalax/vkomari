# vKomari - 虚拟komari探针服务器节点 (Main Branch)

🚀 **vKomari** 是一个轻量级的虚拟服务器监控代理集群管理工具，能够模拟大量服务器节点并实时上报状态数据（如 CPU、内存、磁盘、流量等）到监控面板（兼容哪吒监控等 WebSocket 上报协议）。

## ✨ 核心特性

- **轻量高效**：基于 Node.js 原生开发，内存占用极低。
- **动态模拟**：智能模拟 CPU 波动、内存增长、磁盘占用及网络流量，数据曲线极其真实。
- **全方位模拟**：支持 CPU (多核/架构)、内存、交换分区、磁盘、操作系统、地区、甚至 GPU 信息的模拟。
- **集群管理**：内置管理面板，可自由添加、编辑、批量启停虚拟节点。
- **Docker 支持**：一键部署，环境隔离。

<img width="1368" height="892" alt="image" src="https://github.com/user-attachments/assets/8043966c-5b9a-4c99-8cf7-2e778a2389a1" />


## 🛠️ 快速开始

### 方式一：使用 Docker Compose (推荐)

1. 下载 `docker-compose.yml`。
2. 运行部署命令：
   ```bash
   docker compose up -d
   ```
3. 访问面板：`http://your-ip:25770`

### 方式二：直接运行 (Node.js)

1. 安装依赖：
   ```bash
   npm install
   ```
2. 启动程序：
   ```bash
   npm start
   ```

## 🔐 默认凭据

- **用户名**：`admin`
- **默认密码**：`vkomari`
> *首次登录后请务必及时修改密码。*

## 📁 目录结构

- `server.js`: 核心逻辑与 API。
- `public/`: 管理面板前端界面。
- `data/`: 存储节点配置信息 (JSON 格式)。

## 📄 开源协议
MIT License
