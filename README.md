# vKomari

vKomari 是一个轻量级虚拟 VPS 节点面板，可以创建虚拟节点，并把模拟的状态数据上报到 Komari 和 CF-VPS-Monitor 探针面板。

## 功能

- Web 面板管理多个虚拟节点。
- 支持 Komari 上报和 Komari Agent 自动发现导入。
- 支持 CF-VPS-Monitor 上报。
- 支持 CF-VPS-Monitor Agent WebSocket 策略：前台有人查看时实时上报，无人查看时后台间隔上报。
- 可模拟 CPU、内存、交换分区、磁盘、流量、进程、连接数、系统、内核、地区、IP、GPU 等信息。
- 支持节点导入、导出和模板。
- 支持 Docker Compose 一键部署。

## Docker Compose 一键部署

下载 `docker-compose.yml`：

```bash
wget -O docker-compose.yml https://raw.githubusercontent.com/kadidalax/vkomari/main/docker-compose.yml
```

启动：

```bash
docker compose up -d
```

访问：

```text
http://你的服务器IP:25770
```

默认账号：

```text
用户名：admin
密码：vkomari
```

首次登录后请及时修改密码。

## 可选配置

如需自定义端口、JWT 密钥或出站代理，在 `docker-compose.yml` 同目录创建 `.env`：

```env
PORT=25770
JWT_SECRET=请改成一段足够长的随机字符串

# 可选：连接 Komari / CF-VPS-Monitor 外网面板需要代理时填写
# HTTP_PROXY=http://host.docker.internal:10808
# HTTPS_PROXY=http://host.docker.internal:10808
```

重新启动：

```bash
docker compose up -d
```

数据保存在 Docker volume：`vkomari_data`。

## 更新

```bash
docker compose pull
docker compose up -d
```

## 常用命令

查看日志：

```bash
docker compose logs -f
```

重启：

```bash
docker compose restart
```

停止：

```bash
docker compose down
```

删除应用和数据：

```bash
docker compose down -v
```

## 本地开发

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## 许可证

MIT
