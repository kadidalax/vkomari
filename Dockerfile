# 第一阶段：构建环境 (用于编译 sqlite3 等原生模块)
FROM node:20-alpine AS builder

# 安装编译所需的依赖
RUN apk add --no-cache python3 make g++

WORKDIR /app

# 只复制 package.json 以利用缓存
COPY package.json ./
RUN npm install --production --no-audit

# 第二阶段：生产环境 (保持极致轻量)
FROM node:20-alpine

ENV TZ=Asia/Shanghai
# 仅保留基础运行环境
RUN apk add --no-cache tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

WORKDIR /app

# 从构建阶段仅复制已编译好的 node_modules
COPY --from=builder /app/node_modules ./node_modules
# 复制源码
COPY . .

# 清理构建残留和不必要的元数据
RUN rm -rf .dockerignore Dockerfile docker-compose.yml 需求.txt 下拉数据.md update_ips.py data

EXPOSE 25770

# 使用 node 直接启动
CMD ["node", "server.js"]
