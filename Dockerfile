# 使用极致轻量的 Node.js 镜像
FROM node:20-alpine

ENV TZ=Asia/Shanghai
# 安装基础依赖
RUN apk add --no-cache tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

WORKDIR /app

# 复制 package.json 并安装依赖
COPY package.json ./
RUN npm install --production --no-audit

# 复制源码
COPY . .

# 清理不必要的元数据
RUN rm -rf .dockerignore Dockerfile docker-compose.yml 需求.txt 下拉数据.md update_ips.py data

EXPOSE 25770

# 使用 node 直接启动
CMD ["node", "server.js"]
