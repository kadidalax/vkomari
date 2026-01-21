FROM node:20-alpine

ENV TZ=Asia/Shanghai
RUN apk add --no-cache tzdata python3 make g++ && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

WORKDIR /app

COPY package.json ./
RUN npm install --production --no-audit

COPY . .

EXPOSE 4000
CMD ["node", "server.js"]