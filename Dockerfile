# 洛一后端 Dockerfile
# 多阶段构建，减小镜像体积

# ============ 构建阶段 ============
FROM golang:1.24-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# 复制依赖文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建二进制文件
# CGO_ENABLED=1 是 SQLite 需要的
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o luo_one_core ./cmd/main.go

# ============ 运行阶段 ============
FROM alpine:3.19

# 安装运行时依赖
RUN apk add --no-cache ca-certificates tzdata

# 设置时区
ENV TZ=Asia/Shanghai

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/luo_one_core .

# 创建数据目录
RUN mkdir -p /app/data /app/emails

# 设置环境变量
ENV LUO_ONE_DATA_DIR=/app/data
ENV LUO_ONE_DATABASE_PATH=/app/data/luo_one.db
ENV LUO_ONE_EMAILS_DIR=/app/emails
ENV LUO_ONE_API_PORT=8080
ENV LUO_ONE_LOG_LEVEL=INFO

# 暴露端口
EXPOSE 8080

# 数据卷 - 分离数据库和邮件存储
VOLUME ["/app/data", "/app/emails"]

# 启动命令
CMD ["./luo_one_core"]
