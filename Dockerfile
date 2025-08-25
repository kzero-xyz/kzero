# 使用Rust官方镜像作为基础，基于Ubuntu 24.04
FROM rust:1.81.0 AS builder

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive

# 设置rustup使用已安装的工具链，避免重新下载
RUN rustup default 1.81.0 && \
    rustup target add wasm32-unknown-unknown && \
    rustup component add rust-src rustfmt clippy

# 安装系统依赖
# https://docs.polkadot.com/develop/parachains/install-polkadot-sdk/#__tabbed_1_2
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    pkg-config \
    libssl-dev \
    libclang-dev \
    libudev-dev \
    libprotobuf-dev \
    protobuf-compiler \
    cmake \
    clang \
    curl \
    llvm \
    make \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 先复制依赖锁定文件，利用Docker层缓存
COPY Cargo.lock ./

# 复制Cargo.toml文件
COPY Cargo.toml ./

# 复制所有源代码
COPY . .

# 构建项目（使用release模式）
RUN cargo build --release --bin node-template

# 创建运行时镜像 - 使用更轻量的debian-slim
FROM debian:bookworm-slim AS runtime

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# 创建运行时用户
RUN useradd -m -u 1000 -s /bin/bash appuser

# 设置工作目录
WORKDIR /app

# 从构建阶段复制可执行文件
COPY --from=builder /app/target/release/node-template /usr/local/bin/

# 切换到运行时用户
USER appuser

# 暴露端口（Substrate默认端口）
EXPOSE 9944 30333 30334

# 设置入口点
ENTRYPOINT ["node-template"]

# 默认命令
CMD ["--help"]
