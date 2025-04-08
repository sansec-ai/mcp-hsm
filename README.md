# MCP协议密码套件 (mcp-hsm)  [English Version](./README_en.md)

[![GitHub](https://img.shields.io/github/license/sansec-ai/mcp-hsm)](https://github.com/sansec-ai/mcp-hsm)

## 简介

mcp-hsm 是一个基于 MCP 协议的密码套件，旨在为 AI 应用提供高效的密码学支持。它支持 SM2 / SM3 / SM4 算法，通过硬件模块加速性能优化，并提供安全的密钥存储与管理。

## 功能特点

- **标准 MCP 协议**：方便 AI 应用集成
- **支持 SM2 / SM3 / SM4 算法**：满足国产密码学标准
- **硬件模块加速**：优化性能，提升处理速度
- **HSM 密钥管理**：提供更安全的密钥存储与管理
- **满足 GM/T 0018 标准**：确保符合国家密码学规范

## 架构概述

![架构图](./doc/architecture.jpg)

- **MCP 客户端**：通过 1 : 1 连接与 mcp-hsm 进行通信
- **mcp-hsm**：提供对称加解密、非对称加解密、签名验签、Hash 计算和密钥管理等功能
- **硬件驱动**：支持多种硬件模块，实现底层硬件加速

## 安装与使用

### 安装

```bash
git clone https://github.com/sansec-ai/mcp-hsm.git
cd mcp-hsm
uv venv
source .venv/bin/activate
# 启动测试
uv run tools/server.py
```

### 配置
- 将符合《GM/T 0018》标准的密码设备接口库重命名后放入 lib 目录。对于 Windows 系统，接口库命名为 hsm_0018.dll，对于 Linux 系统，重命名为 libhsm_0018.so。
- 接口库所需要的配置文件，请根据密码设备供应商的建议放置到相应路径下。
- 在 Roo Code 设置菜单中，配置 API 提供商、URL、API 密钥以及模型等基础信息。
![API提供商](./doc/API提供商.png)
- 在 Roo Code 的 MCP 服务管理菜单中，检查 mcp-hsm 服务是否已连接。
![MCP服务管理](./doc/MCP服务管理.png)

### 使用示例
- 例如，使用给定的对称密钥，对随机数据进行SM4 ECB模式加密。
- 在 Roo Code中输入内容：
```plaintext
生成32字节随机数作为待加密数据，使用0123456789abcdef0123456789abcdef作为对称密钥，进行SM4 ECB加密。
```
- MCP 服务调用过程如图所示：
![对称运算](./doc/对称运算1.png)
![对称运算](./doc/对称运算2.png)

## 贡献指南
欢迎贡献代码或提出改进建议！请参考贡献指南了解如何参与项目。

## 许可证
mcp-hsm 遵循 Apache License 2.0 协议，允许自由使用、修改和分发。

## 联系我们
如需进一步了解或技术支持，请访问 GitHub项目页面 或联系项目维护者。