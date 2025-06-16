# 🔐 EIP-712 签名器

一个安全的 EIP-712 签名工具，采用前后端分离架构，私钥安全保存在后端服务器中。

## ✨ 特性

- 🔒 **安全第一**: 私钥保存在后端环境变量中，不会暴露到前端
- 🛠️ **通用性强**: 支持任意 EIP-712 结构的签名
- 🔧 **自动修复**: 自动处理常见的 EIP-712 类型问题
- 🌐 **前后端分离**: 清晰的 API 架构
- ✅ **签名验证**: 自动验证签名的正确性
- 📊 **详细输出**: 提供签名分解和调试信息

## 🚀 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/yourusername/eip712-signer.git
cd eip712-signer
```

### 2. 安装依赖

```bash
npm install
```

### 3. 配置环境变量

```bash
# 复制环境变量示例文件
cp env.example .env

# 编辑 .env 文件，填入你的私钥
nano .env
```

在 `.env` 文件中设置：

```env
PRIVATE_KEY=0x你的私钥
PORT=3000
HOST=localhost
```

### 4. 启动服务器

```bash
# 生产环境
npm start

# 开发环境（自动重启）
npm run dev
```

### 5. 使用前端界面

打开 `frontend.html` 文件，或者在浏览器中访问服务器提供的前端页面。

## 📖 API 文档

### POST /api/sign

签名 EIP-712 数据

**请求体：**

```json
{
  "domain": {
    "name": "AuthTransfer",
    "chainId": 1,
    "verifyingContract": "0x40aA958dd87FC8305b97f2BA922CDdCa374bcD7f"
  },
  "message": {
    "details": [{
      "token": "0x0000000000000000000000000000000000000000",
      "expiration": 3242342
    }],
    "spenders": ["0xF3dE3C0d654FDa23daD170f0f320a92172509127"],
    "nonce": 1750070899677
  },
  "primaryType": "Permits",
  "types": {
    "Permits": [
      {"name": "details", "type": "PermitDetails[]"},
      {"name": "spenders", "type": "address[]"},
      {"name": "nonce", "type": "uint256"}
    ],
    "PermitDetails": [
      {"name": "token", "type": "address"},
      {"name": "expiration", "type": "uint256"}
    ]
  }
}
```

**响应：**

```json
{
  "success": true,
  "signature": "0x1a3e5a7a5532c2e0e5c56e5cfecceca23c352575f3292ccdf8af4253156fc383...",
  "signerAddress": "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c",
  "recoveredAddress": "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c",
  "isValid": true,
  "primaryType": "Permits",
  "signatureBreakdown": {
    "r": "0x1a3e5a7a5532c2e0e5c56e5cfecceca23c352575f3292ccdf8af4253156fc3837",
    "s": "0x9517195e01af23955aba3d59d7919e9318092421f40496f427d3cf922952829",
    "v": 28,
    "recoveryParam": 1
  },
  "timestamp": "2023-12-16T10:30:00.000Z"
}
```

### GET /api/health

健康检查

**响应：**

```json
{
  "status": "ok",
  "service": "EIP-712 签名服务",
  "timestamp": "2023-12-16T10:30:00.000Z",
  "version": "1.0.0"
}
```

### GET /api/address

获取签名地址

**响应：**

```json
{
  "address": "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c",
  "timestamp": "2023-12-16T10:30:00.000Z"
}
```

## 🔧 常见问题修复

### EIP712Domain 错误

如果遇到 "ambiguous primary types" 错误，本工具会自动：

1. 移除 `types` 中的 `EIP712Domain` 定义
2. 自动推断 `primaryType`
3. 清理冲突的类型定义

### 支持的 EIP-712 结构

- ✅ 标准 EIP-712 消息
- ✅ 嵌套类型结构
- ✅ 数组类型
- ✅ 自定义 domain
- ✅ 自动类型推断

## 🛡️ 安全说明

1. **私钥安全**: 私钥只保存在服务器环境变量中
2. **环境隔离**: `.env` 文件被 Git 忽略
3. **CORS 配置**: 生产环境请配置适当的 CORS 策略
4. **HTTPS**: 生产环境建议使用 HTTPS

## 📁 项目结构

```
eip712-signer/
├── server.js              # 后端 API 服务器
├── frontend.html           # 前端界面
├── package.json           # 项目配置
├── .gitignore            # Git 忽略文件
├── env.example           # 环境变量示例
└── README.md             # 项目文档
```

## 🔨 开发

### 安装开发依赖

```bash
npm install --save-dev nodemon
```

### 运行开发服务器

```bash
npm run dev
```

## 📝 环境变量

| 变量名 | 必需 | 默认值 | 说明 |
|--------|------|--------|------|
| `PRIVATE_KEY` | ✅ | - | 签名私钥 |
| `PORT` | ❌ | 3000 | 服务器端口 |
| `HOST` | ❌ | localhost | 服务器地址 |

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## ⚠️ 免责声明

本工具仅供学习和测试用途。在生产环境中使用时，请确保：

1. 私钥安全管理
2. 适当的网络安全配置
3. 定期安全审计
4. 遵循最佳安全实践

**使用本工具的风险由用户自行承担。** 