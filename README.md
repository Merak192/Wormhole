# Wormhole - P2P 加密即时聊天

基于 WebRTC + Cloudflare Pages + KV 的端到端加密 P2P 聊天应用

## 项目结构

```
Wormhole/
├── index.html              # 主页面（连接界面 + 聊天界面）
├── styles.css              # 暗色主题样式
├── script.ts               # 前端 TypeScript 源码
├── script.js               # 编译后的 JavaScript（由 tsc 生成）
├── package.json            # 项目依赖
├── tsconfig.json           # 前端 TypeScript 配置
├── wrangler.toml           # Cloudflare Pages 配置
├── README.md
└── functions/              # Cloudflare Pages Functions（TypeScript 源码，由 Wrangler 自动编译）
    ├── _middleware.ts      # CORS 中间件
    ├── offer.ts            # 创建/获取 WebRTC offer
    ├── answer.ts           # 创建/获取 WebRTC answer
    ├── candidate.ts        # 交换 ICE 候选
    ├── state.ts            # 查询会话状态
    └── types.d.ts          # 类型声明
```

## 技术架构

- **P2P 通信**: WebRTC Data Channel
- **信令服务器**: Cloudflare Pages Functions + KV（HTTP REST API）
- **加密**: Web Crypto API → AES-256-GCM
- **密钥交换**: ECDH P-256
- **存储**: SessionStorage（页面关闭即清除）

## 快速开始

### 1. 本地开发

```bash
# 安装依赖
npm install

# 编译 TypeScript
npm run build

# 本地开发（需要 Cloudflare 登录）
npx wrangler pages dev . --compatibility-date=2024-01-01
```

访问 `http://127.0.0.1:8788`

### 2. 部署到 Cloudflare Pages

1. 将仓库推送到 GitHub
2. 在 Cloudflare Dashboard → Pages → 创建项目
3. 连接 GitHub 仓库
4. 设置构建设置：
   - 构建命令: `npm run build`
   - 构建目录: `.`
5. 在 Workers & Pages → KV → 创建命名空间（binding 名称: `WORM_HOLE`）
6. 绑定 KV 命名空间到项目
7. 部署完成

### 3. 使用方法

1. 打开两个浏览器标签页
2. 标签页 A：输入 4 位数字，点击"创建房间"
3. 标签页 B：输入相同数字，点击"加入房间"
4. 连接成功后开始加密聊天

## 安全特性

- ✅ 端到端 AES-256-GCM 加密
- ✅ ECDH P-256 密钥交换
- ✅ 消息仅存储在浏览器本地
- ✅ 关闭浏览器后自动清除聊天记录
- ✅ 服务器不存储任何聊天内容

## 注意事项

1. KV 键的 TTL 为 10 分钟，超时自动清除
2. 4 位号码理论上限 10000 个，并发较低时碰撞概率小
3. 需要两个浏览器窗口/标签页同时在线才能完成信令交换
4. 建议在 HTTPS 环境下使用（WebRTC 需要安全上下文）
