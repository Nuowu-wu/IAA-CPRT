# Kali Monitor System

一个具有黑客风格的系统监控界面。

## 功能特点

- Matrix风格代码雨背景
- 实时系统监控
- 性能数据可视化
- 设备信息追踪
- 实时摄像头监控
- 位置信息追踪

## 部署到 Render

1. 在 Render.com 注册账号并登录

2. 点击 "New +" 按钮，选择 "Web Service"

3. 连接你的 GitHub 仓库
   - 如果是第一次使用，需要配置 GitHub 集成
   - 选择包含此项目的仓库

4. 配置部署设置：
   - **Name**: 输入你想要的服务名称
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

5. 配置环境变量：
   - `PORT`: 3000
   - `NODE_ENV`: production
   - `ADMIN_AUTH`: 设置你的管理员认证信息（格式：username:password）

6. 点击 "Create Web Service" 开始部署

## 本地开发

1. 安装依赖：
```bash
npm install
```

2. 创建 .env 文件：
```bash
PORT=3000
ADMIN_AUTH=admin:secret
```

3. 启动开发服务器：
```bash
npm run dev
```

## 访问监控页面

1. 部署完成后，访问 Render 提供的域名
2. 监控页面路径：`/monitor`
3. 使用配置的管理员账号密码登录

## 注意事项

- 确保在生产环境中修改默认的管理员密码
- 定期检查和清理日志文件
- 建议配置自定义域名
- 监控数据建议定期备份 