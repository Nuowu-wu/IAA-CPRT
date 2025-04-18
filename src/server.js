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
        this.app.use(bodyParser.json());
        this.app.use(bodyParser.urlencoded({ extended: true }));

        // 静态文件服务
        this.app.use(express.static(path.join(__dirname, '../public')));
    }

    setupRoutes() {
        // 主页路由
        this.app.get('/', (req, res) => {
            res.redirect('/login.html');
        });

        // 监控页面路由
        this.app.get('/monitor', (req, res) => {
            res.sendFile(path.join(__dirname, '../public/monitor.html'));
        });

        // 登录验证
        this.app.post('/api/auth', (req, res) => {
            console.log('Login attempt:', req.body); // 添加日志
            const { username, password } = req.body;
            
            if (!username || !password) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Username and password are required'
                });
            }

            if (username === 'kali' && password === 'kali') {
                console.log('Login successful for user:', username); // 添加日志
                res.status(200).json({ 
                    status: 'success',
                    message: 'Authentication successful'
                });
            } else {
                console.log('Login failed for user:', username); // 添加日志
                res.status(401).json({ 
                    status: 'error',
                    message: 'Invalid credentials'
                });
            }
        });
// ... rest of the code ...
