const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hys_credit_platform_2024_secret_key';
const ADMIN_KEY = process.env.ADMIN_KEY || 'adminKey2024';

// 中间件
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ---------- 重要：静态文件服务 ----------
// 前端文件放在 public 目录，Render 会托管
app.use(express.static('public'));

// ---------- PostgreSQL 连接 ----------
// Render 会自动注入 DATABASE_URL 环境变量
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// 初始化数据库表
async function initDB() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                company_code TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS enterprises (
                id SERIAL PRIMARY KEY,
                code TEXT UNIQUE,
                data TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS appeals (
                id SERIAL PRIMARY KEY,
                company_code TEXT,
                enterprise_name TEXT,
                subject TEXT NOT NULL,
                content TEXT NOT NULL,
                attachment TEXT,
                status TEXT DEFAULT 'pending',
                review_comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP
            )
        `);
        // 创建默认管理员
        const adminCheck = await client.query('SELECT * FROM users WHERE username = $1', ['admin']);
        if (adminCheck.rows.length === 0) {
            const hashed = bcrypt.hashSync('admin123', 10);
            await client.query(
                'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
                ['admin', hashed, 'admin']
            );
            console.log('✅ 默认管理员已创建: admin / admin123');
        }
        console.log('✅ 数据库初始化完成');
    } catch (err) {
        console.error('数据库初始化失败:', err);
    } finally {
        client.release();
    }
}
initDB();

// ---------- 中间件 ----------
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: '未授权' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ error: '无效token' });
    }
};

const adminMiddleware = (req, res, next) => {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
    next();
};

// ---------- 路由 ----------
app.post('/api/auth/register', async (req, res) => {
    const { username, password, role, company_code, admin_key } = req.body;
    if (!username || !password) return res.status(400).json({ error: '请填写完整信息' });
    if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
    if (role === 'admin' && admin_key !== ADMIN_KEY) return res.status(400).json({ error: '管理员密钥错误' });
    if (role === 'enterprise' && !company_code) return res.status(400).json({ error: '企业用户需填写统一社会信用代码' });
    try {
        const hashed = bcrypt.hashSync(password, 10);
        await pool.query(
            'INSERT INTO users (username, password, role, company_code) VALUES ($1, $2, $3, $4)',
            [username, hashed, role, company_code || null]
        );
        res.json({ success: true, message: '注册成功' });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: '用户名已存在' });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '请填写账号和密码' });
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ error: '账号或密码错误' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: '账号或密码错误' });
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role, company_code: user.company_code }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, username: user.username, role: user.role, company_code: user.company_code } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/auth/verify', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

app.get('/api/enterprises', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM enterprises ORDER BY updated_at DESC');
        const data = result.rows.map(row => JSON.parse(row.data));
        const updateTime = result.rows.length > 0 ? result.rows[0].updated_at : new Date().toISOString();
        res.json({ data, updateTime });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/enterprises', authMiddleware, adminMiddleware, async (req, res) => {
    const { enterprises, updateTime } = req.body;
    if (!enterprises || !Array.isArray(enterprises) || enterprises.length === 0) {
        return res.status(400).json({ error: '无效数据' });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM enterprises');
        let count = 0;
        for (const ent of enterprises) {
            const code = ent['统一社会信用代码'] || ent['code'] || 'code_' + Date.now() + '_' + count;
            const dataStr = JSON.stringify(ent);
            await client.query(
                'INSERT INTO enterprises (code, data, updated_at) VALUES ($1, $2, $3)',
                [code, dataStr, updateTime || new Date().toISOString()]
            );
            count++;
        }
        await client.query('COMMIT');
        res.json({ success: true, message: '已更新 ' + count + ' 家企业' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.post('/api/enterprises/merge', authMiddleware, adminMiddleware, async (req, res) => {
    const { enterprises } = req.body;
    if (!enterprises || !Array.isArray(enterprises) || enterprises.length === 0) {
        return res.status(400).json({ error: '无效数据' });
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        let merged = 0, added = 0;
        for (const ent of enterprises) {
            const code = ent['统一社会信用代码'] || ent['code'] || 'code_' + Date.now() + '_' + merged;
            const dataStr = JSON.stringify(ent);
            await client.query(
                'INSERT INTO enterprises (code, data, updated_at) VALUES ($1, $2, $3) ON CONFLICT (code) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at',
                [code, dataStr, new Date().toISOString()]
            );
            merged++;
            added++;
        }
        await client.query('COMMIT');
        res.json({ success: true, message: `合并完成: 更新 ${merged} 家, 新增 ${added} 家` });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.put('/api/enterprises/:code/rectify', authMiddleware, adminMiddleware, async (req, res) => {
    const code = req.params.code;
    try {
        const result = await pool.query('SELECT * FROM enterprises WHERE code = $1', [code]);
        if (result.rows.length === 0) return res.status(404).json({ error: '企业不存在' });
        const ent = JSON.parse(result.rows[0].data);
        ent['整改状态'] = '已整改';
        ent['整改期限'] = '-';
        const dataStr = JSON.stringify(ent);
        await pool.query(
            'UPDATE enterprises SET data = $1, updated_at = $2 WHERE code = $3',
            [dataStr, new Date().toISOString(), code]
        );
        res.json({ success: true, message: '已标记为已整改' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/appeals', authMiddleware, async (req, res) => {
    const isAdmin = req.user?.role === 'admin';
    let sql = 'SELECT * FROM appeals';
    let params = [];
    if (!isAdmin) {
        sql += ' WHERE company_code = $1';
        params.push(req.user.company_code || '');
    }
    sql += ' ORDER BY created_at DESC';
    try {
        const result = await pool.query(sql, params);
        res.json({ data: result.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/appeals', authMiddleware, async (req, res) => {
    if (req.user.role !== 'enterprise') return res.status(403).json({ error: '仅企业用户可发起申诉' });
    const { subject, content, attachment } = req.body;
    if (!subject || !content) return res.status(400).json({ error: '请填写完整信息' });
    const company_code = req.user.company_code || '';
    let enterprise_name = '';
    if (company_code) {
        try {
            const result = await pool.query('SELECT * FROM enterprises WHERE code = $1', [company_code]);
            if (result.rows.length > 0) {
                const ent = JSON.parse(result.rows[0].data);
                enterprise_name = ent['企业名称'] || '';
            }
        } catch (e) {}
    }
    try {
        await pool.query(
            'INSERT INTO appeals (company_code, enterprise_name, subject, content, attachment) VALUES ($1, $2, $3, $4, $5)',
            [company_code, enterprise_name, subject, content, attachment || '']
        );
        res.json({ success: true, message: '申诉已提交' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/appeals/:id', authMiddleware, adminMiddleware, async (req, res) => {
    const { status, review_comment } = req.body;
    const id = req.params.id;
    if (!['pending', 'approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: '无效状态' });
    }
    try {
        await pool.query(
            'UPDATE appeals SET status = $1, review_comment = $2, reviewed_at = $3 WHERE id = $4',
            [status, review_comment || '', new Date().toISOString(), id]
        );
        res.json({ success: true, message: '审核完成' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, role, company_code, created_at FROM users');
        res.json({ data: result.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/users/:id/reset', authMiddleware, adminMiddleware, async (req, res) => {
    const userId = req.params.id;
    try {
        const hashed = bcrypt.hashSync('123456', 10);
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, userId]);
        res.json({ success: true, message: '密码已重置为 123456' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    const userId = parseInt(req.params.id);
    const currentUserId = req.user.id;
    try {
        const target = await pool.query('SELECT role FROM users WHERE id = $1', [userId]);
        if (target.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
        if (currentUserId !== 1 && target.rows[0].role === 'admin') {
            return res.status(403).json({ error: '无权删除管理员' });
        }
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        res.json({ success: true, message: '用户已删除' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 文件上传
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, 'appeal_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8) + ext);
    }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: '未上传文件' });
    const filePath = '/uploads/' + req.file.filename;
    res.json({ filePath, success: true });
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.listen(PORT, () => {
    console.log(`🚀 信用监管平台后端运行在 http://localhost:${PORT}`);
    console.log(`📁 数据库: PostgreSQL (Render)`);
});
