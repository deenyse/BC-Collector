const path = require('path');
const fs = require('fs');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
require('dotenv').config();
const https = require('https');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');

// Environment
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/bc_collectors';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const DEBUG = (process.env.DEBUG || '').toLowerCase() === 'true';

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Multer setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const safeOriginal = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 150);
        cb(null, `${timestamp}-${safeOriginal}`);
    },
});
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowed = [
            'application/pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        if (allowed.includes(file.mimetype)) return cb(null, true);
        cb(new Error('Only PDF and DOCX files are allowed'));
    },
    limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
});

// Models
const File = require('./models/File');
const QAPair = require('./models/QAPair');
const User = require('./models/User');

// Express app
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Debug helper
function debug(event, data) {
    if (!DEBUG) return;
    try { console.log(`[DEBUG] ${event}`, data || ''); } catch (_) {}
}

// Simple request logger (debug-only)
app.use((req, res, next) => {
    debug('request', { method: req.method, path: req.path });
    next();
});

// Static: uploads and frontend
app.use('/uploads', express.static(uploadsDir));
const frontendDir = path.join(__dirname, '..', '..', 'src', 'frontend', 'dist');
app.use('/', express.static(frontendDir));

// Simple CDN proxy with in-memory cache for pdf.js
const cdnCache = {};
function fetchCdnOnce(url, contentType) {
    return new Promise((resolve, reject) => {
        if (cdnCache[url]) return resolve(cdnCache[url]);
        https.get(url, (resp) => {
            if (resp.statusCode !== 200) return reject(new Error(`CDN status ${resp.statusCode}`));
            const chunks = [];
            resp.on('data', d => chunks.push(d));
            resp.on('end', () => {
                const buf = Buffer.concat(chunks);
                cdnCache[url] = { buf, contentType, cachedAt: Date.now() };
                resolve(cdnCache[url]);
            });
        }).on('error', reject);
    });
}

app.get('/vendor/pdf.min.js', async (req, res) => {
    try {
        const { buf, contentType } = await fetchCdnOnce(
            'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.4.168/pdf.min.js',
            'application/javascript; charset=utf-8'
        );
        res.setHeader('Content-Type', contentType);
        res.send(buf);
    } catch (e) {
        res.status(502).send('Bad Gateway');
    }
});

app.get('/vendor/pdf.worker.min.js', async (req, res) => {
    try {
        const { buf, contentType } = await fetchCdnOnce(
            'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.4.168/pdf.worker.min.js',
            'application/javascript; charset=utf-8'
        );
        res.setHeader('Content-Type', contentType);
        res.send(buf);
    } catch (e) {
        res.status(502).send('Bad Gateway');
    }
});

// Mongo connection
mongoose
    .connect(MONGO_URI)
    .then(() => {
        console.log('MongoDB connected');
        ensureSeedUsers().catch(console.error);
    })
    .catch(err => console.error('MongoDB connection error:', err));

// Seed users if none exist
async function ensureSeedUsers() {
    const count = await User.countDocuments();
    if (count > 0) return;
    const users = [
        { username: 'user1', password: 'user1' },
        { username: 'user2', password: 'user2' },
    ];
    for (const u of users) {
        const hash = await bcrypt.hash(u.password, 10);
        await User.create({ username: u.username, passwordHash: hash });
    }
    console.log('Seeded users: user1/user1, user2/user2');
}

// Auth middleware
function authMiddleware(req, res, next) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Routes
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id.toString(), username: user.username }, JWT_SECRET, { expiresIn: '7d' });
        debug('auth:login', { username });
        res.json({ token, user: { id: user._id.toString(), username: user.username } });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const saved = await File.create({
            filename: req.file.originalname,
            filepath: `/uploads/${req.file.filename}`,
        });
        debug('upload:success', { id: saved._id.toString(), filename: saved.filename });
        res.status(201).json(saved);
    } catch (err) {
        console.error(err);
        debug('upload:error', { message: err.message });
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.get('/api/file/:id', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return res.status(404).json({ error: 'File not found' });
        debug('file:get', { id: file._id.toString() });
        res.json(file);
    } catch (err) {
        debug('file:get:error', { message: err.message });
        res.status(400).json({ error: 'Invalid id' });
    }
});

app.get('/api/files', async (req, res) => {
    const files = await File.find().sort({ uploadedAt: -1 });
    debug('files:list', { count: files.length });
    res.json(files);
});

app.post('/api/qa', authMiddleware, async (req, res) => {
    try {
        const { fileId, textPiece, question, answer } = req.body;
        if (!fileId || !textPiece || !question || !answer) return res.status(400).json({ error: 'Missing fields' });
        const exists = await File.exists({ _id: fileId });
        if (!exists) return res.status(404).json({ error: 'File not found' });
        const saved = await QAPair.create({ fileId, textPiece, question, answer, createdBy: req.user.id });
        debug('qa:create', { id: saved._id.toString(), fileId });
        res.status(201).json(saved);
    } catch (err) {
        console.error(err);
        debug('qa:create:error', { message: err.message });
        res.status(500).json({ error: 'Failed to save Q&A' });
    }
});

app.get('/api/qa/:fileId', async (req, res) => {
    try {
        const list = await QAPair.find({ fileId: req.params.fileId })
            .sort({ createdAt: -1 })
            .populate('createdBy', 'username');
        debug('qa:list', { fileId: req.params.fileId, count: list.length });
        res.json(list);
    } catch (err) {
        debug('qa:list:error', { message: err.message });
        res.status(400).json({ error: 'Invalid fileId' });
    }
});

app.get('/api/qa', async (req, res) => {
    try {
        const { fileId } = req.query;
        const filter = fileId ? { fileId } : {};
        const list = await QAPair.find(filter)
            .sort({ createdAt: -1 })
            .populate('fileId', 'filename')
            .populate('createdBy', 'username');
        debug('qa:listAll', { count: list.length, filtered: !!fileId });
        res.json(list);
    } catch (err) {
        debug('qa:listAll:error', { message: err.message });
        res.status(500).json({ error: 'Failed to list Q&A' });
    }
});

app.delete('/api/qa/:id', async (req, res) => {
    try {
        const deleted = await QAPair.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: 'Not found' });
        debug('qa:delete', { id: req.params.id });
        res.json({ ok: true });
    } catch (err) {
        debug('qa:delete:error', { message: err.message });
        res.status(400).json({ error: 'Invalid id' });
    }
});

// === УЛУЧШЕННЫЙ ДЕБАГ-МАРШРУТ ===
app.get('/debug', (req, res) => {
    const isWindows = process.platform === 'win32';
    const cwd = process.cwd();
    const root = process.env.RENDER ? '/opt/render/project/src' : cwd;
    const possibleFrontendPaths = [
        path.join(cwd, '..', '..', 'src', 'frontend', 'dist'),
        path.join(cwd, 'src', 'frontend', 'dist'),
        path.join(cwd, '..', 'frontend', 'dist'),
        path.join(cwd, 'frontend', 'dist'),
        path.join(cwd, 'dist'),
        path.join(root, 'src', 'frontend', 'dist'),
        path.join(root, 'frontend', 'dist'),
        '/opt/render/project/src/frontend/dist',
        '/app/src/frontend/dist',
        '/app/dist',
    ];

    const results = [];
    const indexPaths = [];

    // Проверяем каждый путь
    possibleFrontendPaths.forEach((dir, i) => {
        const exists = fs.existsSync(dir);
        const indexPath = path.join(dir, 'index.html');
        const indexExists = fs.existsSync(indexPath);

        results.push({
            [`Path #${i+1}`]: dir,
            'Exists': exists ? 'YES' : 'NO',
            'index.html': indexExists ? 'FOUND' : 'NOT FOUND',
            'Full index path': indexPath,
        });

        if (indexExists) {
            indexPaths.push(indexPath);
        }
    });

    // Читаем содержимое ключевых папок
    const listDir = (dir, label) => {
        try {
            if (!fs.existsSync(dir)) return `${label}: [DIR NOT FOUND]`;
            const items = fs.readdirSync(dir);
            return `${label}: [ ${items.length} items: [${items.slice(0, 20).join(', ')}${items.length > 20 ? '...' : ''}]`;
        } catch (e) {
            return `${label}: [ERROR READING] ${e.message}`;
        }
    };

    const keyDirs = [
        [cwd, 'process.cwd()'],
        [path.dirname(__dirname), '__dirname parent'],
        [__dirname, '__dirname'],
        [root, 'RENDER root'],
        ['/opt/render/project/src', 'Render /opt/.../src'],
        ['/app', '/app (common in containers)'],
    ].map(([dir, label]) => listDir(dir, label));

    // Попробуем найти index.html рекурсивно (ограничим глубину)
    const findIndexHtml = () => {
        const seen = new Set();
        const search = (dir, depth = 0) => {
            if (depth > 4 || seen.has(dir)) return [];
            seen.add(dir);
            let found = [];
            try {
                const items = fs.readdirSync(dir);
                if (items.includes('index.html')) {
                    found.push(path.join(dir, 'index.html'));
                }
                for (const item of items) {
                    const full = path.join(dir, item);
                    if (fs.statSync(full).isDirectory()) {
                        found = found.concat(search(full, depth + 1));
                    }
                }
            } catch (_) {}
            return found;
        };
        return search('/opt/render/project/src', 0)
            .concat(search(cwd, 0))
            .concat(search('/app', 0))
            .slice(0, 10);
    };

    const foundIndexFiles = findIndexHtml();

    // Попытка выполнить `ls` или `dir`
    const execCmd = isWindows ? 'dir' : 'ls -la';
    exec(execCmd, { timeout: 5000 }, (err, stdout, stderr) => {
        const output = err ? `ERROR: ${err.message}\n${stderr}` : stdout;

        res.type('text/plain');
        res.send(`
╔══════════════════════════════════════════════════════════════════════════════╗
║                               SERVER DEBUG INFO                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Server Time: ${new Date().toLocaleString()}
Platform: ${process.platform} (${isWindows ? 'Windows' : 'Unix'})
Node.js: ${process.version}
Environment: ${process.env.NODE_ENV || 'development'}
RENDER: ${!!process.env.RENDER}
process.cwd(): ${cwd}
__dirname: ${__dirname}
frontendDir (original): ${frontendDir}
fs.existsSync(frontendDir): ${fs.existsSync(frontendDir) ? 'YES' : 'NO'}
index.html exists: ${fs.existsSync(path.join(frontendDir, 'index.html')) ? 'YES' : 'NO'}

DIRECTORY LISTINGS:
${keyDirs.join('\n')}

POSSIBLE FRONTEND DIST PATHS:
${results.map(r => Object.entries(r).map(([k, v]) => `  ${k.padEnd(20)}: ${v}`).join('\n')).join('\n\n')}

FOUND index.html (recursive search):
${foundIndexFiles.length > 0 ? foundIndexFiles.map(p => `  FOUND: ${p}`).join('\n') : '  NONE FOUND'}

EXEC: ${execCmd} (current dir)
${'-'.repeat(60)}
${output}
${'-'.repeat(60)}

TIPS:
• Если index.html найден — обнови frontendDir в коде
• На Render: фронтенд должен быть в /opt/render/project/src/frontend/dist
• Убедись, что в package.json есть скрипт build и dist попадает в репозиторий
• Или используй Render Build Command: "npm run build:frontend && npm run start"

`);
    });
});


// Fallback to frontend index.html
app.get('*', (req, res) => {
    const indexPath = path.join(frontendDir, 'index.html');
    if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
    res.status(404).send('Not Found');
});


// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
