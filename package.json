const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'wordbook-secret-key-change-this';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./wordbook.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS user_vocabulary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        pack_name TEXT NOT NULL,
        words TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        UNIQUE(user_id, pack_name)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS user_wrong_book (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        word_data TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS user_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        vocabulary TEXT NOT NULL,
        studied_indices TEXT NOT NULL,
        last_index INTEGER DEFAULT -1,
        current_round_total INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    
    console.log('Database initialized');
});

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Username already exists' });
                    }
                    return res.status(500).json({ error: err.message });
                }
                const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET, { expiresIn: '7d' });
                res.json({ success: true, token, userId: this.lastID, username });
            }
        );
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: 'User not found' });
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(400).json({ error: 'Invalid password' });
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, userId: user.id, username: user.username });
    });
});

app.post('/api/save-vocabulary', authMiddleware, (req, res) => {
    const { packName, words } = req.body;
    db.run(
        `INSERT INTO user_vocabulary (user_id, pack_name, words) VALUES (?, ?, ?)
         ON CONFLICT(user_id, pack_name) DO UPDATE SET words = ?`,
        [req.userId, packName, JSON.stringify(words), JSON.stringify(words)],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.get('/api/get-vocabulary', authMiddleware, (req, res) => {
    db.all('SELECT pack_name, words FROM user_vocabulary WHERE user_id = ?', [req.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const packs = {};
        rows.forEach(row => { packs[row.pack_name] = JSON.parse(row.words); });
        res.json({ success: true, packs });
    });
});

app.post('/api/save-wrong-book', authMiddleware, (req, res) => {
    const { wrongBook } = req.body;
    db.run(
        `INSERT INTO user_wrong_book (user_id, word_data) VALUES (?, ?)`,
        [req.userId, JSON.stringify(wrongBook)],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.get('/api/get-wrong-book', authMiddleware, (req, res) => {
    db.get(
        'SELECT word_data FROM user_wrong_book WHERE user_id = ? ORDER BY id DESC LIMIT 1',
        [req.userId],
        (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, wrongBook: row ? JSON.parse(row.word_data) : [] });
        }
    );
});

app.post('/api/save-progress', authMiddleware, (req, res) => {
    const { vocabulary, studiedIndices, lastIndex, currentRoundTotal } = req.body;
    db.run(
        `INSERT INTO user_progress (user_id, vocabulary, studied_indices, last_index, current_round_total, updated_at)
         VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT DO UPDATE SET 
            vocabulary = ?, studied_indices = ?, last_index = ?, current_round_total = ?, updated_at = CURRENT_TIMESTAMP`,
        [req.userId, JSON.stringify(vocabulary), JSON.stringify(studiedIndices), lastIndex, currentRoundTotal,
         JSON.stringify(vocabulary), JSON.stringify(studiedIndices), lastIndex, currentRoundTotal],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

app.get('/api/get-progress', authMiddleware, (req, res) => {
    db.get(
        'SELECT vocabulary, studied_indices, last_index, current_round_total FROM user_progress WHERE user_id = ? ORDER BY id DESC LIMIT 1',
        [req.userId],
        (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!row) return res.json({ success: true, hasData: false });
            res.json({
                success: true,
                hasData: true,
                vocabulary: JSON.parse(row.vocabulary),
                studiedIndices: JSON.parse(row.studied_indices),
                lastIndex: row.last_index,
                currentRoundTotal: row.current_round_total
            });
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
