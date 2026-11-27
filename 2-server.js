// سيرفر موقع "مشاهدة": حسابات + رفع فيديوهات + بحث + لايك + تعليقات
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
// لو مفيش JWT_SECRET بنعمل واحد عشوائي (الجلسات هتتمسح مع كل تشغيل). في النشر الحقيقي حطه في Environment.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'app.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  filename TEXT NOT NULL,
  views INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS likes (
  user_id INTEGER NOT NULL,
  video_id INTEGER NOT NULL,
  PRIMARY KEY (user_id, video_id)
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  video_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const app = express();
app.use(express.json({ limit: '100kb' }));

// ---------- مساعدات ----------
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'لازم تسجل دخول' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'الجلسة انتهت، سجل دخول تاني' });
  }
}
const sign = (u) => jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: '30d' });
const videoOut = (v) => ({ ...v, url: '/uploads/' + v.filename, filename: undefined });

// ---------- الحسابات ----------
app.post('/api/register', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (username.length < 3 || username.length > 30) return res.status(400).json({ error: 'اسم المستخدم من 3 لـ 30 حرف' });
  if (password.length < 6) return res.status(400).json({ error: 'كلمة السر 6 حروف على الأقل' });
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username))
    return res.status(409).json({ error: 'الاسم ده مستخدم' });
  const info = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .run(username, bcrypt.hashSync(password, 10));
  const user = { id: info.lastInsertRowid, username };
  res.status(201).json({ token: sign(user), user });
});

app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(String(req.body.username || '').trim());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.password_hash))
    return res.status(401).json({ error: 'بيانات الدخول غلط' });
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
});

app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

// ---------- الفيديوهات ----------
const ALLOWED = ['.mp4', '.webm', '.mov', '.m4v', '.ogv'];
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) =>
      cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase()),
  }),
  limits: { fileSize: 200 * 1024 * 1024 }, // 200 ميجا
  fileFilter: (req, file, cb) =>
    cb(null, ALLOWED.includes(path.extname(file.originalname).toLowerCase())),
});

app.post('/api/videos', auth, upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'ارفع ملف فيديو (mp4 أو webm أو mov)' });
  const title = String(req.body.title || '').trim().slice(0, 120);
  if (!title) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'اكتب عنوان للفيديو' });
  }
  const description = String(req.body.description || '').slice(0, 2000);
  const info = db.prepare('INSERT INTO videos (user_id, title, description, filename) VALUES (?,?,?,?)')
    .run(req.user.id, title, description, req.file.filename);
  res.status(201).json({ id: info.lastInsertRowid });
});

const LIST_SQL = `
  SELECT v.id, v.title, v.description, v.filename, v.views, v.created_at,
         u.username AS author,
         (SELECT COUNT(*) FROM likes l WHERE l.video_id = v.id) AS likes
  FROM videos v JOIN users u ON u.id = v.user_id`;

app.get('/api/videos', (req, res) => {
  const q = String(req.query.q || '').trim();
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  const offset = parseInt(req.query.offset) || 0;
  const rows = q
    ? db.prepare(LIST_SQL + ' WHERE v.title LIKE ? ORDER BY v.id DESC LIMIT ? OFFSET ?')
        .all('%' + q.replace(/[%_]/g, '') + '%', limit, offset)
    : db.prepare(LIST_SQL + ' ORDER BY v.id DESC LIMIT ? OFFSET ?').all(limit, offset);
  res.json({ videos: rows.map(videoOut) });
});

app.get('/api/videos/:id', (req, res) => {
  const v = db.prepare(LIST_SQL + ' WHERE v.id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'الفيديو مش موجود' });
  db.prepare('UPDATE videos SET views = views + 1 WHERE id = ?').run(v.id);
  v.views += 1;
  res.json(videoOut(v));
});

app.delete('/api/videos/:id', auth, (req, res) => {
  const v = db.prepare('SELECT * FROM videos WHERE id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'الفيديو مش موجود' });
  if (v.user_id !== req.user.id) return res.status(403).json({ error: 'مش فيديو بتاعك' });
  db.prepare('DELETE FROM videos WHERE id = ?').run(v.id);
  db.prepare('DELETE FROM comments WHERE video_id = ?').run(v.id);
  db.prepare('DELETE FROM likes WHERE video_id = ?').run(v.id);
  fs.unlink(path.join(UPLOAD_DIR, v.filename), () => {});
  res.json({ ok: true });
});

// لايك: بيشتغل كتبديل (لايك / شيل اللايك)
app.post('/api/videos/:id/like', auth, (req, res) => {
  const id = Number(req.params.id);
  if (!db.prepare('SELECT 1 FROM videos WHERE id = ?').get(id)) return res.status(404).json({ error: 'الفيديو مش موجود' });
  const has = db.prepare('SELECT 1 FROM likes WHERE user_id = ? AND video_id = ?').get(req.user.id, id);
  if (has) db.prepare('DELETE FROM likes WHERE user_id = ? AND video_id = ?').run(req.user.id, id);
  else db.prepare('INSERT INTO likes (user_id, video_id) VALUES (?, ?)').run(req.user.id, id);
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM likes WHERE video_id = ?').get(id);
  res.json({ liked: !has, likes: n });
});

// ---------- التعليقات ----------
app.get('/api/videos/:id/comments', (req, res) => {
  res.json({
    comments: db.prepare(`SELECT c.id, c.body, c.created_at, u.username AS author
      FROM comments c JOIN users u ON u.id = c.user_id
      WHERE c.video_id = ? ORDER BY c.id DESC LIMIT 200`).all(req.params.id),
  });
});

app.post('/api/videos/:id/comments', auth, (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 1000);
  if (!body) return res.status(400).json({ error: 'اكتب التعليق' });
  if (!db.prepare('SELECT 1 FROM videos WHERE id = ?').get(req.params.id)) return res.status(404).json({ error: 'الفيديو مش موجود' });
  const info = db.prepare('INSERT INTO comments (video_id, user_id, body) VALUES (?,?,?)')
    .run(req.params.id, req.user.id, body);
  res.status(201).json({ id: info.lastInsertRowid });
});

// ---------- الملفات ----------
// express.static بيدعم Range، يعني الفيديو يتقدم ويرجع عادي
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: 'الملف كبير (الحد 200 ميجا)' });
  console.error(err);
  res.status(500).json({ error: 'حصل خطأ في السيرفر' });
});

app.listen(PORT, () => console.log('شغال على http://localhost:' + PORT));
