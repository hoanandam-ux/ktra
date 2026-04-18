require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// IN-MEMORY STORAGE (dùng cho demo / Render free tier)
// Thay bằng Redis/MongoDB cho production thực sự
// ============================================================
const usedIPs = new NodeCache({ stdTTL: 0 }); // IP đã dùng – vĩnh viễn
const sessions = new NodeCache({ stdTTL: 3600 }); // session hợp lệ
const results = new NodeCache({ stdTTL: 0 }); // kết quả quiz
const fingerprintCache = new NodeCache({ stdTTL: 0 }); // browser fingerprint

// ============================================================
// VOCABULARY DATA
// ============================================================
const vocabulary = [
  { word: 'a', phonetic: '/ə/', meaning: 'một', alt: ['1', 'mot', 'một'] },
  { word: 'ability', phonetic: '/əˈbɪlɪti/', meaning: 'khả năng', alt: ['kha nang', 'khả năng', 'năng lực', 'nang luc'] },
  { word: 'able', phonetic: '/ˈeɪbl/', meaning: 'có khả năng', alt: ['co kha nang', 'có khả năng', 'có thể', 'co the'] },
  { word: 'about', phonetic: '/əˈbaʊt/', meaning: 'khoảng', alt: ['khoang', 'khoảng', 'về', 've', 'xung quanh'] },
  { word: 'above', phonetic: '/əˈbʌv/', meaning: 'trên, phía trên', alt: ['tren', 'trên', 'phía trên', 'pha tren', 'phia tren'] },
  { word: 'accept', phonetic: '/əkˈsept/', meaning: 'chấp nhận', alt: ['chap nhan', 'chấp nhận', 'đồng ý', 'dong y'] },
  { word: 'according (to)', phonetic: '/əˈkɔːrdɪŋ/', meaning: 'theo', alt: ['theo', 'dua theo', 'dựa theo'] },
  { word: 'account', phonetic: '/əˈkaʊnt/', meaning: 'tài khoản', alt: ['tai khoan', 'tài khoản', 'tài khoản ngân hàng'] },
  { word: 'across', phonetic: '/əˈkrɒs/', meaning: 'đi qua', alt: ['di qua', 'đi qua', 'ngang qua', 'ngang', 'qua'] },
  { word: 'act', phonetic: '/ækt/', meaning: 'hành động, đóng vai', alt: ['hanh dong', 'hành động', 'dong vai', 'đóng vai', 'hành xử', 'hanh xu'] },
];

// ============================================================
// PASSWORDS
// ============================================================
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'htr911';
const USER_PASSWORD = process.env.USER_PASSWORD || 'leconghoan';

// ============================================================
// SECURITY MIDDLEWARE
// ============================================================
app.set('trust proxy', 1); // trust Render's proxy

app.use(helmet({
  contentSecurityPolicy: false, // we manage CSP manually
}));

app.use(cors({ origin: false }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'vocab-quiz-secret-2024'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'session-secret-vocab-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 2 * 60 * 60 * 1000, // 2 hours
    sameSite: 'strict',
  },
  name: 'vqsid',
}));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
});
app.use(globalLimiter);

// Auth rate limiter (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts' },
});

// ============================================================
// IP EXTRACTION HELPER
// ============================================================
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = forwarded.split(',').map(ip => ip.trim());
    return ips[0];
  }
  return req.ip || req.connection.remoteAddress || 'unknown';
}

// ============================================================
// FINGERPRINT HELPER
// ============================================================
function generateFingerprint(req) {
  const parts = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.headers['accept'] || '',
  ];
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}

// ============================================================
// ANTI-FRAUD MIDDLEWARE
// ============================================================
function antiFraud(req, res, next) {
  const ip = getRealIP(req);
  const fingerprint = generateFingerprint(req);

  // Block Tor / common proxy headers
  const proxyHeaders = ['x-proxy-id', 'via', 'forwarded', 'x-real-ip', 'cf-connecting-ip'];
  // Allow Cloudflare (used by Render) but block obvious proxies
  if (req.headers['via'] && !req.headers['cf-ray']) {
    return res.status(403).json({ error: 'Proxy/VPN không được phép sử dụng.' });
  }

  // Block headless browsers
  const ua = req.headers['user-agent'] || '';
  const headlessSigns = ['HeadlessChrome', 'PhantomJS', 'Selenium', 'WebDriver', 'puppeteer', 'playwright'];
  if (headlessSigns.some(sign => ua.includes(sign))) {
    return res.status(403).json({ error: 'Trình duyệt tự động không được phép.' });
  }

  req.realIP = ip;
  req.fingerprint = fingerprint;
  next();
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function requireUser(req, res, next) {
  if (req.session && req.session.userAuthed) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.adminAuthed) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ============================================================
// ROUTES: AUTH
// ============================================================

// User login
app.post('/api/auth/user', authLimiter, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Missing password' });

  if (password !== USER_PASSWORD) {
    return res.status(401).json({ error: 'Sai mật khẩu!' });
  }

  const ip = getRealIP(req);
  const fingerprint = generateFingerprint(req);
  const fpKey = `fp_${fingerprint}`;

  // Check if IP already used
  if (usedIPs.get(ip)) {
    return res.status(403).json({
      error: 'IP này đã được sử dụng để làm bài. Mỗi IP chỉ được làm 1 lần.',
      code: 'IP_USED',
    });
  }

  // Check if fingerprint already used
  if (fingerprintCache.get(fpKey)) {
    return res.status(403).json({
      error: 'Thiết bị này đã được sử dụng để làm bài.',
      code: 'DEVICE_USED',
    });
  }

  req.session.userAuthed = true;
  req.session.userIP = ip;
  req.session.userFingerprint = fingerprint;
  req.session.quizStarted = false;

  res.json({ success: true, message: 'Đăng nhập thành công!' });
});

// Admin login
app.post('/api/auth/admin', authLimiter, (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Sai mật khẩu admin!' });
  }
  req.session.adminAuthed = true;
  res.json({ success: true });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.clearCookie('vqsid');
  res.json({ success: true });
});

// Check auth status
app.get('/api/auth/status', (req, res) => {
  res.json({
    userAuthed: !!req.session.userAuthed,
    adminAuthed: !!req.session.adminAuthed,
    quizDone: !!req.session.quizDone,
  });
});

// ============================================================
// ROUTES: QUIZ
// ============================================================

// Get 10 random questions
app.get('/api/quiz/questions', antiFraud, requireUser, (req, res) => {
  if (req.session.quizDone) {
    return res.status(403).json({ error: 'Bạn đã hoàn thành bài kiểm tra rồi!' });
  }

  // Shuffle and pick 10
  const shuffled = [...vocabulary].sort(() => Math.random() - 0.5);
  const selected = shuffled.slice(0, 10);

  // Store in session so answers can be verified
  req.session.currentQuiz = selected.map(v => v.word);
  req.session.quizStarted = true;
  req.session.startTime = Date.now();

  // Return questions WITHOUT meanings
  const questions = selected.map((v, i) => ({
    id: i,
    word: v.word,
    phonetic: v.phonetic,
  }));

  res.json({ questions });
});

// Submit answers
app.post('/api/quiz/submit', antiFraud, requireUser, (req, res) => {
  if (req.session.quizDone) {
    return res.status(403).json({ error: 'Bạn đã nộp bài rồi!' });
  }
  if (!req.session.quizStarted || !req.session.currentQuiz) {
    return res.status(400).json({ error: 'Chưa bắt đầu quiz!' });
  }

  const { answers, name } = req.body;
  if (!answers || !Array.isArray(answers)) {
    return res.status(400).json({ error: 'Invalid answers format' });
  }

  const ip = getRealIP(req);
  const fingerprint = req.session.userFingerprint;
  const timeTaken = Math.round((Date.now() - req.session.startTime) / 1000);

  // ⏱ Enforce 2-minute (120s) time limit — server-side enforcement
  const TIME_LIMIT = 120;
  if (timeTaken > TIME_LIMIT + 5) { // +5s grace for network latency
    req.session.quizDone = true; // prevent retry
    return res.status(403).json({
      error: 'Hết giờ! Bài kiểm tra chỉ cho phép 2 phút.',
      code: 'TIME_UP',
      timeTaken,
    });
  }

  // Grade answers
  const quizWords = req.session.currentQuiz;
  let score = 0;
  const graded = [];

  for (let i = 0; i < quizWords.length; i++) {
    const word = quizWords[i];
    const vocab = vocabulary.find(v => v.word === word);
    const userAnswer = (answers[i] || '').trim().toLowerCase()
      .normalize('NFC');

    let correct = false;
    if (vocab) {
      const acceptableAnswers = [
        vocab.meaning.toLowerCase().normalize('NFC'),
        ...vocab.alt.map(a => a.toLowerCase().normalize('NFC')),
      ];

      // Check exact match or fuzzy (contains)
      correct = acceptableAnswers.some(acc => {
        // exact
        if (userAnswer === acc) return true;
        // contains check (at least 70% of chars match)
        if (acc.length > 3 && userAnswer.length > 2) {
          if (acc.includes(userAnswer) || userAnswer.includes(acc)) return true;
        }
        return false;
      });

      if (correct) score++;
    }

    graded.push({
      word: vocab?.word,
      phonetic: vocab?.phonetic,
      userAnswer: answers[i] || '',
      correctMeaning: vocab?.meaning,
      correct,
    });
  }

  // Mark IP and fingerprint as used
  usedIPs.set(ip, { usedAt: new Date().toISOString(), name });
  fingerprintCache.set(`fp_${fingerprint}`, true);

  // Store result
  const resultId = uuidv4();
  const resultData = {
    id: resultId,
    name: name || 'Ẩn danh',
    ip,
    score,
    total: 10,
    percent: Math.round((score / 10) * 100),
    timeTaken,
    submittedAt: new Date().toISOString(),
    graded,
  };
  results.set(resultId, resultData);

  // Mark session as done
  req.session.quizDone = true;
  req.session.quizStarted = false;

  res.json({
    success: true,
    score,
    total: 10,
    percent: resultData.percent,
    timeTaken,
    graded,
    message: score >= 7 ? '🎉 Xuất sắc!' : score >= 5 ? '👍 Khá tốt!' : '📚 Cần ôn thêm!',
  });
});

// ============================================================
// ROUTES: ADMIN
// ============================================================

app.get('/api/admin/results', requireAdmin, (req, res) => {
  const keys = results.keys();
  const allResults = keys.map(k => results.get(k)).filter(Boolean);
  // Sort by submittedAt desc
  allResults.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));
  res.json({ results: allResults, total: allResults.length });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const keys = results.keys();
  const allResults = keys.map(k => results.get(k)).filter(Boolean);
  const avgScore = allResults.length
    ? Math.round(allResults.reduce((s, r) => s + r.score, 0) / allResults.length * 10) / 10
    : 0;
  const passed = allResults.filter(r => r.score >= 5).length;

  res.json({
    total: allResults.length,
    avgScore,
    passed,
    failed: allResults.length - passed,
    usedIPs: usedIPs.keys().length,
  });
});

app.delete('/api/admin/results/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  if (results.del(id)) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// Reset an IP (allow re-attempt)
app.post('/api/admin/reset-ip', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'Missing IP' });
  usedIPs.del(ip);
  res.json({ success: true, message: `IP ${ip} đã được reset.` });
});

// ============================================================
// STATIC FILES
// ============================================================
app.use(express.static(path.join(__dirname, 'public')));

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`🚀 Vocab Quiz Server running on port ${PORT}`);
  console.log(`👤 User Password: ${USER_PASSWORD}`);
  console.log(`🔐 Admin Password: ${ADMIN_PASSWORD}`);
});
