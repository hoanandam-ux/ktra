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
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// IN-MEMORY STORAGE
// ============================================================
const usedIPs         = new NodeCache({ stdTTL: 0 });   // IP đã làm bài
const fingerprintCache = new NodeCache({ stdTTL: 0 });  // browser fingerprint
const results         = new NodeCache({ stdTTL: 0 });   // kết quả quiz
const dirtyIPCache    = new NodeCache({ stdTTL: 3600 }); // cache kết quả check dirty IP

// ============================================================
// VOCABULARY DATA
// ============================================================
const vocabulary = [
  { word: 'a',              phonetic: '/ə/',            meaning: 'một',                   alt: ['1','mot','một'] },
  { word: 'ability',        phonetic: '/əˈbɪlɪti/',    meaning: 'khả năng',              alt: ['kha nang','năng lực','nang luc'] },
  { word: 'able',           phonetic: '/ˈeɪbl/',        meaning: 'có khả năng',           alt: ['co kha nang','có thể','co the'] },
  { word: 'about',          phonetic: '/əˈbaʊt/',       meaning: 'khoảng',                alt: ['khoang','về','ve','xung quanh'] },
  { word: 'above',          phonetic: '/əˈbʌv/',        meaning: 'trên, phía trên',       alt: ['tren','phía trên','pha tren','tren phia tren'] },
  { word: 'accept',         phonetic: '/əkˈsept/',      meaning: 'chấp nhận',             alt: ['chap nhan','đồng ý','dong y'] },
  { word: 'according (to)', phonetic: '/əˈkɔːrdɪŋ/',   meaning: 'theo',                  alt: ['dua theo','dựa theo'] },
  { word: 'account',        phonetic: '/əˈkaʊnt/',      meaning: 'tài khoản',             alt: ['tai khoan'] },
  { word: 'across',         phonetic: '/əˈkrɒs/',       meaning: 'đi qua',                alt: ['di qua','ngang qua','ngang','qua'] },
  { word: 'act',            phonetic: '/ækt/',           meaning: 'hành động, đóng vai',   alt: ['hanh dong','hành động','dong vai','đóng vai','hanh dong dong vai'] },
];

// ============================================================
// PASSWORDS
// ============================================================
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'htr911';
const USER_PASSWORD  = process.env.USER_PASSWORD  || 'leconghoan';

// ============================================================
// KNOWN DIRTY IP RANGES (VPN / Public DNS / datacenter)
// ============================================================
const DIRTY_IP_PREFIXES = [
  '1.1.1.',     // Cloudflare DNS
  '1.0.0.',     // Cloudflare DNS alt
  '8.8.8.',     // Google DNS
  '8.8.4.',     // Google DNS alt
  '9.9.9.',     // Quad9
  '208.67.',    // OpenDNS
  '4.2.2.',     // Level3
];

// Known VPN/hosting ASN ranges (common ones) — extend as needed
const DIRTY_IP_EXACT = new Set([
  '10.0.0.1','192.168.1.1', // internal (shouldn't appear in prod)
]);

// ============================================================
// DIRTY IP CHECKER
// ============================================================
function isKnownDirtyIP(ip) {
  if (DIRTY_IP_EXACT.has(ip)) return { dirty: true, reason: 'IP nội bộ không hợp lệ' };
  if (DIRTY_IP_PREFIXES.some(prefix => ip.startsWith(prefix)))
    return { dirty: true, reason: 'IP thuộc dải DNS công cộng / VPN đã biết' };
  return { dirty: false };
}

// Async check via ip-api.com (free, no key needed)
function checkIPReputation(ip) {
  return new Promise((resolve) => {
    // Skip check for private / loopback
    if (['127.0.0.1','::1','localhost','unknown'].includes(ip) ||
        ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
      return resolve({ dirty: false });
    }

    // Check cache first
    const cached = dirtyIPCache.get(`dirty_${ip}`);
    if (cached !== undefined) return resolve(cached);

    const url = `http://ip-api.com/json/${ip}?fields=status,proxy,hosting,isp,org,country`;
    const req = require('http').get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          let result = { dirty: false };
          if (json.proxy === true) {
            result = { dirty: true, reason: `Phát hiện Proxy / VPN (${json.isp || ''})` };
          } else if (json.hosting === true) {
            result = { dirty: true, reason: `IP thuộc datacenter / hosting (${json.org || json.isp || ''})` };
          }
          dirtyIPCache.set(`dirty_${ip}`, result);
          resolve(result);
        } catch (e) {
          resolve({ dirty: false }); // fail open if API down
        }
      });
    });
    req.on('error', () => resolve({ dirty: false }));
    req.setTimeout(3000, () => { req.destroy(); resolve({ dirty: false }); });
  });
}

// ============================================================
// SECURITY MIDDLEWARE
// ============================================================
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
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
    maxAge: 2 * 60 * 60 * 1000,
    sameSite: 'strict',
  },
  name: 'vqsid',
}));

const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 100, standardHeaders: true, legacyHeaders: false });
const authLimiter   = rateLimit({ windowMs: 15*60*1000, max: 15, message: { error: 'Quá nhiều lần thử. Vui lòng thử lại sau.' } });
app.use(globalLimiter);

// ============================================================
// HELPERS
// ============================================================
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',').map(s => s.trim())[0];
  return req.ip || req.connection.remoteAddress || 'unknown';
}

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
  // Block headless browsers
  const ua = req.headers['user-agent'] || '';
  const headlessSigns = ['HeadlessChrome','PhantomJS','Selenium','WebDriver','puppeteer','playwright'];
  if (headlessSigns.some(s => ua.includes(s))) {
    return res.status(403).json({ error: 'Trình duyệt tự động không được phép.' });
  }
  // Block obvious proxy headers (not CF)
  if (req.headers['via'] && !req.headers['cf-ray']) {
    return res.status(403).json({ error: 'Proxy/VPN không được phép.' });
  }
  req.realIP = getRealIP(req);
  req.fingerprint = generateFingerprint(req);
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

// User login — with dirty IP check + fingerprint reset support
app.post('/api/auth/user', authLimiter, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Missing password' });
  if (password !== USER_PASSWORD) return res.status(401).json({ error: 'Sai mã truy cập!' });

  const ip          = getRealIP(req);
  const fingerprint = generateFingerprint(req);
  const fpKey       = `fp_${fingerprint}`;

  // --- DIRTY IP CHECK (VPN/proxy/datacenter/4G carrier grade NAT) ---
  const knownDirty = isKnownDirtyIP(ip);
  if (knownDirty.dirty) {
    return res.status(403).json({
      error: `IP bẩn — không thể truy cập: ${knownDirty.reason}`,
      code: 'DIRTY_IP',
    });
  }

  // Async reputation check
  const reputation = await checkIPReputation(ip);
  if (reputation.dirty) {
    return res.status(403).json({
      error: `IP bẩn — không thể truy cập: ${reputation.reason}`,
      code: 'DIRTY_IP',
    });
  }

  // --- IP LOCK CHECK ---
  // BUG FIX: also clear fingerprint when IP was reset by admin
  const ipRecord = usedIPs.get(ip);
  if (ipRecord) {
    return res.status(403).json({
      error: 'IP này đã được sử dụng để làm bài. Mỗi IP chỉ được làm 1 lần.',
      code: 'IP_USED',
    });
  }

  // --- FINGERPRINT CHECK ---
  // BUG FIX: only block if the fingerprint's associated IP is NOT reset
  const fpRecord = fingerprintCache.get(fpKey);
  if (fpRecord) {
    // Check: if the IP stored in fpRecord was reset, allow
    const storedIP = fpRecord.ip;
    const storedIPStillUsed = usedIPs.get(storedIP);
    if (storedIPStillUsed) {
      return res.status(403).json({
        error: 'Thiết bị này đã được sử dụng để làm bài.',
        code: 'DEVICE_USED',
      });
    }
    // IP was reset by admin → clear the fingerprint lock too
    fingerprintCache.del(fpKey);
  }

  req.session.userAuthed     = true;
  req.session.userIP         = ip;
  req.session.userFingerprint = fingerprint;
  req.session.quizStarted    = false;
  res.json({ success: true, message: 'Đăng nhập thành công!' });
});

// Admin login
app.post('/api/auth/admin', authLimiter, (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Sai mật khẩu admin!' });
  req.session.adminAuthed = true;
  res.json({ success: true });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.clearCookie('vqsid');
  res.json({ success: true });
});

// Status
app.get('/api/auth/status', (req, res) => {
  res.json({
    userAuthed:  !!req.session.userAuthed,
    adminAuthed: !!req.session.adminAuthed,
    quizDone:    !!req.session.quizDone,
  });
});

// Quick dirty-IP pre-check (called by frontend before login)
app.get('/api/auth/ip-check', async (req, res) => {
  const ip = getRealIP(req);
  const knownDirty = isKnownDirtyIP(ip);
  if (knownDirty.dirty) return res.json({ dirty: true, reason: knownDirty.reason, ip });
  const reputation = await checkIPReputation(ip);
  res.json({ dirty: reputation.dirty, reason: reputation.reason || null, ip });
});

// ============================================================
// ROUTES: QUIZ — Mixed (5 EN→VI + 5 VI→EN, shuffled together)
// ============================================================
app.get('/api/quiz/questions', antiFraud, requireUser, (req, res) => {
  if (req.session.quizDone) return res.status(403).json({ error: 'Bạn đã hoàn thành bài kiểm tra rồi!' });

  // 10 en2vi (Câu 1-10: điền tiếng Việt) + 10 vi2en (Câu 11-20: điền tiếng Anh)
  // Each half shuffled independently so word order varies each attempt
  const shuffledEn2Vi = [...vocabulary].sort(() => Math.random() - 0.5);
  const shuffledVi2En = [...vocabulary].sort(() => Math.random() - 0.5);
  const mixed = [
    ...shuffledEn2Vi.map(v => ({ word: v.word, mode: 'en2vi' })),
    ...shuffledVi2En.map(v => ({ word: v.word, mode: 'vi2en' })),
  ];

  req.session.currentQuiz = mixed.map(q => q.word);
  req.session.quizModes   = mixed.map(q => q.mode); // store per-question modes
  req.session.quizStarted = true;
  req.session.startTime   = Date.now();

  const questions = mixed.map((item, i) => {
    const v = vocabulary.find(x => x.word === item.word);
    return {
      id:     i,
      mode:   item.mode,
      prompt: item.mode === 'en2vi' ? v.word    : v.meaning,
      hint:   item.mode === 'en2vi' ? v.phonetic : null,
    };
  });

  res.json({ questions });
});

// ============================================================
// ROUTES: QUIZ — Submit (works for both modes)
// ============================================================
app.post('/api/quiz/submit', antiFraud, requireUser, (req, res) => {
  if (req.session.quizDone) return res.status(403).json({ error: 'Bạn đã nộp bài rồi!' });
  if (!req.session.quizStarted || !req.session.currentQuiz) return res.status(400).json({ error: 'Chưa bắt đầu quiz!' });

  const { answers, name } = req.body;
  if (!answers || !Array.isArray(answers)) return res.status(400).json({ error: 'Invalid answers format' });

  const ip        = getRealIP(req);
  const fingerprint = req.session.userFingerprint;
  const timeTaken = Math.round((Date.now() - req.session.startTime) / 1000);
  const quizModes = req.session.quizModes || []; // per-question modes

  // Time limit enforcement
  const TIME_LIMIT = 120;
  if (timeTaken > TIME_LIMIT + 5) {
    req.session.quizDone = true;
    return res.status(403).json({ error: 'Hết giờ! Bài kiểm tra chỉ cho phép 2 phút.', code: 'TIME_UP', timeTaken });
  }

  // Grade
  const quizWords = req.session.currentQuiz;
  let score = 0;
  const graded = [];

  for (let i = 0; i < quizWords.length; i++) {
    const word  = quizWords[i];
    const vocab = vocabulary.find(v => v.word === word);
    const raw   = (answers[i] || '').trim().toLowerCase().normalize('NFC');
    let correct = false;

    if (vocab) {
      const mode = quizModes[i] || 'en2vi';
      if (mode === 'en2vi') {
        // User typed Vietnamese meaning
        const acceptable = [
          vocab.meaning.toLowerCase().normalize('NFC'),
          ...vocab.alt.map(a => a.toLowerCase().normalize('NFC')),
        ];
        correct = acceptable.some(acc =>
          raw === acc || (acc.length > 3 && raw.length > 2 && (acc.includes(raw) || raw.includes(acc)))
        );
      } else {
        // vi2en: user typed the English word
        const acceptable = [vocab.word.toLowerCase()];
        // also accept without parentheses part e.g. "according" for "according (to)"
        const simplified = vocab.word.replace(/\s*\(.*\)/, '').trim().toLowerCase();
        if (simplified !== vocab.word.toLowerCase()) acceptable.push(simplified);
        correct = acceptable.some(acc => raw === acc);
      }
    }

    if (correct) score++;
    const qMode = quizModes[i] || 'en2vi';
    graded.push({
      word:          vocab?.word,
      phonetic:      vocab?.phonetic,
      meaning:       vocab?.meaning,
      prompt:        qMode === 'en2vi' ? vocab?.word    : vocab?.meaning,
      correctAnswer: qMode === 'en2vi' ? vocab?.meaning : vocab?.word,
      userAnswer:    answers[i] || '',
      correct,
      mode:          qMode,
    });
  }

  // Lock IP and fingerprint — store fingerprint with its IP so reset works correctly
  usedIPs.set(ip, { usedAt: new Date().toISOString(), name });
  fingerprintCache.set(`fp_${fingerprint}`, { ip, lockedAt: new Date().toISOString() });

  // Store result
  const resultId = uuidv4();
  results.set(resultId, {
    id:          resultId,
    name:        name || 'Ẩn danh',
    ip,
    score,
    total:       20,
    percent:     Math.round((score / 20) * 100),
    timeTaken,
    submittedAt: new Date().toISOString(),
    graded,
  });

  req.session.quizDone    = true;
  req.session.quizStarted = false;

  res.json({
    success: true,
    score,
    total:    20,
    percent:  Math.round((score / 20) * 100),
    timeTaken,
    graded,
    message: score >= 14 ? '🎉 Xuất sắc!' : score >= 10 ? '👍 Khá tốt!' : '📚 Cần ôn thêm!',
  });
});

// ============================================================
// ROUTES: ADMIN
// ============================================================
app.get('/api/admin/results', requireAdmin, (req, res) => {
  const all = results.keys().map(k => results.get(k)).filter(Boolean);
  all.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));
  res.json({ results: all, total: all.length });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const all     = results.keys().map(k => results.get(k)).filter(Boolean);
  const avgScore = all.length
    ? Math.round(all.reduce((s, r) => s + r.score, 0) / all.length * 10) / 10
    : 0;
  const passed = all.filter(r => r.score >= 10).length;
  res.json({ total: all.length, avgScore, passed, failed: all.length - passed, usedIPs: usedIPs.keys().length });
});

app.delete('/api/admin/results/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  if (results.del(id)) res.json({ success: true });
  else res.status(404).json({ error: 'Not found' });
});

// BUG FIX: Reset IP + also remove associated fingerprint lock
app.post('/api/admin/reset-ip', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'Missing IP' });

  // Remove IP lock
  usedIPs.del(ip);

  // Also remove all fingerprint locks associated with this IP
  let fpRemoved = 0;
  fingerprintCache.keys().forEach(key => {
    const val = fingerprintCache.get(key);
    if (val && val.ip === ip) {
      fingerprintCache.del(key);
      fpRemoved++;
    }
  });

  res.json({ success: true, message: `IP ${ip} đã được reset. Xóa thêm ${fpRemoved} fingerprint liên quan.` });
});

// ============================================================
// STATIC + SPA
// ============================================================
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`🚀 VocabQuiz running on port ${PORT}`);
});
