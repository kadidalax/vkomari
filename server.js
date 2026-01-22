const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const WebSocket = require('ws');
const nodePath = require('path');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const https = require('https');
const http = require('http');

var IP_PREFIXES = {
    'CN': ['116.198.', '121.40.', '47.94.', '39.108.'],
    'HK': ['103.152.', '45.125.', '156.251.', '103.117.'],
    'TW': ['61.216.', '114.34.', '118.163.', '211.72.'],
    'MO': ['122.100.', '60.246.', '202.175.'],
    'JP': ['45.76.', '139.162.', '150.95.', '160.16.'],
    'SG': ['128.199.', '159.89.', '206.189.', '8.219.'],
    'KR': ['121.78.', '211.234.', '125.141.', '222.122.'],
    'US': ['104.238.', '45.63.', '66.42.', '149.28.'],
    'DE': ['5.189.', '78.46.', '88.99.', '116.202.'],
    'GB': ['51.15.', '178.62.', '139.59.', '167.71.'],
    'NL': ['45.63.', '95.179.', '136.244.', '185.216.'],
    'FR': ['51.158.', '163.172.', '62.210.', '54.37.'],
    'RU': ['45.141.', '185.22.', '91.218.', '46.17.'],
    'CA': ['149.56.', '158.69.', '192.99.', '51.79.'],
    'AU': ['103.16.', '45.121.', '139.99.', '168.138.'],
    'IN': ['103.21.', '139.59.', '143.110.', '68.183.'],
    'BR': ['177.54.', '191.96.', '45.174.', '168.227.'],
    'TH': ['103.253.', '171.97.', '49.228.', '182.52.'],
    'VN': ['103.97.', '171.244.', '14.225.', '42.112.'],
    'MY': ['103.106.', '175.139.', '60.54.', '103.86.'],
    'ID': ['103.28.', '36.92.', '114.4.', '103.10.'],
    'PH': ['103.78.', '112.198.', '49.145.', '103.225.'],
    'AR': ['181.47.', '190.2.', '200.55.', '45.170.'],
    'MX': ['187.188.', '189.203.', '201.163.', '200.68.'],
    'ZA': ['102.165.', '154.0.', '196.216.', '105.224.'],
    'TR': ['185.193.', '31.145.', '78.186.', '176.33.'],
    'AE': ['94.200.', '185.176.', '86.96.', '185.23.'],
    'SA': ['188.247.', '185.70.', '95.177.', '185.117.'],
    'IT': ['151.38.', '79.2.', '93.35.', '5.90.'],
    'ES': ['88.27.', '95.127.', '185.253.', '37.223.'],
    'PT': ['188.37.', '85.243.', '94.63.', '5.249.'],
    'PL': ['185.243.', '91.232.', '5.184.', '37.47.'],
    'SE': ['185.213.', '45.83.', '194.68.', '31.211.'],
    'NO': ['185.35.', '91.189.', '178.164.', '193.90.'],
    'FI': ['185.31.', '95.175.', '91.152.', '193.64.'],
    'DK': ['185.206.', '91.198.', '185.129.', '193.163.'],
    'CH': ['185.181.', '178.197.', '31.164.', '146.0.'],
    'AT': ['185.216.', '78.142.', '91.118.', '185.101.'],
    'BE': ['185.232.', '91.183.', '178.51.', '193.191.'],
    'IE': ['185.107.', '87.44.', '92.251.', '193.1.'],
    'CZ': ['185.8.', '89.221.', '46.174.', '193.86.'],
    'RO': ['185.225.', '89.40.', '86.105.', '193.226.'],
    'HU': ['185.33.', '89.134.', '84.0.', '193.225.'],
    'GR': ['185.4.', '94.66.', '79.166.', '193.92.'],
    'UA': ['185.65.', '91.194.', '176.36.', '193.19.'],
    'KZ': ['185.125.', '95.56.', '178.89.', '2.132.'],
    'NZ': ['103.197.', '125.236.', '49.50.', '202.36.'],
    'CL': ['185.112.', '190.107.', '200.54.', '152.172.']
};

function generateFakeIP(region) {
    var prefixes = IP_PREFIXES[region] || IP_PREFIXES['US'];
    var prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    var third = Math.floor(Math.random() * 256);
    var fourth = Math.floor(Math.random() * 254) + 1;
    return prefix + third + '.' + fourth;
}

// ISO 国家代码转 emoji 旗帜
function isoToEmoji(code) {
    if (!code || code.length !== 2) return '🏳️';
    return String.fromCodePoint(
        ...code.toUpperCase().split('').map(function(c) { return 0x1F1E6 + c.charCodeAt(0) - 65; })
    );
}

var PORT = 4000;
var DB_PATH = process.env.DB_PATH || nodePath.join(__dirname, 'data', 'database.sqlite');
var JWT_SECRET = process.env.JWT_SECRET || 'vkomari-secret-key-2026';
var LOGIN_ATTEMPTS = new Map();
var LOCKOUT_TIME = 300000;

var dbDir = nodePath.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

var app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cors());
app.use(express.static(nodePath.join(__dirname, 'public')));

var db = new sqlite3.Database(DB_PATH);

db.serialize(function () {
    db.run('CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, server_address TEXT, client_secret TEXT, client_uuid TEXT, cpu_model TEXT, cpu_cores INTEGER, ram_total INTEGER, swap_total INTEGER, disk_total INTEGER, os TEXT, arch TEXT, virtualization TEXT, region TEXT, kernel_version TEXT, load_profile TEXT, cpu_min REAL, cpu_max REAL, mem_min REAL, mem_max REAL, swap_min REAL, swap_max REAL, disk_min REAL, disk_max REAL, net_min INTEGER, net_max INTEGER, conn_min INTEGER, conn_max INTEGER, proc_min INTEGER, proc_max INTEGER, report_interval INTEGER DEFAULT 1, enabled INTEGER DEFAULT 1, boot_time INTEGER DEFAULT 0, fake_ip TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');

    db.all('PRAGMA table_info(nodes)', function (err, rows) {
        if (rows && !rows.some(function (c) { return c.name === 'fake_ip'; })) {
            db.run('ALTER TABLE nodes ADD COLUMN fake_ip TEXT');
        }
    });

    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT)', [], function () {
        db.get('SELECT * FROM users WHERE username=?', ['admin'], function (e, r) {
            if (!r) {
                var salt = crypto.randomBytes(16).toString('hex');
                var hash = crypto.pbkdf2Sync('vkomari', salt, 10000, 64, 'sha512').toString('hex');
                db.run('INSERT INTO users (username,password,salt) VALUES (?,?,?)', ['admin', hash, salt]);
                console.log('[vKomari] Default admin created (user: admin, pass: vkomari).');
            }
        });
    });
});

function hashPwd(p, s) {
    s = s || crypto.randomBytes(16).toString('hex');
    return { hash: crypto.pbkdf2Sync(p, s, 10000, 64, 'sha512').toString('hex'), salt: s };
}

function checkLoginAttempts(ip) {
    if (!LOGIN_ATTEMPTS.has(ip)) return true;
    var entry = LOGIN_ATTEMPTS.get(ip);
    if (Date.now() - entry.lastAttempt > LOCKOUT_TIME) { LOGIN_ATTEMPTS.delete(ip); return true; }
    return entry.count < 5;
}

function recordFailedLogin(ip) {
    var entry = LOGIN_ATTEMPTS.get(ip) || { count: 0, lastAttempt: 0 };
    entry.count++; entry.lastAttempt = Date.now();
    LOGIN_ATTEMPTS.set(ip, entry);
}

function auth(req, res, next) {
    var t = (req.headers['authorization'] || '').split(' ')[1];
    if (!t) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(t, JWT_SECRET, function (e, u) {
        if (e) return res.status(403).json({ error: 'Invalid token' });
        req.user = u; next();
    });
}

var activeAgents = new Map();

function Agent(config) {
    this.config = config;
    this.ws = null;
    this.timers = { heartbeat: null, info: null, reconnect: null };
    this.state = { connected: false, sendCount: 0, totalUp: 0, totalDown: 0, lastError: '' };

    // 确保配置值有效
    var cpu_min = Number(config.cpu_min) || 0.5;
    var cpu_max = Number(config.cpu_max) || 5.0;
    var mem_min = Number(config.mem_min) || 5.0;
    var mem_max = Number(config.mem_max) || 15.0;
    var swap_min = Number(config.swap_min) || 0;
    var swap_max = Number(config.swap_max) || 1.0;
    var disk_min = Number(config.disk_min) || 10.0;
    var disk_max = Number(config.disk_max) || 10.5;

    this.sim = {
        cpu: this.randFloat(cpu_min, cpu_max),
        mem: this.randFloat(mem_min, mem_max),
        swap: this.randFloat(swap_min, swap_max),
        disk: this.randFloat(disk_min, disk_max),
        conn: this.rand(Number(config.conn_min) || 2, Number(config.conn_max) || 10),
        proc: this.rand(Number(config.proc_min) || 40, Number(config.proc_max) || 60)
    };
    this.bootTime = config.boot_time > 0 ? config.boot_time : Math.floor(Date.now() / 1000) - 86400 * this.rand(1, 30);
    this.uuid = config.client_uuid || crypto.randomUUID();
    this.shouldReconnect = false;
}

Agent.prototype.rand = function (min, max) {
    min = Number(min) || 0; max = Number(max) || 0;
    if (min > max) { var t = min; min = max; max = t; }
    return Math.floor(Math.random() * (max - min + 1) + min);
};

Agent.prototype.randFloat = function (min, max) {
    min = Number(min) || 0; max = Number(max) || 0;
    if (min > max) { var t = min; min = max; max = t; }
    return Math.random() * (max - min) + min;
};

// 增强的波动算法：随机游走 + 噪声
Agent.prototype.fluctuate = function (current, min, max, volatility) {
    min = Number(min) || 0;
    max = Number(max) || 0;
    current = Number(current) || min;

    if (min > max) { var t = min; min = max; max = t; }
    if (min === max) return min;

    var range = max - min;
    var step = range * 0.05 * (Math.random() - 0.5); // 减小步长
    var next = current + step;
    return Math.max(min, Math.min(max, next));
};

Agent.prototype.start = function () {
    if (!this.config.enabled) return;
    this.shouldReconnect = true;
    this.connect();
};

Agent.prototype.stop = function () {
    this.shouldReconnect = false;
    if (this.timers.heartbeat) clearInterval(this.timers.heartbeat);
    if (this.timers.info) clearInterval(this.timers.info);
    if (this.timers.reconnect) clearTimeout(this.timers.reconnect);
    if (this.ws) { try { this.ws.close(); this.ws.terminate(); } catch (e) { } this.ws = null; }
    this.state.connected = false;
};

Agent.prototype.update = function (newConfig) {
    var wasEnabled = !!this.config.enabled;
    var needsRestart = this.config.server_address !== newConfig.server_address || this.config.client_secret !== newConfig.client_secret;
    this.config = newConfig;

    // 重置模拟状态到新的范围内
    this.sim.cpu = this.randFloat(newConfig.cpu_min, newConfig.cpu_max);
    this.sim.mem = this.randFloat(newConfig.mem_min, newConfig.mem_max);
    this.sim.swap = this.randFloat(newConfig.swap_min, newConfig.swap_max);
    this.sim.disk = this.randFloat(newConfig.disk_min, newConfig.disk_max);
    this.sim.conn = this.rand(newConfig.conn_min, newConfig.conn_max);
    this.sim.proc = this.rand(newConfig.proc_min, newConfig.proc_max);

    if (newConfig.boot_time > 0) this.bootTime = newConfig.boot_time;
    if (!newConfig.enabled) this.stop();
    else if (!wasEnabled || needsRestart) { this.stop(); this.start(); }
};

Agent.prototype.connect = function () {
    var self = this;
    if (!this.shouldReconnect || (this.ws && this.ws.readyState === WebSocket.OPEN)) return;
    var addr = (this.config.server_address || '').trim().replace(/\/+$/, '');
    if (!addr) return;
    if (!/^(ws|http)s?:\/\//.test(addr)) addr = 'wss://' + addr;
    var wsUrl = addr.replace(/^http/, 'ws') + '/api/clients/report?token=' + encodeURIComponent(this.config.client_secret);
    var httpUrl = addr.replace(/^ws/, 'http');
    console.log('[vKomari] Connecting: ' + this.config.name);
    try {
        this.ws = new WebSocket(wsUrl, {
            headers: { 'User-Agent': 'komari-agent/0.1.0', 'Origin': httpUrl },
            handshakeTimeout: 10000, rejectUnauthorized: false
        });
        this.ws.on('open', function () {
            console.log('[vKomari] ✓ Linked: ' + self.config.name);
            self.state.connected = true; self.state.lastError = '';
            self.uploadInfo(httpUrl); self.startLoops(httpUrl);
        });
        this.ws.on('error', function (e) { self.state.lastError = e.message; self.state.connected = false; });
        this.ws.on('close', function () {
            self.state.connected = false; self.ws = null;
            if (self.shouldReconnect) self.timers.reconnect = setTimeout(function () { self.connect(); }, 5000);
        });
    } catch (e) {
        this.state.lastError = e.message;
        if (this.shouldReconnect) this.timers.reconnect = setTimeout(function () { self.connect(); }, 5000);
    }
};

Agent.prototype.uploadInfo = function (baseUrl) {
    var c = this.config;
    var info = {
        name: c.name,
        cpu_name: c.cpu_model || 'Intel Xeon',
        virtualization: c.virtualization || 'kvm',
        arch: c.arch || 'amd64',
        cpu_cores: parseInt(c.cpu_cores) || 2,
        os: c.os || 'Linux',
        gpu_name: '',
        ipv4: c.fake_ip || '127.0.0.1',
        region: isoToEmoji(c.region) || '🇨🇳',
        mem_total: Math.floor((parseInt(c.ram_total) || 1024) * 1048576),
        swap_total: Math.floor((parseInt(c.swap_total) || 0) * 1048576),
        disk_total: Math.floor((parseInt(c.disk_total) || 10240) * 1048576),
        version: '0.20.5'
    };

    var self = this;
    var path = '/api/clients/uploadBasicInfo';
    
    try {
        var url = new URL(baseUrl + path + '?token=' + encodeURIComponent(c.client_secret));
        var postData = JSON.stringify(info);
        var req = (url.protocol === 'https:' ? https : http).request({
            hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname + url.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Content-Length': Buffer.byteLength(postData),
                'User-Agent': 'komari-agent/0.1.0'
            },
            rejectUnauthorized: false
        }, function (res) {
            var body = '';
            res.on('data', function(chunk) { body += chunk; });
            res.on('end', function() {
                if (res.statusCode === 200 && body.indexOf('success') !== -1) {
                    console.log('[vKomari] ✓ Basic info uploaded: ' + self.config.name);
                } else {
                    console.log('[vKomari] ! Basic info (' + res.statusCode + '): ' + self.config.name + ' - ' + body.substring(0, 100));
                }
            });
        });
        req.on('error', function (err) {
            console.log('[vKomari] ! Basic info error: ' + self.config.name + ' - ' + err.message);
        });
        req.write(postData);
        req.end();
    } catch (e) {
        console.log('[vKomari] ! Basic info exception: ' + e.message);
    }
};

Agent.prototype.startLoops = function (httpUrl) {
    var self = this;
    clearInterval(this.timers.heartbeat); clearInterval(this.timers.info);
    var iv = Math.max(1000, Math.min(10000, (this.config.report_interval || 1) * 1000));
    this.sendData();
    this.timers.heartbeat = setInterval(function () { if (self.ws && self.ws.readyState === WebSocket.OPEN) self.sendData(); }, iv);
    this.timers.info = setInterval(function () { if (self.state.connected) self.uploadInfo(httpUrl); }, 300000);
};

Agent.prototype.sendData = function () {
    var c = this.config;

    // 确定当前资源使用百分比
    this.sim.cpu = this.fluctuate(this.sim.cpu, Number(c.cpu_min) || 0, Number(c.cpu_max) || 100, 0.5);
    this.sim.mem = this.fluctuate(this.sim.mem, Number(c.mem_min) || 0, Number(c.mem_max) || 100, 0.2);
    this.sim.swap = this.fluctuate(this.sim.swap, Number(c.swap_min) || 0, Number(c.swap_max) || 100, 0.1);
    this.sim.disk = this.fluctuate(this.sim.disk, Number(c.disk_min) || 0, Number(c.disk_max) || 100, 0.01);

    var netUp = this.rand(c.net_min || 100, c.net_max || 5000);
    var netDown = this.rand(c.net_min || 100, c.net_max || 5000);
    var interval = c.report_interval || 1;
    this.state.totalUp += netUp * interval;
    this.state.totalDown += netDown * interval;

    var baseLoad = (this.sim.cpu / 100) * (c.cpu_cores || 1);
    var load1 = parseFloat((baseLoad * this.randFloat(0.8, 1.2)).toFixed(2));

    this.sim.conn = Math.round(this.fluctuate(this.sim.conn, c.conn_min || 2, c.conn_max || 10, 0.5));
    if (this.sim.conn < (c.conn_min || 2)) this.sim.conn = c.conn_min || 2;
    this.sim.proc = Math.round(this.fluctuate(this.sim.proc, c.proc_min || 40, c.proc_max || 60, 0.5));
    if (this.sim.proc < (c.proc_min || 40)) this.sim.proc = c.proc_min || 40;

    var ramTotal = Math.floor((Number(c.ram_total) || 1024) * 1048576);
    var swapTotal = Math.floor((Number(c.swap_total) || 0) * 1048576);
    var diskTotal = Math.floor((Number(c.disk_total) || 10240) * 1048576);

    var memUsed = Math.floor(ramTotal * this.sim.mem / 100);
    var swapUsed = Math.floor(swapTotal * this.sim.swap / 100);
    var diskUsed = Math.floor(diskTotal * this.sim.disk / 100);

    var data = {
        type: 'report',
        cpu: { usage: parseFloat(this.sim.cpu.toFixed(1)) },
        ram: { total: ramTotal, used: memUsed },
        swap: { total: swapTotal, used: swapUsed },
        disk: { total: diskTotal, used: diskUsed },
        load: { load1: load1, load5: parseFloat((load1 * 0.92).toFixed(2)), load15: parseFloat((load1 * 0.85).toFixed(2)) },
        network: { up: netUp, down: netDown, totalUp: this.state.totalUp, totalDown: this.state.totalDown },
        connections: { tcp: this.sim.conn, udp: this.rand(0, 5) },
        process: this.sim.proc,
        uptime: Math.floor(Date.now() / 1000) - this.bootTime,
        message: ''
    };

    try {
        this.ws.send(JSON.stringify(data));
        this.state.sendCount++;
    } catch (e) {
        console.log('[vKomari] Send error:', e.message);
    }
};

Agent.prototype.status = function () {
    return { online: this.state.connected, sendCount: this.state.sendCount, uptime: Math.floor(Date.now() / 1000) - this.bootTime, lastError: this.state.lastError };
};

function loadNodes() {
    db.all('SELECT * FROM nodes', [], function (e, rows) {
        if (!e && rows) rows.forEach(function (r) {
            if (activeAgents.has(r.id)) activeAgents.get(r.id).stop();
            var a = new Agent(r); activeAgents.set(r.id, a); a.start();
        });
        console.log('[vKomari] Loaded ' + (rows ? rows.length : 0) + ' nodes');
    });
}

app.post('/api/login', function (req, res) {
    var ip = req.ip;
    if (!checkLoginAttempts(ip)) return res.status(429).json({ error: 'Too many attempts' });
    var username = req.body.username, password = req.body.password;
    db.get('SELECT * FROM users WHERE username=?', [username], function (e, u) {
        if (e || !u) { recordFailedLogin(ip); return res.status(401).json({ error: 'Invalid' }); }
        var h = hashPwd(password, u.salt);
        if (h.hash !== u.password) { recordFailedLogin(ip); return res.status(401).json({ error: 'Invalid' }); }
        var token = jwt.sign({ username: u.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token: token, isDefault: h.hash === hashPwd('vkomari', u.salt).hash });
    });
});

app.post('/api/change-password', auth, function (req, res) {
    var newPassword = req.body.newPassword;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Too short' });
    var h = hashPwd(newPassword);
    db.run('UPDATE users SET password=?, salt=?', [h.hash, h.salt], function (e) { res.json({ success: !e }); });
});

app.get('/api/nodes', auth, function (req, res) {
    db.all('SELECT * FROM nodes ORDER BY id DESC', [], function (e, rows) {
        if (e) return res.status(500).json({ error: e.message });
        var result = rows.map(function (r) {
            var status = activeAgents.has(r.id) ? activeAgents.get(r.id).status() : { online: false };
            return Object.assign({}, r, status);
        });
        res.json(result);
    });
});

app.post('/api/toggle', auth, function (req, res) {
    var id = req.body.id, enabled = req.body.enabled ? 1 : 0;
    db.run('UPDATE nodes SET enabled=? WHERE id=?', [enabled, id], function (e) {
        if (e) return res.status(500).json({ error: e.message });
        if (activeAgents.has(id)) {
            var agent = activeAgents.get(id);
            agent.update(Object.assign({}, agent.config, { enabled: enabled }));
        }
        res.json({ status: 'ok' });
    });
});

app.post('/api/nodes', auth, function (req, res) {
    var d = req.body;
    if (!d.client_uuid) d.client_uuid = crypto.randomUUID();
    if (!d.id && !d.fake_ip) d.fake_ip = generateFakeIP(d.region || 'US');

    var fields = 'name,server_address,client_secret,client_uuid,cpu_model,cpu_cores,ram_total,swap_total,disk_total,os,arch,virtualization,region,kernel_version,load_profile,cpu_min,cpu_max,mem_min,mem_max,swap_min,swap_max,disk_min,disk_max,net_min,net_max,conn_min,conn_max,proc_min,proc_max,report_interval,enabled,boot_time,fake_ip';
    var keys = fields.split(',');
    var values = keys.map(function (k) { return d[k] === undefined ? null : d[k]; });

    if (d.id) {
        var setClause = keys.map(function (k) { return k + '=?'; }).join(',');
        var sql = 'UPDATE nodes SET ' + setClause + ' WHERE id=?';
        values.push(d.id);
        db.run(sql, values, function (e) {
            if (e) { console.error(e); return res.status(500).json({ error: e.message }); }
            var cfg = Object.assign({}, d, { id: d.id });
            if (activeAgents.has(d.id)) activeAgents.get(d.id).update(cfg);
            else { var a = new Agent(cfg); activeAgents.set(d.id, a); a.start(); }
            res.json({ status: 'updated' });
        });
    } else {
        var placeholders = keys.map(function () { return '?'; }).join(',');
        var sql = 'INSERT INTO nodes (' + keys.join(',') + ') VALUES (' + placeholders + ')';
        db.run(sql, values, function (e) {
            if (e) { console.error(e); return res.status(500).json({ error: e.message }); }
            var id = this.lastID;
            var a = new Agent(Object.assign({}, d, { id: id }));
            activeAgents.set(id, a); a.start();
            res.json({ status: 'created', id: id });
        });
    }
});

app.post('/api/batch', auth, function (req, res) {
    var en = req.body.action === 'start' ? 1 : 0;
    db.run('UPDATE nodes SET enabled=?', [en], function (e) {
        if (e) return res.status(500).json({ error: e.message });
        activeAgents.forEach(function (a) { a.update(Object.assign({}, a.config, { enabled: en })); });
        res.json({ status: 'ok' });
    });
});

app.post('/api/delete', auth, function (req, res) {
    var id = req.body.id;
    db.run('DELETE FROM nodes WHERE id=?', [id], function (e) {
        if (e) return res.status(500).json({ error: e.message });
        if (activeAgents.has(id)) { activeAgents.get(id).stop(); activeAgents.delete(id); }
        res.json({ status: 'ok' });
    });
});

app.get('/api/presets', function (req, res) {
    res.json({
        low: { cpu_min: 1, cpu_max: 30, mem_min: 8, mem_max: 12, swap_min: 0, swap_max: 0, disk_min: 8, disk_max: 8.1, net_min: 100, net_max: 2000, conn_min: 2, conn_max: 5, proc_min: 35, proc_max: 45 },
        mid: { cpu_min: 1, cpu_max: 60, mem_min: 35, mem_max: 45, swap_min: 1, swap_max: 5, disk_min: 35, disk_max: 35.5, net_min: 10240, net_max: 102400, conn_min: 30, conn_max: 80, proc_min: 70, proc_max: 90 },
        high: { cpu_min: 1, cpu_max: 90, mem_min: 80, mem_max: 90, swap_min: 20, swap_max: 40, disk_min: 75, disk_max: 80, net_min: 1048576, net_max: 5242880, conn_min: 300, conn_max: 800, proc_min: 120, proc_max: 200 }
    });
});

app.listen(PORT, function () { console.log('[vKomari] v0.1.0 running on port ' + PORT); loadNodes(); });
