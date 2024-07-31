const http = require('http');
const httpProxy = require('http-proxy');
const net = require('net');
const fs = require('fs');
const readline = require('readline');
const url = require('url');
const express = require('express');

const app = express();
app.use(express.json());

let rules = [];
const blockedIPs = [];
const blockedURLs = ['/blocked-url', '/forbidden'];
const blockedMethods = ['POST', 'DELETE'];
const blockedDomains = [
    'qc.x8.games', 'sky88.com', 'dangky789.vin', 'choiwin789.in',
    'lp.webda88.vip', 'choiwin79.in', 'vic2.club'
];
const validTokens = ['your_secure_token']; // Replace with your tokens

// Load blocking rules from a file
async function loadRules(filePath) {
    const rules = [];
    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    for await (const line of rl) {
        if (!line || line.startsWith('!') || line.startsWith('@@')) continue;
        try {
            rules.push(new RegExp(line.replace(/\*/g, '.*')));
        } catch (e) {
            console.error(`Invalid rule: ${line} - Error: ${e.message}`);
        }
    }

    return rules;
}

// Initialize blocking rules
async function init() {
    rules = await loadRules('./blockedWebList.txt');
    if (!rules.length) {
        console.error('Failed to load rules');
    } else {
        console.log('Rules loaded successfully');
    }
}

init();

const proxy = httpProxy.createProxyServer({});

// API endpoint to get blocked IPs
app.get('/api/blocked-ips', (req, res) => {
    res.json(blockedIPs);
});

// API endpoint to add a blocked IP
app.post('/api/blocked-ips', (req, res) => {
    const { ip } = req.body;
    if (ip && !blockedIPs.includes(ip)) {
        blockedIPs.push(ip);
        res.status(201).json({ message: 'IP added to blocked list' });
    } else {
        res.status(400).json({ message: 'Invalid IP or IP already blocked' });
    }
});

// API endpoint to remove a blocked IP
app.delete('/api/blocked-ips/:ip', (req, res) => {
    const { ip } = req.params;
    const index = blockedIPs.indexOf(ip);
    if (index > -1) {
        blockedIPs.splice(index, 1);
        res.json({ message: 'IP removed from blocked list' });
    } else {
        res.status(404).json({ message: 'IP not found in blocked list' });
    }
});

// API endpoint to get blocking rules
app.get('/api/rules', (req, res) => {
    res.json(rules.map(rule => rule.source));
});

// API endpoint to add a blocking rule
app.post('/api/rules', async (req, res) => {
    const { rule } = req.body;
    try {
        const newRule = new RegExp(rule.replace(/\*/g, '.*'));
        rules.push(newRule);
        res.status(201).json({ message: 'Rule added to blocking list' });
    } catch (e) {
        res.status(400).json({ message: `Invalid rule: ${rule} - Error: ${e.message}` });
    }
});

// API endpoint to remove a blocking rule
app.delete('/api/rules', async (req, res) => {
    const { rule } = req.body;
    const regex = new RegExp(rule.replace(/\*/g, '.*'));
    const index = rules.findIndex(r => r.source === regex.source);
    if (index > -1) {
        rules.splice(index, 1);
        res.json({ message: 'Rule removed from blocking list' });
    } else {
        res.status(404).json({ message: 'Rule not found in blocking list' });
    }
});

const server = http.createServer((req, res) => {
    const clientIP = req.connection.remoteAddress;
    console.log(`Client IP: ${clientIP}`);

    // Simple authentication
    const token = req.headers['x-auth-token'];
    if (!validTokens.includes(token)) {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        res.end('Unauthorized');
        return;
    }

    try {
        if (blockedIPs.includes(clientIP)) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Access denied');
            return;
        }

        if (blockedURLs.includes(req.url)) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('URL is blocked');
            return;
        }

        if (blockedMethods.includes(req.method)) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Method is blocked');
            return;
        }

        if (req.headers.host && blockedDomains.some(domain => req.headers.host.includes(domain))) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Domain is blocked');
            return;
        }
    } catch (error) {
        console.log(`Error processing request: ${error.message}`);
    }

    const requestURL = `http://${req.headers.host}${req.url}`;
    const isBlocked = rules.some(rule => rule.test(requestURL));
    if (isBlocked) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Content blocked');
        return;
    }

    if (req.headers.host && req.headers.host.includes('google.com') && req.url.includes('/search')) {
        const parsedUrl = new URL(requestURL);
        const queryParams = new URLSearchParams(parsedUrl.search);
        const searchQuery = queryParams.get('q');
        console.log('----------------------------------------------------');
        console.log(`Google search query: ${searchQuery}`);
        console.log('----------------------------------------------------');
    }

    delete req.headers['x-forwarded-for'];
    delete req.headers['x-forwarded-host'];
    delete req.headers['x-forwarded-server'];

    const target = req.url.startsWith('https://') ? req.url : 'https://vlxx.mobi';

    proxy.web(req, res, { target: target, changeOrigin: true }, (err) => {
        console.error(`Proxy error: ${err}`);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Something went wrong.');
    });
});

proxy.on('proxyRes', (proxyRes, req, res) => {
    let body = '';
    const contentType = proxyRes.headers['content-type'] || '';
    proxyRes.on('data', chunk => {
        body += chunk;
    });
    proxyRes.on('end', () => {
        if (contentType.includes('text/html')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const requestURL = url.href;
            const isBlocked = rules.some(rule => rule.test(requestURL));
            if (isBlocked) {
                res.writeHead(403, { 'Content-Type': 'text/plain' });
                res.end('Content blocked');
            } else {
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                res.end(body);
            }
        } else {
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            res.end(body);
        }
    });
});

proxy.on("proxyReq", (proxyReq, req, res) => {
    console.log(proxyReq.headers);
});

proxy.on('error', (err, req, res) => {
    console.error(`Proxy error: ${err.message}`);
    if (res.writeHead && !res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
    }
    res.end('Proxy error: Something went wrong.');
});

server.on('connect', (req, socket, head) => {
    const clientIP = req.socket.remoteAddress;
    console.log(`Client IP: ${clientIP} - Requested URL: ${req.url}`);

    const { hostname, port = 443 } = new URL(`https://${req.url}`);

    // Simple authentication
    const token = req.headers['x-auth-token'];
    if (!validTokens.includes(token)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.end('Unauthorized');
        return;
    }

    if (blockedDomains.some(domain => hostname.includes(domain))) {
        console.log(`Domain is blocked: ${hostname} - Client IP: ${clientIP} - Requested URL:${req.url}`);
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.end('Access denied');
        return;
    }

    if (blockedIPs.includes(clientIP)) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.end('Access denied');
        return;
    }

    const srvSocket = net.connect(port, hostname, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        srvSocket.write(head);
        srvSocket.pipe(socket);
        socket.pipe(srvSocket);
    });

    srvSocket.on('timeout', () => {
        console.error(`Socket timeout: ${hostname}:${port}`);
        socket.write('HTTP/1.1 504 Gateway Timeout\r\n\r\n');
        socket.end('Connection timed out.');
        srvSocket.end();
    });

    srvSocket.on('error', (err) => {
        console.error(`Socket error: ${err}`);
        socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        socket.end('Something went wrong.');
    });

    srvSocket.on('close', () => {
        console.log(`Connection closed: ${clientIP} Time: ${new Date()}`);
    });

    socket.on('error', (err) => {
        console.error(`Socket error: ${err}`);
    });

    socket.on('end', () => {
        console.log(`Connection ended: ${clientIP}`);
    });

    srvSocket.on('end', () => {
        console.log(`Service socket ended: ${hostname}`);
    });

    socket.on('close', () => {
        console.log(`Client socket closed: ${clientIP}`);
    });
});

const virtualIP = "169.254.200.255";
const port = 8080;

server.listen(port, virtualIP, () => {
    console.log(`Proxy server is running on http://${virtualIP}:${port}`);
});

app.listen(3000, () => {
    console.log('API server is running on http://localhost:3000');
});
