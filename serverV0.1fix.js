const http = require('http');
const httpProxy = require('http-proxy');
const net = require('net');
const fs = require('fs');
const readline = require('readline');
const url = require('url');

async function loadRules(filePath, type) {
    const rules = [];
    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    for await (const line of rl) {
        if (!line || line.startsWith('!') || line.startsWith('@@')) continue;

        try {
            switch (type) {
                case 'string':
                    rules.push(line.trim());
                    break;
                case 'number':
                    const number = parseFloat(line.trim());
                    if (!isNaN(number)) {
                        rules.push(number);
                    }
                    break;
                case 'RegExp':
                    rules.push(new RegExp(line.replace(/\*/g, '.*')));
                    break;
                default:
                    throw new Error(`Unsupported type: ${type}`);
            }
        } catch (e) {
            console.error(`Invalid rule: ${line} - Error: ${e.message}`);
        }
    }

    return rules;
}

let rules = [];
let blockedDomains = []
const init = async () => {
    rules = await loadRules('./blockedWebList.txt', 'RegExp');
    blockedDomains = await loadRules('./blockedDomains.txt', 'string');
    console.log({ 'Blocked Domains:': blockedDomains });
    if (!rules.length) {
        console.error('Failed to load rules');
    }
    if (!blockedDomains.length) {
        console.error('Failed to load domain block rules');
    }
    else {
        //console.clear();
        console.log('Rules And Domain loaded successfully');
    }
}

init();

const proxy = httpProxy.createProxyServer({});
const blockedIPs = [];
const blockedURLs = ['/blocked-url', '/forbidden'];
const blockedMethods = ['POST', 'DELETE'];
// const blockedDomains = ['qc.x8.games', 'sky88.com', 'dangky789.vin', 'choiwin789.in', 'lp.webda88.vip', 'choiwin79.in', 'vic2.club'];
const server = http.createServer((req, res) => {

    const clientIP = req.connection.remoteAddress;
    console.log(`HTTP Client IP: ${clientIP} `);

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

    // Kiểm tra URL yêu cầu với các quy tắc trong easylist
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
        if (!res.headersSent) {

            res.writeHead(500, { 'Content-Type': 'text/plain' });

        }

        res.end('Something went wrong.');
    });
});

proxy.on('proxyRes', (proxyRes, req, res) => {
    let body = '';
    const contentType = res.headers['content-type'] || '';
    proxyRes.on('data', chunk => {
        body += chunk;
    });
    proxyRes.on('end', () => {
        const contentType = res.headers['content-type'] || proxyRes.headers['content-type']
        const contentTYPE = proxyRes.headers['content-type'] || res.headers['content-type'] || req.headers['content-type'] || res.rawHeaders['content-type'];
        const typeRes = ['image', 'video', 'audio', 'img']
        if (contentTYPE && typeRes.some(type => contentTYPE.includes(type))) {
            console.log('----------------------------------------------------');
            console.log(`Has Content-Type: ${contentType}`);
            console.log('----------------------------------------------------');
        }
        if (contentType && contentType.includes('text/html')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const requestURL = url.href;
            const isBlocked = rules.some(rule => rule.test(requestURL));
            if (isBlocked) {
                if (!res.headersSent) {
                    res.writeHead(403, { 'Content-Type': 'text/plain' });
                }
                res.end('Content blocked');
            } else {
                if (!res.headersSent) {
                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                }
                res.end(body);
            }
        } else {
            if (!res.headersSent) {
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
            }
            res.end(body);
        }
    });
});

proxy.on("proxyReq", (proxyReq, req, res) => {
    try {
        if (proxyReq && proxyReq.headers) {
            console.log('proxyReq.headers:', proxyReq.headers);
            console.log('---------------------------------------------------------');
        }
        if (req.rawHeaders) {
            console.log('proxyReq.headers:', req.rawHeaders);
        }
        else {
            console.log('proxyReq.headers is undefined');
        }
    } catch (error) {
        console.error(`Error in proxyReq callback: ${error.message}`);
    }
});


proxy.on('error', (err, req, res) => {
    console.error(`Proxy error: ${err.message}`);
    if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
    }
    res.end('Proxy error: Something went wrong.');
});

server.on('connect', (req, socket, head) => {
    const clientIP = req.socket.remoteAddress;
    console.log(`Client IP: ${clientIP} - Requested URL: ${req.url}`);

    const { hostname } = new URL(`https://${req.url}`);
    const port = req.url.split(':')[1] || 8080;
    try {
        if (blockedDomains.some(domain => hostname.includes(domain))) {
            console.log(`Domain is blocked: ${hostname} - Client IP: ${clientIP} - Requested URL:${req.url}`);
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end('Access denied');
            socket.destroy();
            return;
        }
        if (blockedIPs.includes(clientIP)) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.end('Access denied');
            socket.destroy();
            return;
        }
    } catch (error) {
        console.log(`Error in block function ${error}`)
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
        if (err.code === 'ECONNRESET') {
            console.error(`srvSocket ECONNRESET error: ${err.message}`);
        } else {
            console.error(`srvSocket error: ${err.message}`);
        }
        socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        socket.end('Something went wrong.');
    });

    srvSocket.on('close', () => {
        console.log(`Connection closed: ${clientIP}  Time: ${new Date().toLocaleString()}`);
    });

    socket.on('error', (err) => {
        if (err.code === 'ECONNRESET') {
            console.error(`Client socket ECONNRESET error: ${err.message}`);
        } else {
            console.error(`Client socket error: ${err.message}`);
        }
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
server.on('error', (err) => {
    console.error(`Server error: ${err.message}`);
});

//192.168.1.3
const virtualIP = "169.254.200.255";
const port = 8080;

server.listen(port, virtualIP, () => {
    console.log(`Proxy server is running on http://${virtualIP}:${port}`);
});
