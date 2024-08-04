const http = require('http');
const httpProxy = require('http-proxy');
const net = require('net');
const fs = require('fs');
const readline = require('readline');
const https = require('https');
const { URL } = require('url');
const winston = require('winston');
const config = require('./config.json');

// Cấu hình logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => `${timestamp} ${level}: ${message}`)
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'proxy.log' })
    ]
});

// Hàm tải quy tắc từ tệp
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

// Hàm khởi tạo
let rules = [];
let blockedDomains = [];
const init = async () => {
    rules = await loadRules(config.blockedWebListPath, 'RegExp');
    blockedDomains = await loadRules(config.blockedDomainsPath, 'string');
    logger.info({ 'Blocked Domains:': blockedDomains });
    if (!rules.length) {
        logger.error('Failed to load rules');
    }
    if (!blockedDomains.length) {
        logger.error('Failed to load domain block rules');
    } else {
        logger.info('Rules And Domain loaded successfully');
    }
}

init();

// Hàm gửi yêu cầu HTTPS
const sendHttpsRequest = (hostname, path, method, headers) => {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: hostname,
            port: 443,
            path: path,
            method: method,
            headers: headers
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        });

        req.on('error', (e) => {
            reject(e);
        });

        req.end();
    });
};

// Tạo proxy server
const proxy = httpProxy.createProxyServer({});
const blockedIPs = config.blockedIPs;
const blockedURLs = config.blockedURLs;
const blockedMethods = config.blockedMethods;

// Xử lý yêu cầu HTTP
const handleRequest = async (req, res) => {
    const clientIP = req.connection.remoteAddress;
    logger.info(`HTTP Client IP: ${clientIP}`);

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

        // Kiểm tra URL yêu cầu với các quy tắc trong easylist
        const requestURL = `http://${req.headers.host}${req.url}`;
        const isBlocked = rules.some(rule => rule.test(requestURL));
        if (isBlocked) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Content blocked');
            return;
        }

        // Thu thập thông tin từ yêu cầu client
        const hostname = req.headers.host;
        const path = req.url;
        const method = req.method;
        const headers = req.headers;

        // Gửi yêu cầu HTTPS
        try {
            const response = await sendHttpsRequest(hostname, path, method, headers);
            logger.info(`Response from ${hostname}${path}: ${response.statusCode}`);

            // Gửi phản hồi lại cho client
            res.writeHead(response.statusCode, response.headers);
            res.end(response.body);
        } catch (error) {
            logger.error(`Error sending HTTPS request: ${error.message}`);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Error sending request to destination server.');
        }
    } catch (error) {
        logger.error(`Error processing request: ${error.message}`);
    }
};

// Xử lý kết nối
const handleConnect = (req, socket, head) => {
    const clientIP = req.socket.remoteAddress;
    logger.info(`Client IP: ${clientIP} - Requested URL: ${req.url}`);

    const { hostname } = new URL(`https://${req.url}`);
    const port = req.url.split(':')[1] || 443;

    try {
        if (blockedIPs.includes(clientIP)) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.destroy();
            return;
        }

        if (blockedURLs.includes(req.url)) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.destroy();
            return;
        }

        if (hostname && blockedDomains.some(domain => hostname.includes(domain))) {
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.destroy();
            return;
        }

        const srvSocket = net.connect(port, hostname, () => {
            socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            srvSocket.write(head);
            srvSocket.pipe(socket);
            socket.pipe(srvSocket);
        });

        srvSocket.on('error', (err) => {
            logger.error(`Error establishing connection to ${req.url}: ${err.message}`);
            socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
            socket.destroy();
        });
    } catch (error) {
        logger.error(`Error processing connect request: ${error.message}`);
    }
};

// Tạo server HTTP
const server = http.createServer(handleRequest);

// Thêm sự kiện cho proxy
proxy.on('proxyRes', (proxyRes, req, res) => {
    let body = '';
    proxyRes.on('data', chunk => {
        body += chunk;
    });
    proxyRes.on('end', () => {
        const contentType = proxyRes.headers['content-type'];
        const typeRes = ['image', 'video', 'audio', 'img'];
        if (contentType && typeRes.some(type => contentType.includes(type))) {
            logger.info(`Has Content-Type: ${contentType}`);
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

proxy.on('proxyReq', (proxyReq, req, res) => {
    try {
        if (proxyReq && proxyReq.headers) {
            logger.info('proxyReq.headers:', proxyReq.headers);
        }
        if (req.rawHeaders) {
            logger.info('proxyReq.headers:', req.rawHeaders);
        } else {
            logger.info('proxyReq.headers is undefined');
        }
    } catch (error) {
        logger.error(`Error in proxyReq callback: ${error.message}`);
    }
});

proxy.on('error', (err, req, res) => {
    logger.error(`Proxy error: ${err.message}`);
    if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
    }
    res.end('Proxy error: Something went wrong.');
});

// Xử lý sự kiện 'connect' để chuyển tiếp các yêu cầu CONNECT
server.on('connect', handleConnect);

// Lắng nghe trên cổng được cấu hình
const port = config.port || 8080;
server.listen(port, () => {
    logger.info(`Proxy server is running on port ${port}`);
});
