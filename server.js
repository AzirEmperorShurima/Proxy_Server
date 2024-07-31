const http = require('http');
const httpProxy = require('http-proxy');
const net = require('net');
const fs = require('fs');
const readline = require('readline');
const url = require('url');
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
let rules = [];

async function init() {
    rules = await loadRules('./blockedWebList.txt');
    if (!rules.length) {
        console.error('Failed to load rules');
    } else {
        //console.clear();
        console.log('Rules loaded successfully');
    }
}

init();

const proxy = httpProxy.createProxyServer({});
const blockedIPs = [];
const blockedURLs = ['/blocked-url', '/forbidden'];
const blockedMethods = ['POST', 'DELETE'];
const blockedDomains = ['qc.x8.games', 'sky88.com', 'dangky789.vin', 'choiwin789.in', 'lp.webda88.vip', 'choiwin79.in', 'vic2.club'];

const server = http.createServer((req, res) => {

    const clientIP = req.connection.remoteAddress;
    console.log(`Client IP: ${clientIP}`);
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
    if (contentType.includes('image') || contentType.includes('video')) {
        // res.writeHead(403, { 'Content-Type': 'text/plain' });
        // res.end('Content type blocked');
        // proxyRes.destroy(); // Hủy kết nối phản hồi
        // return;
        console.log({
            'LOG ERR': 'IMG - VIDEO'
        });
    }
    proxyRes.on('end', () => {
        const contentType = proxyRes.headers['content-type'];
        if (contentType && contentType.includes('text/html')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const requestURL = url.href;
            const isBlocked = rules.some(rule => rule.test(requestURL));
            if (isBlocked) {
                res.writeHead(403, { 'Content-Type': 'text/plain' });
                res.end('Content blocked');
            } else {
                if (contentType.includes('image') || contentType.includes('video')) {
                    console.log({
                        'LOG ERR': 'IMG - VIDEO'
                    });
                }
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                res.end(body);
            }
        } else {
            if (contentType.includes('image') || contentType.includes('video')) {
                console.log({
                    'LOG ERR': 'IMG - VIDEO'
                });
            }
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            res.end(body);
        }
    });
});
proxy.on("proxyReq", (proxyReq, req, res) => {
    console.log(proxyReq.headers)
})

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

    const { hostname } = new URL(`https://${req.url}`);
    const port = req.url.split(':')[1] || 8080
    const newURL = new URL(`https://${req.url}`);

    // const requestURL = `https://${req.headers.host}${req.url}`;
    // const isBlocked = rules.some(rule => rule.test(requestURL));
    // if (isBlocked) {
    //     res.writeHead(403, { 'Content-Type': 'text/plain' });
    //     console.error(`Content blocked: ${requestURL} - Client IP: ${clientIP}`);
    //     res.end('Content blocked');
    //     return;
    // }
    // const arrBuffer = head.buffer;
    // const uint8Array = new Uint8Array(arrBuffer);
    // const decoded = new TextDecoder('utf-8')
    // const decodedString = decoded.decode(uint8Array)
    // delete req.headers['user-agent'];
    // req.headers['x-forwarded-host'] = '123.456.789';
    //   req.headers['x-forwarded-server'] = 'proxy.example.com';
    // req.headers['x-forwarded-for'] = '123.456.789';
    // req.headers.location = req.url;

    // console.table([{ "Request Url - IP ": req.url + ' - ' + clientIP, "Port - HostName - PathName": port + " - " + hostname + " - " + pathname }])
    // console.log(req.headers)
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
    srvSocket.on('data', (chunk) => {
        // const arrBuffer = chunk.buffer;
        // const uint8Array = new Uint8Array(arrBuffer);
        // const decoded = new TextDecoder('utf-8')
        // const decodedString = decoded.decode(uint8Array)

        // console.log(`Received data from ${hostname}:${port}: 
        //      ${decodedString}
        //     `);
        // console.log(!chunk.includes('CONNECT www.google.com'))
        if (chunk.includes('google')) {
            console.log('-----------------------------')
            console.log('CONNECT www.google.com')
            console.log('-----------------------------')
        }
        if (chunk.toString().includes('CONNECT www.google.com')) {
            const requestString = chunk.toString();
            const searchQueryMatch = requestString.match(/q=([^&]*)/);
            if (searchQueryMatch) {
                const searchQuery = decodeURIComponent(searchQueryMatch[1]);
                console.log(`Search query: ${searchQuery}`);
            }
        }
    });

    srvSocket.on('error', (err) => {
        console.error(`Socket error: ${err}`);
        socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        socket.end('Something went wrong.');
    });

    srvSocket.on('close', () => {
        console.log(`Connection closed: ${clientIP}  Time: ${new Date()}`);
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

//192.168.1.3
const virtualIP = "169.254.200.255";
const port = 8080;

server.listen(port, virtualIP, () => {
    console.log(`Proxy server is running on http://${virtualIP}:${port}`);
});
