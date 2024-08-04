const https = require('https');

const options = {
    hostname: 'google.com',
    port: 443,
    path: '/',
    method: 'GET',
    headers: {
        'User-Agent': 'Node.js'
    }
};

const req = https.request(options, (res) => {
    console.log(`Status Code: ${res.statusCode}`);
    console.log('Headers:', res.headers);

    res.on('data', (d) => {
        process.stdout.write(d);
    });
});

req.on('error', (e) => {
    console.error(e);
});

req.end();
