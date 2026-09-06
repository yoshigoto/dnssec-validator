const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

const {
    app,
    validateDomainName,
    normalizeDomainName,
    checkRateLimit
} = require('../dnssec-validator');

function request(server, { method = 'GET', path = '/', body, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const address = server.address();
        const request = http.request({
            hostname: '127.0.0.1',
            port: address.port,
            method,
            path,
            headers
        }, response => {
            let responseBody = '';
            response.setEncoding('utf8');
            response.on('data', chunk => { responseBody += chunk; });
            response.on('end', () => resolve({
                statusCode: response.statusCode,
                headers: response.headers,
                body: responseBody
            }));
        });
        request.on('error', reject);
        if (body !== undefined) request.write(body);
        request.end();
    });
}

test('ドメイン名を検証する', () => {
    assert.deepEqual(validateDomainName('Example.COM.'), { valid: true });
    assert.equal(validateDomainName('example.com;').valid, false);
    assert.equal(validateDomainName('not a domain').valid, false);
    assert.equal(validateDomainName('').valid, false);
    assert.equal(validateDomainName('a'.repeat(254)).valid, false);
});

test('ドメイン名を正規化する', () => {
    assert.equal(normalizeDomainName('WWW.Example.COM.'), 'www.example.com');
});

test('クライアントごとのレート制限を適用する', () => {
    const clientIp = `test-${Date.now()}-${Math.random()}`;
    for (let requestNumber = 0; requestNumber < 30; requestNumber++) {
        assert.equal(checkRateLimit(clientIp).allowed, true);
    }
    const limited = checkRateLimit(clientIp);
    assert.equal(limited.allowed, false);
    assert.equal(limited.remaining, 0);
    assert.ok(limited.waitSeconds > 0);
});

test('GET / は UI を返し、セキュリティヘッダーを付ける', async () => {
    const server = app.listen(0);
    try {
        const response = await request(server);
        assert.equal(response.statusCode, 200);
        assert.match(response.headers['content-type'], /text\/html/);
        assert.equal(response.headers['x-content-type-options'], 'nosniff');
        assert.equal(response.headers['x-frame-options'], 'DENY');
        assert.match(response.body, /DNSSEC委任状態検証ツール/);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});

test('POST /api/validate は不正なドメインを DNS 問い合わせ前に拒否する', async () => {
    const server = app.listen(0);
    try {
        const response = await request(server, {
            method: 'POST',
            path: '/api/validate',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: 'bad domain' })
        });
        assert.equal(response.statusCode, 400);
        assert.match(JSON.parse(response.body).error, /無効な文字|形式が無効/);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});

test('不正な JSON は 400 を返す', async () => {
    const server = app.listen(0);
    try {
        const response = await request(server, {
            method: 'POST',
            path: '/api/validate',
            headers: { 'Content-Type': 'application/json' },
            body: '{"domain":'
        });
        assert.equal(response.statusCode, 400);
        assert.equal(JSON.parse(response.body).error, 'JSON リクエストの形式が無効です');
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});