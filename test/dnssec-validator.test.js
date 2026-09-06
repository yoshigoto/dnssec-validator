const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dnsPacket = require('dns-packet');
const http = require('node:http');
const test = require('node:test');

const {
    app,
    validateDomainName,
    normalizeDomainName,
    checkRateLimit,
    getZoneApex,
    getResourceRecord,
    verifyDnskeyWithDs,
    calculateKeyTag,
    buildDnskeyFullRdata,
    encodeDomainNameCanonical,
    checkSignatureExpiration,
    findARecordNodataProof,
    nsec3Hash,
    toBase32Hex
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

function makeDnskeyData() {
    return { flags: 257, algorithm: 8, key: Buffer.from('test-public-key') };
}

function makeDsForDnskey(domain, dnskeyData) {
    const fullRdata = buildDnskeyFullRdata(dnskeyData);
    const digest = crypto.createHash('sha256')
        .update(Buffer.concat([encodeDomainNameCanonical(domain), fullRdata]))
        .digest();
    return {
        keyTag: calculateKeyTag(dnskeyData.algorithm, fullRdata),
        algorithm: dnskeyData.algorithm,
        digestType: 2,
        digest
    };
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

test('DS と DNSKEY のダイジェストが一致する', () => {
    const domain = 'example.test';
    const dnskeyData = makeDnskeyData();
    const dsRecord = makeDsForDnskey(domain, dnskeyData);
    const result = verifyDnskeyWithDs(domain, dnskeyData, dsRecord);

    assert.equal(result.match, true);
    assert.equal(result.keyTag, dsRecord.keyTag);
});

test('DS のダイジェスト不一致を検出する', () => {
    const domain = 'example.test';
    const dnskeyData = makeDnskeyData();
    const dsRecord = makeDsForDnskey(domain, dnskeyData);
    dsRecord.digest[0] ^= 0xff;
    const result = verifyDnskeyWithDs(domain, dnskeyData, dsRecord);

    assert.equal(result.match, false);
    assert.match(result.reason, /Digestが異なります/);
});

test('未対応の DS Digest Type を拒否する', () => {
    const dnskeyData = makeDnskeyData();
    const result = verifyDnskeyWithDs('example.test', dnskeyData, {
        keyTag: 1,
        algorithm: 8,
        digestType: 99,
        digest: Buffer.alloc(32)
    });

    assert.equal(result.match, false);
    assert.match(result.reason, /未対応のDigest Type/);
});

test('RRSIG の未開始・期限切れを検出する', () => {
    const now = Math.floor(Date.now() / 1000);
    const notStarted = checkSignatureExpiration({ data: { inception: now + 60, expiration: now + 120 } });
    const expired = checkSignatureExpiration({ data: { inception: now - 120, expiration: now - 60 } });

    assert.equal(notStarted.valid, false);
    assert.match(notStarted.reason, /まだ有効になっていません/);
    assert.equal(expired.valid, false);
    assert.match(expired.reason, /期限が切れています/);
});

test('NSEC3 による A レコード不存在証明を検出する', () => {
    const domain = 'www.example.test';
    const salt = Buffer.from('a1b2', 'hex');
    const iterations = 2;
    const ownerHash = toBase32Hex(nsec3Hash(domain, salt, iterations));
    const proof = {
        name: `${ownerHash}.example.test`,
        type: 'NSEC3',
        data: { algorithm: 1, salt, iterations, rrtypes: ['SOA'] }
    };

    assert.equal(findARecordNodataProof(domain, [proof]), proof);
    assert.equal(findARecordNodataProof(domain, [{
        ...proof,
        data: { ...proof.data, rrtypes: ['A', 'SOA'] }
    }]), null);
});

test('権威 SOA 応答からゾーン頂点を確定する', async () => {
    const result = await getZoneApex('www.example.test', {
        initialNameserver: '192.0.2.1',
        queryUdp: async () => dnsPacket.encode({
            type: 'response',
            flags: dnsPacket.AUTHORITATIVE_ANSWER,
            answers: [{
                name: 'example.test',
                type: 'SOA',
                data: {
                    mname: 'ns.example.test',
                    rname: 'hostmaster.example.test',
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 86400,
                    minimum: 300
                }
            }]
        })
    });

    assert.equal(result.zoneApex, 'example.test');
    assert.equal(result.parentNs, '');
    assert.equal(result.currentNs, '192.0.2.1');
});

test('FORMERR の場合は EDNS なしで再試行する', async () => {
    let queryCount = 0;
    const result = await getZoneApex('www.formerr.test', {
        initialNameserver: '192.0.2.2',
        queryUdp: async () => {
            queryCount++;
            if (queryCount === 1) {
                return dnsPacket.encode({ type: 'response', rcode: 'FORMERR' });
            }
            return dnsPacket.encode({
                type: 'response',
                flags: dnsPacket.AUTHORITATIVE_ANSWER,
                answers: [{
                    name: 'formerr.test',
                    type: 'SOA',
                    data: {
                        mname: 'ns.formerr.test',
                        rname: 'hostmaster.formerr.test',
                        serial: 1,
                        refresh: 3600,
                        retry: 600,
                        expire: 86400,
                        minimum: 300
                    }
                }]
            });
        }
    });

    assert.equal(queryCount, 2);
    assert.equal(result.zoneApex, 'formerr.test');
});

test('UDP 切断応答を TCP で再取得する', async () => {
    const calls = [];
    const result = await getResourceRecord('example.test', '192.0.2.3', 'A', {
        queryUdp: async () => {
            calls.push('udp');
            return dnsPacket.encode({ type: 'response', flags: dnsPacket.TRUNCATED_RESPONSE, answers: [] });
        },
        queryTcp: async () => {
            calls.push('tcp');
            return dnsPacket.streamEncode({
                type: 'response',
                answers: [{ name: 'example.test', type: 'A', data: '192.0.2.10' }],
                authorities: []
            });
        }
    });

    assert.deepEqual(calls, ['udp', 'tcp']);
    assert.deepEqual(result.resourceRecords.map(record => record.data), ['192.0.2.10']);
});

test('委任先が同じ IP の場合も親子同居として探索結果を保持する', async () => {
    const requests = [];
    const sharedNameserver = '192.0.2.53';
    const result = await getZoneApex('host.co-located.test', {
        initialNameserver: sharedNameserver,
        queryUdp: async serverIp => {
            requests.push(serverIp);
            if (requests.length === 1) {
                return dnsPacket.encode({
                    type: 'response',
                    authorities: [{ name: 'co-located.test', type: 'NS', data: 'ns.co-located.test', ttl: 300 }],
                    additionals: [{ name: 'ns.co-located.test', type: 'A', data: sharedNameserver, ttl: 300 }]
                });
            }
            return dnsPacket.encode({
                type: 'response',
                flags: dnsPacket.AUTHORITATIVE_ANSWER,
                answers: [{
                    name: 'co-located.test',
                    type: 'SOA',
                    data: {
                        mname: 'ns.co-located.test',
                        rname: 'hostmaster.co-located.test',
                        serial: 1,
                        refresh: 3600,
                        retry: 600,
                        expire: 86400,
                        minimum: 300
                    }
                }]
            });
        }
    });

    assert.deepEqual(requests, [sharedNameserver, sharedNameserver]);
    assert.equal(result.zoneApex, 'co-located.test');
    assert.equal(result.parentNs, sharedNameserver);
    assert.equal(result.currentNs, sharedNameserver);
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