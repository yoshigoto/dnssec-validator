import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import test from 'node:test';

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import dnsPacket from 'dns-packet';

import {
    app,
    validateDomainName,
    normalizeDomainName,
    checkRateLimit,
    getZoneApex,
    getARecord,
    getResourceRecord,
    verifyDnskeyWithDs,
    isZoneSigningKey,
    calculateKeyTag,
    buildDnskeyFullRdata,
    encodeDomainNameCanonical,
    checkSignatureExpiration,
    verifyMLDSASignature,
    createARecordValidation,
    isValidationSuccessful,
    findARecordNodataProof,
    findNxDomainProof,
    nsec3Hash,
    toBase32Hex,
    analyzeARecordNodataProof,
    createTimeoutGuardedResponder
} from '../dnssec-validator.js';

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

test('ML-DSA-44 の署名を検証する', () => {
    const { publicKey, secretKey } = ml_dsa44.keygen(new Uint8Array(ml_dsa44.lengths.seed));
    const message = Buffer.from('dnssec ml-dsa-44');
    const signature = Buffer.from(ml_dsa44.sign(message, secretKey));

    assert.deepEqual(
        verifyMLDSASignature(Buffer.from(publicKey), signature, message, 18),
        { verified: true, reason: '' }
    );

    signature[0] ^= 1;
    assert.equal(verifyMLDSASignature(Buffer.from(publicKey), signature, message, 18).verified, false);
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

test('ゾーン頂点でもAレコードDNSSEC検証を開始する', () => {
    const validation = createARecordValidation();

    assert.equal(validation.queried, true);
    assert.equal(validation.recordsFound, false);
    assert.deepEqual(validation.signatures, []);
});

test('全信頼連鎖とAレコード署名が有効な場合だけ検証成功とする', () => {
    const diagram = {
        checks: { dsSignature: true, dnskeySignature: true, dsKeyMatch: true },
        child: { aRecordValidation: { queried: true, recordsFound: true, signatures: [{ trustChainVerified: true }] } }
    };

    assert.equal(isValidationSuccessful(diagram), true);
    diagram.checks.dsSignature = false;
    assert.equal(isValidationSuccessful(diagram), false);
    diagram.checks.dsSignature = true;
    diagram.child.aRecordValidation.signatures[0].trustChainVerified = false;
    assert.equal(isValidationSuccessful(diagram), false);
});

test('Aレコードがない場合は有効な不在証明を検証成功の必須条件とする', () => {
    const diagram = {
        checks: { dsSignature: true, dnskeySignature: true, dsKeyMatch: true },
        child: { aRecordValidation: { queried: true, recordsFound: false, signatures: [], denialProof: { verified: true } } }
    };

    assert.equal(isValidationSuccessful(diagram), true);
    diagram.child.aRecordValidation.denialProof.verified = false;
    assert.equal(isValidationSuccessful(diagram), false);
    diagram.child.aRecordValidation.error = 'timeout';
    assert.equal(isValidationSuccessful(diagram), false);
});

test('NSEC3によるAレコード不存在証明を検出する', () => {
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

test('NSEC3のtype bitmapがAを示すNODATA証明の不成立理由を返す', () => {
    const domain = 'target.type.mismatch.nsec3.rsasha256.dnssec-check.jp';
    const salt = Buffer.alloc(0);
    const iterations = 1;
    const ownerHash = toBase32Hex(nsec3Hash(domain, salt, iterations));
    const result = analyzeARecordNodataProof(domain, [{
        name: `${ownerHash}.type.mismatch.nsec3.rsasha256.dnssec-check.jp`,
        type: 'NSEC3',
        data: { algorithm: 1, salt, iterations, rrtypes: ['A', 'SOA'] }
    }]);

    assert.equal(result.record, null);
    assert.match(result.diagnostics.join('\n'), /NSEC3のtype bitmapにAが含まれるため/);
});

test('NSEC による NXDOMAIN 証明を構成する', () => {
    const proof = findNxDomainProof('missing.child.example.test', [
        { name: 'child.example.test', type: 'NSEC', data: { nextDomain: 'next.example.test', rrtypes: ['NS'] } },
        { name: 'a.example.test', type: 'NSEC', data: { nextDomain: 'z.example.test', rrtypes: [] } }
    ]);

    assert.deepEqual(proof.diagnostics, []);
    assert.equal(proof.records.length, 3);
    assert.deepEqual(proof.observedNsec, [
        { name: 'child.example.test', nextDomain: 'next.example.test' },
        { name: 'a.example.test', nextDomain: 'z.example.test' }
    ]);
});

test('別の NSEC が存在する自己ループ NSEC を NXDOMAIN 証明に使わない', () => {
    const proof = findNxDomainProof('b.cover.example.test', [
        { name: 'aaaa.cover.example.test', type: 'NSEC', data: { nextDomain: 'localhost.cover.example.test', rrtypes: ['NSEC'] } },
        { name: 'cover.example.test', type: 'NSEC', data: { nextDomain: 'cover.example.test', rrtypes: ['SOA', 'NSEC'] } }
    ]);

    assert.deepEqual(proof.records, []);
    assert.match(proof.diagnostics.join('\n'), /ワイルドカード/);
});

test('NSEC3 による NXDOMAIN 証明を構成する', () => {
    const domain = 'missing.child.example.test';
    const salt = Buffer.from('0102', 'hex');
    const iterations = 1;
    const closestEncloser = 'child.example.test';
    const closestHash = toBase32Hex(nsec3Hash(closestEncloser, salt, iterations));
    const broadOwner = '0'.repeat(32);
    const broadNext = Buffer.alloc(20, 0xff);
    const records = [
        {
            name: `${closestHash}.example.test`,
            type: 'NSEC3',
            data: { algorithm: 1, salt, iterations, nextDomain: Buffer.alloc(20), rrtypes: [] }
        },
        {
            name: `${broadOwner}.example.test`,
            type: 'NSEC3',
            data: { algorithm: 1, salt, iterations, nextDomain: broadNext, rrtypes: [] }
        }
    ];
    const proof = findNxDomainProof(domain, records);

    assert.deepEqual(proof.diagnostics, []);
    assert.equal(proof.records.length, 3);
    assert.equal(proof.observedNsec3.length, 2);
});

test('別の NSEC3 が存在する自己ループ NSEC3 を NXDOMAIN 証明に使わない', () => {
    const domain = 'd.cover.mismatch.nsec3.rsasha256.dnssec-check.jp';
    const zone = 'cover.mismatch.nsec3.rsasha256.dnssec-check.jp';
    const records = [
        {
            name: `RJ3NBAJD8F317DC9PTEB4NU1KUHKANKR.${zone}`,
            type: 'NSEC3',
            data: { algorithm: 1, salt: Buffer.alloc(0), iterations: 1, nextDomain: Buffer.from('0227728663325e074b1d265da065c14121a90e68', 'hex'), rrtypes: ['NS', 'SOA'] }
        },
        {
            name: `616T0P4F7D40NUOI4AKBQQJJSP37KJGI.${zone}`,
            type: 'NSEC3',
            data: { algorithm: 1, salt: Buffer.alloc(0), iterations: 1, nextDomain: Buffer.from('4f2e5aa3eff30fb4f96f1267bdc3ec85a5a2539f', 'hex'), rrtypes: ['A'] }
        },
        {
            name: `F7JI3MDI05SUMC1DNS8VH1CQKK2FFUVF.${zone}`,
            type: 'NSEC3',
            data: { algorithm: 1, salt: Buffer.alloc(0), iterations: 1, nextDomain: Buffer.from('79e721d9b20179eb302dbf11f8859aa504f7fbef', 'hex'), rrtypes: ['A', 'AAAA'] }
        }
    ];

    const proof = findNxDomainProof(domain, records);

    assert.deepEqual(proof.records, []);
    assert.match(proof.diagnostics.join('\n'), /ワイルドカード/);
});

test('Aレコード解決を dns-self-resolver に委譲する', async () => {
    const result = await getARecord('host.glue-fallback.test', {
        resolveHostnameIPv4Self: async hostname => {
            assert.equal(hostname, 'host.glue-fallback.test');
            return '192.0.2.20';
        }
    });

    assert.equal(result, '192.0.2.20');
});

test('既知のネームサーバー情報を自己解決へ渡す', async () => {
    let dependencies;
    const result = await getARecord('known.example.test', {
        knownAddresses: new Map([['known.example.test', '192.0.2.21']]),
        dnsResponseCache: new Map(),
        resolveHostnameIPv4Self: async (hostname, receivedDependencies) => {
            assert.equal(hostname, 'known.example.test');
            dependencies = receivedDependencies;
            return '192.0.2.21';
        }
    });

    assert.equal(result, '192.0.2.21');
    assert.ok(dependencies.knownAddresses instanceof Map);
    assert.ok(dependencies.dnsResponseCache instanceof Map);
});

test('DNSKEY の ZSK ビットを判定する', () => {
    assert.equal(isZoneSigningKey(256), true);
    assert.equal(isZoneSigningKey(257), true);
    assert.equal(isZoneSigningKey(0), false);
});

test('権威 SOA 応答からゾーン頂点を確定する', async () => {
    const result = await getZoneApex('www.example.test', {
        initialNameserver: '192.0.2.1',
        queryDirectlyUDP: async () => ({
            rcode: 'NOERROR',
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

test('共有リゾルバーへDOビット付き問い合わせを渡してDNSSECリソースレコードを抽出する', async () => {
    const result = await getResourceRecord('example.test', '192.0.2.3', 'A', {
        queryDirectlyUDP: async (domain, serverIp, cache, qType, queryOptions) => {
            assert.equal(domain, 'example.test');
            assert.equal(serverIp, '192.0.2.3');
            assert.ok(cache instanceof Map);
            assert.equal(qType, 'A');
            assert.deepEqual(queryOptions, { useEdns: true, dnssecOk: true });
            return {
                rcode: 'NOERROR',
                answers: [{ name: 'example.test', type: 'A', data: '192.0.2.10' }],
                authorities: []
            };
        }
    });

    assert.deepEqual(result.resourceRecords.map(record => record.data), ['192.0.2.10']);
});

test('out-of-bailiwick の参照アドレスを追加セクションから採用する', async () => {
    const requests = [];
    const result = await getZoneApex('www.child.example.test', {
        initialNameserver: '192.0.2.1',
        resolveHostnameIPv4Self: async () => {
            throw new Error('参照アドレスの自己解決は不要');
        },
        queryDirectlyUDP: async (domain, serverIp) => {
            requests.push(serverIp);
            if (requests.length === 1) {
                return {
                    rcode: 'NOERROR',
                    authorities: [{ name: 'child.example.test', type: 'NS', data: 'ns.external.test' }],
                    additionals: [{ name: 'ns.external.test', type: 'A', data: '192.0.2.22' }]
                };
            }
            return {
                rcode: 'NOERROR',
                flags: dnsPacket.AUTHORITATIVE_ANSWER,
                answers: [{ name: 'child.example.test', type: 'SOA', data: {} }]
            };
        }
    });

    assert.deepEqual(requests, ['192.0.2.1', '192.0.2.22']);
    assert.equal(result.zoneApex, 'child.example.test');
});

test('委任先が同じ IP の場合も親子同居として探索結果を保持する', async () => {
    const requests = [];
    const sharedNameserver = '192.0.2.53';
    const result = await getZoneApex('host.co-located.test', {
        initialNameserver: sharedNameserver,
        queryDirectlyUDP: async (domain, serverIp) => {
            requests.push(serverIp);
            if (requests.length === 1) {
                return {
                    rcode: 'NOERROR',
                    authorities: [{ name: 'co-located.test', type: 'NS', data: 'ns.co-located.test', ttl: 300 }],
                    additionals: [{ name: 'ns.co-located.test', type: 'A', data: sharedNameserver, ttl: 300 }]
                };
            }
            return {
                rcode: 'NOERROR',
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
            };
        }
    });

    assert.deepEqual(requests, [sharedNameserver, sharedNameserver]);
    assert.equal(result.zoneApex, 'co-located.test');
    assert.equal(result.parentNs, sharedNameserver);
    assert.equal(result.currentNs, sharedNameserver);
});

test('親子ゾーンの NS RRset を委任応答から個別に保持する', async () => {
    const responses = [
        { rcode: 'NOERROR', authorities: [{ name: 'parent.test', type: 'NS', data: 'ns1.parent.test', ttl: 300 }] },
        { rcode: 'NOERROR', authorities: [{ name: 'child.parent.test', type: 'NS', data: 'ns1.child.test', ttl: 300 }, { name: 'child.parent.test', type: 'NS', data: 'ns2.child.test', ttl: 300 }] },
        {
            rcode: 'NOERROR',
            flags: dnsPacket.AUTHORITATIVE_ANSWER,
            answers: [{
                name: 'child.parent.test', type: 'SOA',
                data: { mname: 'ns1.child.test', rname: 'hostmaster.child.parent.test', serial: 1, refresh: 3600, retry: 600, expire: 86400, minimum: 300 }
            }]
        }
    ];
    const result = await getZoneApex('host.child.parent.test', {
        initialNameserver: '192.0.2.1',
        resolveHostnameIPv4Self: async hostname => ({
            'ns1.parent.test': '192.0.2.2',
            'ns1.child.test': '192.0.2.3'
        })[hostname] || null,
        queryDirectlyUDP: async () => responses.shift()
    });

    assert.deepEqual(result.parentNameservers, ['ns1.parent.test']);
    assert.deepEqual(result.childNameservers, ['ns1.child.test', 'ns2.child.test']);
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
        assert.equal(JSON.parse(response.body).error, 'JSONリクエストの形式が無効です');
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});

function makeFakeResponse() {
    const res = { statusCode: null, body: null };
    res.status = code => { res.statusCode = code; return res; };
    res.json = body => { res.body = body; return res; };
    return res;
}

test('createTimeoutGuardedResponder: 制限時間内に手動で応答すればタイムアウト応答は送られない (ML-DSA 等の大きな鍵で処理が長引いても HTML エラーページ化を防ぐ)', async () => {
    const res = makeFakeResponse();
    const sendJson = createTimeoutGuardedResponder(res, 20, () => ({ success: false, timedOut: true }));
    sendJson(200, { success: true });
    await new Promise(resolve => setTimeout(resolve, 40));
    assert.deepEqual(res.body, { success: true });
    assert.equal(res.statusCode, 200);
});

test('createTimeoutGuardedResponder: 制限時間を超えると自動でタイムアウト応答が送られる', async () => {
    const res = makeFakeResponse();
    createTimeoutGuardedResponder(res, 10, () => ({ success: false, timedOut: true }));
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.deepEqual(res.body, { success: false, timedOut: true });
    assert.equal(res.statusCode, 200);
});

test('createTimeoutGuardedResponder: タイムアウト後に本処理が完了しても二重応答しない', async () => {
    const res = makeFakeResponse();
    const sendJson = createTimeoutGuardedResponder(res, 10, () => ({ success: false, timedOut: true }));
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.deepEqual(res.body, { success: false, timedOut: true });
    sendJson(500, { success: false, lateResult: true });
    assert.deepEqual(res.body, { success: false, timedOut: true });
    assert.equal(res.statusCode, 200);
});