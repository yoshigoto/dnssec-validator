import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import dnsPacket from 'dns-packet';

import { verifyMLDSASignature, verifyRecordRrsig } from '../dnssec-validator.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/ml-dsa44.json', import.meta.url), 'utf8'));

function flipFirstByte(value) {
    const changed = Buffer.from(value);
    changed[0] ^= 1;
    return changed;
}

for (const vector of fixture.vectors) {
    const publicKey = Buffer.from(vector.publicKeyBase64, 'base64');
    const message = Buffer.from(vector.messageHex, 'hex');
    const signature = Buffer.from(vector.signatureBase64, 'base64');
    const verify = (key = publicKey, sig = signature, msg = message, algorithm = 18) =>
        verifyMLDSASignature(key, sig, msg, algorithm);

    test(`${vector.source}の固定ML-DSA-44署名を署名生成なしで検証する`, () => {
        assert.equal(publicKey.length, 1312);
        assert.equal(signature.length, 2420);
        assert.ok(message.length > 0);
        assert.deepEqual(verify(), { verified: true, reason: '' });
    });

    test(`${vector.source}の固定ML-DSA-44ベクトルの鍵・署名・メッセージ改ざんを拒否する`, () => {
        const results = [
            verify(flipFirstByte(publicKey)),
            verify(publicKey, flipFirstByte(signature)),
            verify(publicKey, signature, flipFirstByte(message))
        ];
        for (const result of results) {
            assert.equal(result.verified, false);
            assert.equal(typeof result.reason, 'string');
            assert.ok(result.reason.length > 0);
        }
        assert.deepEqual(verify(), { verified: true, reason: '' });
    });

    test(`${vector.source}の固定ML-DSA-44署名は不正長の鍵・署名と未対応アルゴリズムを拒否する`, () => {
        for (const key of [Buffer.alloc(0), publicKey.subarray(0, -1), Buffer.concat([publicKey, Buffer.from([0])])]) {
            const result = verify(key);
            assert.equal(result.verified, false, `public key length ${key.length}`);
            assert.ok(result.reason.length > 0);
        }
        for (const sig of [Buffer.alloc(0), signature.subarray(0, -1), Buffer.concat([signature, Buffer.from([0])])]) {
            const result = verify(publicKey, sig);
            assert.equal(result.verified, false, `signature length ${sig.length}`);
            assert.ok(result.reason.length > 0);
        }
        assert.deepEqual(verify(publicKey, signature, message, 19), {
            verified: false, reason: '未対応のML-DSAアルゴリズム [19]'
        });
    });

    test(`${vector.source}の非空コンテキストで作られた固定署名を空コンテキストでは受理しない`, () => {
        assert.equal(vector.context, 'dnssec-validator-test');
        const contextSignature = Buffer.from(vector.contextSignatureBase64, 'base64');
        assert.equal(contextSignature.length, 2420);
        const result = verify(publicKey, contextSignature);
        assert.equal(result.verified, false);
        assert.ok(result.reason.length > 0);
    });

    test(`${vector.source}の固定署名をDNSKEY/RRSIGとしてデコードしRRsetを検証する`, t => {
        // The fixed RRSIG must not expire as wall-clock time advances.
        t.mock.method(Date, 'now', () => fixture.verificationTime * 1000);
        const dnskey = {
            name: 'example.test', type: 'DNSKEY', ttl: 300,
            data: { flags: 256, protocol: 3, algorithm: 18, key: publicKey }
        };
        const rrsig = {
            name: fixture.domain, type: 'RRSIG', ttl: 300,
            data: { ...vector.rrsig, signature }
        };
        const decoded = dnsPacket.decode(dnsPacket.encode({
            type: 'response', id: 1,
            answers: [...fixture.records, dnskey, rrsig]
        }));
        const records = decoded.answers.filter(record => record.type === 'A');
        const key = decoded.answers.find(record => record.type === 'DNSKEY');
        const sig = decoded.answers.find(record => record.type === 'RRSIG');
        const verifyRrset = (rrset, recordSignature = sig) =>
            verifyRecordRrsig(rrset, recordSignature, key, fixture.domain);
        assert.equal(verifyRrset(records).verified, true);
        assert.equal(verifyRrset([...records].reverse()).verified, true);
        assert.equal(verifyRrset([
            { ...records[0], data: '192.0.2.46' }, ...records.slice(1)
        ]).verified, false);
        assert.equal(verifyRrset(records.slice(1)).verified, false);
        assert.equal(verifyRrset(records, {
            ...sig, data: { ...sig.data, signature: flipFirstByte(signature) }
        }).verified, false);
    });
}
