import crypto from 'node:crypto';
import { realpathSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import dnsPacket from 'dns-packet';	// https://github.com/mafintosh/dns-packet
import dnsTypes from 'dns-packet/types.js';
import {
    ROOT_SERVER_BOOTSTRAP_IP,
    getReferralAddressRecords,
    isInBailiwickGlue,
    normalizeDnsName as normalizeResolverDnsName,
    queryDirectlyUDP,
    resolveHostnameIPv4Self
} from 'dns-self-resolver';
import express from 'express';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '4kb', type: 'application/json' }));
app.use((req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Content-Security-Policy': "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'"
    });
    next();
});

// --- 定数定義 ---
const ROOT_NAMESERVER = ROOT_SERVER_BOOTSTRAP_IP;
const dnssecResponseCache = new Map();
const MAX_DOMAIN_LENGTH = 253;
const RATE_LIMIT_REQUESTS_PER_MINUTE = 60;
const rateLimitMap = new Map(); // IP: { count, resetTime }
const API_VALIDATE_TIMEOUT_MS = 25000; // ホスティング基盤側のゲートウェイタイムアウト(HTMLエラーページ化)より先に必ずJSONで応答するための上限
const VALIDATION_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SRV'];

// --- ドメイン名バリデーション関数 ---
function validateDomainName(domain) {
    if (!domain || typeof domain !== 'string') {
        return { valid: false, error: 'ドメイン名は空ではない文字列である必要があります' };
    }
    
    // DNSインジェクション対策: 危険な文字をフィルタ
    if (/[;\\\"'<>()\[\]{}|`~!@#$%^&*+=\s]/g.test(domain)) {
        return { valid: false, error: 'ドメイン名に無効な文字が含まれています' };
    }
    
    // 長さチェック
    if (domain.length > MAX_DOMAIN_LENGTH) {
        return { valid: false, error: `ドメイン名が長すぎます (最大: ${MAX_DOMAIN_LENGTH}文字)` };
    }
    
    // ドメイン名フォーマットチェック
    const domainRegex = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$/i;
    if (!domainRegex.test(domain)) {
        return { valid: false, error: 'ドメイン名の形式が無効です' };
    }
    
    return { valid: true };
}

// --- ドメイン名正規化関数 ---
function normalizeDomainName(domain) {
    return domain.toLowerCase().replace(/\.$/, ''); // 末尾のドット削除、小文字化
}

// --- 一定時間内に応答が送信されなければ、指定された内容で自動的に一度だけ応答するガードを作る ---
function createTimeoutGuardedResponder(res, timeoutMs, buildTimeoutBody) {
    let responded = false;
    const sendJson = (status, body) => {
        if (responded) return;
        responded = true;
        clearTimeout(timeoutTimer);
        res.status(status).json(body);
    };
    const timeoutTimer = setTimeout(() => sendJson(200, buildTimeoutBody()), timeoutMs);
    return sendJson;
}

// --- レート制限チェック関数 ---
function checkRateLimit(clientIp) {
    const now = Date.now();
    
    if (!rateLimitMap.has(clientIp)) {
        rateLimitMap.set(clientIp, { count: 1, resetTime: now + 60000 });
        return { allowed: true, remaining: RATE_LIMIT_REQUESTS_PER_MINUTE - 1 };
    }
    
    const record = rateLimitMap.get(clientIp);
    if (now >= record.resetTime) {
        // リセット
        rateLimitMap.set(clientIp, { count: 1, resetTime: now + 60000 });
        return { allowed: true, remaining: RATE_LIMIT_REQUESTS_PER_MINUTE - 1 };
    }
    
    if (record.count >= RATE_LIMIT_REQUESTS_PER_MINUTE) {
        const waitSeconds = Math.ceil((record.resetTime - now) / 1000);
        return { allowed: false, remaining: 0, waitSeconds };
    }
    
    record.count++;
    return { allowed: true, remaining: RATE_LIMIT_REQUESTS_PER_MINUTE - record.count };
}

async function getResourceRecord(domain, serverIp, rType, options = {}) {
    const queryUdp = options.queryDirectlyUDP || queryDirectlyUDP;
    const queryOptions = { useEdns: true, dnssecOk: true };
    const res = await queryUdp(domain, serverIp, options.dnsResponseCache || dnssecResponseCache, rType, queryOptions);
    if (res.error) {
        throw new Error(`${serverIp}へのDNSクエリ失敗: ${res.error}${res.detail ? ` (${res.detail})` : ''}`);
    }

    const answers = res.answers || [];
    const resourceRecords = answers.filter(a => a.type === rType);
    let rrsigRecords = [];
    if (resourceRecords.length !== 0) {
        rrsigRecords = answers.filter(a => a.type === 'RRSIG' && a.data.typeCovered === rType);
    }

    const authorityRecords = res.authorities || [];
    const denialRecords = authorityRecords.filter(record => record.type === 'NSEC' || record.type === 'NSEC3');
    const denialRrsigRecords = authorityRecords.filter(record => record.type === 'RRSIG' && (record.data.typeCovered === 'NSEC' || record.data.typeCovered === 'NSEC3'));
    return { resourceRecords, rrsigRecords, denialRecords, denialRrsigRecords, rcode: res.rcode };
}

function getAuthorityRecordValue(record) {
    if (record.type === 'DS') {
        return [record.data.keyTag, record.data.algorithm, record.data.digestType, Buffer.from(record.data.digest).toString('hex')];
    }
    if (record.type === 'DNSKEY') {
        return [record.data.flags, record.data.protocol, record.data.algorithm, Buffer.from(record.data.key).toString('hex')];
    }
    if (record.type === 'NS') {
        return [normalizeResolverDnsName(record.data)];
    }
    return [normalizeResolverDnsName(record.name), record.type, JSON.stringify(record.data)];
}

function summarizeAuthorityRecord(record) {
    if (record.type === 'DS') {
        return `Key Tag ${record.data.keyTag} / alg ${record.data.algorithm} / digest ${record.data.digestType}`;
    }
    if (record.type === 'DNSKEY') {
        return `Key Tag ${calculateKeyTag(record.data.algorithm, buildDnskeyFullRdata(record.data))} / alg ${record.data.algorithm} / flags ${record.data.flags}`;
    }
    return normalizeResolverDnsName(record.data);
}

async function compareAuthorityRecordSets(zoneApex, nameservers, recordType, options = {}) {
    const queryUdp = options.queryDirectlyUDP || queryDirectlyUDP;
    const dnsResponseCache = options.dnsResponseCache || dnssecResponseCache;
    const normalizedApex = normalizeResolverDnsName(zoneApex);
    const servers = await Promise.all(nameservers.map(async nameserver => {
        try {
            const serverIp = await getARecord(nameserver, {
                queryDirectlyUDP: queryUdp,
                resolveHostnameIPv4Self: options.resolveHostnameIPv4Self,
                knownAddresses: options.knownAddresses,
                dnsResponseCache
            });
            const response = await queryUdp(zoneApex, serverIp, dnsResponseCache, recordType, { useEdns: true, dnssecOk: true });
            if (response.error) {
                throw new Error(`${response.error}${response.detail ? ` (${response.detail})` : ''}`);
            }
            const sections = recordType === 'NS' ? [...(response.answers || []), ...(response.authorities || [])] : (response.answers || []);
            const records = sections.filter(record => record.type === recordType && normalizeResolverDnsName(record.name) === normalizedApex);
            const values = [...new Set(records.map(record => JSON.stringify(getAuthorityRecordValue(record))))].sort();
            return {
                name: normalizeResolverDnsName(nameserver),
                ip: serverIp,
                status: 'ok',
                rcode: response.rcode || '',
                recordCount: records.length,
                records: records.map(summarizeAuthorityRecord),
                fingerprint: JSON.stringify(values)
            };
        } catch (error) {
            return { name: normalizeResolverDnsName(nameserver), ip: '', status: 'error', error: error.message };
        }
    }));

    const successfulServers = servers.filter(server => server.status === 'ok');
    const fingerprints = new Set(successfulServers.map(server => server.fingerprint));
    const complete = servers.length > 0 && successfulServers.length === servers.length;
    return {
        recordType,
        complete,
        consistent: complete && fingerprints.size === 1,
        hasDifferences: fingerprints.size > 1,
        servers: servers.map(({ fingerprint, ...server }) => server)
    };
}

// --- ヘルパー関数: Aレコードを取得する ---
async function getARecord(domain, options = {}) {
    if (net.isIP(domain)) {
        return domain;
    }

    const resolveIPv4 = options.resolveHostnameIPv4Self || resolveHostnameIPv4Self;
    const ipAddress = await resolveIPv4(domain, {
        queryDirectlyUDP: options.queryDirectlyUDP,
        knownAddresses: options.knownAddresses,
        dnsResponseCache: options.dnsResponseCache
    });
    if (!ipAddress) {
        throw new Error(`Aレコード取得失敗[${domain}]: ルートからの自己解決でIPアドレスが見つかりません`);
    }
    return ipAddress;
}

// --- ヘルパー関数: ゾーン頂点をルートから辿って取得する ---
async function getZoneApex(domain, options = {}) {
    const queryUdp = options.queryDirectlyUDP || queryDirectlyUDP;
    const resolveIPv4 = options.resolveHostnameIPv4Self || resolveHostnameIPv4Self;
    const dnsResponseCache = options.dnsResponseCache || new Map();
    let currentNs = options.initialNameserver || ROOT_NAMESERVER;
    let parentNs = '';
    let parentNameservers = [];
    let childNameservers = [];
    let zoneApex = '';
    let lastDelegationZone = '';
    let rcode = '';
    let hasCnameOrDname = false;
    let discoveryError = '';

    for (let i = 0; i < 10; i++) {
        const isRootNameserver = currentNs === ROOT_NAMESERVER;
        let currentServerIp;
        try {
            currentServerIp = net.isIP(currentNs) ? currentNs : await resolveIPv4(currentNs, {
                queryDirectlyUDP: options.queryDirectlyUDP,
                knownAddresses: options.knownAddresses,
                dnsResponseCache
            });
        } catch (error) {
            if (!lastDelegationZone) throw error;
            discoveryError = `委任先 [${currentNs}] の IP アドレス取得失敗: ${error.message}`;
            break;
        }
        if (!currentServerIp) {
            if (lastDelegationZone) {
                discoveryError = `委任先 [${currentNs}] の IP アドレスを自己解決できません`;
                break;
            }
            throw new Error(`ネームサーバー [${currentNs}] の IP アドレスを自己解決できません`);
        }
        const res = await queryUdp(domain, currentServerIp, dnsResponseCache, 'SOA');

        if (res.error === 'TIMEOUT' || res.error === 'SEND_ERROR' || res.error === 'DECODE_ERROR') {
            continue;
        }
        rcode = res.rcode;

        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024;
        const isAuthoritative = (res.flags & AUTHORITATIVE_ANSWER) !== 0;
        const answers = res.answers || [];
        const authorities = res.authorities || [];
        const additionals = res.additionals || [];
        if (isAuthoritative) {
            if (res.rcode === 'NOERROR') {
                if (answers.length > 0) {
                    const cnameRecord = answers.find(r => r.type === 'CNAME');
                    if (cnameRecord) {
                        hasCnameOrDname = true;
                        break;
                    }
                    const dnameRecord = answers.find(r => r.type === 'DNAME');
                    if (dnameRecord) {
                        hasCnameOrDname = true;
                        break;
                    }
                    const soaRecord = answers.find(r => r.type === 'SOA');
                    if (soaRecord) {
                        zoneApex = soaRecord.name;
                        break;
                    }
                } else if (authorities.length > 0) {
                    const soaRecord = authorities.find(r => r.type === 'SOA');
                    if (soaRecord) {
                        zoneApex = soaRecord.name;
                        break;
                    }
                }
            }
            if (res.rcode === 'NXDOMAIN') {
                if (authorities.length > 0) {
                    const soaRecord = authorities.find(r => r.type === 'SOA');
                    if (soaRecord) {
                        zoneApex = soaRecord.name;
                        break;
                    }
                }
            }
        }
        if (!isAuthoritative && authorities.length > 0) {
            const nsRecords = authorities.filter(r => r.type === 'NS');
            if (nsRecords.length > 0) {
                const delegationZone = normalizeResolverDnsName(nsRecords[0].name);
                if (delegationZone === lastDelegationZone) {
                    discoveryError = `委任点 [${delegationZone}] の referral が繰り返され、委任先の権威 SOA を取得できませんでした。`;
                    break;
                }
                parentNameservers = childNameservers;
                childNameservers = nsRecords.map(record => record.data);
                lastDelegationZone = delegationZone;
                // 委任先ゾーン内のグルーレコードを優先選択し、ホスト名解決による getARecord の循環参照を回避する
                let chosenNsRecord = null;
                let chosenNsIp = null;
                for (const nsRecord of nsRecords) {
                    const nsNames = [normalizeResolverDnsName(nsRecord.data)];
                    const glueA = additionals.find(record => record.type === 'A' && isInBailiwickGlue(record, nsNames, nsRecord.name));
                    if (glueA) {
                        chosenNsRecord = nsRecord;
                        chosenNsIp = glueA.data;
                        break;
                    }
                }
                if (!chosenNsRecord) {
                    const delegationZone = nsRecords[0].name;
                    const referralAddresses = getReferralAddressRecords(
                        additionals,
                        nsRecords.map(record => record.data),
                        delegationZone,
                        'strict',
                        isRootNameserver ? '.' : delegationZone
                    );
                    const referralA = referralAddresses.find(record => record.type === 'A');
                    if (referralA) {
                        chosenNsRecord = nsRecords.find(record => normalizeResolverDnsName(record.data) === normalizeResolverDnsName(referralA.name));
                        chosenNsIp = referralA.data;
                    }
                }
                if (!chosenNsRecord) {
                    chosenNsRecord = nsRecords[0];
                }
                parentNs = currentNs;
                currentNs = chosenNsIp || chosenNsRecord.data;
            }
        }
    }

    if (!zoneApex && lastDelegationZone && !hasCnameOrDname) {
        zoneApex = lastDelegationZone;
        discoveryError ||= `委任点 [${zoneApex}] の権威 SOA を取得できませんでした。`;
    }

    if (zoneApex && childNameservers.length > 0 && lastDelegationZone !== normalizeResolverDnsName(zoneApex)) {
        parentNameservers = childNameservers;
        parentNs = parentNameservers[0];
        childNameservers = [];
        for (const nameserver of parentNameservers) {
            try {
                const serverIp = await getARecord(nameserver, {
                    queryDirectlyUDP: queryUdp,
                    resolveHostnameIPv4Self: resolveIPv4,
                    knownAddresses: options.knownAddresses,
                    dnsResponseCache
                });
                const response = await queryUdp(zoneApex, serverIp, dnsResponseCache, 'NS', { useEdns: true, dnssecOk: true });
                if (response.error) continue;
                const nsRecords = [...(response.answers || []), ...(response.authorities || [])].filter(record =>
                    record.type === 'NS' && normalizeResolverDnsName(record.name) === normalizeResolverDnsName(zoneApex));
                if (nsRecords.length === 0) continue;
                childNameservers = [...new Map(nsRecords.map(record => [normalizeResolverDnsName(record.data), record.data])).values()];
                currentNs = childNameservers[0];
                break;
            } catch (error) { }
        }
    }

    return { currentNs: currentNs, parentNs: parentNs, parentNameservers, childNameservers, zoneApex: zoneApex, rcode: rcode, hasCnameOrDname: hasCnameOrDname, discoveryError };
}

// --- ヘルパー関数: RRSIG 署名の有効期限チェック ---
function checkSignatureExpiration(rrsig) {
    const now = Math.floor(Date.now() / 1000); // 現在時刻 (秒)
    const expiration = rrsig.data.expiration;
    const inception = rrsig.data.inception;
    
    if (now < inception) {
        return { valid: false, reason: `署名はまだ有効になっていません (有効期限開始: ${new Date(inception * 1000).toISOString()})` };
    }
    if (now > expiration) {
        return { valid: false, reason: `署名の有効期限が切れています (有効期限終了: ${new Date(expiration * 1000).toISOString()})` };
    }
    return { valid: true };
}

// --- ヘルパー関数: RSA署名の検証 ---
function verifyRSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm) {
    try {
        let keyType = '';
        switch (algorithm) {
            case 5:  // RSASHA1
                keyType = 'sha1';
                break;
            case 7:  // RSASHA1-NSEC3-SHA1
                keyType = 'sha1';
                break;
            case 8:  // RSASHA256
                keyType = 'sha256';
                break;
            case 10: // RSASHA512
                keyType = 'sha512';
                break;
            default:
                return { verified: false, reason: `未対応のRSAアルゴリズム [${algorithm}]` };
        }
        
        // DNSKEYのRSA公開鍵(RFC 3110)を解析: Exponent Length + Exponent + Modulus
        let offset = 0;
        let expLen = publicKeyBuffer.readUInt8(0);
        offset = 1;
        if (expLen === 0) {
            expLen = publicKeyBuffer.readUInt16BE(1);
            offset = 3;
        }
        const exponent = publicKeyBuffer.subarray(offset, offset + expLen);
        const modulus = publicKeyBuffer.subarray(offset + expLen);
        
        // JWK 形式に変換して公開鍵を生成
        const publicKeyObj = crypto.createPublicKey({
            key: { kty: 'RSA', n: modulus.toString('base64url'), e: exponent.toString('base64url') },
            format: 'jwk'
        });
        
        // Node.js crypto.createVerify を使用して署名を検証
        const verifier = crypto.createVerify(keyType.toUpperCase());
        verifier.update(messageBuffer);
        
        const verified = verifier.verify(publicKeyObj, signatureBuffer);
        
        return { 
            verified, 
            reason: verified ? '' : `RSA署名検証に失敗しました。`
        };
    } catch (err) {
        return { verified: false, reason: `RSA署名検証でエラーが発生しました。: ${err.message}` };
    }
}

// --- ヘルパー関数: ECDSA署名の検証 ---
function verifyECDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm) {
    try {
        let curveName = '';
        let hashAlgo = '';
        let coordLen = 0;
        switch (algorithm) {
            case 13: // ECDSAP256SHA256
                curveName = 'P-256';
                hashAlgo = 'sha256';
                coordLen = 32;
                break;
            case 14: // ECDSAP384SHA384
                curveName = 'P-384';
                hashAlgo = 'sha384';
                coordLen = 48;
                break;
            default:
                return { verified: false, reason: `未対応のECDSAアルゴリズム [${algorithm}]` };
        }
        
        // DNSKEY の生の座標 (X||Y) を JWK 形式に変換して公開鍵を生成
        const x = publicKeyBuffer.subarray(0, coordLen);
        const y = publicKeyBuffer.subarray(coordLen, coordLen * 2);
        const publicKey = crypto.createPublicKey({
            key: { kty: 'EC', crv: curveName, x: x.toString('base64url'), y: y.toString('base64url') },
            format: 'jwk'
        });
        
        const verifier = crypto.createVerify(hashAlgo.toUpperCase());
        verifier.update(messageBuffer);
        
        // DNSSECの署名はr||sの固定長(IEEE P1363)形式のため、そのまま検証可能
        const verified = verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, signatureBuffer);
        
        return { 
            verified, 
            reason: verified ? '' : `ECDSA署名検証に失敗しました。`
        };
    } catch (err) {
        return { verified: false, reason: `ECDSA署名検証でエラーが発生しました。: ${err.message}` };
    }
}

// --- ヘルパー関数: EdDSA署名の検証 ---
function verifyEdDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm) {
    try {
        let crvName = '';
        switch (algorithm) {
            case 15: // ED25519
                crvName = 'Ed25519';
                break;
            case 16: // ED448
                crvName = 'Ed448';
                break;
            default:
                return { verified: false, reason: `未対応のEdDSAアルゴリズム [${algorithm}]` };
        }
        
        // DNSKEY の生の公開鍵バイト列を JWK (OKP) 形式に変換して公開鍵を生成
        const publicKey = crypto.createPublicKey({
            key: { kty: 'OKP', crv: crvName, x: publicKeyBuffer.toString('base64url') },
            format: 'jwk'
        });
        
        // EdDSAは事前ハッシュを行わないため、createVerifyではなくワンショットAPIを使用する
        const verified = crypto.verify(null, messageBuffer, publicKey, signatureBuffer);
        
        return { 
            verified, 
            reason: verified ? '' : `EdDSA署名検証に失敗しました。`
        };
    } catch (err) {
        return { verified: false, reason: `EdDSA署名検証でエラーが発生しました。: ${err.message}` };
    }
}

// --- ヘルパー関数: ML-DSA-44署名の検証 ---
function verifyMLDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm) {
    if (algorithm !== 18) {
        return { verified: false, reason: `未対応のML-DSAアルゴリズム [${algorithm}]` };
    }

    try {
        const verified = ml_dsa44.verify(signatureBuffer, messageBuffer, publicKeyBuffer);
        return {
            verified,
            reason: verified ? '' : 'ML-DSA-44署名検証に失敗しました。'
        };
    } catch (err) {
        return { verified: false, reason: `ML-DSA-44署名検証でエラーが発生しました。: ${err.message}` };
    }
}

// --- ヘルパー関数: ドメイン名を DNSワイヤーフォーマットに変換 (正規化・非圧縮) ---
function encodeDomainNameCanonical(domain) {
    const labels = domain.replace(/\.$/, '').toLowerCase().split('.');
    const chunks = [];
    for (const label of labels) {
        if (!label) continue;
        chunks.push(Buffer.from([label.length]), Buffer.from(label, 'ascii'));
    }
    chunks.push(Buffer.from([0x00]));
    return Buffer.concat(chunks);
}

// --- ヘルパー関数: DNSKEYレコードから公開鍵バイト列を取得 ---
function getDnskeyRawKey(dnskeyData) {
    return dnskeyData.key || dnskeyData.publicKey;
}

// --- ヘルパー関数: DNSKEY の完全な RDATA (Flags+Protocol+Algorithm+公開鍵) を復元 (RFC 4034) ---
function buildDnskeyFullRdata(dnskeyData) {
    const headerBuf = Buffer.alloc(4);
    headerBuf.writeUInt16BE(dnskeyData.flags, 0);
    headerBuf.writeUInt8(3, 2); // dns-packet では DNSKEY の Protocol は 3 固定
    headerBuf.writeUInt8(dnskeyData.algorithm, 3);
    return Buffer.concat([headerBuf, getDnskeyRawKey(dnskeyData)]);
}

function dsSummary(data) {
    return { keyTag: data.keyTag, algorithm: data.algorithm, digestType: data.digestType, digest: Buffer.from(data.digest).toString('hex').toLowerCase() };
}

function compareProposedDs(proposals, parentDs) {
    const fingerprint = record => `${record.keyTag}/${record.algorithm}/${record.digestType}/${record.digest}`;
    const parent = new Set(parentDs.map(fingerprint));
    const proposed = new Set(proposals.map(fingerprint));
    return {
        status: proposed.size === 0 ? 'absent' : proposed.size === parent.size && [...proposed].every(value => parent.has(value)) ? 'match' : 'different',
        proposed: proposals,
        toAdd: proposals.filter(record => !parent.has(fingerprint(record))),
        toRemove: parentDs.filter(record => !proposed.has(fingerprint(record)))
    };
}

async function diagnoseDsProposals(zoneApex, parentDsInfo, childIp, options = {}) {
    const result = { parentDs: [], cds: null, cdnskey: null, notes: [] };
    if (!parentDsInfo || parentDsInfo.rcode !== 'NOERROR') {
        result.notes.push('親側DSを確認できないため、提案との差分は判定できません。');
        return result;
    }
    result.parentDs = parentDsInfo.resourceRecords.filter(record => normalizeDomainName(record.name) === normalizeDomainName(zoneApex)).map(record => dsSummary(record.data));
    const [cdsResponse, cdnskeyResponse] = await Promise.allSettled([
        getResourceRecord(zoneApex, childIp, 'CDS', options),
        getResourceRecord(zoneApex, childIp, 'CDNSKEY', options)
    ]);
    for (const [type, response] of [['cds', cdsResponse], ['cdnskey', cdnskeyResponse]]) {
        if (response.status === 'rejected' || response.value.rcode !== 'NOERROR') {
            result[type] = { status: 'error', error: response.status === 'rejected' ? response.reason.message : `応答コード: ${response.value.rcode}` };
            continue;
        }
        try {
            const records = response.value.resourceRecords.filter(record => normalizeDomainName(record.name) === normalizeDomainName(zoneApex));
            const proposals = records.map(record => {
                const raw = record.data;
                if (!Buffer.isBuffer(raw) || raw.length < 5) throw new Error('RDATAが不正です');
                if (type === 'cds') return dsSummary({ keyTag: raw.readUInt16BE(0), algorithm: raw[2], digestType: raw[3], digest: raw.subarray(4) });
                if (raw[2] !== 3) throw new Error('CDNSKEYのProtocolが3ではありません');
                return { flags: raw.readUInt16BE(0), protocol: raw[2], algorithm: raw[3], key: raw.subarray(4) };
            });
            const deletion = proposals.length === 1 && (type === 'cds'
                ? proposals[0].keyTag === 0 && proposals[0].algorithm === 0 && proposals[0].digestType === 0 && proposals[0].digest === '00'
                : proposals[0].flags === 0 && proposals[0].algorithm === 0 && proposals[0].key.length === 1 && proposals[0].key[0] === 0);
            if (deletion) {
                result[type] = { status: 'delete', proposed: [], toAdd: [], toRemove: result.parentDs };
            } else if (type === 'cds') {
                result[type] = compareProposedDs(proposals, result.parentDs);
            } else {
                const digestTypes = [...new Set(result.parentDs.map(record => record.digestType).filter(digestType => [1, 2, 4].includes(digestType)))];
                if (digestTypes.length === 0) digestTypes.push(2);
                const hashes = { 1: 'sha1', 2: 'sha256', 4: 'sha384' };
                const dsRecords = proposals.flatMap(key => digestTypes.map(digestType => ({
                    keyTag: calculateKeyTag(key.algorithm, buildDnskeyFullRdata(key)),
                    algorithm: key.algorithm,
                    digestType,
                    digest: crypto.createHash(hashes[digestType]).update(encodeDomainNameCanonical(zoneApex)).update(buildDnskeyFullRdata(key)).digest('hex')
                })));
                result[type] = compareProposedDs(dsRecords, result.parentDs);
                result[type].digestTypes = digestTypes;
            }
        } catch (error) {
            result[type] = { status: 'error', error: error.message };
        }
    }
    const cdsProposal = result.cds?.proposed?.map(record => JSON.stringify(record)).sort();
    const cdnskeyProposal = result.cdnskey?.proposed?.map(record => JSON.stringify(record)).sort();
    if (['match', 'different', 'delete'].includes(result.cds?.status) && ['match', 'different', 'delete'].includes(result.cdnskey?.status) &&
        (result.cds.status !== result.cdnskey.status || JSON.stringify(cdsProposal) !== JSON.stringify(cdnskeyProposal))) {
        result.notes.push('CDSとCDNSKEYの提案が異なる可能性があります。両方の内容を確認してください。');
    }
    if (result.cds?.status === 'absent' && result.cdnskey?.status === 'absent') result.notes.push('子ゾーンからのDS変更提案はありません。');
    if (result.parentDs.some(record => ![1, 2, 4].includes(record.digestType)) && result.cdnskey?.status !== 'absent') {
        result.notes.push('親DSに未対応のDigest Typeがあり、CDNSKEYからの比較には含めていません。');
    }
    return result;
}

// --- ヘルパー関数: RRSIG 署名の検証 (メイン関数) ---
// rrset: 同じ Type Covered を持つ全リソースレコードの配列 (RFC 4034 の署名対象RRset)
function verifyRRSIGSignature(rrset, rrsig, dnskeyRecord, domain) {
    // 1. 署名の有効期限チェック
    const expirationCheck = checkSignatureExpiration(rrsig);
    if (!expirationCheck.valid) {
        return { verified: false, reason: expirationCheck.reason };
    }
    
    // 2. DNSKEYからKey Tagを計算
    const rawKeyBuf = getDnskeyRawKey(dnskeyRecord.data);
    const fullRdata = buildDnskeyFullRdata(dnskeyRecord.data);
    const calculatedKeyTag = calculateKeyTag(dnskeyRecord.data.algorithm, fullRdata);
    
    // 3. Key Tagの確認
    if (calculatedKeyTag !== rrsig.data.keyTag) {
        return { 
            verified: false, 
            reason: `Key Tag不一致: DNSKEY [${calculatedKeyTag}] vs RRSIG [${rrsig.data.keyTag}]`
        };
    }
    
    // 4. アルゴリズムの確認
    if (dnskeyRecord.data.algorithm !== rrsig.data.algorithm) {
        return { 
            verified: false, 
            reason: `アルゴリズム不一致: DNSKEY [${dnskeyRecord.data.algorithm}] vs RRSIG [${rrsig.data.algorithm}]`
        };
    }
    
    // 5. RRSIG RDATA (署名フィールドを除く) をワイヤーフォーマットで構築 (RFC 4034 3.1.8.1)
    const signerNameBuf = encodeDomainNameCanonical(rrsig.data.signersName || domain);
    const rrsigRdataHeader = Buffer.alloc(18);
    rrsigRdataHeader.writeUInt16BE(dnsTypes.toType(rrsig.data.typeCovered), 0);
    rrsigRdataHeader.writeUInt8(rrsig.data.algorithm, 2);
    rrsigRdataHeader.writeUInt8(rrsig.data.labels, 3);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.expiration, 8);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.inception, 12);
    rrsigRdataHeader.writeUInt16BE(rrsig.data.keyTag, 16);
    
    // 6. 署名対象 RRset (全レコード) を RR ワイヤーフォーマットに変換し、正規順序 (RFC 4034 6.3) に並べ替え
    const ownerNameBuf = encodeDomainNameCanonical(domain);
    const typeCoveredNum = dnsTypes.toType(rrsig.data.typeCovered);
    const rdataList = (rrset && rrset.length > 0 ? rrset : [dnskeyRecord])
        .map(r => buildDnskeyFullRdata(r.data))
        .sort(Buffer.compare);
    
    const rrWireBufs = rdataList.map(rdata => {
        const rrHeader = Buffer.alloc(10);
        rrHeader.writeUInt16BE(typeCoveredNum, 0);
        rrHeader.writeUInt16BE(1, 2); // CLASS IN
        rrHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
        rrHeader.writeUInt16BE(rdata.length, 8);
        return Buffer.concat([ownerNameBuf, rrHeader, rdata]);
    });
    
    // 7. メッセージ (署名対象) を構築 = RRSIG_RDATA + 正規順序のRRset
    const messageBuffer = Buffer.concat([rrsigRdataHeader, signerNameBuf, ...rrWireBufs]);
    
    // 8. 公開鍵を抽出
    const publicKeyBuffer = rawKeyBuf;
    if (!publicKeyBuffer) {
        return { verified: false, reason: `DNSKEYから公開鍵を抽出できません` };
    }
    
    // 9. 署名データを取得
    const signatureBuffer = rrsig.data.signature;
    if (!signatureBuffer) {
        return { verified: false, reason: `RRSIGから署名データを抽出できません` };
    }
    
    // 10. アルゴリズムに応じて署名を検証
    const algorithm = dnskeyRecord.data.algorithm;
    let signatureResult;
    
    if (algorithm === 5 || algorithm === 7 || algorithm === 8 || algorithm === 10) {
        // RSA系アルゴリズム
        signatureResult = verifyRSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 13 || algorithm === 14) {
        // ECDSA系アルゴリズム
        signatureResult = verifyECDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 15 || algorithm === 16) {
        // EdDSA系アルゴリズム
        signatureResult = verifyEdDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 18) {
        signatureResult = verifyMLDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else {
        return { verified: false, reason: `未対応の暗号アルゴリズム [${algorithm}]` };
    }
    
    return signatureResult;
}

function buildDsRdata(dsRecord) {
    const digest = Buffer.isBuffer(dsRecord.digest) ? dsRecord.digest : Buffer.from(dsRecord.digest || []);
    const rdata = Buffer.alloc(4 + digest.length);
    rdata.writeUInt16BE(dsRecord.keyTag, 0);
    rdata.writeUInt8(dsRecord.algorithm, 2);
    rdata.writeUInt8(dsRecord.digestType, 3);
    digest.copy(rdata, 4);
    return rdata;
}

function createRecordValidation(recordType = 'A') {
    return { recordType, queried: true, recordsFound: false, signatures: [], trustChain: { dsMatchedKskKeyTags: [], dnskeyRrsetSignatures: [] } };
}

function createARecordValidation() {
    return createRecordValidation('A');
}

function isValidationSuccessful(diagram) {
    const checks = diagram && diagram.checks;
    if (!checks || !checks.dsSignature || !checks.dnskeySignature || !checks.dsKeyMatch) {
        return false;
    }

    const aRecordValidation = diagram.child && diagram.child.aRecordValidation;
    if (!aRecordValidation || !aRecordValidation.queried || aRecordValidation.error) {
        return false;
    }
    if (aRecordValidation.recordsFound) {
        return aRecordValidation.signatures.some(signature => signature.trustChainVerified === true);
    }
    return Boolean(aRecordValidation.denialProof && aRecordValidation.denialProof.verified === true);
}

function classifyValidationResult(diagram, timedOut = false) {
    const checks = diagram && diagram.checks || {};
    const parent = diagram && diagram.parent || {};
    const child = diagram && diagram.child || {};
    const aRecordValidation = child.aRecordValidation;
    if (timedOut) return { status: 'indeterminate', statusLabel: '判定不能（タイムアウト）', nextChecks: ['権威サーバーへの疎通を確認し、時間をおいて再試行してください。'] };
    if (parent.dsAbsenceProof && parent.dsAbsenceProof.verified === true) {
        return { status: 'insecure', statusLabel: 'Insecure（未署名の委任）', nextChecks: ['親側のNSEC/NSEC3不在証明を検証しました。DNSSECを使う場合は、子ゾーンのDNSKEY/RRSIGを整えて親にDSを登録してください。', '未署名運用が意図したものか、ドメイン管理者に確認してください。'] };
    }
    if (parent.dsAbsenceProof && parent.dsAbsenceProof.invalid && parent.dsAbsenceProof.signaturesVerified) {
        return { status: 'bogus', statusLabel: 'Bogus（DS不在証明の不整合）', nextChecks: ['親ゾーンのNSEC3 Opt-Outのカバー範囲を確認してください。対象名のハッシュは範囲の終端（Next）には含まれません。', '親ゾーンのNSEC3を再生成・署名し、各権威サーバーへ反映してください。'] };
    }
    if (!parent.ds || parent.ds.length === 0) {
        return { status: 'indeterminate', statusLabel: '判定不能（DS不在を確認できません）', nextChecks: ['親側のNSEC/NSEC3不在証明とそのRRSIGが取得・検証できるか確認してください。', '親の権威サーバーへの疎通を確認して再試行してください。'] };
    }
    if (isValidationSuccessful(diagram)) {
        return { status: 'secure', statusLabel: 'Secure（検証成功）', nextChecks: ['追加確認は不要です。'] };
    }
    if (aRecordValidation && aRecordValidation.error) {
        return { status: 'indeterminate', statusLabel: '判定不能（検証データ不足）', nextChecks: ['権威サーバーへの疎通と応答を確認し、時間をおいて再試行してください。'] };
    }
    if (!child.dnskey || child.dnskey.length === 0) {
        return { status: 'indeterminate', statusLabel: '判定不能（子DNSKEY未取得）', nextChecks: ['子ゾーンの権威サーバーとDNSKEY応答を確認してください。'] };
    }
    if (checks.dsKeyMatch === false || (parent.rrsig && parent.rrsig.length === 0) || (parent.dnskey && parent.dnskey.length > 0 && parent.rrsig && parent.rrsig.some(signature => signature.verified === false)) || (checks.dnskeySignature === false && child.rrsig && child.rrsig.some(signature => signature.verified === false)) || (aRecordValidation && ((aRecordValidation.recordsFound && (aRecordValidation.signatures || []).some(signature => signature.trustChainVerified !== true)) || (!aRecordValidation.recordsFound && aRecordValidation.denialProof && aRecordValidation.denialProof.verified !== true)))) {
        return { status: 'bogus', statusLabel: 'Bogus（DNSSEC検証失敗）', nextChecks: ['親のDSと子のKSK/DNSKEYのKey Tag・アルゴリズム・Digestを照合してください。', 'DNSKEY RRsetおよび対象レコードのRRSIGの有効期間・署名鍵・不在証明を確認してください。', '鍵更新後であれば、親のDS更新と各権威サーバーへの反映状況を確認してください。'] };
    }
    return { status: 'indeterminate', statusLabel: '判定不能（検証情報不足）', nextChecks: ['親子の権威サーバーから必要なRRset・RRSIGを取得できるか確認して再試行してください。'] };
}
        
function verifyDSSignature(dsRecords, rrsig, dnskeyRecord, zoneName) {
    const expirationCheck = checkSignatureExpiration(rrsig);
    if (!expirationCheck.valid) {
        return { verified: false, reason: expirationCheck.reason };
    }

    const fullRdata = buildDnskeyFullRdata(dnskeyRecord.data);
    const calculatedKeyTag = calculateKeyTag(dnskeyRecord.data.algorithm, fullRdata);
    if (calculatedKeyTag !== rrsig.data.keyTag) {
        return {
            verified: false,
            reason: `DS RRSIG Key Tag不一致: DNSKEY [${calculatedKeyTag}] vs RRSIG [${rrsig.data.keyTag}]`
        };
    }

    if (dnskeyRecord.data.algorithm !== rrsig.data.algorithm) {
        return {
            verified: false,
            reason: `DS RRSIGアルゴリズム不一致: DNSKEY[${dnskeyRecord.data.algorithm}] vs RRSIG[${rrsig.data.algorithm}]`
        };
    }

    const signerNameBuf = encodeDomainNameCanonical(rrsig.data.signersName || zoneName);
    const rrsigRdataHeader = Buffer.alloc(18);
    rrsigRdataHeader.writeUInt16BE(dnsTypes.toType(rrsig.data.typeCovered), 0);
    rrsigRdataHeader.writeUInt8(rrsig.data.algorithm, 2);
    rrsigRdataHeader.writeUInt8(rrsig.data.labels, 3);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.expiration, 8);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.inception, 12);
    rrsigRdataHeader.writeUInt16BE(rrsig.data.keyTag, 16);

    const ownerNameBuf = encodeDomainNameCanonical(zoneName);
    const typeCoveredNum = dnsTypes.toType(rrsig.data.typeCovered);
    const rrWireBufs = (dsRecords || [])
        .map(record => {
            const rdata = buildDsRdata(record.data);
            const rrHeader = Buffer.alloc(10);
            rrHeader.writeUInt16BE(typeCoveredNum, 0);
            rrHeader.writeUInt16BE(1, 2);
            rrHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
            rrHeader.writeUInt16BE(rdata.length, 8);
            return Buffer.concat([ownerNameBuf, rrHeader, rdata]);
        })
        .sort(Buffer.compare);

    const messageBuffer = Buffer.concat([rrsigRdataHeader, signerNameBuf, ...rrWireBufs]);
    const signatureBuffer = rrsig.data.signature;
    if (!signatureBuffer) {
        return { verified: false, reason: `DS RRSIGから署名データを抽出できません` };
    }

    const publicKeyBuffer = getDnskeyRawKey(dnskeyRecord.data);
    if (!publicKeyBuffer) {
        return { verified: false, reason: `親DNSKEYから公開鍵を抽出できません` };
    }

    const algorithm = dnskeyRecord.data.algorithm;
    let signatureResult;

    if (algorithm === 5 || algorithm === 7 || algorithm === 8 || algorithm === 10) {
        signatureResult = verifyRSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 13 || algorithm === 14) {
        signatureResult = verifyECDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 15 || algorithm === 16) {
        signatureResult = verifyEdDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 18) {
        signatureResult = verifyMLDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else {
        return { verified: false, reason: `未対応の暗号アルゴリズム [${algorithm}]` };
    }

    return signatureResult;
}

// --- ヘルパー関数: アルゴリズムごとの特性を考慮した正確な Key Tag 計算 ---
function calculateKeyTag(algorithm, fullRdata) {
    // 1. アルゴリズム 1 (RSAMD5) の場合
    if (algorithm === 1) {
        if (fullRdata.length < 4) return 0;
        return fullRdata.readUInt16BE(fullRdata.length - 3);
    }

    // 2. RFC 4034 Appendix B. Key Tag Calculation (RSAMD5以外は全アルゴリズム共通・ビッグエンディアン)
    let ac = 0;
    for (let i = 0; i < fullRdata.length; i += 2) {
        let val = 0;
        if (i + 1 < fullRdata.length) {
            val = fullRdata.readUInt16BE(i);
        } else {
            val = fullRdata.readUInt8(i) << 8;
        }
        ac += val;
    }
    ac = (ac + (ac >> 16)) & 0xFFFF;
    return ac;
}

// --- メインの検証関数 (RSASHA256完全対応版) ---
function verifyDnskeyWithDs(domain, dnskeyData, dsRecord) {
    const dnskeyAlgos = {
        1: 'RSAMD5 (非推奨)', 5: 'RSASHA1 (非推奨)', 7: 'RSASHA1-NSEC3-SHA1 (非推奨)',
        8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384',
        15: 'ED25519', 16: 'ED448', 18: 'ML-DSA-44'
    };
    const dsDigestTypes = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

    const keyAlgoName = dnskeyAlgos[dnskeyData.algorithm] || `Unknown (${dnskeyData.algorithm})`;
    const dsDigestName = dsDigestTypes[dsRecord.digestType] || `Unknown (${dsRecord.digestType})`;

    let algoName = '';
    switch (dsRecord.digestType) {
        case 1: algoName = 'sha1'; break;
        case 2: algoName = 'sha256'; break;
        case 4: algoName = 'sha384'; break;
        default:
            return { match: false, keyTag: null, reason: `未対応のDigest Type [${dsRecord.digestType}]` };
    }

    // 1. ドメイン名をワイヤーフォーマットに変換
    const nameBuf = encodeDomainNameCanonical(domain);

    // 2. DNSKEY データバッファの取得
    const rawKeyBuf = getDnskeyRawKey(dnskeyData);
    if (!rawKeyBuf) {
        return { match: false, keyTag: null, reason: `DNSKEY のデータが取得できません。` };
    }

    // 3. 正確に復元された RDATA で Key Tag を計算 (RFC 4034)
    const fullRdata = buildDnskeyFullRdata(dnskeyData);
    const ac = calculateKeyTag(dnskeyData.algorithm, fullRdata);

    // 4. ハッシュの計算 (Name + RDATA)
    const calculatedDigest = crypto.createHash(algoName).update(nameBuf).update(fullRdata).digest('hex').toLowerCase();
    const targetDigest = dsRecord.digest.toString('hex').toLowerCase();

    // 5. 突合チェック
    if (ac === dsRecord.keyTag) {
        if (calculatedDigest === targetDigest) {
            let warnings = [];
            if ((dnskeyData.algorithm === 13 || dnskeyData.algorithm === 15) && dsRecord.digestType === 1) {
                warnings.push(`子の鍵は強力な ${keyAlgoName} ですが、親のDSハッシュが古い ${dsDigestName} です。`);
            }
            return { 
                match: true,
                keyTag: ac,
                reason: warnings.length > 0 ? `${warnings.join('\n')}` : '' };
        } else {
            return {
                match: false,
                keyTag: ac,
                reason: `Key Tag[${ac}]は一致しますが、Digestが異なります。\n子の計算ハッシュ値: ${calculatedDigest}\n親の想定ハッシュ値: ${targetDigest}` };
        }
    }

    return { 
        match: false,
        keyTag: ac,
        reason: ''
    };
}

function verifyRecordRrsig(records, rrsig, dnskeyRecord, domain) {
    const expirationCheck = checkSignatureExpiration(rrsig);
    if (!expirationCheck.valid) {
        return { verified: false, reason: expirationCheck.reason };
    }
    const keyTag = calculateKeyTag(dnskeyRecord.data.algorithm, buildDnskeyFullRdata(dnskeyRecord.data));
    if (keyTag !== rrsig.data.keyTag || dnskeyRecord.data.algorithm !== rrsig.data.algorithm) {
        return { verified: false, reason: '' };
    }

    const rrsigHeader = Buffer.alloc(18);
    const recordType = rrsig.data.typeCovered;
    rrsigHeader.writeUInt16BE(dnsTypes.toType(recordType), 0);
    rrsigHeader.writeUInt8(rrsig.data.algorithm, 2);
    rrsigHeader.writeUInt8(rrsig.data.labels, 3);
    rrsigHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
    rrsigHeader.writeUInt32BE(rrsig.data.expiration, 8);
    rrsigHeader.writeUInt32BE(rrsig.data.inception, 12);
    rrsigHeader.writeUInt16BE(rrsig.data.keyTag, 16);
    const ownerName = encodeDomainNameCanonical(domain);
    const rdataList = records.map(record => dnsPacket.record(recordType).encode(record.data).subarray(2)).sort(Buffer.compare);
    const rrWireRecords = rdataList.map(rdata => {
        const header = Buffer.alloc(10);
        header.writeUInt16BE(dnsTypes.toType(recordType), 0);
        header.writeUInt16BE(1, 2);
        header.writeUInt32BE(rrsig.data.originalTTL, 4);
        header.writeUInt16BE(rdata.length, 8);
        return Buffer.concat([ownerName, header, rdata]);
    });
    const message = Buffer.concat([rrsigHeader, encodeDomainNameCanonical(rrsig.data.signersName || domain), ...rrWireRecords]);
    const signature = rrsig.data.signature;
    const publicKey = getDnskeyRawKey(dnskeyRecord.data);
    if (!signature || !publicKey) {
        return { verified: false, reason: `${recordType}レコード署名の検証データを取得できません` };
    }
    if ([5, 7, 8, 10].includes(dnskeyRecord.data.algorithm)) {
        return verifyRSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    if ([13, 14].includes(dnskeyRecord.data.algorithm)) {
        return verifyECDSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    if ([15, 16].includes(dnskeyRecord.data.algorithm)) {
        return verifyEdDSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    if (dnskeyRecord.data.algorithm === 18) {
        return verifyMLDSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    return { verified: false, reason: `未対応の暗号アルゴリズム [${dnskeyRecord.data.algorithm}]` };
}

function verifyARecordRrsig(aRecords, rrsig, dnskeyRecord, domain) {
    return verifyRecordRrsig(aRecords, rrsig, dnskeyRecord, domain);
}

function isZoneSigningKey(flags) {
    return (flags & 0x0100) !== 0;
}

function verifyDenialRecordRrsig(record, rrsig, dnskeyRecord) {
    const expirationCheck = checkSignatureExpiration(rrsig);
    if (!expirationCheck.valid) {
        return { verified: false, reason: expirationCheck.reason };
    }
    const keyTag = calculateKeyTag(dnskeyRecord.data.algorithm, buildDnskeyFullRdata(dnskeyRecord.data));
    if (keyTag !== rrsig.data.keyTag || dnskeyRecord.data.algorithm !== rrsig.data.algorithm) {
        return { verified: false, reason: '' };
    }

    const typeCovered = rrsig.data.typeCovered;
    const rrsigHeader = Buffer.alloc(18);
    rrsigHeader.writeUInt16BE(dnsTypes.toType(typeCovered), 0);
    rrsigHeader.writeUInt8(rrsig.data.algorithm, 2);
    rrsigHeader.writeUInt8(rrsig.data.labels, 3);
    rrsigHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
    rrsigHeader.writeUInt32BE(rrsig.data.expiration, 8);
    rrsigHeader.writeUInt32BE(rrsig.data.inception, 12);
    rrsigHeader.writeUInt16BE(rrsig.data.keyTag, 16);
    const rdata = dnsPacket.record(typeCovered).encode(record.data).subarray(2);
    const recordHeader = Buffer.alloc(10);
    recordHeader.writeUInt16BE(dnsTypes.toType(typeCovered), 0);
    recordHeader.writeUInt16BE(1, 2);
    recordHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
    recordHeader.writeUInt16BE(rdata.length, 8);
    const message = Buffer.concat([rrsigHeader, encodeDomainNameCanonical(rrsig.data.signersName || record.name), encodeDomainNameCanonical(record.name), recordHeader, rdata]);
    const signature = rrsig.data.signature;
    const publicKey = getDnskeyRawKey(dnskeyRecord.data);
    if (!signature || !publicKey) {
        return { verified: false, reason: '不在証明の署名データを取得できません' };
    }
    if ([5, 7, 8, 10].includes(dnskeyRecord.data.algorithm)) {
        return verifyRSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    if ([13, 14].includes(dnskeyRecord.data.algorithm)) {
        return verifyECDSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    if ([15, 16].includes(dnskeyRecord.data.algorithm)) {
        return verifyEdDSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    if (dnskeyRecord.data.algorithm === 18) {
        return verifyMLDSASignature(publicKey, signature, message, dnskeyRecord.data.algorithm);
    }
    return { verified: false, reason: `未対応の暗号アルゴリズム [${dnskeyRecord.data.algorithm}]` };
}

function normalizeDnsName(name) {
    return (name || '').toLowerCase().replace(/\.$/, '');
}

function compareDnsNames(left, right) {
    const leftLabels = normalizeDnsName(left).split('.').reverse();
    const rightLabels = normalizeDnsName(right).split('.').reverse();
    for (let index = 0; index < Math.min(leftLabels.length, rightLabels.length); index++) {
        if (leftLabels[index] < rightLabels[index]) return -1;
        if (leftLabels[index] > rightLabels[index]) return 1;
    }
    return leftLabels.length - rightLabels.length;
}

function valueIsCovered(target, start, end) {
    if (start < end) return target > start && target < end;
    if (start > end) return target > start || target < end;
    return target !== start;
}

function dnsNameIsCovered(target, start, end) {
    const startToEnd = compareDnsNames(start, end);
    const targetToStart = compareDnsNames(target, start);
    const targetToEnd = compareDnsNames(target, end);
    if (startToEnd < 0) return targetToStart > 0 && targetToEnd < 0;
    if (startToEnd > 0) return targetToStart > 0 || targetToEnd < 0;
    return targetToStart !== 0;
}

function nsec3Hash(domain, salt, iterations) {
    let hash = crypto.createHash('sha1').update(encodeDomainNameCanonical(domain)).update(salt).digest();
    for (let index = 0; index < iterations; index++) {
        hash = crypto.createHash('sha1').update(hash).update(salt).digest();
    }
    return hash;
}

function toBase32Hex(buffer) {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    let bits = 0;
    let value = 0;
    let result = '';
    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            result += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    return bits > 0 ? result + alphabet[(value << (5 - bits)) & 31] : result;
}

function analyzeRecordNodataProof(domain, recordType, denialRecords) {
    const diagnostics = [];
    const normalizedDomain = normalizeDnsName(domain);
    for (const record of denialRecords) {
        const isMatchingNsec = record.type === 'NSEC' && normalizeDnsName(record.name) === normalizedDomain;
        const isMatchingNsec3 = record.type === 'NSEC3' && record.data.algorithm === 1 && record.name.split('.')[0].toUpperCase() === toBase32Hex(nsec3Hash(domain, record.data.salt, record.data.iterations));
        if (!isMatchingNsec && !isMatchingNsec3) continue;

        if (!record.data.rrtypes.includes(recordType)) {
            return { record, diagnostics };
        }
            diagnostics.push(`${record.type}のtype bitmapに${recordType}が含まれるため、${domain}の${recordType}レコード不在を証明できません`);
    }
    return { record: null, diagnostics };
}

function analyzeARecordNodataProof(domain, denialRecords) {
    return analyzeRecordNodataProof(domain, 'A', denialRecords);
}

function analyzeDsAbsenceProof(domain, denialRecords, rcode = 'NOERROR') {
    const diagnostics = [];
    const normalizedDomain = normalizeDnsName(domain);
    const records = denialRecords || [];
    const observedNsec = records.filter(record => record.type === 'NSEC').map(record => ({ name: record.name, nextDomain: record.data.nextDomain }));
    const observedNsec3 = records.filter(record => record.type === 'NSEC3').map(record => ({
        ownerHash: record.name.split('.')[0].toUpperCase(),
        nextHash: toBase32Hex(record.data.nextDomain),
        flags: record.data.flags,
        iterations: record.data.iterations,
        salt: record.data.salt.toString('hex').toUpperCase() || '-'
    }));
    if (rcode !== 'NOERROR') {
        return { records: [], type: '', diagnostics: [`DS問い合わせの応答コードがNOERRORではありません: ${rcode}`], observedNsec, observedNsec3 };
    }

    const matchingNsec = records.find(record => record.type === 'NSEC' && normalizeDnsName(record.name) === normalizedDomain);
    if (matchingNsec) {
        if (matchingNsec.data.rrtypes.includes('NS') && !matchingNsec.data.rrtypes.includes('DS')) {
            return { records: [matchingNsec], type: 'NSEC', diagnostics, observedNsec, observedNsec3 };
        }
        diagnostics.push('委任点のNSECにNSがないか、DSが含まれているためDS不在を証明できません');
    }

    const matchingNsec3 = records.find(record => {
        if (record.type !== 'NSEC3' || record.data.algorithm !== 1) return false;
        const parentZone = normalizeDnsName(record.name).split('.').slice(1).join('.');
        return normalizedDomain.endsWith(`.${parentZone}`) && record.name.split('.')[0].toUpperCase() === toBase32Hex(nsec3Hash(domain, record.data.salt, record.data.iterations));
    });
    if (matchingNsec3) {
        if (matchingNsec3.data.rrtypes.includes('NS') && !matchingNsec3.data.rrtypes.includes('DS')) {
            return { records: [matchingNsec3], type: 'NSEC3', diagnostics, observedNsec, observedNsec3 };
        }
        diagnostics.push('委任点のNSEC3にNSがないか、DSが含まれているためDS不在を証明できません');
    }

    const nsec3OptOut = records.find(record => {
        if (record.type !== 'NSEC3' || record.data.algorithm !== 1 || (record.data.flags & 1) === 0) return false;
        const ownerLabels = normalizeDnsName(record.name).split('.');
        const parentZone = ownerLabels.slice(1).join('.');
        if (!normalizedDomain.endsWith(`.${parentZone}`)) return false;
        const targetHash = toBase32Hex(nsec3Hash(domain, record.data.salt, record.data.iterations));
        return valueIsCovered(targetHash, ownerLabels[0].toUpperCase(), toBase32Hex(record.data.nextDomain));
    });
    if (nsec3OptOut) {
        return { records: [nsec3OptOut], type: 'NSEC3', diagnostics: ['NSEC3 Opt-Outによる未署名委任の不在証明'], observedNsec, observedNsec3 };
    }

    const boundaryMismatch = records.find(record => {
        if (record.type !== 'NSEC3' || record.data.algorithm !== 1 || (record.data.flags & 1) === 0) return false;
        const parentZone = normalizeDnsName(record.name).split('.').slice(1).join('.');
        return normalizedDomain.endsWith(`.${parentZone}`) &&
            toBase32Hex(nsec3Hash(domain, record.data.salt, record.data.iterations)) === toBase32Hex(record.data.nextDomain);
    });
    if (boundaryMismatch) {
        return {
            records: [boundaryMismatch], type: 'NSEC3', invalid: true,
            diagnostics: [`NSEC3 Opt-Outのカバー範囲が不整合です: ${domain} のハッシュ ${toBase32Hex(boundaryMismatch.data.nextDomain)} は Next と一致しますが、範囲の終端はカバー対象に含まれません。`],
            observedNsec, observedNsec3
        };
    }

    if (records.length === 0) diagnostics.push('親サーバーの応答にNSEC/NSEC3不在証明がありません');
    else if (diagnostics.length === 0) diagnostics.push('委任点のDS不在を示すNSEC/NSEC3がありません');
    return { records: [], type: '', diagnostics, observedNsec, observedNsec3 };
}

function findARecordNodataProof(domain, denialRecords) {
    return analyzeARecordNodataProof(domain, denialRecords).record;
}

function findNxDomainProof(domain, denialRecords) {
    const nsecRecords = denialRecords.filter(record => record.type === 'NSEC');
    const labels = normalizeDnsName(domain).split('.');
    const closestEncloserCandidates = labels.slice(1).map((label, index) => labels.slice(index + 1).join('.'));
    const observedNsec = nsecRecords.map(record => ({ name: record.name, nextDomain: record.data.nextDomain }));
    const coversName = (record, name) => {
        const isSelfLoop = normalizeDnsName(record.name) === normalizeDnsName(record.data.nextDomain);
        const hasOtherNsecOwner = nsecRecords.some(candidate => normalizeDnsName(candidate.name) !== normalizeDnsName(record.name));
        return !(isSelfLoop && hasOtherNsecOwner) && dnsNameIsCovered(name, record.name, record.data.nextDomain);
    };
    for (const closestEncloser of closestEncloserCandidates) {
        const closestEncloserRecord = nsecRecords.find(record => normalizeDnsName(record.name) === closestEncloser);
        if (!closestEncloserRecord) {
            continue;
        }
        const nextCloser = `${labels[closestEncloserCandidates.indexOf(closestEncloser)]}.${closestEncloser}`;
        const wildcard = `*.${closestEncloser}`;
        const nextCloserRecord = nsecRecords.find(record => coversName(record, nextCloser));
        const wildcardRecord = nsecRecords.find(record => coversName(record, wildcard));
        if (nextCloserRecord && wildcardRecord) {
            return { records: [closestEncloserRecord, nextCloserRecord, wildcardRecord], diagnostics: [], observedNsec };
        }
        const missing = [];
        if (!nextCloserRecord) {
            missing.push(`next closer (${nextCloser}) をカバーする NSEC`);
        }
        if (!wildcardRecord) {
            missing.push(`ワイルドカード (${wildcard}) をカバーする NSEC`);
        }
        return { records: [], diagnostics: [`closest encloser: ${closestEncloser}`, `不足: ${missing.join('、')}`], observedNsec };
    }
    if (nsecRecords.length > 0) {
        return { records: [], diagnostics: [`closest encloser の存在を示す NSEC がありません: ${closestEncloserCandidates.join(', ')}`], observedNsec };
    }

    const nsec3Records = denialRecords.filter(record => record.type === 'NSEC3' && record.data.algorithm === 1);
    const observedNsec3 = nsec3Records.map(record => ({
        ownerHash: record.name.split('.')[0].toUpperCase(),
        nextHash: toBase32Hex(record.data.nextDomain),
        iterations: record.data.iterations,
        salt: record.data.salt.toString('hex').toUpperCase() || '-'
    }));
    if (nsec3Records.length === 0) {
        return { records: [], diagnostics: ['権威サーバーの応答に NSEC/NSEC3 レコードがありません'], observedNsec3 };
    }

    const hasOtherNsec3Owner = record => nsec3Records.some(candidate => normalizeDnsName(candidate.name) !== normalizeDnsName(record.name));

    for (let closestEncloserIndex = 1; closestEncloserIndex < labels.length; closestEncloserIndex++) {
        const closestEncloser = labels.slice(closestEncloserIndex).join('.');
        const nextCloser = labels.slice(closestEncloserIndex - 1).join('.');
        const wildcard = `*.${closestEncloser}`;
        for (const closestEncloserRecord of nsec3Records) {
            const { salt, iterations } = closestEncloserRecord.data;
            const closestEncloserHash = toBase32Hex(nsec3Hash(closestEncloser, salt, iterations));
            if (closestEncloserRecord.name.split('.')[0].toUpperCase() !== closestEncloserHash) {
                continue;
            }

            const coversName = (record, name) => {
                const ownerHash = record.name.split('.')[0].toUpperCase();
                const nextHash = toBase32Hex(record.data.nextDomain);
                const nameHash = toBase32Hex(nsec3Hash(name, salt, iterations));
                const isSelfLoop = ownerHash === nextHash;
                return !(isSelfLoop && hasOtherNsec3Owner(record)) && valueIsCovered(nameHash, ownerHash, nextHash);
            };
            const nextCloserRecord = nsec3Records.find(record => record.data.iterations === iterations && Buffer.compare(record.data.salt, salt) === 0 && coversName(record, nextCloser));
            const wildcardRecord = nsec3Records.find(record => record.data.iterations === iterations && Buffer.compare(record.data.salt, salt) === 0 && coversName(record, wildcard));
            if (nextCloserRecord && wildcardRecord) {
                return { records: [closestEncloserRecord, nextCloserRecord, wildcardRecord], diagnostics: [], observedNsec3 };
            }
            const missing = [];
            if (!nextCloserRecord) missing.push(`next closer (${nextCloser}) をカバーする NSEC3`);
            if (!wildcardRecord) missing.push(`ワイルドカード (${wildcard}) をカバーする NSEC3`);
            return { records: [], diagnostics: [`closest encloser: ${closestEncloser}`, `不足: ${missing.join('、')}`], observedNsec3 };
        }
    }
    return { records: [], diagnostics: [`closest encloser の存在を示す NSEC3 がありません: ${closestEncloserCandidates.join(', ')}`], observedNsec3 };
}

// --- メイン検証 API (入力バリデーション・レート制限強化版) ---
app.post('/api/validate', async (req, res) => {
    let { domain, recordType = 'A' } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    
    // 入力バリデーション
    const validation = validateDomainName(domain);
    if (!validation.valid) {
        return res.status(400).json({ error: validation.error });
    }
    recordType = typeof recordType === 'string' ? recordType.toUpperCase() : '';
    if (!VALIDATION_RECORD_TYPES.includes(recordType)) {
        return res.status(400).json({ error: `対応していないレコード種別です: ${recordType || '未指定'}` });
    }
    
    // レート制限チェック
    const rateLimit = checkRateLimit(clientIp);
    if (!rateLimit.allowed) {
        res.set('Retry-After', String(rateLimit.waitSeconds));
        return res.status(429).json({ 
            error: `リクエスト制限に達しました。${rateLimit.waitSeconds}秒後に再度お試しください。` 
        });
    }

    // ドメイン名を正規化
    domain = normalizeDomainName(domain);

    const validationDependencies = req.app.locals.dnssecValidationDependencies || {};
    const discoverZoneApex = validationDependencies.getZoneApex || getZoneApex;
    const resolveNameserverAddress = validationDependencies.getARecord || getARecord;
    const fetchResourceRecord = validationDependencies.getResourceRecord || getResourceRecord;
    const compareAuthorityRecords = validationDependencies.compareAuthorityRecordSets || compareAuthorityRecordSets;
    const diagnoseDsProposal = validationDependencies.diagnoseDsProposals || diagnoseDsProposals;
    
    let logs = [];
    let success = false;
    const diagram = {
        parent: { name: domain, server: '', ds: [], rrsig: [], dnskey: [], dsAbsenceProof: null },
        child: { name: domain, server: '', dnskey: [], rrsig: [], aRecordValidation: null },
        checks: { dsSignature: false, dnskeySignature: false, dsKeyMatch: false },
        authorityChecks: null,
        dsProposal: null
    };

    // 大きな鍵長(ML-DSA等)でDNSのTCPフォールバックが多発すると処理が長引くため、
    // 必ず期限内に(HTMLエラーページではなく)JSONで応答できるようにガードする
    const addClassification = (payload, timedOut = false) => ({ ...payload, ...classifyValidationResult(diagram, timedOut) });
    const sendJsonRaw = createTimeoutGuardedResponder(res, API_VALIDATE_TIMEOUT_MS, () => addClassification(
        { success: false, timedOut: true, logs: [...logs, `検証処理が制限時間 (${API_VALIDATE_TIMEOUT_MS / 1000}秒) を超えたため中断しました。`], diagram },
        true
    ));
    const sendJson = (statusCode, payload) => sendJsonRaw(statusCode, addClassification(payload));

    try {
        // 1. ドメイン名からゾーン頂点を取得
        const zoneApexInfo = await discoverZoneApex(domain);
        if (zoneApexInfo.zoneApex === '') {
            if (zoneApexInfo.hasCnameOrDname) {
                return sendJson(200, { success: false, logs: [...logs, 'このドメイン名は CNAME/DNAME のためゾーン頂点を特定できませんでした。'], diagram });
            } else {
                return sendJson(200, { success: false, logs: [...logs, `${zoneApexInfo.currentNs} から先の探索ができませんでした。(rcode: ${zoneApexInfo.rcode})`], diagram });
            }
        }
        if (zoneApexInfo.discoveryError) {
            logs.push(zoneApexInfo.discoveryError, `委任点 [${zoneApexInfo.zoneApex}] を対象に、親側のDSと不在証明の検証を続行します。`);
        }
        diagram.parent.name = zoneApexInfo.zoneApex;
        diagram.parent.server = zoneApexInfo.parentNameservers.join(', ') || zoneApexInfo.parentNs || zoneApexInfo.currentNs;
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.childNameservers.join(', ') || zoneApexInfo.currentNs;
        const parentAuthorityNames = zoneApexInfo.parentNameservers.length > 0
            ? zoneApexInfo.parentNameservers
            : zoneApexInfo.parentNs ? [zoneApexInfo.parentNs] : [];
        const childAuthorityNames = zoneApexInfo.discoveryError ? [] : zoneApexInfo.childNameservers.length > 0
            ? zoneApexInfo.childNameservers
            : [zoneApexInfo.currentNs];
        const comparisonOptions = { dnsResponseCache: dnssecResponseCache };
        const [parentNsComparison, parentDsComparison, childNsComparison, childDnskeyComparison] = await Promise.all([
            compareAuthorityRecords(zoneApexInfo.zoneApex, parentAuthorityNames, 'NS', comparisonOptions),
            compareAuthorityRecords(zoneApexInfo.zoneApex, parentAuthorityNames, 'DS', comparisonOptions),
            compareAuthorityRecords(zoneApexInfo.zoneApex, childAuthorityNames, 'NS', comparisonOptions),
            compareAuthorityRecords(zoneApexInfo.zoneApex, childAuthorityNames, 'DNSKEY', comparisonOptions)
        ]);
        diagram.authorityChecks = {
            parent: { nameservers: parentNsComparison, ds: parentDsComparison },
            child: { nameservers: childNsComparison, dnskey: childDnskeyComparison }
        };
        let tempLog = '';
        if (zoneApexInfo.parentNs !== '') {
            tempLog += `${zoneApexInfo.parentNs} または `;
        }

        // 2. 親サーバーからDSレコードを取得
        let targetNs = zoneApexInfo.parentNs;
        let parentIp = '';
        let dsInfo = null;
        let parentDsInfo = null;
        let parentDsIp = '';
        diagram.parent.server = zoneApexInfo.parentNameservers.join(', ') || targetNs || zoneApexInfo.currentNs;
        
        try {
            if (targetNs) {
                parentIp = await resolveNameserverAddress(targetNs);
                dsInfo = await fetchResourceRecord(zoneApexInfo.zoneApex, parentIp, 'DS');
                parentDsInfo = dsInfo;
                parentDsIp = parentIp;
            }
        } catch (err) {
            logs.push(`親サーバー [${targetNs}] へのクエリ失敗: ${err.message}`);
            parentIp = '';
        }

        let childIp = '';
        if (zoneApexInfo.discoveryError) {
            diagram.dsProposal = { parentDs: [], cds: null, cdnskey: null, notes: ['委任先の権威 SOA を取得できないため、子ゾーンの提案の取得は省略しました。'] };
        } else if (parentDsInfo) {
            try {
                childIp = await resolveNameserverAddress(zoneApexInfo.currentNs);
                diagram.dsProposal = await diagnoseDsProposal(zoneApexInfo.zoneApex, parentDsInfo, childIp);
            } catch (err) {
                diagram.dsProposal = { parentDs: [], cds: null, cdnskey: null, notes: [`子ゾーンの提案を取得できませんでした: ${err.message}`] };
            }
        } else {
            diagram.dsProposal = { parentDs: [], cds: null, cdnskey: null, notes: ['親側DSを取得できないため、提案との差分は判定できません。'] };
        }
        
        if (!dsInfo || dsInfo.resourceRecords.length === 0) {
            try {
                if (!zoneApexInfo.discoveryError) {
                    targetNs = zoneApexInfo.currentNs;
                    diagram.parent.server = zoneApexInfo.parentNameservers.join(', ') || targetNs;
                    parentIp = await resolveNameserverAddress(targetNs);
                    dsInfo = await fetchResourceRecord(zoneApexInfo.zoneApex, parentIp, 'DS');
                }
            } catch (err) {
                logs.push(`現在のサーバー [${targetNs}] へのクエリ失敗: ${err.message}`);
                parentIp = '';
            }
            
            if (!dsInfo || dsInfo.resourceRecords.length === 0) {
                const proofResult = analyzeDsAbsenceProof(zoneApexInfo.zoneApex, parentDsInfo && parentDsInfo.denialRecords, parentDsInfo && parentDsInfo.rcode);
                const denialProof = {
                    rcode: parentDsInfo && parentDsInfo.rcode || '',
                    type: proofResult.type,
                    invalid: Boolean(proofResult.invalid),
                    signaturesVerified: false,
                    verified: false,
                    diagnostics: [...proofResult.diagnostics],
                    observedNsec: proofResult.observedNsec,
                    observedNsec3: proofResult.observedNsec3,
                    records: proofResult.records.map(record => {
                        const signature = (parentDsInfo.denialRrsigRecords || []).find(candidate => candidate.data.typeCovered === record.type && normalizeDnsName(candidate.name) === normalizeDnsName(record.name));
                        return { name: record.name, type: record.type, expiration: signature && signature.data.expiration };
                    })
                };
                if (proofResult.records.length > 0 && parentDsIp) {
                    const recordResults = [];
                    for (const record of proofResult.records) {
                        const signatures = (parentDsInfo.denialRrsigRecords || []).filter(signature => signature.data.typeCovered === record.type && normalizeDnsName(signature.name) === normalizeDnsName(record.name));
                        let verified = false;
                        for (const signature of signatures) {
                            const signerName = signature.data.signersName || zoneApexInfo.zoneApex;
                            const normalizedSignerName = normalizeDnsName(signerName);
                            const isParentSigner = normalizedSignerName === '' || (normalizedSignerName !== normalizeDnsName(zoneApexInfo.zoneApex) && normalizeDnsName(zoneApexInfo.zoneApex).endsWith(`.${normalizedSignerName}`));
                            if (!isParentSigner) {
                                denialProof.diagnostics.push(`不在証明の署名者が親ゾーンではありません: ${signerName}`);
                                continue;
                            }
                            try {
                                const parentDnskeyInfo = await fetchResourceRecord(signerName, parentDsIp, 'DNSKEY');
                                const parentDnskeyRecords = parentDnskeyInfo.resourceRecords || [];
                                diagram.parent.dnskey = parentDnskeyRecords.map(key => ({
                                    keyTag: calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data)),
                                    flags: key.data.flags,
                                    algorithm: key.data.algorithm
                                }));
                                verified = parentDnskeyRecords.some(key => verifyDenialRecordRrsig(record, signature, key).verified);
                                if (verified) break;
                            } catch (err) {
                                denialProof.diagnostics.push(`親DNSKEYの取得に失敗 [${signerName}]: ${err.message}`);
                            }
                        }
                        recordResults.push(verified);
                        if (!verified) denialProof.diagnostics.push(`対応する有効な${record.type} RRSIGを検証できませんでした: ${record.name}`);
                    }
                    denialProof.signaturesVerified = recordResults.length > 0 && recordResults.every(Boolean);
                    denialProof.verified = !denialProof.invalid && denialProof.signaturesVerified;
                }
                diagram.parent.dsAbsenceProof = denialProof;
                const absenceMessage = denialProof.verified
                    ? '親側のNSEC/NSEC3不在証明を検証しました。DNSSEC未署名の委任です。'
                    : denialProof.invalid && denialProof.signaturesVerified
                        ? '親側のNSEC3署名は有効ですが、Opt-Outのカバー範囲が不整合なためDS不在証明は成立しません。'
                    : '親サーバーにDSレコードが見つかりませんが、不在証明を検証できないため未署名委任とは判定できません。';
                return sendJson(200, { success: false, logs: [...logs, absenceMessage, ...denialProof.diagnostics], diagram });
            }
        }
        
        if (!parentIp) {
            return sendJson(200, { success: false, logs: [...logs, '親サーバーの IP アドレス取得に失敗しました。'], diagram });
        }
        
        const dsRecords = dsInfo.resourceRecords;
        diagram.parent.name = zoneApexInfo.zoneApex;
        diagram.parent.server = zoneApexInfo.parentNameservers.join(', ') || targetNs;
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.childNameservers.join(', ') || zoneApexInfo.currentNs;
        diagram.parent.ds = dsRecords.map(ds => ({
            keyTag: ds.data.keyTag,
            algorithm: ds.data.algorithm,
            digestType: ds.data.digestType,
            digest: ds.data.digest.toString('hex')
        }));
        const rrsigRecords = dsInfo.rrsigRecords;
        diagram.parent.rrsig = rrsigRecords.map(rrsig => ({
            keyTag: rrsig.data.keyTag,
            typeCovered: rrsig.data.typeCovered,
            algorithm: rrsig.data.algorithm,
            expiration: rrsig.data.expiration,
            verified: null
        }));
        if (rrsigRecords.length === 0) {
            logs.push(`親サーバーにDSレコードに対する署名(RRSIGレコード)が見つかりません。`);
        } else {
            let dsSignatureVerified = false;
            let verifiedKeyTag = new Array();
            for (let rrsigIndex = 0; rrsigIndex < rrsigRecords.length; rrsigIndex++) {
                const rrsig = rrsigRecords[rrsigIndex];
                const signerName = rrsig.data.signersName || zoneApexInfo.zoneApex;
                let rrsigVerified = false;
                try {
                    const parentDnskeyInfo = await fetchResourceRecord(signerName, parentIp, 'DNSKEY');
                    const parentDnskeyRecords = parentDnskeyInfo.resourceRecords || [];
                    diagram.parent.dnskey = parentDnskeyRecords.map(key => ({
                        keyTag: calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data)),
                        flags: key.data.flags,
                        algorithm: key.data.algorithm
                    }));
                    for (const key of parentDnskeyRecords) {
                        const keyTag = calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data));
                        if (key.data.algorithm === rrsig.data.algorithm && keyTag === rrsig.data.keyTag) {
                            const signatureResult = verifyDSSignature(dsRecords, rrsig, key, zoneApexInfo.zoneApex);
                            rrsigVerified = signatureResult.verified;
                            if (signatureResult.verified) {
                                dsSignatureVerified = true;
                                diagram.checks.dsSignature = true;
                                verifiedKeyTag.push(keyTag);
                            } else {
                                if (signatureResult.reason && signatureResult.reason !== '') {
                                    logs.push(signatureResult.reason);
                                }
                            }
                        }
                    }
                    diagram.parent.rrsig[rrsigIndex].verified = rrsigVerified;
                } catch (err) {
                    diagram.parent.rrsig[rrsigIndex].verified = false;
                    logs.push(`DS RRSIG 検証用の親 DNSKEY 取得失敗 [${signerName}]: ${err.message}`);
                }
            }

            if (dsSignatureVerified !== true) {
                logs.push(`DSレコードに関する署名検証に失敗しました。`);
            }
        }

        // 3. 子ゾーンの権威サーバーを自動検出して DNSKEY を取得
        try {
            childIp = childIp || await resolveNameserverAddress(zoneApexInfo.currentNs);
        } catch (err) {
            return sendJson(200, { success: false, logs: [...logs, `子サーバー [${zoneApexInfo.currentNs}] の IP アドレス取得失敗: ${err.message}`], diagram });
        }
        
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.childNameservers.join(', ') || zoneApexInfo.currentNs;
        
        let dnskeyInfo = null;
        try {
            dnskeyInfo = await fetchResourceRecord(zoneApexInfo.zoneApex, childIp, 'DNSKEY');
        } catch (err) {
            return sendJson(200, { success: false, logs: [...logs, `子サーバーからDNSKEYレコード取得失敗: ${err.message}`], diagram });
        }
        
        const dnskeyRecords = dnskeyInfo.resourceRecords;
        if (dnskeyRecords.length === 0) {
            return sendJson(200, { success: false, logs: [...logs, '子サーバーにDNSKEYレコードが存在しません。'], diagram });
        }
        diagram.child.dnskey = dnskeyRecords.map(key => ({
            keyTag: calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data)),
            flags: key.data.flags,
            algorithm: key.data.algorithm
        }));
        
            // 3.5. DNSKEYレコード署名検証(オプション)
        const dnskeyRrsig = dnskeyInfo.rrsigRecords;
        diagram.child.rrsig = dnskeyRrsig.map(rrsig => ({
            keyTag: rrsig.data.keyTag,
            typeCovered: rrsig.data.typeCovered,
            algorithm: rrsig.data.algorithm,
            expiration: rrsig.data.expiration,
            verified: null
        }));
        if (dnskeyRrsig.length > 0) {
            // DNSKEYレコード署名を検証(自己署名KSKで検証)
            const kskRecords = dnskeyRecords.filter(r => r.data.flags === 257); // KSK のみ
            let signatureVerified = false;
            let verifiedKeyTag = new Array();
            for (let rrsigIndex = 0; rrsigIndex < dnskeyRrsig.length; rrsigIndex++) {
                const rrsig = dnskeyRrsig[rrsigIndex];
                let rrsigVerified = false;
                for (const ksk of kskRecords) {
                    // DNSKEYレコードからKey Tagを計算
                    const calculatedKeyTag = calculateKeyTag(ksk.data.algorithm, buildDnskeyFullRdata(ksk.data));
                    if (ksk.data.algorithm === rrsig.data.algorithm && calculatedKeyTag === rrsig.data.keyTag) {
                        const signatureResult = verifyRRSIGSignature(dnskeyRecords, rrsig, ksk, zoneApexInfo.zoneApex);
                        rrsigVerified = signatureResult.verified;
                        if (signatureResult.verified) {
                            signatureVerified = true;
                            diagram.checks.dnskeySignature = true;
                            verifiedKeyTag.push(calculatedKeyTag);
                        } else {
                            if (signatureResult.reason && signatureResult.reason !== '') {
                                logs.push(signatureResult.reason);
                            }
                        }
                    }
                }
                diagram.child.rrsig[rrsigIndex].verified = rrsigVerified;
            }
            
            if (signatureVerified !== true) {
                logs.push(`DNSKEYレコードに関する署名検証に失敗しました。`);
            } else {
                // 自己署名検証に使われたKSKが親ゾーンのDSレコードのKey Tagと一致するか確認
                const dsRecordKeyTags = dsRecords.map(ds => ds.data.keyTag);
                const unmatchedKskKeyTags = [...new Set(verifiedKeyTag)].filter(keyTag => !dsRecordKeyTags.includes(keyTag));
                if (unmatchedKskKeyTags.length > 0) {
                    logs.push(`DNSKEYレコードの署名検証に使用したKSK(Key Tag: ${unmatchedKskKeyTags.join(', ')})は、親ゾーンのDSレコードのKey Tagと一致しません。`);
                }
            }
        } else {
                    logs.push(`DNSKEYレコードに対する署名(RRSIG)が見つかりませんでした。`);
        }

        // 4. 信頼の連鎖を検証 (DS と DNSKEY の突合)
        const dsMatchedKskRecords = [];
        for (const ds of dsRecords) {
            for (const key of dnskeyRecords) {
                const result = verifyDnskeyWithDs(zoneApexInfo.zoneApex, key.data, ds.data);
                if (result.match) {
                    dsMatchedKskRecords.push(key);
                } else if (result.reason && result.reason !== '') {
                    logs.push(result.reason);
                }
            }
        }
        const matchFound = dsMatchedKskRecords.length > 0;
        diagram.checks.dsKeyMatch = matchFound;

        {
            const aRecordValidation = createRecordValidation(recordType);
            diagram.child.aRecordValidation = aRecordValidation;
            try {
                const dsMatchedKskKeyTags = dsMatchedKskRecords.map(key => calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data)));
                aRecordValidation.trustChain.dsMatchedKskKeyTags = [...new Set(dsMatchedKskKeyTags)];
                for (const rrsig of dnskeyRrsig) {
                    for (const ksk of dsMatchedKskRecords) {
                        const kskKeyTag = calculateKeyTag(ksk.data.algorithm, buildDnskeyFullRdata(ksk.data));
                        if (ksk.data.algorithm !== rrsig.data.algorithm || kskKeyTag !== rrsig.data.keyTag) continue;
                        if (verifyRRSIGSignature(dnskeyRecords, rrsig, ksk, zoneApexInfo.zoneApex).verified) {
                            aRecordValidation.trustChain.dnskeyRrsetSignatures.push({ kskKeyTag, algorithm: rrsig.data.algorithm });
                        }
                    }
                }
                const aInfo = await fetchResourceRecord(domain, childIp, recordType);
                aRecordValidation.recordsFound = aInfo.resourceRecords.length > 0;
                for (const rrsig of aInfo.rrsigRecords) {
                    let verified = false;
                    let zskKeyTag = null;
                    let reason = '';
                    for (const key of dnskeyRecords) {
                        const result = verifyRecordRrsig(aInfo.resourceRecords, rrsig, key, domain);
                        if (result.reason) reason = result.reason;
                        if (result.verified) {
                            verified = true;
                            zskKeyTag = calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data));
                            break;
                        }
                    }
                    const verifiedByZsk = dnskeyRecords.some(key => isZoneSigningKey(key.data.flags) && calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data)) === zskKeyTag);
                    const dnskeyRrsetVerifiedByKsk = aRecordValidation.trustChain.dnskeyRrsetSignatures.length > 0;
                    aRecordValidation.signatures.push({ keyTag: rrsig.data.keyTag, algorithm: rrsig.data.algorithm, expiration: rrsig.data.expiration, verified, reason, zskKeyTag, trustChainVerified: verified && verifiedByZsk && dnskeyRrsetVerifiedByKsk });
                }
                if (!aRecordValidation.recordsFound) {
                    const nxDomainProof = aInfo.rcode === 'NXDOMAIN' ? findNxDomainProof(domain, aInfo.denialRecords) : null;
                    const nodataProof = nxDomainProof ? null : analyzeRecordNodataProof(domain, recordType, aInfo.denialRecords);
                    const denialRecord = nodataProof ? nodataProof.record : null;
                    const denialRecords = nxDomainProof ? nxDomainProof.records : denialRecord ? [denialRecord] : [];
                    const denialProof = { rcode: aInfo.rcode, type: denialRecords.length > 0 ? denialRecords[0].type : '', verified: false };
                    if (nxDomainProof) {
                        denialProof.diagnostics = nxDomainProof.diagnostics;
                        denialProof.observedNsec = nxDomainProof.observedNsec;
                        denialProof.observedNsec3 = nxDomainProof.observedNsec3;
                    } else if (nodataProof) {
                        denialProof.diagnostics = nodataProof.diagnostics;
                    }
                    aRecordValidation.denialProof = denialProof;
                    if (denialRecords.length > 0) {
                        denialProof.records = denialRecords.map(record => {
                            const signature = aInfo.denialRrsigRecords.find(candidate => candidate.data.typeCovered === record.type && normalizeDnsName(candidate.name) === normalizeDnsName(record.name));
                            return { name: record.name, type: record.type, expiration: signature && signature.data.expiration };
                        });
                        denialProof.verified = denialRecords.every(record => {
                            const signature = aInfo.denialRrsigRecords.find(candidate => candidate.data.typeCovered === record.type && normalizeDnsName(candidate.name) === normalizeDnsName(record.name));
                            return signature && dnskeyRecords.some(key => verifyDenialRecordRrsig(record, signature, key).verified);
                        });
                    }
                }
            } catch (err) {
                aRecordValidation.error = err.message;
                logs.push(`${recordType}レコードのDNSSEC検証に失敗しました: ${err.message}`);
            }
        }

        success = isValidationSuccessful(diagram);
        if (!matchFound) {
            logs.push(`親ゾーンのDSレコードと子ゾーンのDNSKEYレコードの突合に失敗しました。DNSSECが正しく委任されていない可能性があります。`);
        } else if (!success && diagram.child.aRecordValidation && !diagram.child.aRecordValidation.error) {
            logs.push(`ドメイン名に対する${recordType}レコードの署名または不在証明の検証に失敗しました。`);
        }

        sendJson(200, { success, logs, diagram });

    } catch (err) {
        const errorMsg = `予期しないエラーが発生しました: ${err.message}`;
        logs.push(errorMsg);
        sendJson(500, { error: errorMsg, logs, diagram });
    }
});

// --- UI (HTML) を返却するエンドポイント ---
app.get('/dnssec-validator-client.js', (req, res) => {
    res.sendFile(__dirname + '/dnssec-validator-client.js');
});

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.use((error, req, res, next) => {
    if (error.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'JSONリクエストの形式が無効です' });
    }
    if (error.type === 'entity.too.large') {
        return res.status(413).json({ error: 'リクエスト本文が大きすぎます' });
    }
    console.error(error);
    res.status(500).json({ error: 'サーバー内部でエラーが発生しました' });
});

const PORT = 3002;

function isMainModule() {
    const entryPoint = process.argv[1];
    if (!entryPoint) return false;
    const modulePath = fileURLToPath(import.meta.url);
    try {
        return realpathSync(entryPoint) === realpathSync(modulePath);
    } catch {
        return path.resolve(entryPoint) === modulePath;
    }
}

if (isMainModule()) {
    const server = app.listen(PORT, '127.0.0.1', () => {
        console.log(`Webサーバーが起動しました: http://localhost:${PORT}`);
    });
    server.on('error', error => {
        console.error(`Webサーバーの起動に失敗しました: ${error.message}`);
        process.exitCode = 1;
    });
}

export {
    app,
    validateDomainName,
    normalizeDomainName,
    checkRateLimit,
    getZoneApex,
    getARecord,
    getResourceRecord,
    compareAuthorityRecordSets,
    diagnoseDsProposals,
    verifyDnskeyWithDs,
    verifyRecordRrsig,
    isZoneSigningKey,
    calculateKeyTag,
    buildDnskeyFullRdata,
    encodeDomainNameCanonical,
    checkSignatureExpiration,
    verifyMLDSASignature,
    createARecordValidation,
    isValidationSuccessful,
    classifyValidationResult,
    analyzeARecordNodataProof,
    analyzeRecordNodataProof,
    analyzeDsAbsenceProof,
    findARecordNodataProof,
    findNxDomainProof,
    nsec3Hash,
    toBase32Hex,
    createTimeoutGuardedResponder
};
