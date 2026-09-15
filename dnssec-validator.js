import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import dnsPacket from 'dns-packet';	// https://github.com/mafintosh/dns-packet
import dnsTypes from 'dns-packet/types.js';
import {
    ROOT_SERVER_BOOTSTRAP_IP,
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
const RATE_LIMIT_REQUESTS_PER_MINUTE = 30;
const rateLimitMap = new Map(); // IP: { count, resetTime }
const API_VALIDATE_TIMEOUT_MS = 25000; // ホスティング基盤側のゲートウェイタイムアウト(HTMLエラーページ化)より先に必ずJSONで応答するための上限

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
    if (now > record.resetTime) {
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

// --- ヘルパー関数: Aレコードを取得する ---
async function getARecord(domain, options = {}) {
    if (net.isIP(domain)) {
        return domain;
    }

    const resolveIPv4 = options.resolveHostnameIPv4Self || resolveHostnameIPv4Self;
    const ipAddress = await resolveIPv4(domain, { queryDirectlyUDP: options.queryDirectlyUDP });
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
    let rcode = '';
    let hasCnameOrDname = false;

    for (let i = 0; i < 10; i++) {
        const currentServerIp = net.isIP(currentNs) ? currentNs : await resolveIPv4(currentNs);
        if (!currentServerIp) {
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
                parentNameservers = childNameservers;
                childNameservers = nsRecords.map(record => record.data);
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
                    chosenNsRecord = nsRecords[0];
                }
                parentNs = currentNs;
                currentNs = chosenNsIp || chosenNsRecord.data;
            }
        }
    }

    return { currentNs: currentNs, parentNs: parentNs, parentNameservers, childNameservers, zoneApex: zoneApex, rcode: rcode, hasCnameOrDname: hasCnameOrDname };
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
    let buf = Buffer.alloc(0);
    for (const label of labels) {
        if (!label) continue;
        const lenBuf = Buffer.from([label.length]);
        const labelBuf = Buffer.from(label, 'ascii');
        buf = Buffer.concat([buf, lenBuf, labelBuf]);
    }
    return Buffer.concat([buf, Buffer.from([0x00])]);
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

function createARecordValidation() {
    return { queried: true, recordsFound: false, signatures: [], trustChain: { dsMatchedKskKeyTags: [], dnskeyRrsetSignatures: [] } };
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
    const hashInput = Buffer.concat([nameBuf, fullRdata]);
    const calculatedDigest = crypto.createHash(algoName).update(hashInput).digest('hex').toLowerCase();
    const targetDigest = dsRecord.digest.toString('hex').toLowerCase();

    // 5. 突合チェック
    const isKsk = dnskeyData.flags === 257 ? "KSK" : "ZSK";

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

function verifyARecordRrsig(aRecords, rrsig, dnskeyRecord, domain) {
    const expirationCheck = checkSignatureExpiration(rrsig);
    if (!expirationCheck.valid) {
        return { verified: false, reason: expirationCheck.reason };
    }
    const keyTag = calculateKeyTag(dnskeyRecord.data.algorithm, buildDnskeyFullRdata(dnskeyRecord.data));
    if (keyTag !== rrsig.data.keyTag || dnskeyRecord.data.algorithm !== rrsig.data.algorithm) {
        return { verified: false, reason: '' };
    }

    const rrsigHeader = Buffer.alloc(18);
    rrsigHeader.writeUInt16BE(dnsTypes.toType('A'), 0);
    rrsigHeader.writeUInt8(rrsig.data.algorithm, 2);
    rrsigHeader.writeUInt8(rrsig.data.labels, 3);
    rrsigHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
    rrsigHeader.writeUInt32BE(rrsig.data.expiration, 8);
    rrsigHeader.writeUInt32BE(rrsig.data.inception, 12);
    rrsigHeader.writeUInt16BE(rrsig.data.keyTag, 16);
    const ownerName = encodeDomainNameCanonical(domain);
    const rdataList = aRecords.map(record => dnsPacket.record('A').encode(record.data).subarray(2)).sort(Buffer.compare);
    const rrWireRecords = rdataList.map(rdata => {
        const header = Buffer.alloc(10);
        header.writeUInt16BE(dnsTypes.toType('A'), 0);
        header.writeUInt16BE(1, 2);
        header.writeUInt32BE(rrsig.data.originalTTL, 4);
        header.writeUInt16BE(rdata.length, 8);
        return Buffer.concat([ownerName, header, rdata]);
    });
    const message = Buffer.concat([rrsigHeader, encodeDomainNameCanonical(rrsig.data.signersName || domain), ...rrWireRecords]);
    const signature = rrsig.data.signature;
    const publicKey = getDnskeyRawKey(dnskeyRecord.data);
    if (!signature || !publicKey) {
        return { verified: false, reason: 'Aレコード署名の検証データを取得できません' };
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

function analyzeARecordNodataProof(domain, denialRecords) {
    const diagnostics = [];
    const normalizedDomain = normalizeDnsName(domain);
    for (const record of denialRecords) {
        const isMatchingNsec = record.type === 'NSEC' && normalizeDnsName(record.name) === normalizedDomain;
        const isMatchingNsec3 = record.type === 'NSEC3' && record.data.algorithm === 1 && record.name.split('.')[0].toUpperCase() === toBase32Hex(nsec3Hash(domain, record.data.salt, record.data.iterations));
        if (!isMatchingNsec && !isMatchingNsec3) continue;

        if (!record.data.rrtypes.includes('A')) {
            return { record, diagnostics };
        }
            diagnostics.push(`${record.type}のtype bitmapにAが含まれるため、${domain}のAレコード不在を証明できません`);
    }
    return { record: null, diagnostics };
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
    let { domain } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    
    // 入力バリデーション
    const validation = validateDomainName(domain);
    if (!validation.valid) {
        return res.status(400).json({ error: validation.error });
    }
    
    // レート制限チェック
    const rateLimit = checkRateLimit(clientIp);
    if (!rateLimit.allowed) {
        return res.status(429).json({ 
            error: `リクエスト制限に達しました。${rateLimit.waitSeconds}秒後に再度お試しください。` 
        });
    }

    // ドメイン名を正規化
    domain = normalizeDomainName(domain);
    
    let logs = [];
    let success = false;
    const diagram = {
        parent: { name: domain, server: '', ds: [], rrsig: [], dnskey: [] },
        child: { name: domain, server: '', dnskey: [], rrsig: [], aRecordValidation: null },
        checks: { dsSignature: false, dnskeySignature: false, dsKeyMatch: false }
    };

    // 大きな鍵長(ML-DSA等)でDNSのTCPフォールバックが多発すると処理が長引くため、
    // 必ず期限内に(HTMLエラーページではなく)JSONで応答できるようにガードする
    const sendJson = createTimeoutGuardedResponder(res, API_VALIDATE_TIMEOUT_MS, () => (
        { success: false, logs: [...logs, `検証処理が制限時間 (${API_VALIDATE_TIMEOUT_MS / 1000}秒) を超えたため中断しました。`], diagram }
    ));

    try {
        // 1. ドメイン名からゾーン頂点を取得
        const zoneApexInfo = await getZoneApex(domain);
        if (zoneApexInfo.zoneApex === '') {
            if (zoneApexInfo.hasCnameOrDname) {
                return sendJson(200, { success: false, logs: [...logs, 'このドメイン名は CNAME/DNAME のためゾーン頂点を特定できませんでした。'], diagram });
            } else {
                return sendJson(200, { success: false, logs: [...logs, `${zoneApexInfo.currentNs} から先の探索ができませんでした。(rcode: ${zoneApexInfo.rcode})`], diagram });
            }
        }
        diagram.parent.name = zoneApexInfo.zoneApex;
        diagram.parent.server = zoneApexInfo.parentNameservers.join(', ') || zoneApexInfo.parentNs || zoneApexInfo.currentNs;
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.childNameservers.join(', ') || zoneApexInfo.currentNs;
        let tempLog = '';
        if (zoneApexInfo.parentNs !== '') {
            tempLog += `${zoneApexInfo.parentNs} または `;
        }

        // 2. 親サーバーからDSレコードを取得
        let targetNs = zoneApexInfo.parentNs;
        let parentIp = '';
        let dsInfo = null;
        diagram.parent.server = zoneApexInfo.parentNameservers.join(', ') || targetNs || zoneApexInfo.currentNs;
        
        try {
            if (targetNs) {
                parentIp = await getARecord(targetNs);
                dsInfo = await getResourceRecord(zoneApexInfo.zoneApex, parentIp, 'DS');
            }
        } catch (err) {
            logs.push(`親サーバー [${targetNs}] へのクエリ失敗: ${err.message}`);
            parentIp = '';
        }
        
        if (!dsInfo || dsInfo.resourceRecords.length === 0) {
            try {
                targetNs = zoneApexInfo.currentNs;
                diagram.parent.server = zoneApexInfo.parentNameservers.join(', ') || targetNs;
                parentIp = await getARecord(targetNs);
                dsInfo = await getResourceRecord(zoneApexInfo.zoneApex, parentIp, 'DS');
            } catch (err) {
                logs.push(`現在のサーバー [${targetNs}] へのクエリ失敗: ${err.message}`);
                parentIp = '';
            }
            
            if (!dsInfo || dsInfo.resourceRecords.length === 0) {
                return sendJson(200, { success: false, logs: [...logs, '親サーバーにDSレコードが見つかりません。DNSSECが未委任の可能性があります。'], diagram });
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
                    const parentDnskeyInfo = await getResourceRecord(signerName, parentIp, 'DNSKEY');
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
        let childIp = '';
        try {
            childIp = await getARecord(zoneApexInfo.currentNs);
        } catch (err) {
            return sendJson(200, { success: false, logs: [...logs, `子サーバー [${zoneApexInfo.currentNs}] の IP アドレス取得失敗: ${err.message}`], diagram });
        }
        
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.childNameservers.join(', ') || zoneApexInfo.currentNs;
        
        let dnskeyInfo = null;
        try {
            dnskeyInfo = await getResourceRecord(zoneApexInfo.zoneApex, childIp, 'DNSKEY');
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
            const aRecordValidation = createARecordValidation();
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
                const aInfo = await getResourceRecord(domain, childIp, 'A');
                aRecordValidation.recordsFound = aInfo.resourceRecords.length > 0;
                for (const rrsig of aInfo.rrsigRecords) {
                    let verified = false;
                    let zskKeyTag = null;
                    let reason = '';
                    for (const key of dnskeyRecords) {
                        const result = verifyARecordRrsig(aInfo.resourceRecords, rrsig, key, domain);
                        if (result.reason) reason = result.reason;
                        if (result.verified) {
                            verified = true;
                            zskKeyTag = calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data));
                            break;
                        }
                    }
                    const verifiedByZsk = dnskeyRecords.some(key => isZoneSigningKey(key.data.flags) && calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data)) === zskKeyTag);
                    const dnskeyRrsetVerifiedByKsk = aRecordValidation.trustChain.dnskeyRrsetSignatures.length > 0;
                    aRecordValidation.signatures.push({ keyTag: rrsig.data.keyTag, algorithm: rrsig.data.algorithm, verified, reason, zskKeyTag, trustChainVerified: verified && verifiedByZsk && dnskeyRrsetVerifiedByKsk });
                }
                if (!aRecordValidation.recordsFound) {
                    const nxDomainProof = aInfo.rcode === 'NXDOMAIN' ? findNxDomainProof(domain, aInfo.denialRecords) : null;
                    const nodataProof = nxDomainProof ? null : analyzeARecordNodataProof(domain, aInfo.denialRecords);
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
                        denialProof.records = denialRecords.map(record => ({ name: record.name, type: record.type }));
                        denialProof.verified = denialRecords.every(record => {
                            const signature = aInfo.denialRrsigRecords.find(candidate => candidate.data.typeCovered === record.type && normalizeDnsName(candidate.name) === normalizeDnsName(record.name));
                            return signature && dnskeyRecords.some(key => verifyDenialRecordRrsig(record, signature, key).verified);
                        });
                    }
                }
            } catch (err) {
                aRecordValidation.error = err.message;
                logs.push(`AレコードのDNSSEC検証に失敗しました: ${err.message}`);
            }
        }

        success = isValidationSuccessful(diagram);
        if (!matchFound) {
            logs.push(`親ゾーンのDSレコードと子ゾーンのDNSKEYレコードの突合に失敗しました。DNSSECが正しく委任されていない可能性があります。`);
        } else if (!success && diagram.child.aRecordValidation && !diagram.child.aRecordValidation.error) {
            logs.push(`ドメイン名に対するAレコードの署名または不在証明の検証に失敗しました。`);
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

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    app.listen(PORT, () => {
        console.log(`Webサーバーが起動しました: http://localhost:${PORT}`);
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
    verifyDnskeyWithDs,
    isZoneSigningKey,
    calculateKeyTag,
    buildDnskeyFullRdata,
    encodeDomainNameCanonical,
    checkSignatureExpiration,
    verifyMLDSASignature,
    createARecordValidation,
    isValidationSuccessful,
    analyzeARecordNodataProof,
    findARecordNodataProof,
    findNxDomainProof,
    nsec3Hash,
    toBase32Hex,
    createTimeoutGuardedResponder
};
