const express = require('express');
const net = require('net');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');	// https://github.com/mafintosh/dns-packet
const dnsTypes = require('dns-packet/types');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
app.use(express.json());
app.use((req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Content-Security-Policy': "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'"
    });
    next();
});

// --- 定数定義 ---
const ROOT_NAMESERVER = '198.41.0.4'; // a.root-servers.net
const MAX_RECURSION_DEPTH = 10;
const DNS_QUERY_TIMEOUT = 5000;
const DNS_UDP_PAYLOAD_SIZE = 1232;
const MAX_DOMAIN_LENGTH = 253;
const RATE_LIMIT_REQUESTS_PER_MINUTE = 30;
const rateLimitMap = new Map(); // IP: { count, resetTime }

// --- ドメイン名バリデーション関数 ---
function validateDomainName(domain) {
    if (!domain || typeof domain !== 'string') {
        return { valid: false, error: 'ドメイン名は空ではない文字列である必要があります' };
    }
    
    // DNS インジェクション対策: 危険な文字をフィルタ
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

// --- キャッシュ: ルートから辿った委任情報 (ゾーン→ネームサーバー名) とネームサーバー名→IPアドレスの解決結果を getARecord/getZoneApex 間で使い回す ---
const DEFAULT_CACHE_TTL_MS = 300000; // レコードに TTL が無い場合のフォールバック
const delegationCache = new Map(); // zone(小文字・末尾ドット無し) -> { ns, parentNs, expiresAt }
const nameserverIpCache = new Map(); // ホスト名(小文字・末尾ドット無し) -> { ip, expiresAt }

function normalizeCacheKey(name) {
    return (name || '').toLowerCase().replace(/\.$/, '') || '.';
}

// --- ヘルパー関数: 委任情報 (ゾーン→ネームサーバー名/親ネームサーバー名) をキャッシュに記録 ---
function cacheDelegation(zone, ns, parentNs, ttlSeconds) {
    if (!zone || !ns) return;
    const ttlMs = (typeof ttlSeconds === 'number' && ttlSeconds > 0) ? ttlSeconds * 1000 : DEFAULT_CACHE_TTL_MS;
    delegationCache.set(normalizeCacheKey(zone), { ns, parentNs: parentNs || '', expiresAt: Date.now() + ttlMs });
}

// --- ヘルパー関数: ドメイン名に最も近い委任情報をキャッシュから探す (ルートからの再探索を省略) ---
function findCachedDelegation(domain) {
    const labels = normalizeCacheKey(domain).split('.');
    for (let i = 0; i < labels.length; i++) {
        const zone = labels.slice(i).join('.') || '.';
        const cached = delegationCache.get(zone);
        if (!cached) continue;
        if (Date.now() > cached.expiresAt) {
            delegationCache.delete(zone);
            continue;
        }
        return cached;
    }
    return null;
}

// --- ヘルパー関数: ネームサーバー名の IP アドレス解決結果をキャッシュに記録 ---
function cacheNameserverIp(hostname, ip, ttlSeconds) {
    if (!hostname || !ip) return;
    const ttlMs = (typeof ttlSeconds === 'number' && ttlSeconds > 0) ? ttlSeconds * 1000 : DEFAULT_CACHE_TTL_MS;
    nameserverIpCache.set(normalizeCacheKey(hostname), { ip, expiresAt: Date.now() + ttlMs });
}

// --- ヘルパー関数: キャッシュ済みのネームサーバー IP アドレスを取得 ---
function getCachedNameserverIp(hostname) {
    const key = normalizeCacheKey(hostname);
    const cached = nameserverIpCache.get(key);
    if (!cached) return null;
    if (Date.now() > cached.expiresAt) {
        nameserverIpCache.delete(key);
        return null;
    }
    return cached.ip;
}

// --- ヘルパー関数: キャッシュされた委任先が解決対象自身のホスト名と同じ (自己参照) 場合は使わない ---
function isUsableCachedNs(candidateNs, targetDomain) {
    if (!candidateNs) return false;
    if (net.isIP(candidateNs)) return true;
    return normalizeCacheKey(candidateNs) !== normalizeCacheKey(targetDomain);
}

// --- ネームサーバー名解決が自己参照して循環しているかを検出するための進行中セット ---
const inFlightNsResolutions = new Set();

// --- ヘルパー関数: ネームサーバー名を IP アドレスに解決 (フルサービスリゾルバや OS の名前解決には依存せず、キャッシュと getARecord で自前解決) ---
async function resolveNameserverIp(serverIp) {
    if (net.isIP(serverIp)) {
        return serverIp;
    }

    const cachedIp = getCachedNameserverIp(serverIp);
    if (cachedIp) {
        return cachedIp;
    }

    const key = normalizeCacheKey(serverIp);
    if (inFlightNsResolutions.has(key)) {
        throw new Error(`ネームサーバー名 [${serverIp}] の解決が循環参照になっています (グルーレコードが不足している可能性があります)`);
    }

    inFlightNsResolutions.add(key);
    try {
        const ip = await getARecord(serverIp);
        cacheNameserverIp(serverIp, ip);
        return ip;
    } finally {
        inFlightNsResolutions.delete(key);
    }
}

// --- ヘルパー関数: 指定したIPアドレスにUDPでDNSクエリを送信 (ホスト名の場合は事前に名前解決) ---
function queryDnsUdp(serverIp, buf, timeout = DNS_QUERY_TIMEOUT) {
    return new Promise((resolve, reject) => {
        (async () => {
            const resolvedIp = net.isIP(serverIp) ? serverIp : await resolveNameserverIp(serverIp);

            const client = dgram.createSocket('udp4');
            const timer = setTimeout(() => {
                client.close();
                reject(new Error(`タイムアウト (${timeout}ms): ${serverIp}`));
            }, timeout);

            client.on('message', (msg) => {
                clearTimeout(timer);
                client.close();
                resolve(msg);
            });

            client.on('error', (err) => {
                clearTimeout(timer);
                client.close();
                reject(err);
            });

            client.send(buf, 0, buf.length, 53, resolvedIp);
        })().catch(reject);
    });
}

// --- ヘルパー関数: 指定したIPアドレスにTCPでDNSクエリを送信 (ホスト名の場合は事前に名前解決) ---
function queryDnsTcp(serverIp, buf) {
    return new Promise((resolve, reject) => {
        (async () => {
            const resolvedIp = net.isIP(serverIp) ? serverIp : await resolveNameserverIp(serverIp);

            var responseBuffer = null;
            var expectedLength = 0;
            const client = new net.Socket();

            client.connect(53, resolvedIp, () => {
                client.write(buf);
            });

            client.on('data', (data) => {
                if (responseBuffer == null) {
                    if (data.byteLength > 1) {
                        const plen = data.readUInt16BE(0);
                        expectedLength = plen;
                        responseBuffer = Buffer.from(data);
                    }
                } else {
                    responseBuffer = Buffer.concat([responseBuffer, data]);
                }
                if (responseBuffer.byteLength >= expectedLength) {
                    client.end();
                }
            });

            client.on('error', (err) => {
                reject(err);
            });

            client.on('close', (hadError) => {
                if (!hadError) {
                    resolve(responseBuffer);
                } else {
                    reject(hadError);
                }
            });
        })().catch(reject);
    });
}

// --- ヘルパー関数: 指定されたタイプのリソースレコードを取得する ---
async function getResourceRecord(domain, serverIp, rType) {
    let resourceRecords = [];
    let rrsigRecords = [];

    let buf = dnsPacket.encode({
        type: 'query',
        id: Math.floor(Math.random() * 65535),
        questions: [{ type: rType, name: domain }],
        additionals: [{ type: 'OPT', name: '.', udpPayloadSize: DNS_UDP_PAYLOAD_SIZE, flags: dnsPacket.DNSSEC_OK }]
    });
    let msg = await queryDnsUdp(serverIp, buf);
    let res = dnsPacket.decode(msg);

    if (res.flags & dnsPacket.TRUNCATED_RESPONSE) {
        buf = dnsPacket.streamEncode({
            type: 'query',
            id: Math.floor(Math.random() * 65535),
            questions: [{ type: rType, name: domain }],
            additionals: [{ type: 'OPT', name: '.', flags: dnsPacket.DNSSEC_OK }]
        });
        msg = await queryDnsTcp(serverIp, buf);
        res = dnsPacket.streamDecode(msg);
    }

    resourceRecords = res.answers.filter(a => a.type === rType);
    if (resourceRecords.length !== 0) {
        rrsigRecords = res.answers.filter(a => a.type === 'RRSIG' && a.data.typeCovered === rType);
    }

    return { resourceRecords: resourceRecords, rrsigRecords: rrsigRecords };
}

// --- ヘルパー関数: Aレコードを取得する (エラーハンドリング強化版) ---
// ネームサーバー名の解決にも使われるため、循環参照を避けるため常にルートから辿る (委任キャッシュは使わない)
async function getARecord(domain) {
    // domain が既に IP アドレスの場合は問い合わせ不要
    if (net.isIP(domain)) {
        return domain;
    }

    let currentNs = ROOT_NAMESERVER;
    let ipAddress = '';
    let candidateQueue = []; // 現在の委任レベルで未試行の NS 候補 (優先NSが失敗した際のフォールバック用)

    for (let i = 0; i < MAX_RECURSION_DEPTH; i++) {
        try {
            const buf = dnsPacket.encode({
                type: 'query',
                id: Math.floor(Math.random() * 65535),
                questions: [{ type: 'A', name: domain }],
                additionals: [{ type: 'OPT', name: '.', udpPayloadSize: DNS_UDP_PAYLOAD_SIZE }]
            });
            const msg = await queryDnsUdp(currentNs, buf);
            const res = dnsPacket.decode(msg);
            const aRecord = res.answers.find(a => a.type === 'A');
            if (aRecord) {
                ipAddress = aRecord.data;
                break;
            }
            const nsAuthRecords = res.authorities.filter(a => a.type === 'NS');
            if (nsAuthRecords.length === 0) {
                throw new Error(`${currentNs} から Aレコードの委任情報が得られません`);
            }
            // グルーレコード (additionals の A) を持つ NS を優先候補にし、残りはフォールバック候補として保持する (捨てない)
            const candidates = nsAuthRecords.map(nsAuthRecord => {
                const glueA = res.additionals.find(a => a.type === 'A' && a.name === nsAuthRecord.data);
                cacheDelegation(nsAuthRecord.name, nsAuthRecord.data, currentNs, nsAuthRecord.ttl);
                if (glueA) {
                    cacheNameserverIp(nsAuthRecord.data, glueA.data, glueA.ttl);
                }
                return { name: nsAuthRecord.data, ip: glueA ? glueA.data : null };
            });
            candidates.sort((a, b) => (a.ip ? 0 : 1) - (b.ip ? 0 : 1));

            const chosen = candidates.shift();
            candidateQueue = candidates;
            currentNs = chosen.ip || chosen.name;
        } catch (err) {
            // 優先NSが失敗した場合、同じ委任レベルで捨てていない他の NS 候補を試す
            if (candidateQueue.length > 0) {
                const next = candidateQueue.shift();
                currentNs = next.ip || next.name;
                continue;
            }
            if (i === MAX_RECURSION_DEPTH - 1) {
                throw new Error(`Aレコード取得失敗 [${domain}]: ${err.message}`);
            }
        }
    }
    
    if (!ipAddress) {
        throw new Error(`Aレコード取得失敗 [${domain}]: ${MAX_RECURSION_DEPTH} 回の再帰でも IP アドレスが見つかりません`);
    }
    
    return ipAddress;
}

// --- ヘルパー関数: ゾーン頂点をルートから辿って取得する (エラーハンドリング強化版) ---
async function getZoneApex(domain) {
    const cachedDelegation = findCachedDelegation(domain);
    const useCachedDelegation = cachedDelegation && isUsableCachedNs(cachedDelegation.ns, domain);
    let currentNs = useCachedDelegation ? cachedDelegation.ns : ROOT_NAMESERVER;
    let parentNs = useCachedDelegation ? cachedDelegation.parentNs : '';
    let zoneApex = '';
    let rcode = '';
    let cdName = false;

    for (let i = 0; i < 10; i++) {
        let buf = dnsPacket.encode({
            type: 'query',
            id: Math.floor(Math.random() * 65535),
            questions: [{ type: 'SOA', name: domain }],
            additionals: [{ type: 'OPT', name: '.', udpPayloadSize: DNS_UDP_PAYLOAD_SIZE }]
        });
        let msg = await queryDnsUdp(currentNs, buf);
        let res = dnsPacket.decode(msg);

        if (res.flags & dnsPacket.TRUNCATED_RESPONSE) {
            buf = dnsPacket.streamEncode({
                type: 'query',
                id: Math.floor(Math.random() * 65535),
                questions: [{ type: 'SOA', name: domain }]
            });
            msg = await queryDnsTcp(currentNs, buf);
            res = dnsPacket.streamDecode(msg);
        }

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
                        cdName = true;
                        break;
                    }
                    const dnameRecord = answers.find(r => r.type === 'DNAME');
                    if (dnameRecord) {
                        cdName = true;
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
                // グルーレコード (additionals の A) を持つ NS を優先選択し、ホスト名解決による getARecord の循環参照を回避する
                let chosenNsRecord = null;
                let chosenNsIp = null;
                for (const nsRecord of nsRecords) {
                    const glueA = additionals.find(a => a.type === 'A' && a.name === nsRecord.data);
                    if (glueA) {
                        chosenNsRecord = nsRecord;
                        chosenNsIp = glueA.data;
                        cacheNameserverIp(nsRecord.data, glueA.data, glueA.ttl);
                        break;
                    }
                }
                if (!chosenNsRecord) {
                    chosenNsRecord = nsRecords[0];
                }
                cacheDelegation(chosenNsRecord.name, chosenNsRecord.data, currentNs, chosenNsRecord.ttl);
                parentNs = currentNs;
                currentNs = chosenNsIp || chosenNsRecord.data;
            }
        }
    }

    return { currentNs: currentNs, parentNs: parentNs, zoneApex: zoneApex, rcode: rcode, cdName: cdName };
}

// --- ヘルパー関数: RRSIG署名の有効期限チェック ---
function checkSignatureExpiration(rrsig) {
    const now = Math.floor(Date.now() / 1000); // 現在時刻（秒）
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
        
        // DNSKEY の RSA公開鍵 (RFC 3110) を解析: Exponent Length + Exponent + Modulus
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
        
        // DNSKEY の生の座標(X||Y)を JWK 形式に変換して公開鍵を生成
        const x = publicKeyBuffer.subarray(0, coordLen);
        const y = publicKeyBuffer.subarray(coordLen, coordLen * 2);
        const publicKey = crypto.createPublicKey({
            key: { kty: 'EC', crv: curveName, x: x.toString('base64url'), y: y.toString('base64url') },
            format: 'jwk'
        });
        
        const verifier = crypto.createVerify(hashAlgo.toUpperCase());
        verifier.update(messageBuffer);
        
        // DNSSEC の署名は r||s の固定長(IEEE P1363)形式のため、そのまま検証可能
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
        
        // EdDSA は事前ハッシュを行わないため、createVerify ではなくワンショット API を使用する
        const verified = crypto.verify(null, messageBuffer, publicKey, signatureBuffer);
        
        return { 
            verified, 
            reason: verified ? '' : `EdDSA署名検証に失敗しました。`
        };
    } catch (err) {
        return { verified: false, reason: `EdDSA署名検証でエラーが発生しました。: ${err.message}` };
    }
}

// --- ヘルパー関数: ドメイン名をDNSワイヤーフォーマットに変換（正規化・非圧縮） ---
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

// --- ヘルパー関数: RRSIG署名の検証（メイン関数） ---
// rrset: 同じ Type Covered を持つ全リソースレコードの配列（RFC 4034 の署名対象RRset）
function verifyRRSIGSignature(rrset, rrsig, dnskeyRecord, domain) {
    // 1. 署名の有効期限チェック
    const expirationCheck = checkSignatureExpiration(rrsig);
    if (!expirationCheck.valid) {
        return { verified: false, reason: expirationCheck.reason };
    }
    
    // 2. DNSKEYから Key Tag を計算
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
    
    // 5. RRSIG RDATA（署名フィールドを除く）をワイヤーフォーマットで構築 (RFC 4034 3.1.8.1)
    const signerNameBuf = encodeDomainNameCanonical(rrsig.data.signersName || domain);
    const rrsigRdataHeader = Buffer.alloc(18);
    rrsigRdataHeader.writeUInt16BE(dnsTypes.toType(rrsig.data.typeCovered), 0);
    rrsigRdataHeader.writeUInt8(rrsig.data.algorithm, 2);
    rrsigRdataHeader.writeUInt8(rrsig.data.labels, 3);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.originalTTL, 4);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.expiration, 8);
    rrsigRdataHeader.writeUInt32BE(rrsig.data.inception, 12);
    rrsigRdataHeader.writeUInt16BE(rrsig.data.keyTag, 16);
    
    // 6. 署名対象RRset（全レコード）を RR ワイヤーフォーマットに変換し、正規順序 (RFC 4034 6.3) に並べ替え
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
    
    // 7. メッセージ（署名対象）を構築 = RRSIG_RDATA + 正規順序のRRset
    const messageBuffer = Buffer.concat([rrsigRdataHeader, signerNameBuf, ...rrWireBufs]);
    
    // 8. 公開鍵を抽出
    const publicKeyBuffer = rawKeyBuf;
    if (!publicKeyBuffer) {
        return { verified: false, reason: `DNSKEY から公開鍵を抽出できません` };
    }
    
    // 9. 署名データを取得
    const signatureBuffer = rrsig.data.signature;
    if (!signatureBuffer) {
        return { verified: false, reason: `RRSIG から署名データを抽出できません` };
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
            reason: `DS RRSIG アルゴリズム不一致: DNSKEY [${dnskeyRecord.data.algorithm}] vs RRSIG [${rrsig.data.algorithm}]`
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
        return { verified: false, reason: `DS RRSIG から署名データを抽出できません` };
    }

    const publicKeyBuffer = getDnskeyRawKey(dnskeyRecord.data);
    if (!publicKeyBuffer) {
        return { verified: false, reason: `親 DNSKEY から公開鍵を抽出できません` };
    }

    const algorithm = dnskeyRecord.data.algorithm;
    let signatureResult;

    if (algorithm === 5 || algorithm === 7 || algorithm === 8 || algorithm === 10) {
        signatureResult = verifyRSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 13 || algorithm === 14) {
        signatureResult = verifyECDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
    } else if (algorithm === 15 || algorithm === 16) {
        signatureResult = verifyEdDSASignature(publicKeyBuffer, signatureBuffer, messageBuffer, algorithm);
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

    // 2. RFC 4034 Appendix B. Key Tag Calculation（RSAMD5以外は全アルゴリズム共通・ビッグエンディアン）
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
        15: 'ED25519', 16: 'ED448'
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
                reason: `Key Tag [${ac}] は一致しますが、Digestが異なります。\n 子の計算ハッシュ値: ${calculatedDigest}\n 親の想定ハッシュ値: ${targetDigest}` };
        }
    }

    return { 
        match: false,
        keyTag: ac,
        reason: ''
    };
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
        child: { name: domain, server: '', dnskey: [], rrsig: [] },
        checks: { dsSignature: false, dnskeySignature: false, dsKeyMatch: false }
    };

    try {
        // 1. ドメイン名からゾーン頂点を取得
        const zoneApexInfo = await getZoneApex(domain);
        if (zoneApexInfo.zoneApex === '') {
            if (zoneApexInfo.cdName) {
                return res.json({ success: false, logs: [...logs, 'このドメイン名は CNAME/DNAME のためゾーン頂点を特定できませんでした。'], diagram });
            } else {
                return res.json({ success: false, logs: [...logs, `${zoneApexInfo.currentNs} から先の探索ができませんでした。(rcode: ${zoneApexInfo.rcode})`], diagram });
            }
        }
        diagram.parent.name = zoneApexInfo.zoneApex;
        diagram.parent.server = zoneApexInfo.parentNs || zoneApexInfo.currentNs;
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.currentNs;
        let tempLog = '';
        if (zoneApexInfo.parentNs !== '') {
            tempLog += `${zoneApexInfo.parentNs} または `;
        }

        // 2. 親サーバーから DSレコードを取得 (エラーハンドリング強化版)
        let targetNs = zoneApexInfo.parentNs;
        let parentIp = '';
        let dsInfo = null;
        diagram.parent.server = targetNs || zoneApexInfo.currentNs;
        
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
                diagram.parent.server = targetNs;
                parentIp = await getARecord(targetNs);
                dsInfo = await getResourceRecord(zoneApexInfo.zoneApex, parentIp, 'DS');
            } catch (err) {
                logs.push(`現在のサーバー [${targetNs}] へのクエリ失敗: ${err.message}`);
                parentIp = '';
            }
            
            if (!dsInfo || dsInfo.resourceRecords.length === 0) {
                return res.json({ success: false, logs: [...logs, '親サーバーに DSレコードが見つかりません。DNSSEC が未委任の可能性があります。'], diagram });
            }
        }
        
        if (!parentIp) {
            return res.json({ success: false, logs: [...logs, '親サーバーの IP アドレス取得に失敗しました。'], diagram });
        }
        
        const dsRecords = dsInfo.resourceRecords;
        diagram.parent.name = zoneApexInfo.zoneApex;
        diagram.parent.server = targetNs;
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.currentNs;
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
            logs.push(`親サーバーに DSレコードに対する署名 (RRSIGレコード) が見つかりません。`);
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

        // 3. 子ゾーンの権威サーバーを自動検出して DNSKEY を取得 (エラーハンドリング強化版)
        let childIp = '';
        try {
            childIp = await getARecord(zoneApexInfo.currentNs);
        } catch (err) {
            return res.json({ success: false, logs: [...logs, `子サーバー [${zoneApexInfo.currentNs}] の IP アドレス取得失敗: ${err.message}`], diagram });
        }
        
        diagram.child.name = zoneApexInfo.zoneApex;
        diagram.child.server = zoneApexInfo.currentNs;
        
        let dnskeyInfo = null;
        try {
            dnskeyInfo = await getResourceRecord(zoneApexInfo.zoneApex, childIp, 'DNSKEY');
        } catch (err) {
            return res.json({ success: false, logs: [...logs, `子サーバーから DNSKEYレコード取得失敗: ${err.message}`], diagram });
        }
        
        const dnskeyRecords = dnskeyInfo.resourceRecords;
        if (dnskeyRecords.length === 0) {
            return res.json({ success: false, logs: [...logs, '子サーバーに DNSKEYレコードが存在しません。'], diagram });
        }
        diagram.child.dnskey = dnskeyRecords.map(key => ({
            keyTag: calculateKeyTag(key.data.algorithm, buildDnskeyFullRdata(key.data)),
            flags: key.data.flags,
            algorithm: key.data.algorithm
        }));
        
        // 3.5. DNSKEYレコード署名検証（オプション）
        const dnskeyRrsig = dnskeyInfo.rrsigRecords;
        diagram.child.rrsig = dnskeyRrsig.map(rrsig => ({
            keyTag: rrsig.data.keyTag,
            typeCovered: rrsig.data.typeCovered,
            algorithm: rrsig.data.algorithm,
            verified: null
        }));
        if (dnskeyRrsig.length > 0) {
            // DNSKEYレコード署名を検証（自己署名KSKで検証）
            const kskRecords = dnskeyRecords.filter(r => r.data.flags === 257); // KSK のみ
            let signatureVerified = false;
            let verifiedKeyTag = new Array();
            for (let rrsigIndex = 0; rrsigIndex < dnskeyRrsig.length; rrsigIndex++) {
                const rrsig = dnskeyRrsig[rrsigIndex];
                let rrsigVerified = false;
                for (const ksk of kskRecords) {
                    // DNSKEYレコードから Key Tag を計算
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
                // 自己署名検証に使われた KSK が親ゾーンの DSレコードの Key Tag と一致するか確認
                const dsRecordKeyTags = dsRecords.map(ds => ds.data.keyTag);
                const unmatchedKskKeyTags = [...new Set(verifiedKeyTag)].filter(keyTag => !dsRecordKeyTags.includes(keyTag));
                if (unmatchedKskKeyTags.length > 0) {
                    logs.push(`DNSKEYレコードの署名検証に使用した KSK (Key Tag: ${unmatchedKskKeyTags.join(', ')}) は、親ゾーンの DSレコードの Key Tag と一致しません。`);
                }
            }
        } else {
            logs.push(`DNSKEYレコードに対する署名 (RRSIG) が見つかりませんでした。`);
        }

        // 4. 信頼の連鎖を検証（DS と DNSKEY の突合）
        let matchFound = false;
        let dsKeyTags = dsRecords.map(ds => ds.data.keyTag);
        for (const ds of dsRecords) {
            for (const key of dnskeyRecords) {
                const result = verifyDnskeyWithDs(zoneApexInfo.zoneApex, key.data, ds.data);
                if (result.match) {
                    matchFound = true;
                } else {
                    if (result.reason && result.reason !== '') {
                        logs.push(result.reason);
                    }
                }
            }
        }

        diagram.checks.dsKeyMatch = matchFound;

        if (matchFound) {
            success = true;
        } else {
            logs.push(`親ゾーンの DSレコードと子ゾーンの DNSKEYレコードの突合に失敗しました。DNSSEC が正しく委任されていない可能性があります。`);
        }

        res.json({ success, logs, diagram });

    } catch (err) {
        const errorMsg = `予期しないエラーが発生しました: ${err.message}`;
        logs.push(errorMsg);
        res.status(500).json({ error: errorMsg, logs, diagram });
    }
});

// --- UI (HTML) を返却するエンドポイント ---
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <title>DNSSEC委任状態検証ツール</title>
        <style>
            :root { --ink: #172b4d; --muted: #667085; --line: #cbd5e1; --blue: #2563eb; --teal: #0f766e; --good: #15803d; --bad: #b42318; --paper: #f8fafc; }
            * { box-sizing: border-box; }
            body { font-family: Georgia, 'Yu Mincho', serif; margin: 0; padding: 32px 18px; background: linear-gradient(135deg, #e0f2fe, #f8fafc 45%, #fef3c7); color: var(--ink); }
            .card { max-width: 1120px; margin: 0 auto; padding: 30px; background: rgba(255,255,255,.92); border: 1px solid rgba(23,43,77,.12); box-shadow: 0 18px 45px rgba(23,43,77,.12); }
            h1 { margin: 0 0 6px; font-size: 28px; letter-spacing: 0; }
            .lead { margin: 0 0 24px; color: var(--muted); font-family: sans-serif; font-size: 14px; }
            .form-group { margin-bottom: 24px; }
            label { display: block; margin-bottom: 8px; font-weight: bold; }
            .input-row { display: flex; align-items: center; gap: 10px; }
            input[type="text"] { flex: 1; min-width: 0; padding: 12px 14px; border: 1px solid var(--line); border-radius: 7px; font: 15px sans-serif; }
            input[type="text"]:focus { border-color: var(--blue); outline: 3px solid #bfdbfe; }
            button { background: var(--ink); color: white; border: none; padding: 12px 24px; border-radius: 7px; cursor: pointer; font: bold 15px sans-serif; white-space: nowrap; }
            button:hover { background: var(--blue); }

            @media (max-width: 560px) {
                .input-row {
                    flex-direction: column;
                    align-items: stretch;
                }

                button {
                    width: 100%;
                }
            }

            .explanation-title { display: none; }
            .explanation-box { display: none; }
            .result-status-box { padding: 13px 16px; border-radius: 7px; font: bold 16px sans-serif; margin: 20px 0; display: none; border-left: 5px solid; }
            .status-loading { background: #eff6ff; color: #1d4ed8; border-color: var(--blue); }
            .status-success { background: #ecfdf3; color: var(--good); border-color: var(--good); }
            .status-failed { background: #fff1f0; color: var(--bad); border-color: var(--bad); }
            .validation-error-details { display: none; margin: 12px 0 18px; padding: 12px 14px; background: #fff7ed; border: 1px solid #fed7aa; border-left: 4px solid #f97316; color: #7c2d12; font: 12px/1.6 Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
            .diagram { display: none; overflow-x: auto; padding: 14px 0 4px; font-family: sans-serif; }
            .diagram-header { display: flex; justify-content: space-between; gap: 20px; margin-bottom: 6px; color: var(--muted); font-size: 13px; }
            .apex-summary { display: flex; flex-wrap: wrap; gap: 6px 20px; margin-bottom: 14px; color: var(--muted); font: 12px sans-serif; }
            .diagram-grid { min-width: 500px; display: grid; grid-template-columns: minmax(0, 1fr); grid-template-rows: auto auto auto auto minmax(58px, auto) auto auto auto; align-items: center; gap: 0 16px; }
            .zone { position: relative; z-index: 3; align-self: stretch; padding: 14px; background: transparent; border: 1px solid var(--line); border-radius: 9px; pointer-events: none; }
            .zone-title { position: absolute; top: 10px; left: 14px; margin: 0; padding: 2px 6px; border-radius: 4px; font-size: 14px; line-height: 1.4; color: var(--muted); white-space: nowrap; }
            .node { position: relative; z-index: 2; justify-self: center; width: 86%; min-height: 80px; padding: 8px 14px; background: white; border: 2px solid var(--line); border-radius: 10px; box-shadow: 0 5px 12px rgba(23,43,77,.07); }
            .node.good { border-color: #86efac; background: #f0fdf4; }
            .node.bad { border-color: #fca5a5; background: #fff1f2; }
            .node-title { font-weight: bold; font-size: 15px; }
            .node-meta { color: var(--muted); font-size: 12px; line-height: 1.55; overflow-wrap: anywhere; word-break: break-word; margin-left: 14px; }
            .arrow { position: relative; display: flex; align-items: center; justify-content: center; color: var(--muted); font-size: 12px; text-align: center; min-height: 80px; }
            .arrow::before { content: ''; position: absolute; top: 0; bottom: 0; border-left: 2px solid var(--line); z-index: 0; }
            .arrow::after { content: ''; position: absolute; left: 50%; bottom: -1px; width: 9px; height: 9px; border-right: 2px solid var(--line); border-bottom: 2px solid var(--line); transform: translateX(-50%) rotate(45deg); z-index: 0; }
            .arrow span { position: relative; z-index: 1; padding: 4px 7px; background: #fff; border-radius: 5px; }
            .arrow.good::before { border-color: #4ade80; }
            .arrow.good::after { border-color: #4ade80; }
            .arrow.good span { color: var(--good); }
            .arrow.bad::before { border-color: #f87171; }
            .arrow.bad::after { border-color: #f87171; }
            .arrow.bad span { color: var(--bad); }
            .parent-zone { grid-column: 1; grid-row: 1 / 5; }
            .child-zone { grid-column: 1; grid-row: 6 / 9; }
            .parent-ds { grid-column: 1; grid-row: 3; margin-bottom: 10px; }
            .parent-rrsig { grid-column: 1; grid-row: 2; margin-bottom: 10px; }
            .parent-key { grid-column: 1; grid-row: 1; margin-bottom: 10px; margin-top: 36px; }
            .child-key { grid-column: 1; grid-row: 6; margin-top: 36px; margin-bottom: 10px; }
            .child-rrsig { grid-column: 1; grid-row: 7; margin-bottom: 10px; }
            .chain-arrow { grid-column: 1; grid-row: 5; }
            .signature-arrow { grid-column: 2; grid-row: 4; }
            .legend { margin-top: 16px; color: var(--muted); font: 12px sans-serif; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>DNSSEC委任状態検証ツール</h1>
            <p class="lead">親ゾーンの DS と子ゾーンの KSK を元に信頼の連鎖を検証します。</p>

            <!-- 入力欄とボタンを <form> タグで囲み、onsubmitイベントを設定 -->
            <form id="validateForm" onsubmit="validate(event)">
              <div class="form-group">
                <label>検証するドメイン名</label>
                <div class="input-row">
                  <input type="text" id="domain" placeholder="example.com" autofocus>
                  <button type="submit">検証スタート</button>
                </div>
              </div>
            </form>

            <div id="explanationTitle" class="explanation-title">📋 説明</div>
            <div id="explanationBox" class="explanation-box">
                <a href="https://jprs.jp/glossary/index.php?ID=0158">フルサービスリゾルバー</a>のように、入力された
                <a href="https://jprs.jp/glossary/index.php?ID=0083">ドメイン名</a>に関する親 (上位) の
                <a href="https://jprs.jp/glossary/index.php?ID=0145">権威サーバー</a>を
                <a href="https://jprs.jp/glossary/index.php?ID=0148">ルート</a>から辿って探し出し、
                <a href="https://jprs.jp/glossary/index.php?ID=0213">DSレコード</a>を取得して、当該ドメイン名の権威サーバーが持つ DNSKEY と照合します。
            </div>

            <div id="statusBox" class="result-status-box"></div>
            <div id="validation-error-details" class="validation-error-details" role="alert"></div>
            <section id="diagram" class="diagram" aria-live="polite">
                <div class="diagram-header"><strong>検証結果の関係図</strong></div>
                <div class="apex-summary"><span id="zoneApexSummary">ゾーン頂点：未確認</span></div>
                <div class="diagram-grid">
                    <div class="zone parent-zone"><p id="parentZoneTitle" class="zone-title">親ゾーン / 委任元</p></div>
                    <div class="zone child-zone"><p id="childZoneTitle" class="zone-title">子ゾーン / 委任先</p></div>
                    <div id="parentDs" class="node parent-ds"></div>
                    <div id="parentRrsig" class="node parent-rrsig"></div>
                    <div id="parentKey" class="node parent-key"></div>
                    <div id="childKey" class="node child-key"></div>
                    <div id="childRrsig" class="node child-rrsig"></div>
                    <div id="chainArrow" class="arrow chain-arrow"></div>
                </div>
                <div class="legend">矢印のラベルは、親と子の関係に対するハッシュ値検証の結果です。</div>
            </section>
        </div>

        <script>
            const domainInput = document.getElementById('domain');
            const savedDomainKey = 'dnssec-validator-domain';
            const urlParams = new URLSearchParams(window.location.search);
            const domainFromUrl = urlParams.get('domain');
            const MAX_DISPLAY_TEXT_LENGTH = 2000;

            function sanitizeDisplayText(value) {
                const text = (value === null || value === undefined ? '' : String(value))
                    .replace(/[\u0000-\u001F\u007F]+/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim();
                return text.slice(0, MAX_DISPLAY_TEXT_LENGTH);
            }

            function sanitizeDisplayLines(value) {
                if (Array.isArray(value)) {
                    return value.map(item => sanitizeDisplayText(item));
                }
                return [sanitizeDisplayText(value)];
            }

            try {
                domainInput.value = sanitizeDisplayText(domainFromUrl || localStorage.getItem(savedDomainKey) || '');
            } catch (e) {
                domainInput.value = sanitizeDisplayText(domainFromUrl || '');
            }

            domainInput.addEventListener('input', () => {
                try {
                    localStorage.setItem(savedDomainKey, sanitizeDisplayText(domainInput.value));
                } catch (e) {
                }
            });

            const dnssecAlgorithmNames = {
                1: 'RSAMD5',
                5: 'RSASHA1',
                7: 'RSASHA1-NSEC3-SHA1',
                8: 'RSASHA256',
                10: 'RSASHA512',
                13: 'ECDSAP256SHA256',
                14: 'ECDSAP384SHA384',
                15: 'ED25519',
                16: 'ED448'
            };

            function algorithmText(algorithm) {
                return 'alg ' + algorithm + ' (' + (dnssecAlgorithmNames[algorithm] || 'Unknown') + ')';
            }

            function keyText(records, role) {
                if (!records || records.length === 0) return [role + ': 取得できませんでした'];
                return records.map(record => role + ' / Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm));
            }

            function dsText(records) {
                if (!records || records.length === 0) return ['取得できませんでした'];
                return records.map(record => {
                    return 'Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm) + ' / digest ' + record.digest;
                });
            }

            function rrsigText(records) {
                if (!records || records.length === 0) return ['取得できませんでした'];
                return records.map(record => {
                    const result = record.verified === true ? '成功 ✓' : record.verified === false ? '失敗 ✕' : '未検証';
                    return 'RRSIG ' + record.typeCovered + ' / Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm) + ' -> 署名検証: ' + result;
                });
            }

            function setNodeContent(nodeId, title, titleColor, lines) {
                const node = document.getElementById(nodeId);
                node.replaceChildren();

                const titleElement = document.createElement('div');
                titleElement.className = 'node-title';
                if (titleColor) {
                    titleElement.style.color = titleColor;
                }
                titleElement.textContent = sanitizeDisplayText(title);
                node.appendChild(titleElement);

                const metaElement = document.createElement('div');
                metaElement.className = 'node-meta';

                const safeLines = sanitizeDisplayLines(lines);
                safeLines.forEach((line, index) => {
                    if (index > 0) {
                        metaElement.appendChild(document.createElement('br'));
                    }
                    metaElement.appendChild(document.createTextNode(line || ''));
                });

                node.appendChild(metaElement);
            }

            function emptyDiagram(domain) {
                return {
                    parent: { name: domain, server: '', ds: [], rrsig: [], dnskey: [] },
                    child: { name: domain, server: '', dnskey: [], rrsig: [] },
                    checks: { dsSignature: false, dnskeySignature: false, dsKeyMatch: false }
                };
            }

            function renderDiagram(diagram) {
                const parentKey = diagram.parent.dnskey.filter(key => key.flags === 256);
                const childKsk = diagram.child.dnskey.filter(key => key.flags === 257);
                document.getElementById('parentZoneTitle').textContent = '親ゾーン / 委任元 (' + (diagram.parent.server || '権威サーバー未確認') + ')';
                document.getElementById('childZoneTitle').textContent = '子ゾーン / 委任先 (' + (diagram.child.server || '権威サーバー未確認') + ')';
                document.getElementById('zoneApexSummary').textContent = 'ゾーン頂点：' + (diagram.parent.name || diagram.child.name || '未確認');

                setNodeContent('parentKey', 'DNSKEY', '', [...keyText(parentKey, 'ZSK'), '※DSの署名検証用公開鍵 (ZSKの秘密鍵はゾーンの RRset への署名に使われる)']);
                setNodeContent('parentRrsig', 'RRSIG', '', [...rrsigText(diagram.parent.rrsig), '※DSを対象とする電子署名']);
                setNodeContent('parentDs', 'DS', 'blue', [...dsText(diagram.parent.ds), '※子KSKのハッシュ値']);
                setNodeContent('childKey', 'DNSKEY', 'blue', [...keyText(childKsk, 'KSK'), '※DNSKEY (KSK/ZSK) の署名検証用公開鍵 (KSKの秘密鍵は DNSKEY RRset への署名に使われる)']);
                setNodeContent('childRrsig', 'RRSIG', '', [...rrsigText(diagram.child.rrsig), '※DNSKEY (KSK/ZSK) を対象とする電子署名']);

                const chainOk = diagram.checks.dsKeyMatch;
                const chainArrow = document.getElementById('chainArrow');
                chainArrow.className = 'arrow chain-arrow ' + (chainOk ? 'good' : 'bad');
                chainArrow.replaceChildren();
                const chainLabel = document.createElement('span');
                chainLabel.textContent = (chainOk ? 'ハッシュ一致 ✓' : 'ハッシュ不一致 ✕') + '\nDS -> KSK';
                chainLabel.style.whiteSpace = 'pre-line';
                chainArrow.appendChild(chainLabel);
                document.getElementById('diagram').style.display = 'block';
            }

            async function validate(event) {
                event.preventDefault();

                let domain = domainInput.value.trim();
                const statusBox = document.getElementById('statusBox');
                const errorDetailsElement = document.getElementById('validation-error-details');
                const explanationTitle = document.getElementById('explanationTitle');
                const explanationBox = document.getElementById('explanationBox');
                const diagram = document.getElementById('diagram');

                try {
                    const urlObj = new URL(domain);
                    if (urlObj && urlObj.hostname) {
                        domain = urlObj.hostname;
                    }
                } catch (e) {
                }

                if(!domain) return alert('ドメイン名を入力してください');

                // 1. ローディング状態の表示
                statusBox.style.display = 'block';
                statusBox.className = 'result-status-box status-loading';
                statusBox.innerText = '検証中... (権威サーバーへ直接クエリを送信しています)';
                errorDetailsElement.style.display = 'none';
                errorDetailsElement.textContent = '';

                renderDiagram(emptyDiagram(domain));

                explanationTitle.style.display = 'none';
                explanationBox.style.display = 'none';

                try {
                    const response = await fetch('./api/validate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain })
                    });
                    const data = await response.json();

                    if (data.error) {
                        statusBox.className = 'result-status-box status-failed';
                        statusBox.innerText = 'エラーが発生しました';
                        errorDetailsElement.textContent = sanitizeDisplayText([data.error, ...(data.logs || [])].join(String.fromCharCode(10)));
                        errorDetailsElement.style.display = 'block';
                        renderDiagram(data.diagram || emptyDiagram(domain));
                    } else {
                        if (data.success) {
                            statusBox.className = 'result-status-box status-success';
                            statusBox.innerText = '検証成功: DNSSEC の委任状態は問題ありません！';
                            if (data.logs && data.logs.length > 0) {
                                errorDetailsElement.textContent = sanitizeDisplayText(data.logs.join(String.fromCharCode(10)));
                                errorDetailsElement.style.display = 'block';
                            }
                        } else {
                            statusBox.className = 'result-status-box status-failed';
                            statusBox.innerText = '検証失敗: 信頼の連鎖が切れています';
                            if (data.logs && data.logs.length > 0) {
                                errorDetailsElement.textContent = sanitizeDisplayText(data.logs.join(String.fromCharCode(10)));
                                errorDetailsElement.style.display = 'block';
                            }
                        }
                        if (data.diagram) renderDiagram(data.diagram);
                    }
                } catch(e) {
                    statusBox.className = 'result-status-box status-failed';
                    statusBox.innerText = '通信エラーが発生しました';
                    errorDetailsElement.textContent = sanitizeDisplayText('詳細: ' + (e && e.message ? e.message : String(e)));
                    errorDetailsElement.style.display = 'block';
                    renderDiagram(emptyDiagram(domain));
                }
            }
        </script>
    </body>
    </html>
    `);
});

const PORT = 3002;
app.listen(PORT, () => {
    console.log(`Webサーバーが起動しました: http://localhost:${PORT}`);
});
