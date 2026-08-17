const express = require('express');
const net = require('net');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');	// https://github.com/mafintosh/dns-packet
const crypto = require('crypto');

const app = express();
app.use(express.json());

// --- 定数定義 ---
const ROOT_NAMESERVER = 'a.root-servers.net';
const MAX_RECURSION_DEPTH = 10;
const DNS_QUERY_TIMEOUT = 5000;
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
    const oneMinuteAgo = now - 60000;
    
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

// --- ヘルパー関数: 指定したIPアドレスにUDPでDNSクエリを送信 ---
function queryDnsUdp(serverIp, buf, timeout = 5000) {
    return new Promise((resolve, reject) => {
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

        client.send(buf, 0, buf.length, 53, serverIp);
    });
}

// --- ヘルパー関数: 指定したIPアドレスにTCPでDNSクエリを送信 ---
function queryDnsTcp(serverIp, buf) {
    return new Promise((resolve, reject) => {
        var responseBuffer = null;
        var expectedLength = 0;
        const client = new net.Socket();

        client.connect(53, serverIp, () => {
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
        additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232, flags: dnsPacket.DNSSEC_OK }]
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
async function getARecord(domain) {
    let currentNs = ROOT_NAMESERVER;
    let ipAddress = '';

    for (let i = 0; i < MAX_RECURSION_DEPTH; i++) {
        try {
            const buf = dnsPacket.encode({
                type: 'query',
                id: Math.floor(Math.random() * 65535),
                questions: [{ type: 'A', name: domain }],
                additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232 }]
            });
            const msg = await queryDnsUdp(currentNs, buf);
            const res = dnsPacket.decode(msg);
            const aRecord = res.answers.find(a => a.type === 'A');
            if (aRecord) {
                ipAddress = aRecord.data;
                break;
            }
            const nsAuthRecord = res.authorities.find(a => a.type === 'NS');
            if (nsAuthRecord) {
                currentNs = nsAuthRecord.data;
            } else {
                throw new Error(`${currentNs} から A レコードの委任情報が得られません`);
            }
        } catch (err) {
            if (i === MAX_RECURSION_DEPTH - 1) {
                throw new Error(`A レコード取得失敗 [${domain}]: ${err.message}`);
            }
        }
    }
    
    if (!ipAddress) {
        throw new Error(`A レコード取得失敗 [${domain}]: ${MAX_RECURSION_DEPTH} 回の再帰でも IP アドレスが見つかりません`);
    }
    
    return ipAddress;
}

// --- ヘルパー関数: ゾーン頂点をルートから辿って取得する (エラーハンドリング強化版) ---
async function getZoneApex(domain) {
    let currentNs = ROOT_NAMESERVER;
    let parentNs = '';
    let zoneApex = '';
    let rcode = '';
    let cdName = false;

    for (let i = 0; i < 10; i++) {
        let buf = dnsPacket.encode({
            type: 'query',
            id: Math.floor(Math.random() * 65535),
            questions: [{ type: 'SOA', name: domain }],
            additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232 }]
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
            const nsRecord = authorities.find(r => r.type === 'NS');
            if (nsRecord) {
                parentNs = currentNs;
                currentNs = nsRecord.data;
            }
        }
    }

    const nsInfo = await getResourceRecord(zoneApex, currentNs, 'NS');
    if (nsInfo) {
        const nsRecord = nsInfo.resourceRecords.find(r => r.data === currentNs);
        if (!nsRecord) {
            const newNs = nsInfo.resourceRecords.find(r => r.type === 'NS');
            if (newNs && newNs.data.length > 0) {
                parentNs = currentNs;
                currentNs = newNs.data;
            }
        }
    }

    return { currentNs: currentNs, parentNs: parentNs, zoneApex: zoneApex, rcode: rcode, cdName: cdName };
}

// --- ヘルパー関数: アルゴリズムごとの特性を考慮した正確な Key Tag 計算 ---
function calculateKeyTag(algorithm, fullRdata) {
    // 1. アルゴリズム 1 (RSAMD5) の場合
    if (algorithm === 1) {
        if (fullRdata.length < 4) return 0;
        return fullRdata.readUInt16BE(fullRdata.length - 3);
    }

    // 2. Ed25519 (15) または Ed448 (16) の場合
    // EdDSA系は16ビットをリトルエンディアンで読み出す
    const isEdDSA = (algorithm === 15 || algorithm === 16);

    // 3. RFC 4034 Appendix B. Key Tag Calculation
    let ac = 0;
    for (let i = 0; i < fullRdata.length; i += 2) {
        let val = 0;
        if (i + 1 < fullRdata.length) {
            val = isEdDSA ? fullRdata.readUInt16LE(i) : fullRdata.readUInt16BE(i);
        } else {
            val = isEdDSA ? fullRdata.readUInt8(i) : (fullRdata.readUInt8(i) << 8);
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
            return { match: false, keyTag: null, reason: `⚠️ 未対応のDigest Type [${dsRecord.digestType}]` };
    }

    // 1. ドメイン名をワイヤーフォーマットに変換 (末尾に0x00を付与)
    const labels = domain.replace(/\.$/, '').split('.');
    let nameBuf = Buffer.alloc(0);
    for (const label of labels) {
        if (!label) continue;
        const lenBuf = Buffer.from([label.length]);
        const labelBuf = Buffer.from(label, 'ascii');
        nameBuf = Buffer.concat([nameBuf, lenBuf, labelBuf]);
    }
    nameBuf = Buffer.concat([nameBuf, Buffer.from([0x00])]); 

    // 2. DNSKEY データバッファの取得
    const rawKeyBuf = dnskeyData.key || dnskeyData.publicKey;
    if (!rawKeyBuf) {
        return { match: false, keyTag: null, reason: '❌ DNSKEY のデータが取得できません。' };
    }

    // 4バイトの正しい共通ヘッダー（Flags, Protocol, Algorithm）を作成 (RFC 4034)
    const headerBuf = Buffer.alloc(4);
    headerBuf.writeUInt16BE(dnskeyData.flags, 0);
    headerBuf.writeUInt8(3, 2);	// dns-packet では DNSKEYリソースレコードの Protocol は 3 固定
    headerBuf.writeUInt8(dnskeyData.algorithm, 3);

    let fullRdata;

    // 現在の rawKeyBuf の先頭4バイトが、これから作ろうとしているヘッダーと「完全に一致するか」を判定
    const hasHeaderAlready = (
        rawKeyBuf.length >= 4 &&
        rawKeyBuf.readUInt16BE(0) === dnskeyData.flags &&
        rawKeyBuf.readUInt8(2) === 3 &&	// dns-packet では DNSKEYリソースレコードの Protocol は 3 固定
        rawKeyBuf.readUInt8(3) === dnskeyData.algorithm
    );

    if (hasHeaderAlready) {
        // すでにヘッダーが含まれているアルゴリズム（ECDSA, Ed25519など）
        fullRdata = rawKeyBuf;
    } else {
        // 4バイト少なくなっているアルゴリズム（RSA系など）
        // 手動で生成した headerBuf を先頭に結合して、完全な RDATA に復元
        fullRdata = Buffer.concat([headerBuf, rawKeyBuf]);
    }

    // 3. 正確に復元された RDATA で Key Tag を計算
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
                warnings.push(`⚠️ 【強度ミスマッチ】子の鍵は強力な ${keyAlgoName} ですが、親のDSハッシュが古い ${dsDigestName} です。`);
            }
            const successMsg = `🟢 【一致】Key Tag [${ac}] とハッシュが完全に一致しました。\n   ➕️子ゾーンの鍵 [${isKsk} / Key Tag: ${ac} (${keyAlgoName})]\n   ➕️親の指定する鍵 [Key Tag: ${dsRecord.keyTag}]\n   ➕️ハッシュ値: ${calculatedDigest}`;
            return { 
                match: true,
                keyTag: ac,
                reason: warnings.length > 0 ? `${successMsg}\n${warnings.join('\n')}` : successMsg };
        } else {
            return {
                match: false,
                keyTag: ac,
                reason: `🟡 【ハッシュミスマッチ】Key Tag [${ac}] は一致しますが、Digestが異なります。\n   ➕️子の計算ハッシュ値: ${calculatedDigest}\n   ➕️親の想定ハッシュ値: ${targetDigest}` };
        }
    }

    return { 
        match: false,
        keyTag: ac,
        reason: `🔴 【スキップ】子ゾーンの鍵は、親の指定する鍵とは異なります。\n   ➕️子ゾーンの鍵 [${isKsk} / Key Tag: ${ac} (${keyAlgoName})]\n   ➕️親の指定する鍵 [Key Tag: ${dsRecord.keyTag}]` 
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

    try {
        // 1. ドメイン名からゾーン頂点を取得
        const zoneApexInfo = await getZoneApex(domain);
        if (zoneApexInfo.zoneApex === '') {
            if (zoneApexInfo.cdName) {
                return res.json({ success: false, logs: [...logs, '⚠️ このドメイン名は CNAME/DNAME のためゾーン頂点を特定できませんでした。'] });
            } else {
                return res.json({ success: false, logs: [...logs, `⚠️ ${zoneApexInfo.currentNs} から先の探索ができませんでした。(rcode: ${zoneApexInfo.rcode})`] });
            }
        }
        let tempLog = '';
        if (zoneApexInfo.parentNs !== '') {
            tempLog += `${zoneApexInfo.parentNs} または `;
        }
        logs.push(`ℹ️ ゾーン頂点は ${zoneApexInfo.zoneApex} 、親候補は ${tempLog}${zoneApexInfo.currentNs} です。`);

        // 2. 親サーバーから DSレコードを取得 (エラーハンドリング強化版)
        let targetNs = zoneApexInfo.parentNs;
        let parentIp = '';
        let dsInfo = null;
        
        try {
            if (targetNs) {
                parentIp = await getARecord(targetNs);
                dsInfo = await getResourceRecord(zoneApexInfo.zoneApex, parentIp, 'DS');
            }
        } catch (err) {
            logs.push(`⚠️ 親サーバー [${targetNs}] へのクエリ失敗: ${err.message}`);
            parentIp = '';
        }
        
        if (!dsInfo || dsInfo.resourceRecords.length === 0) {
            try {
                targetNs = zoneApexInfo.currentNs;
                parentIp = await getARecord(targetNs);
                dsInfo = await getResourceRecord(zoneApexInfo.zoneApex, parentIp, 'DS');
            } catch (err) {
                logs.push(`⚠️ 現在のサーバー [${targetNs}] へのクエリ失敗: ${err.message}`);
                parentIp = '';
            }
            
            if (!dsInfo || dsInfo.resourceRecords.length === 0) {
                return res.json({ success: false, logs: [...logs, '⚠️ 親サーバーに DSレコードが見つかりません。DNSSEC が未委任の可能性があります。'] });
            }
        }
        
        if (!parentIp) {
            return res.json({ success: false, logs: [...logs, '❌ 親サーバーの IP アドレス取得に失敗しました。'] });
        }
        
        logs.push(`ℹ️ 親サーバーは ${targetNs} (${parentIp}) で確定しました。`);
        const dsRecords = dsInfo.resourceRecords;
        logs.push(`✅ 親サーバーから DSレコードを ${dsRecords.length} 件、取得しました。`);
        const rrsigRecords = dsInfo.rrsigRecords;
        if (rrsigRecords.length === 0) {
            logs.push('⚠️ 親サーバーに DSレコードに対する署名 (RRSIGレコード) が見つかりません。');
        } else {
            logs.push(`✅ 親サーバーから DSレコードに対する署名 (RRSIGレコード) を ${rrsigRecords.length} 件、取得しました。`);
            for (const rrsig of rrsigRecords) {
                const expiration = new Date(rrsig.data.expiration * 1000);
                const inception = new Date(rrsig.data.inception * 1000);
                logs.push(`   ➕️ typeCovered: ${rrsig.data.typeCovered}, algorithm: ${rrsig.data.algorithm}, labels: ${rrsig.data.labels}`);
                logs.push(`   ➕️ signersName: ${rrsig.data.signersName}, originalTTL: ${rrsig.data.originalTTL}, keyTag: ${rrsig.data.keyTag}`);
                logs.push(`   ➕️ expiration: ${expiration.toISOString()}, inception: ${inception.toISOString()}`);
                logs.push(`   ➕️ signature: ${rrsig.data.signature.toString('base64')}`);
            }
        }

        // 3. 子ゾーンの権威サーバーを自動検出して DNSKEY を取得 (エラーハンドリング強化版)
        let childIp = '';
        try {
            childIp = await getARecord(zoneApexInfo.currentNs);
        } catch (err) {
            return res.json({ success: false, logs: [...logs, `❌ 子サーバー [${zoneApexInfo.currentNs}] の IP アドレス取得失敗: ${err.message}`] });
        }
        
        logs.push(`ℹ️ 子サーバーは ${zoneApexInfo.currentNs} (${childIp}) です。`);
        if (parentIp && parentIp === childIp) {
            logs.push(`ℹ️ このゾーン頂点は親子同居のようです。`);
        }
        
        let dnskeyInfo = null;
        try {
            dnskeyInfo = await getResourceRecord(zoneApexInfo.zoneApex, childIp, 'DNSKEY');
        } catch (err) {
            return res.json({ success: false, logs: [...logs, `❌ 子サーバーから DNSKEY レコード取得失敗: ${err.message}`] });
        }
        
        const dnskeyRecords = dnskeyInfo.resourceRecords;
        if (dnskeyRecords.length === 0) {
            return res.json({ success: false, logs: [...logs, '❌ 子サーバーに DNSKEYレコードが存在しません。'] });
        }
        logs.push(`✅ 子サーバーから DNSKEYレコードを ${dnskeyRecords.length} 件、取得しました。`);

        // 4. 信頼の連鎖を検証（DS と DNSKEY の突合）
        let matchFound = false;
        for (const ds of dsRecords) {
            for (const key of dnskeyRecords) {
                const result = verifyDnskeyWithDs(zoneApexInfo.zoneApex, key.data, ds.data);
                if (result.reason) logs.push(result.reason);
                if (result.match) matchFound = true;
            }
        }

        if (matchFound) {
            success = true;
            logs.push('🎉 検証成功: 親の DS と子の DNSKEY が正しく紐付いています！');
        } else {
            logs.push('❌ 検証失敗: 一致する鍵の組み合わせが見つかりませんでした。信頼の連鎖が切れています。');
        }

        res.json({ success, logs });

    } catch (err) {
        const errorMsg = `🔴 予期しないエラーが発生しました: ${err.message}`;
        logs.push(errorMsg);
        res.status(500).json({ error: errorMsg, logs });
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
            body { font-family: sans-serif; margin: 0; padding: 20px; background: #f4f6f9; color: #333; }
            .card { max-width: 800px; margin: 0 auto; padding: 25px; background: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; color: #34495e; }
            input[type="text"] { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #bdc3c7; border-radius: 6px; font-size: 14px; }
            input[type="text"]:focus { border-color: #3498db; outline: none; }
            button { background: #007bff; color: white; border: none; padding: 8px 25px; margin-bottom: 20px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; transition: background 0.2s; }
            button:hover { background: #0056b3; }

            /* 説明表示用の枠スタイル */
            .explanation-title { font-weight: bold; margin-bottom: 5px; color: #7f8c8d; }
            .explanation-box { background: #f0f0f0; padding: 15px; border-radius: 6px; border-left: 6px solid; border-color: #a0a0a0; font-size: 14px; }

            /* 結果表示用の枠スタイル */
            .result-status-box { padding: 15px 20px; border-radius: 6px; font-size: 18px; font-weight: bold; margin-top: 25px; display: none; border-left: 6px solid; }
            .status-loading { background-color: #ebf5fb; color: #2980b9; border-color: #3498db; }
            .status-success { background-color: #e8f8f5; color: #117a65; border-color: #2ecc71; }
            .status-failed { background-color: #fce4d6; color: #c0392b; border-color: #e74c3c; }

            /* 詳細ログの枠スタイル */
            .log-title { font-weight: bold; margin-top: 20px; margin-bottom: 5px; color: #7f8c8d; display: none; }
            .log-box {
                background: #f0f0f0; padding: 15px; border-radius: 6px; border-left: 6px solid; border-color: #a0a0a0;
                font-family: 'Courier New', monospace; font-size: 13px; margin-top: 5px; display: none; white-space: pre; overflow-x: scroll;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🔒 DNSSEC委任状態検証ツール</h2>

            <!-- 入力欄とボタンを <form> タグで囲み、onsubmitイベントを設定 -->
            <form id="validateForm" onsubmit="validate(event)">
              <div class="form-group">
                <label>検証するドメイン名</label>
                <input type="text" id="domain" placeholder="example.com" autofocus>
              </div>
              <!-- ボタンのtypeをsubmitに変更 -->
              <button type="submit">検証スタート</button>
            </form>

            <!-- 説明の枠 -->
            <div id="explanationTitle" class="explanation-title">📋 説明</div>
            <div id="explanationBox" class="explanation-box">
                <a href="https://jprs.jp/glossary/index.php?ID=0158">フルサービスリゾルバー</a>のように、入力された
                <a href="https://jprs.jp/glossary/index.php?ID=0083">ドメイン名</a>に関する親 (上位) の
                <a href="https://jprs.jp/glossary/index.php?ID=0145">権威サーバー</a>を
                <a href="https://jprs.jp/glossary/index.php?ID=0148">ルート</a>から辿って探し出し、
                <a href="https://jprs.jp/glossary/index.php?ID=0213">DSレコード</a>を取得して、当該ドメイン名の権威サーバーが持つ DNSKEY と照合します。
            </div>

            <!-- 判定結果を伝える専用の別枠 -->
            <div id="statusBox" class="result-status-box"></div>

            <!-- 詳細ログの枠 -->
            <div id="logTitle" class="log-title">📋 詳細ログ</div>
            <div id="resultLogs" class="log-box"></div>
        </div>

        <script>
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams) {
                document.getElementById('domain').value = urlParams.get('domain');
            }

            async function validate(event) {
                // 画面が勝手にリロード（ページ遷移）するのを防ぐ
                event.preventDefault();

                let domain = document.getElementById('domain').value.trim();
                const statusBox = document.getElementById('statusBox');
                const logTitle = document.getElementById('logTitle');
                const resLogs = document.getElementById('resultLogs');
                const explanationTitle = document.getElementById('explanationTitle');
                const explanationBox = document.getElementById('explanationBox');

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
                statusBox.innerText = '⏳ 検証中... (権威サーバーへ直接クエリを送信しています)';

                logTitle.style.display = 'none';
                resLogs.style.display = 'none';

                explanationTitle.style.display = 'none';
                explanationBox.style.display = 'none';

                try {
                    const response = await fetch('./api/validate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain })
                    });
                    const data = await response.json();

                    // 詳細ログ枠の表示
                    logTitle.style.display = 'block';
                    resLogs.style.display = 'block';

                    if (data.error) {
                        statusBox.className = 'result-status-box status-failed';
                        statusBox.innerText = '❌ エラーが発生しました';
                        resLogs.innerText = data.error;
                    } else {
                        // 2. バックエンドの判定（success: true/false）に基づいて枠を切り替える
                        if (data.success) {
                            statusBox.className = 'result-status-box status-success';
                            statusBox.innerText = '🎉 検証成功: DNSSEC の委任状態は問題ありません！';
                        } else {
                            statusBox.className = 'result-status-box status-failed';
                            statusBox.innerText = '❌ 検証失敗: 信頼の連鎖が切れています';
                        }
                        // 詳細ログを下の暗いボックスへ流し込む
                        resLogs.innerText = data.logs.join('\\n');
                    }
                } catch(e) {
                    statusBox.className = 'result-status-box status-failed';
                    statusBox.innerText = '❌ 通信エラーが発生しました';
                    resLogs.innerText = e.message;
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
