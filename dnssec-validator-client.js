const domainInput = document.getElementById('domain');
const savedDomainKey = 'dnssec-validator-domain';
const domainFromUrl = new URLSearchParams(window.location.search).get('domain');
const MAX_DISPLAY_TEXT_LENGTH = 2000;

function sanitizeDisplayText(value) {
    const text = (value === null || value === undefined ? '' : String(value))
        .replace(/[\u0000-\u0009\u000B-\u001F\u007F]+/g, ' ')
        .replace(/[^\S\r\n]+/g, ' ')
        .trim();
    return text.slice(0, MAX_DISPLAY_TEXT_LENGTH);
}

function sanitizeDisplayLines(value) {
    return (Array.isArray(value) ? value : [value]).map(sanitizeDisplayText);
}

try {
    domainInput.value = sanitizeDisplayText(domainFromUrl || localStorage.getItem(savedDomainKey) || '');
} catch (error) {
    domainInput.value = sanitizeDisplayText(domainFromUrl || '');
}

domainInput.addEventListener('input', () => {
    try { localStorage.setItem(savedDomainKey, sanitizeDisplayText(domainInput.value)); } catch (error) { }
});

const dnssecAlgorithmNames = { 1: 'RSAMD5', 5: 'RSASHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448' };
const algorithmText = algorithm => 'alg ' + algorithm + ' (' + (dnssecAlgorithmNames[algorithm] || 'Unknown') + ')';
const keyText = (records, role) => !records || records.length === 0 ? [role + ': 取得できませんでした'] : records.map(record => role + ' / Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm));
const dsText = records => !records || records.length === 0 ? ['取得できませんでした'] : records.map(record => 'Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm) + ' / digest ' + record.digest);
const rrsigText = records => !records || records.length === 0 ? ['取得できませんでした'] : records.map(record => 'RRSIG ' + record.typeCovered + ' / Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm) + ' -> 署名検証: ' + (record.verified === true ? '成功 ✓' : record.verified === false ? '失敗 ✕' : '未検証'));
const aRecordValidationText = validation => {
    if (!validation || !validation.queried) return ['入力名はゾーン頂点です（検証不要）'];
    if (validation.error) return ['検証できませんでした: ' + validation.error];
    if (!validation.recordsFound) {
        const proof = validation.denialProof;
        if (proof && proof.type) {
            const proofKind = proof.rcode === 'NXDOMAIN' ? '名前不在' : 'Aレコード不在';
            return [proof.type + ' による ' + proofKind + '証明: ' + (proof.verified ? '成功 ✓' : '失敗 ✕'), proof.keyTag ? 'RRSIG ' + proof.type + ' / Key Tag ' + proof.keyTag + ' / ' + algorithmText(proof.algorithm) : '対応する RRSIG が見つかりませんでした'];
        }
        const diagnostics = proof && proof.diagnostics ? proof.diagnostics : [];
        const observedNsec = proof && proof.observedNsec ? proof.observedNsec : [];
        const observedNsec3 = proof && proof.observedNsec3 ? proof.observedNsec3 : [];
        const nsecLines = observedNsec.map(record => '応答 NSEC: ' + record.name + ' -> ' + record.nextDomain);
        const nsec3Lines = observedNsec3.map(record => '応答 NSEC3: ' + record.ownerHash + ' -> ' + record.nextHash + ' / iteration ' + record.iterations + ' / salt ' + record.salt);
        return ['Aレコードの探索: 失敗 ✕', 'NSEC/NSEC3 による不在証明: 失敗 ✕'].concat(diagnostics, nsecLines, nsec3Lines);
    }
    if (validation.signatures.length === 0) return ['Aレコードへの RRSIG の探索: 失敗 ✕'];
    const trustChain = validation.trustChain || {};
    const kskKeyTags = trustChain.dsMatchedKskKeyTags || [];
    const dnskeySignatures = trustChain.dnskeyRrsetSignatures || [];
    const lines = [
        'DS -> KSK: ' + (kskKeyTags.length ? 'Key Tag ' + kskKeyTags.join(', ') + ' が一致 ✓' : '一致する KSK なし ✕'),
        'KSK -> DNSKEY RRset: ' + (dnskeySignatures.length ? dnskeySignatures.map(signature => 'Key Tag ' + signature.kskKeyTag).join(', ') + ' による署名検証: 成功 ✓' : 'DS一致 KSK による署名検証: 失敗 ✕')
    ];
    return lines.concat(validation.signatures.map(signature => 'ZSK -> A RRset: RRSIG A / Key Tag ' + signature.keyTag + ' / ' + algorithmText(signature.algorithm) + ' -> ' + (signature.trustChainVerified ? '信頼の連鎖: 成功 ✓' : '信頼の連鎖: 失敗 ✕')));
};

function setNodeContent(nodeId, title, titleColor, lines) {
    const node = document.getElementById(nodeId);
    node.replaceChildren();
    const titleElement = document.createElement('div');
    titleElement.className = 'node-title';
    if (titleColor) titleElement.style.color = titleColor;
    titleElement.textContent = sanitizeDisplayText(title);
    const metaElement = document.createElement('div');
    metaElement.className = 'node-meta';
    sanitizeDisplayLines(lines).forEach((line, index) => {
        if (index > 0) metaElement.appendChild(document.createElement('br'));
        const failedLabel = '失敗 ✕';
        const failedLabelIndex = line.indexOf(failedLabel);
        if (failedLabelIndex === -1) {
            metaElement.appendChild(document.createTextNode(line));
            return;
        }
        metaElement.appendChild(document.createTextNode(line.slice(0, failedLabelIndex)));
        const failedElement = document.createElement('span');
        failedElement.className = 'signature-failed';
        failedElement.textContent = failedLabel;
        metaElement.append(failedElement, document.createTextNode(line.slice(failedLabelIndex + failedLabel.length)));
    });
    node.append(titleElement, metaElement);
}

function emptyDiagram(domain) {
    return { parent: { name: domain, server: '', ds: [], rrsig: [], dnskey: [] }, child: { name: domain, server: '', dnskey: [], rrsig: [], aRecordValidation: null }, checks: { dsSignature: false, dnskeySignature: false, dsKeyMatch: false } };
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
    setNodeContent('childARecordValidation', '参考：ドメイン名に対する Aレコード DNSSEC検証', '', aRecordValidationText(diagram.child.aRecordValidation));
    const chainArrow = document.getElementById('chainArrow');
    chainArrow.className = 'arrow chain-arrow ' + (diagram.checks.dsKeyMatch ? 'good' : 'bad');
    chainArrow.replaceChildren();
    const chainLabel = document.createElement('span');
    chainLabel.textContent = (diagram.checks.dsKeyMatch ? 'ハッシュ一致 ✓' : 'ハッシュ不一致 ✕') + '\nDS -> KSK';
    chainLabel.style.whiteSpace = 'pre-line';
    chainArrow.appendChild(chainLabel);
    document.getElementById('diagram').style.display = 'block';
}

async function validate(event) {
    event.preventDefault();
    let domain = domainInput.value.trim();
    const statusBox = document.getElementById('statusBox');
    const errorDetailsElement = document.getElementById('validation-error-details');
    try { const url = new URL(domain); if (url.hostname) domain = url.hostname; } catch (error) { }
    if (!domain) return alert('ドメイン名を入力してください');
    statusBox.style.display = 'block';
    statusBox.className = 'result-status-box status-loading';
    statusBox.innerText = '検証中... (権威サーバーへ直接クエリを送信しています)';
    errorDetailsElement.style.display = 'none';
    errorDetailsElement.textContent = '';
    renderDiagram(emptyDiagram(domain));
    try {
        const response = await fetch('./api/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }) });
        const data = await response.json();
        if (data.error) {
            statusBox.className = 'result-status-box status-failed';
            statusBox.innerText = 'エラーが発生しました';
            errorDetailsElement.textContent = sanitizeDisplayText([data.error, ...(data.logs || [])].join('\n'));
            errorDetailsElement.style.display = 'block';
            renderDiagram(data.diagram || emptyDiagram(domain));
        } else {
            statusBox.className = 'result-status-box ' + (data.success ? 'status-success' : 'status-failed');
            statusBox.innerText = data.success ? '検証成功: DNSSEC の委任状態は問題ありません！' : '検証失敗: 信頼の連鎖が切れています';
            if (data.logs && data.logs.length > 0) { errorDetailsElement.textContent = sanitizeDisplayText(data.logs.join('\n')); errorDetailsElement.style.display = 'block'; }
            if (data.diagram) renderDiagram(data.diagram);
        }
    } catch (error) {
        statusBox.className = 'result-status-box status-failed';
        statusBox.innerText = '通信エラーが発生しました';
        errorDetailsElement.textContent = sanitizeDisplayText('詳細: ' + (error && error.message ? error.message : String(error)));
        errorDetailsElement.style.display = 'block';
        renderDiagram(emptyDiagram(domain));
    }
}

document.getElementById('validateForm').addEventListener('submit', validate);