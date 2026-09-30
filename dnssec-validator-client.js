const domainInput = document.getElementById('domain');
const recordTypeInput = document.getElementById('recordType');
const savedDomainKey = 'dnssec-validator-domain';
const urlParameters = new URLSearchParams(window.location.search);
const domainFromUrl = urlParameters.get('domain');
const recordTypeFromUrl = (urlParameters.get('recordType') || '').toUpperCase();
const MAX_DISPLAY_TEXT_LENGTH = 2000;
const RRSIG_EXPIRY_WARNING_SECONDS = 7 * 24 * 60 * 60;

if ([...recordTypeInput.options].some(option => option.value === recordTypeFromUrl)) {
    recordTypeInput.value = recordTypeFromUrl;
}

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

const dnssecAlgorithmNames = { 1: 'RSAMD5', 5: 'RSASHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448', 18: 'ML-DSA-44' };
const algorithmText = algorithm => 'alg ' + algorithm + ' (' + (dnssecAlgorithmNames[algorithm] || 'Unknown') + ')';
const keyText = (records, role) => !records || records.length === 0 ? [role + ': 取得できませんでした'] : records.map(record => role + ' / Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm));
const dsText = records => !records || records.length === 0 ? ['取得できませんでした'] : records.map(record => 'Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm) + ' / digest ' + record.digest);
function rrsigExpirationText(expiration) {
    if (!Number.isFinite(expiration)) return '';
    const remainingSeconds = expiration - Math.floor(Date.now() / 1000);
    const expirationDate = new Intl.DateTimeFormat('ja-JP', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'Asia/Tokyo' }).format(new Date(expiration * 1000));
    let remainingText;
    if (remainingSeconds <= 0) {
        remainingText = '期限切れ';
    } else {
        const totalMinutes = Math.ceil(remainingSeconds / 60);
        const days = Math.floor(totalMinutes / 1440);
        const hours = Math.floor((totalMinutes % 1440) / 60);
        const minutes = totalMinutes % 60;
        remainingText = '残り ' + (days ? days + '日 ' : '') + (hours ? hours + '時間 ' : '') + minutes + '分';
    }
    const warning = remainingSeconds > 0 && remainingSeconds <= RRSIG_EXPIRY_WARNING_SECONDS
        ? ' / 期限間近（7日以内）: 更新状況を確認してください'
        : '';
    return ' / 期限日時 ' + expirationDate + ' JST / ' + remainingText + warning;
}
const rrsigText = records => !records || records.length === 0 ? ['取得できませんでした'] : records.map(record => 'RRSIG ' + record.typeCovered + ' / Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm) + ' -> 署名検証: ' + (record.verified === true ? '成功 ✓' : record.verified === false ? '失敗 ✕' : '未検証') + rrsigExpirationText(record.expiration));
const aRecordValidationText = validation => {
    if (!validation || !validation.queried) return ['検証データを取得できませんでした'];
    const recordType = validation.recordType || 'A';
    if (validation.error) return ['検証できませんでした: ' + validation.error];
    if (!validation.recordsFound) {
        const proof = validation.denialProof;
        if (proof && proof.type) {
            const proofKind = proof.rcode === 'NXDOMAIN' ? '名前不在' : `${recordType}レコード不在`;
            const signatureLines = (proof.records || []).map(record => record.type + ' ' + record.name + rrsigExpirationText(record.expiration));
            const fallbackLine = proof.keyTag
                ? 'RRSIG ' + proof.type + ' / Key Tag ' + proof.keyTag + ' / ' + algorithmText(proof.algorithm) + rrsigExpirationText(proof.expiration)
                : '対応するRRSIGが見つかりませんでした';
            return [proof.type + 'による' + proofKind + '証明: ' + (proof.verified ? '成功 ✓' : '失敗 ✕'), ...(signatureLines.length ? signatureLines : [fallbackLine])];
        }
        const diagnostics = proof && proof.diagnostics ? proof.diagnostics : [];
        const observedNsec = proof && proof.observedNsec ? proof.observedNsec : [];
        const observedNsec3 = proof && proof.observedNsec3 ? proof.observedNsec3 : [];
        const nsecLines = observedNsec.map(record => '応答NSEC: ' + record.name + ' -> ' + record.nextDomain);
        const nsec3Lines = observedNsec3.map(record => '応答NSEC3: ' + record.ownerHash + ' -> ' + record.nextHash + ' / iteration ' + record.iterations + ' / salt ' + record.salt);
        return [`${recordType}レコードの探索: 失敗 ✕`, 'NSEC/NSEC3による不在証明: 失敗 ✕'].concat(diagnostics, nsecLines, nsec3Lines);
    }
    if (validation.signatures.length === 0) return [`${recordType}レコードへのRRSIGの探索: 失敗 ✕`];
    const trustChain = validation.trustChain || {};
    const kskKeyTags = trustChain.dsMatchedKskKeyTags || [];
    const dnskeySignatures = trustChain.dnskeyRrsetSignatures || [];
    const lines = [
        'DS -> KSK: ' + (kskKeyTags.length ? 'Key Tag' + kskKeyTags.join(', ') + 'が一致 ✓' : '一致するKSKなし ✕'),
        'KSK -> DNSKEY RRset: ' + (dnskeySignatures.length ? dnskeySignatures.map(signature => 'Key Tag' + signature.kskKeyTag).join(', ') + 'による署名検証: 成功 ✓' : 'DS一致KSKによる署名検証: 失敗 ✕')
    ];
    return lines.concat(validation.signatures.map(signature => {
        const result = signature.verified === false
            ? '署名検証: 失敗 ✕'
            : signature.trustChainVerified
                ? '信頼の連鎖: 成功 ✓'
                : '信頼の連鎖: 失敗 ✕';
        const line = 'ZSK -> ' + recordType + ' RRset: RRSIG ' + recordType + ' / Key Tag ' + signature.keyTag + ' / ' + algorithmText(signature.algorithm) + ' -> ' + result;
        const lineWithExpiration = line + rrsigExpirationText(signature.expiration);
        return signature.verified === false && signature.reason ? [lineWithExpiration, '失敗理由: ' + signature.reason] : [lineWithExpiration];
    }).flat());
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
        const parts = line.split(/(失敗 ✕|期限間近（7日以内）)/g);
        for (const part of parts) {
            if (part === '失敗 ✕' || part === '期限間近（7日以内）') {
                const marker = document.createElement('span');
                marker.className = part === '失敗 ✕' ? 'signature-failed' : 'signature-expiring';
                marker.textContent = part;
                metaElement.appendChild(marker);
            } else {
                metaElement.appendChild(document.createTextNode(part));
            }
        }
    });
    node.append(titleElement, metaElement);
}

function emptyDiagram(domain) {
    return { parent: { name: domain, server: '', ds: [], rrsig: [], dnskey: [], dsAbsenceProof: null }, child: { name: domain, server: '', dnskey: [], rrsig: [], aRecordValidation: null }, checks: { dsSignature: false, dnskeySignature: false, dsKeyMatch: false }, authorityChecks: null, dsProposal: null };
}

function renderDsProposal(diagnosis) {
    const section = document.getElementById('dsProposal');
    const content = document.getElementById('dsProposalContent');
    content.replaceChildren();
    section.style.display = diagnosis ? 'block' : 'none';
    if (!diagnosis) return;
    const formatDs = record => 'Key Tag ' + record.keyTag + ' / ' + algorithmText(record.algorithm) + ' / digest type ' + record.digestType + ' / ' + record.digest;
    const addLine = text => {
        const line = document.createElement('p');
        line.textContent = sanitizeDisplayText(text);
        content.appendChild(line);
    };
    addLine('親に登録されたDS: ' + (diagnosis.parentDs.length ? diagnosis.parentDs.map(formatDs).join('、') : diagnosis.cds ? 'なし' : '未確認'));
    for (const [label, comparison] of [['CDS', diagnosis.cds], ['CDNSKEYから算出したDS', diagnosis.cdnskey]]) {
        if (!comparison) continue;
        const status = { match: '親DSと一致', different: '親DSと差分あり', absent: '提案なし', delete: '親のDS RRset全体の削除要求', error: '取得・解析失敗' };
        addLine(label + ': ' + status[comparison.status] + (comparison.error ? ' (' + comparison.error + ')' : ''));
        if (comparison.status === 'different') {
            for (const record of comparison.toAdd) addLine('  子の提案のみ: ' + formatDs(record));
            for (const record of comparison.toRemove) addLine('  親の登録のみ: ' + formatDs(record));
        }
    }
    for (const note of diagnosis.notes || []) addLine(note);
}

function renderAuthorityComparisons(authorityChecks) {
    const section = document.getElementById('authorityChecks');
    const tableBody = document.getElementById('authorityChecksBody');
    tableBody.replaceChildren();
    if (!authorityChecks) {
        section.style.display = 'none';
        return;
    }

    const groups = [
        ['親の委任NS RRset', authorityChecks.parent && authorityChecks.parent.nameservers],
        ['親のDS RRset', authorityChecks.parent && authorityChecks.parent.ds],
        ['子の権威NS RRset', authorityChecks.child && authorityChecks.child.nameservers],
        ['子のDNSKEY RRset', authorityChecks.child && authorityChecks.child.dnskey]
    ];
    for (const [title, comparison] of groups) {
        if (!comparison) continue;
        const groupRow = document.createElement('tr');
        groupRow.className = 'authority-group-row';
        const groupCell = document.createElement('th');
        groupCell.scope = 'rowgroup';
        groupCell.textContent = title;
        const statusCell = document.createElement('td');
        const status = comparison.hasDifferences
            ? 'サーバー間に差分あり'
            : comparison.complete && comparison.consistent
                ? '全台の応答一致'
                : '一部未確認';
        statusCell.className = comparison.hasDifferences ? 'authority-status status-difference' : comparison.complete && comparison.consistent ? 'authority-status status-consistent' : 'authority-status status-incomplete';
        statusCell.textContent = status;
        groupCell.colSpan = 2;
        groupRow.append(groupCell, statusCell);
        tableBody.appendChild(groupRow);

        for (const server of comparison.servers || []) {
            const row = document.createElement('tr');
            const nameCell = document.createElement('td');
            nameCell.textContent = sanitizeDisplayText(server.name);
            const addressCell = document.createElement('td');
            addressCell.textContent = sanitizeDisplayText(server.ip || '未取得');
            const recordsCell = document.createElement('td');
            recordsCell.textContent = server.status === 'error'
                ? '取得失敗: ' + sanitizeDisplayText(server.error)
                : (server.records && server.records.length ? sanitizeDisplayLines(server.records).join('、') : '該当RRsetなし') + (server.rcode ? ' / ' + sanitizeDisplayText(server.rcode) : '');
            row.append(nameCell, addressCell, recordsCell);
            tableBody.appendChild(row);
        }
    }
    section.style.display = 'block';
}

function renderDiagram(diagram) {
    renderAuthorityComparisons(diagram.authorityChecks);
    renderDsProposal(diagram.dsProposal);
    const parentKey = diagram.parent.dnskey.filter(key => key.flags === 256);
    const childKsk = diagram.child.dnskey.filter(key => key.flags === 257);
    document.getElementById('parentZoneTitle').textContent = '親ゾーン / 委任元 (' + (diagram.parent.server || '権威サーバー未確認') + ')';
    document.getElementById('childZoneTitle').textContent = '子ゾーン / 委任先 (' + (diagram.child.server || '権威サーバー未確認') + ')';
    document.getElementById('zoneApexSummary').textContent = 'ゾーン頂点：' + (diagram.parent.name || diagram.child.name || '未確認');
    setNodeContent('parentKey', 'DNSKEY', '', [...keyText(parentKey, 'ZSK'), '※DSの署名検証用公開鍵(ZSKの秘密鍵はゾーンのRRsetへの署名に使われる)']);
    setNodeContent('parentRrsig', 'RRSIG', '', [...rrsigText(diagram.parent.rrsig), '※DSを対象とする電子署名']);
    const dsAbsenceProof = diagram.parent.dsAbsenceProof;
    const parentDsLines = diagram.parent.ds && diagram.parent.ds.length > 0
        ? dsText(diagram.parent.ds)
        : dsAbsenceProof
            ? [dsAbsenceProof.verified ? 'DSなし（親側不在証明: 検証成功）' : 'DSなし（親側不在証明: 未確認）', ...(dsAbsenceProof.type ? (dsAbsenceProof.records || []).map(record => record.type + ' ' + record.name + rrsigExpirationText(record.expiration)) : []), ...(dsAbsenceProof.diagnostics || [])]
            : dsText(diagram.parent.ds);
    setNodeContent('parentDs', 'DS', 'blue', [...parentDsLines, '※子KSKのハッシュ値']);
    setNodeContent('childKey', 'DNSKEY', 'blue', [...keyText(childKsk, 'KSK'), '※DNSKEY(KSK/ZSK)の署名検証用公開鍵(KSKの秘密鍵はDNSKEY RRsetへの署名に使われる)']);
    setNodeContent('childRrsig', 'RRSIG', '', [...rrsigText(diagram.child.rrsig), '※DNSKEY (KSK/ZSK) を対象とする電子署名']);
    const recordType = diagram.child.aRecordValidation && diagram.child.aRecordValidation.recordType || 'A';
    setNodeContent('childARecordValidation', 'ドメイン名に対する' + recordType + 'レコードDNSSEC検証', '', aRecordValidationText(diagram.child.aRecordValidation));
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
        const response = await fetch('./api/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain, recordType: recordTypeInput.value }) });
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            const bodyText = await response.text();
            throw new Error(`サーバーから予期しない応答がありました (HTTP ${response.status})。プロキシ/ゲートウェイのタイムアウトなどが考えられます。`, { cause: bodyText });
        }
        const data = await response.json();
        if (data.error) {
            statusBox.className = 'result-status-box status-indeterminate';
            statusBox.innerText = data.statusLabel || '判定不能（エラー）';
            errorDetailsElement.textContent = sanitizeDisplayText([data.error, ...(data.logs || []), ...(data.nextChecks || [])].join('\n'));
            errorDetailsElement.style.display = 'block';
            renderDiagram(data.diagram || emptyDiagram(domain));
        } else {
            const statusClasses = { secure: 'status-success', insecure: 'status-insecure', bogus: 'status-failed', indeterminate: 'status-indeterminate' };
            statusBox.className = 'result-status-box ' + (statusClasses[data.status] || 'status-indeterminate');
            statusBox.innerText = data.statusLabel || (data.success ? 'Secure（検証成功）' : '判定不能');
            const detailLines = [...(data.logs || []), ...(data.status !== 'secure' ? data.nextChecks || [] : [])];
            if (detailLines.length > 0) { errorDetailsElement.textContent = sanitizeDisplayText(detailLines.join('\n')); errorDetailsElement.style.display = 'block'; }
            if (data.diagram) renderDiagram(data.diagram);
        }
    } catch (error) {
        statusBox.className = 'result-status-box status-indeterminate';
        statusBox.innerText = '判定不能（通信エラー）';
        errorDetailsElement.textContent = sanitizeDisplayText('詳細: ' + (error && error.message ? error.message : String(error)) + '\n権威サーバーへの疎通を確認し、時間をおいて再試行してください。');
        errorDetailsElement.style.display = 'block';
        renderDiagram(emptyDiagram(domain));
    }
}

document.getElementById('validateForm').addEventListener('submit', validate);
if (domainInput.value) {
    document.getElementById('validateForm').dispatchEvent(new Event('submit', { cancelable: true }));
}