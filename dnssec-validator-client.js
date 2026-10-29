const domainInput = document.getElementById('domain');
const recordTypeInput = document.getElementById('recordType');
const savedDomainKey = 'dnssec-validator-domain';
const urlParameters = new URLSearchParams(window.location.search);
const domainFromUrl = urlParameters.get('domain');
const recordTypeFromUrl = (urlParameters.get('recordType') || '').toUpperCase();
const isEnglish = urlParameters.get('lang') === 'en';
const MAX_DISPLAY_TEXT_LENGTH = 2000;
const RRSIG_EXPIRY_WARNING_SECONDS = 7 * 24 * 60 * 60;

function translate(value) {
    let text = String(value ?? '');
    if (!isEnglish) return text;
    text = text.replace(/(NSEC\/NSEC3|NSEC3?|DS)による(.+?)証明: (成功 ✓|失敗 ✕)/g, (_match, proofType, kind, result) => {
        const proofTarget = kind === '名前不在' ? 'absence of name' : kind.replace(/レコード不在/g, ' record absence');
        return `${proofType} proof for ${proofTarget}: ${result === '成功 ✓' ? 'Passed ✓' : 'Failed ✕'}`;
    });
    text = text.replace(/([A-Z]+)レコードへのRRSIGの探索: 失敗 ✕/g, 'No RRSIG found for $1 record: Failed ✕');
    text = text.replace(/([A-Z]+)レコードの探索: 失敗 ✕/g, 'No $1 record found: Failed ✕');
    const replacements = [
        ['検証データを取得できませんでした', 'Could not retrieve validation data'],
        ['検証できませんでした', 'Validation failed'],
        ['取得できませんでした', 'Could not retrieve'],
        ['期限間近（7日以内）: 更新状況を確認してください', 'Expiring within 7 days: check renewal'],
        ['※DSの署名検証用公開鍵(ZSKの秘密鍵はゾーンのRRsetへの署名に使われる)', 'Public key used to verify DS signatures (the ZSK private key signs zone RRsets).'],
        ['※DSを対象とする電子署名', 'Signature covering DS records'],
        ['※子KSKのハッシュ値', 'Hash of the child KSK'],
        ['※DNSKEY(KSK/ZSK)の署名検証用公開鍵(KSKの秘密鍵はDNSKEY RRsetへの署名に使われる)', 'Public key used to verify DNSKEY signatures (the KSK private key signs the DNSKEY RRset).'],
        ['※DNSKEY (KSK/ZSK) を対象とする電子署名', 'Signature covering the DNSKEY (KSK/ZSK) RRset'],
        ['DSなし（ハッシュ照合対象なし）', 'No DS (nothing to compare)'],
        ['DSなし（親側不在証明: ', 'No DS (parent-side proof of absence: '],
        ['DSなし', 'No DS'],
        ['親側不在証明', 'parent-side proof of absence'],
        ['検証成功', 'Validation succeeded'],
        ['検証失敗', 'Validation failed'],
        ['署名検証: 成功', 'Signature verification: passed'],
        ['署名検証: 失敗', 'Signature verification: failed'],
        ['信頼の連鎖: 成功', 'Chain of trust: secure'],
        ['信頼の連鎖: 失敗', 'Chain of trust: failed'],
        ['DS一致KSKによる署名検証: 失敗', 'Signature verification by DS-matched KSK: failed'],
        ['による署名検証: 成功', ' signature verification: passed'],
        ['による署名検証: 失敗', ' signature verification: failed'],
        ['一致するKSKなし', 'no matching KSK'],
        ['が一致 ✓', ' matches ✓'],
        ['一致 ✕', 'does not match ✕'],
        ['成功 ✓', 'Passed ✓'],
        ['失敗 ✕', 'Failed ✕'],
        ['未検証', 'Not verified'],
        ['未確認', 'Not checked'],
        ['不整合', 'Inconsistent'],
        ['期限切れ', 'Expired'],
        ['期限日時 ', 'Expiration: '],
        ['残り ', 'Remaining '],
        ['ドメイン名に対する', 'DNSSEC validation for '],
        ['レコードDNSSEC検証', ' record'],
        ['レコードの探索', 'record lookup'],
        ['レコードへの', 'record '],
        ['レコード不在', 'record does not exist'],
        ['名前不在', 'name does not exist'],
        ['による', ' using '],
        ['証明:', ' proof:'],
        ['証明が不足しています', 'The proof is incomplete'],
        ['応答NSEC3:', 'Observed NSEC3:'],
        ['応答NSEC:', 'Observed NSEC:'],
        ['iteration ', 'iterations '],
        ['署名検証', 'Signature verification'],
        ['信頼の連鎖', 'Chain of trust'],
        ['失敗理由:', 'Failure reason:'],
        ['対応するRRSIGが見つかりませんでした', 'No matching RRSIG found'],
        ['親に登録されたDS', 'DS registered with parent'],
        ['親DSと一致', 'Matches parent DS'],
        ['親DSと差分あり', 'Differs from parent DS'],
        ['提案なし', 'No proposal'],
        ['親のDS RRset全体の削除要求', 'Request to delete the entire parent DS RRset'],
        ['取得・解析失敗', 'Retrieval/parsing failed'],
        ['子の提案のみ', 'Proposed by child only'],
        ['親の登録のみ', 'Registered with parent only'],
        ['親の委任NS RRset', 'Parent delegated NS RRset'],
        ['親のDS RRset', 'Parent DS RRset'],
        ['子の権威NS RRset', 'Child authoritative NS RRset'],
        ['子のDNSKEY RRset', 'Child DNSKEY RRset'],
        ['サーバー間に差分あり', 'Differences between servers'],
        ['全台の応答一致', 'All responses match'],
        ['一部未確認', 'Some responses not checked'],
        ['取得失敗:', 'Retrieval failed:'],
        ['未取得', 'Not retrieved'],
        ['該当RRsetなし', 'No matching RRset'],
        ['権威サーバー未確認', 'authoritative server not checked'],
        ['ゾーン頂点：', 'Zone apex: '],
        ['親ゾーン / 委任元', 'Parent zone / Delegating zone'],
        ['子ゾーン / 委任先', 'Child zone / Delegated zone'],
        ['ハッシュ一致', 'Hash matches'],
        ['ハッシュ不一致', 'Hash mismatch'],
        ['ハッシュ照合対象なし', 'nothing to compare'],
        ['Key Tag', 'Key Tag'],
        ['詳細:', 'Details: ']
    ];
    for (const [japanese, english] of replacements) text = text.replaceAll(japanese, english);
    text = text.replace(/期限日時 (.*?) JST/g, 'Expiration: $1 JST');
    text = text.replace(/([0-9]+)日/g, '$1d');
    text = text.replace(/([0-9]+)時間/g, '$1h');
    text = text.replace(/([0-9]+)分/g, '$1m');
    return text;
}

if (isEnglish) {
    document.documentElement.lang = 'en';
    document.title = 'DNSSEC Delegation Validator';
    document.getElementById('englishNote').hidden = false;
    document.querySelectorAll('[data-en]').forEach(element => {
        element.textContent = element.dataset.en;
    });
    const languageLink = document.getElementById('languageLink');
    const japaneseUrl = new URL(window.location.href);
    japaneseUrl.searchParams.delete('lang');
    languageLink.href = `${japaneseUrl.pathname}${japaneseUrl.search}${japaneseUrl.hash}`;
    languageLink.textContent = '日本語';
    languageLink.setAttribute('aria-label', 'Switch to Japanese');
} else {
    const englishUrl = new URL(window.location.href);
    englishUrl.searchParams.set('lang', 'en');
    const languageLink = document.getElementById('languageLink');
    languageLink.href = `${englishUrl.pathname}${englishUrl.search}${englishUrl.hash}`;
    languageLink.setAttribute('aria-label', 'Switch to English');
}

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
const rrsigDateFormatter = new Intl.DateTimeFormat(isEnglish ? 'en-US' : 'ja-JP', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'Asia/Tokyo' });
function rrsigExpirationText(expiration) {
    if (!Number.isFinite(expiration)) return '';
    const remainingSeconds = expiration - Math.floor(Date.now() / 1000);
    const expirationDate = rrsigDateFormatter.format(new Date(expiration * 1000));
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
    titleElement.textContent = sanitizeDisplayText(translate(title));
    const metaElement = document.createElement('div');
    metaElement.className = 'node-meta';
    sanitizeDisplayLines(lines).map(translate).forEach((line, index) => {
        if (index > 0) metaElement.appendChild(document.createElement('br'));
        const parts = line.split(isEnglish ? /(Failed ✕|Expiring within 7 days: check renewal)/g : /(失敗 ✕|期限間近（7日以内）)/g);
        for (const part of parts) {
            if (part === '失敗 ✕' || part === '期限間近（7日以内）' || part === 'Failed ✕' || part === 'Expiring within 7 days: check renewal') {
                const marker = document.createElement('span');
                marker.className = part === '失敗 ✕' || part === 'Failed ✕' ? 'signature-failed' : 'signature-expiring';
                marker.textContent = part;
                metaElement.appendChild(marker);
            } else {
                metaElement.appendChild(document.createTextNode(part));
            }
        }
    });
    node.append(titleElement, metaElement);
}

function setLabeledIdentifier(elementId, label, value, suffix = '') {
    const element = document.getElementById(elementId);
    const identifier = document.createElement('span');
    identifier.className = 'identifier';
    identifier.textContent = sanitizeDisplayText(value);
    element.replaceChildren(document.createTextNode(translate(label)), identifier, document.createTextNode(translate(suffix)));
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
        line.textContent = sanitizeDisplayText(translate(text));
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
        groupCell.textContent = translate(title);
        const statusCell = document.createElement('td');
        const status = comparison.hasDifferences
            ? 'サーバー間に差分あり'
            : comparison.complete && comparison.consistent
                ? '全台の応答一致'
                : '一部未確認';
        statusCell.className = comparison.hasDifferences ? 'authority-status status-difference' : comparison.complete && comparison.consistent ? 'authority-status status-consistent' : 'authority-status status-incomplete';
        statusCell.textContent = translate(status);
        groupCell.colSpan = 2;
        groupRow.append(groupCell, statusCell);
        tableBody.appendChild(groupRow);

        for (const server of comparison.servers || []) {
            const row = document.createElement('tr');
            const nameCell = document.createElement('td');
            nameCell.className = 'identifier';
            nameCell.textContent = sanitizeDisplayText(server.name);
            const addressCell = document.createElement('td');
            addressCell.className = 'identifier';
            addressCell.textContent = sanitizeDisplayText(translate(server.ip || '未取得'));
            const recordsCell = document.createElement('td');
            recordsCell.textContent = translate(server.status === 'error'
                ? '取得失敗: ' + sanitizeDisplayText(server.error)
                : (server.records && server.records.length ? sanitizeDisplayLines(server.records).join('、') : '該当RRsetなし') + (server.rcode ? ' / ' + sanitizeDisplayText(server.rcode) : ''));
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
    setLabeledIdentifier('parentZoneTitle', '親ゾーン / 委任元 (', diagram.parent.server || '権威サーバー未確認', ')');
    setLabeledIdentifier('childZoneTitle', '子ゾーン / 委任先 (', diagram.child.server || '権威サーバー未確認', ')');
    setLabeledIdentifier('zoneApexSummary', 'ゾーン頂点：', diagram.parent.name || diagram.child.name || '未確認');
    setNodeContent('parentKey', 'DNSKEY', '', [...keyText(parentKey, 'ZSK'), '※DSの署名検証用公開鍵(ZSKの秘密鍵はゾーンのRRsetへの署名に使われる)']);
    setNodeContent('parentRrsig', 'RRSIG', '', [...rrsigText(diagram.parent.rrsig), '※DSを対象とする電子署名']);
    const dsAbsenceProof = diagram.parent.dsAbsenceProof;
    const dsAbsenceStatus = dsAbsenceProof && dsAbsenceProof.verified
        ? '検証成功'
        : dsAbsenceProof && dsAbsenceProof.invalid && dsAbsenceProof.signaturesVerified ? '不整合（検証失敗）' : '未確認';
    const parentDsLines = diagram.parent.ds && diagram.parent.ds.length > 0
        ? dsText(diagram.parent.ds)
        : dsAbsenceProof
            ? ['DSなし（親側不在証明: ' + dsAbsenceStatus + '）', ...(dsAbsenceProof.type ? (dsAbsenceProof.records || []).map(record => record.type + ' ' + record.name + rrsigExpirationText(record.expiration)) : []), ...(dsAbsenceProof.diagnostics || [])]
            : dsText(diagram.parent.ds);
    setNodeContent('parentDs', 'DS', 'blue', [...parentDsLines, '※子KSKのハッシュ値']);
    setNodeContent('childKey', 'DNSKEY', 'blue', [...keyText(childKsk, 'KSK'), '※DNSKEY(KSK/ZSK)の署名検証用公開鍵(KSKの秘密鍵はDNSKEY RRsetへの署名に使われる)']);
    setNodeContent('childRrsig', 'RRSIG', '', [...rrsigText(diagram.child.rrsig), '※DNSKEY (KSK/ZSK) を対象とする電子署名']);
    const recordType = diagram.child.aRecordValidation && diagram.child.aRecordValidation.recordType || 'A';
    setNodeContent('childARecordValidation', 'ドメイン名に対する' + recordType + 'レコードDNSSEC検証', '', aRecordValidationText(diagram.child.aRecordValidation));
    const chainArrow = document.getElementById('chainArrow');
    const hasDsAbsenceProof = dsAbsenceProof && (!diagram.parent.ds || diagram.parent.ds.length === 0);
    chainArrow.className = 'arrow chain-arrow ' + (hasDsAbsenceProof ? '' : diagram.checks.dsKeyMatch ? 'good' : 'bad');
    chainArrow.replaceChildren();
    const chainLabel = document.createElement('span');
    chainLabel.textContent = (hasDsAbsenceProof ? 'DSなし（ハッシュ照合対象なし）' : diagram.checks.dsKeyMatch ? 'ハッシュ一致 ✓' : 'ハッシュ不一致 ✕') + '\nDS -> KSK';
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
    if (!domain) return alert(translate('ドメイン名を入力してください'));
    statusBox.style.display = 'block';
    statusBox.className = 'result-status-box status-loading';
    statusBox.innerText = isEnglish ? 'Validating... (sending queries directly to authoritative servers)' : '検証中... (権威サーバーへ直接クエリを送信しています)';
    errorDetailsElement.style.display = 'none';
    errorDetailsElement.textContent = '';
    renderDiagram(emptyDiagram(domain));
    try {
        const response = await fetch('./api/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain, recordType: recordTypeInput.value }) });
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            const bodyText = await response.text();
            throw new Error(isEnglish
                ? `Unexpected response from server (HTTP ${response.status}). The proxy or gateway may have timed out.`
                : `サーバーから予期しない応答がありました (HTTP ${response.status})。プロキシ/ゲートウェイのタイムアウトなどが考えられます。`, { cause: bodyText });
        }
        const data = await response.json();
        if (data.error) {
            statusBox.className = 'result-status-box status-indeterminate';
            statusBox.innerText = isEnglish ? 'Indeterminate (error)' : data.statusLabel || '判定不能（エラー）';
            const errorLines = [data.error, ...(data.logs || [])].filter(Boolean);
            if (errorLines.length > 0) {
                errorDetailsElement.textContent = sanitizeDisplayText(isEnglish
                    ? 'Some diagnostic details are provided by the server in Japanese.\n' + errorLines.join('\n')
                    : errorLines.join('\n'));
                errorDetailsElement.style.display = 'block';
            }
            renderDiagram(data.diagram || emptyDiagram(domain));
        } else {
            const statusClasses = { secure: 'status-success', insecure: 'status-insecure', bogus: 'status-failed', indeterminate: 'status-indeterminate' };
            statusBox.className = 'result-status-box ' + (statusClasses[data.status] || 'status-indeterminate');
            statusBox.innerText = isEnglish
                ? ({ secure: 'Secure (validation succeeded)', insecure: 'Insecure (unsigned delegation)', bogus: 'Bogus (DNSSEC validation failed)', indeterminate: data.timedOut ? 'Indeterminate (timeout)' : 'Indeterminate (insufficient validation data)' }[data.status] || 'Indeterminate')
                : data.statusLabel || (data.success ? 'Secure（検証成功）' : '判定不能');
            const detailLines = [...(data.logs || [])];
            if (detailLines.length > 0) {
                errorDetailsElement.textContent = sanitizeDisplayText(isEnglish
                    ? 'Some diagnostic details are provided by the server in Japanese.\n' + detailLines.join('\n')
                    : detailLines.join('\n'));
                errorDetailsElement.style.display = 'block';
            }
            if (data.diagram) renderDiagram(data.diagram);
        }
    } catch (error) {
        statusBox.className = 'result-status-box status-indeterminate';
        statusBox.innerText = isEnglish ? 'Indeterminate (communication error)' : '判定不能（通信エラー）';
        errorDetailsElement.textContent = sanitizeDisplayText(translate((isEnglish ? 'Details: ' : '詳細: ') + (error && error.message ? error.message : String(error))));
        errorDetailsElement.style.display = 'block';
        renderDiagram(emptyDiagram(domain));
    }
}

document.getElementById('validateForm').addEventListener('submit', validate);
if (domainInput.value) {
    document.getElementById('validateForm').dispatchEvent(new Event('submit', { cancelable: true }));
}