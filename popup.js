const emailInput = document.getElementById('emailInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const settingsBtn = document.getElementById('settingsBtn');
const resultsContainer = document.getElementById('resultsContainer');
const errorContainer = document.getElementById('errorContainer');
const mainView = document.getElementById('mainView');
const settingsView = document.getElementById('settingsView');
const backBtn = document.getElementById('backBtn');
const saveKeysBtn = document.getElementById('saveKeysBtn');

const abuseipdbKeyInput = document.getElementById('abuseipdbKey');
const ipinfoKeyInput = document.getElementById('ipinfoKey');
const virustotalKeyInput = document.getElementById('virustotalKey');

analyzeBtn.addEventListener('click', handleAnalyze);
clearBtn.addEventListener('click', handleClear);
settingsBtn.addEventListener('click', showSettings);
backBtn.addEventListener('click', showMain);
saveKeysBtn.addEventListener('click', saveAPIKeys);

chrome.storage.local.get(['apiKeys'], (result) => {
  if (result.apiKeys) {
    abuseipdbKeyInput.value = result.apiKeys.abuseipdb || '';
    ipinfoKeyInput.value = result.apiKeys.ipinfo || '';
    virustotalKeyInput.value = result.apiKeys.virustotal || '';
  }
});

async function handleAnalyze() {
  const emailData = emailInput.value.trim();
  
  if (!emailData) {
    showError('Please paste email headers');
    return;
  }

  analyzeBtn.disabled = true;
  errorContainer.innerHTML = '';

  try {
    const result = await chrome.runtime.sendMessage({
      action: 'analyzeEmail',
      emailData
    });

    if (result.error) {
      showError(result.error);
    } else {
      displayResults(result);
    }
  } catch (error) {
    showError('Error: ' + error.message);
  } finally {
    analyzeBtn.disabled = false;
  }
}

function displayResults(data) {
  resultsContainer.innerHTML = '';

  if (data.riskScore) {
    const riskCard = createRiskCard(data.riskScore);
    resultsContainer.appendChild(riskCard);
  }

  if (data.senderInfo) {
    const senderCard = createSenderCard(data.senderInfo, data.originatingIP);
    resultsContainer.appendChild(senderCard);
  }

  if (data.authResults) {
    const authCard = createAuthCard(data.authResults);
    resultsContainer.appendChild(authCard);
  }

  if (data.ipinfoData && !data.ipinfoData.error) {
    const geoCard = createGeoCard(data.ipinfoData);
    resultsContainer.appendChild(geoCard);
  }

  if (data.abuseipdbData && !data.abuseipdbData.error) {
    const abuseCard = createAbuseCard(data.abuseipdbData);
    resultsContainer.appendChild(abuseCard);
  }

  if (data.virustotalIP && !data.virustotalIP.error) {
    const vtCard = createVirusTotalCard(data.virustotalIP);
    resultsContainer.appendChild(vtCard);
  }
}

function createRiskCard(riskScore) {
  const card = document.createElement('div');
  card.className = 'result-card';
  
  const badgeClass = `badge badge-${riskScore.level.toLowerCase()}`;

  card.innerHTML = `
    <div class="result-header">
      <div class="result-title">Risk Assessment</div>
      <div class="${badgeClass}">${riskScore.level} (${riskScore.score}/100)</div>
    </div>
    <div style="font-size: 12px; color: #cbd5e1;">
      <strong>Factors:</strong><br>
      ${riskScore.factors.map(f => `• ${f}`).join('<br>')}
    </div>
  `;

  return card;
}

function createSenderCard(senderInfo, originatingIP) {
  const card = document.createElement('div');
  card.className = 'result-card';

  let ipInfo = 'Not found';
  if (originatingIP) {
    if (originatingIP.isPrivate) {
      ipInfo = `${originatingIP.ip} (Private)`;
    } else {
      ipInfo = originatingIP.ip;
    }
  }

  card.innerHTML = `
    <div class="result-header">
      <div class="result-title">Sender Info</div>
    </div>
    <div class="result-row">
      <span class="result-label">Email</span>
      <span class="result-value">${escapeHtml(senderInfo.email || 'N/A')}</span>
    </div>
    <div class="result-row">
      <span class="result-label">Originating IP</span>
      <span class="result-value">${ipInfo}</span>
    </div>
  `;

  return card;
}

function createAuthCard(authResults) {
  const card = document.createElement('div');
  card.className = 'result-card';

  const getStatus = (status) => status === 'pass' ? '✓' : status === 'fail' ? '✗' : '?';

  card.innerHTML = `
    <div class="result-header">
      <div class="result-title">Authentication</div>
    </div>
    <div class="result-row">
      <span class="result-label">SPF</span>
      <span class="result-value">${getStatus(authResults.spf)} ${authResults.spf}</span>
    </div>
    <div class="result-row">
      <span class="result-label">DKIM</span>
      <span class="result-value">${getStatus(authResults.dkim)} ${authResults.dkim}</span>
    </div>
    <div class="result-row">
      <span class="result-label">DMARC</span>
      <span class="result-value">${getStatus(authResults.dmarc)} ${authResults.dmarc}</span>
    </div>
  `;

  return card;
}

function createGeoCard(ipinfoData) {
  const card = document.createElement('div');
  card.className = 'result-card';

  const privacyFlags = [];
  if (ipinfoData.isVPN) privacyFlags.push('VPN');
  if (ipinfoData.isProxy) privacyFlags.push('Proxy');
  if (ipinfoData.isTor) privacyFlags.push('Tor');
  if (ipinfoData.isHosting) privacyFlags.push('Hosting');

  card.innerHTML = `
    <div class="result-header">
      <div class="result-title">Geolocation</div>
    </div>
    <div class="result-row">
      <span class="result-label">Location</span>
      <span class="result-value">${ipinfoData.city}, ${ipinfoData.country}</span>
    </div>
    <div class="result-row">
      <span class="result-label">Org</span>
      <span class="result-value">${escapeHtml(ipinfoData.org || 'N/A')}</span>
    </div>
    ${privacyFlags.length > 0 ? `
    <div class="result-row">
      <span class="result-label">Privacy</span>
      <span class="result-value">${privacyFlags.join(', ')}</span>
    </div>
    ` : ''}
  `;

  return card;
}

function createAbuseCard(abuseipdbData) {
  const card = document.createElement('div');
  card.className = 'result-card';

  card.innerHTML = `
    <div class="result-header">
      <div class="result-title">AbuseIPDB</div>
    </div>
    <div class="result-row">
      <span class="result-label">Abuse Score</span>
      <span class="result-value">${abuseipdbData.abuseConfidenceScore || 0}%</span>
    </div>
    <div class="result-row">
      <span class="result-label">Reports</span>
      <span class="result-value">${abuseipdbData.totalReports || 0}</span>
    </div>
  `;

  return card;
}

function createVirusTotalCard(virustotalIP) {
  const card = document.createElement('div');
  card.className = 'result-card';

  card.innerHTML = `
    <div class="result-header">
      <div class="result-title">VirusTotal</div>
    </div>
    <div class="result-row">
      <span class="result-label">Detections</span>
      <span class="result-value">${virustotalIP.malicious}/${virustotalIP.total}</span>
    </div>
  `;

  return card;
}

function showError(message) {
  errorContainer.innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
}

function handleClear() {
  emailInput.value = '';
  resultsContainer.innerHTML = '';
  errorContainer.innerHTML = '';
}

function showSettings() {
  mainView.style.display = 'none';
  settingsView.style.display = 'block';
}

function showMain() {
  mainView.style.display = 'block';
  settingsView.style.display = 'none';
}

function saveAPIKeys() {
  const keys = {
    abuseipdb: abuseipdbKeyInput.value,
    ipinfo: ipinfoKeyInput.value,
    virustotal: virustotalKeyInput.value,
    whoisxml: ''
  };

  chrome.storage.local.set({ apiKeys: keys }, () => {
    chrome.runtime.sendMessage({
      action: 'updateApiKeys',
      keys
    });

    const btn = saveKeysBtn;
    const originalText = btn.textContent;
    btn.textContent = '✓ Saved!';
    setTimeout(() => {
      btn.textContent = originalText;
    }, 2000);
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}