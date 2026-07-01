const form = document.getElementById('settingsForm');
const abuseipdbKeyInput = document.getElementById('abuseipdbKey');
const ipinfoKeyInput = document.getElementById('ipinfoKey');
const virustotalKeyInput = document.getElementById('virustotalKey');

document.addEventListener('DOMContentLoaded', loadSettings);
form.addEventListener('submit', (e) => {
  e.preventDefault();
  saveSettings();
});

function loadSettings() {
  chrome.storage.local.get(['apiKeys'], (result) => {
    if (result.apiKeys) {
      abuseipdbKeyInput.value = result.apiKeys.abuseipdb || '';
      ipinfoKeyInput.value = result.apiKeys.ipinfo || '';
      virustotalKeyInput.value = result.apiKeys.virustotal || '';
    }
  });
}

function saveSettings() {
  const keys = {
    abuseipdb: abuseipdbKeyInput.value.trim(),
    ipinfo: ipinfoKeyInput.value.trim(),
    virustotal: virustotalKeyInput.value.trim(),
    whoisxml: ''
  };

  chrome.storage.local.set({ apiKeys: keys }, () => {
    chrome.runtime.sendMessage({
      action: 'updateApiKeys',
      keys
    });
    alert('Settings saved!');
  });
}