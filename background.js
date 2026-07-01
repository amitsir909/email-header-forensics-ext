/**
 * Background Service Worker - Handles all API calls and email analysis
 * Manifest V3 compliant
 */

let apiKeys = {
  abuseipdb: '',
  ipinfo: '',
  virustotal: '',
  whoisxml: ''
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['apiKeys'], (result) => {
    if (result.apiKeys) {
      apiKeys = result.apiKeys;
    }
  });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeEmail') {
    analyzeEmail(request.emailData).then(sendResponse);
    return true;
  }
  
  if (request.action === 'updateApiKeys') {
    apiKeys = request.keys;
    chrome.storage.local.set({ apiKeys });
    sendResponse({ success: true });
  }
});

async function analyzeEmail(emailData) {
  try {
    const parser = new EmailParser(emailData);
    
    const senderInfo = parser.getSenderInfo();
    const authResults = parser.getAuthenticationResults();
    const originatingIP = parser.getOriginatingIP();
    const urls = parser.getURLs();
    const attachments = parser.getAttachments();
    const suspiciousScripts = parser.detectSuspiciousScripts();

    if (!originatingIP) {
      return {
        error: 'Could not extract originating IP from email headers',
        senderInfo,
        authResults
      };
    }

    if (parser.isPrivateIP(originatingIP.ip)) {
      return {
        senderInfo,
        authResults,
        originatingIP: {
          ...originatingIP,
          isPrivate: true,
          note: 'Internal/non-routable IP - no external lookup performed'
        },
        suspiciousScripts
      };
    }

    const [ipinfoData, abuseipdbData, virustotalIP, virustotalURLs] = await Promise.all([
      fetchIPInfo(originatingIP.ip),
      fetchAbuseIPDB(originatingIP.ip),
      fetchVirusTotalIP(originatingIP.ip),
      fetchVirusTotalURLs(urls)
    ]);

    const riskScore = computeRiskScore({
      ipinfoData,
      abuseipdbData,
      virustotalIP,
      authResults,
      suspiciousScripts
    });

    return {
      senderInfo,
      authResults,
      originatingIP,
      ipinfoData,
      abuseipdbData,
      virustotalIP,
      virustotalURLs,
      suspiciousScripts,
      riskScore,
      urls,
      attachments,
      rawHeaders: parser.getRawHeaders()
    };
  } catch (error) {
    return {
      error: error.message,
      details: error.stack
    };
  }
}

async function fetchIPInfo(ip) {
  if (!apiKeys.ipinfo) {
    return { error: 'ipinfo.io API key not configured' };
  }

  try {
    const response = await fetch(`https://ipinfo.io/${ip}?token=${apiKeys.ipinfo}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    return {
      city: data.city,
      region: data.region,
      country: data.country,
      loc: data.loc,
      org: data.org,
      asn: data.asn,
      timezone: data.timezone,
      privacy: data.privacy || {},
      isVPN: data.privacy?.vpn || false,
      isProxy: data.privacy?.proxy || false,
      isTor: data.privacy?.tor || false,
      isHosting: data.privacy?.hosting || false
    };
  } catch (error) {
    return { error: error.message };
  }
}

async function fetchAbuseIPDB(ip) {
  if (!apiKeys.abuseipdb) {
    return { error: 'AbuseIPDB API key not configured' };
  }

  try {
    const response = await fetch('https://api.abuseipdb.com/api/v2/check', {
      method: 'POST',
      headers: {
        'Key': apiKeys.abuseipdb,
        'Accept': 'application/json'
      },
      body: new URLSearchParams({
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: ''
      })
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    const abuseData = data.data || {};
    
    return {
      abuseConfidenceScore: abuseData.abuseConfidenceScore || 0,
      totalReports: abuseData.totalReports || 0,
      lastReportedAt: abuseData.lastReportedAt,
      usageType: abuseData.usageType,
      isp: abuseData.isp,
      domain: abuseData.domain,
      hostnames: abuseData.hostnames || [],
      reports: abuseData.reports || []
    };
  } catch (error) {
    return { error: error.message };
  }
}

async function fetchVirusTotalIP(ip) {
  if (!apiKeys.virustotal) {
    return { error: 'VirusTotal API key not configured' };
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: {
        'x-apikey': apiKeys.virustotal
      }
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    const attributes = data.data?.attributes || {};
    const stats = attributes.last_analysis_stats || {};

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      undetected: stats.undetected || 0,
      harmless: stats.harmless || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0),
      lastAnalysisDate: attributes.last_analysis_date,
      country: attributes.country,
      asn: attributes.asn,
      asnOrg: attributes.asn_org
    };
  } catch (error) {
    return { error: error.message };
  }
}

async function fetchVirusTotalURLs(urls) {
  if (!apiKeys.virustotal || urls.length === 0) {
    return [];
  }

  const results = [];
  
  for (const url of urls.slice(0, 5)) {
    try {
      const urlId = btoa(url).replace(/=/g, '');
      
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: {
          'x-apikey': apiKeys.virustotal
        }
      });

      if (response.ok) {
        const data = await response.json();
        const stats = data.data?.attributes?.last_analysis_stats || {};
        
        results.push({
          url,
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          undetected: stats.undetected || 0,
          harmless: stats.harmless || 0,
          total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0)
        });
      }
    } catch (error) {
      results.push({
        url,
        error: error.message
      });
    }
  }

  return results;
}

function computeRiskScore(data) {
  let score = 0;
  let factors = [];

  if (data.abuseipdbData?.abuseConfidenceScore) {
    score += data.abuseipdbData.abuseConfidenceScore / 100 * 40;
    if (data.abuseipdbData.abuseConfidenceScore > 50) {
      factors.push('High abuse confidence');
    }
  }

  if (data.virustotalIP?.malicious) {
    score += Math.min(data.virustotalIP.malicious * 10, 30);
    factors.push(`${data.virustotalIP.malicious} VirusTotal vendors flagged IP`);
  }

  if (data.ipinfoData?.isVPN) {
    score += 15;
    factors.push('VPN detected');
  }
  if (data.ipinfoData?.isProxy) {
    score += 15;
    factors.push('Proxy detected');
  }
  if (data.ipinfoData?.isTor) {
    score += 25;
    factors.push('Tor exit node detected');
  }
  if (data.ipinfoData?.isHosting) {
    score += 10;
    factors.push('Hosting provider IP');
  }

  if (data.authResults?.spf !== 'pass') {
    score += 10;
    factors.push('SPF check failed');
  }
  if (data.authResults?.dkim !== 'pass') {
    score += 10;
    factors.push('DKIM check failed');
  }
  if (data.authResults?.dmarc !== 'pass') {
    score += 10;
    factors.push('DMARC check failed');
  }

  if (data.suspiciousScripts?.scripts?.length > 0) {
    score += 20;
    factors.push('Embedded scripts detected');
  }
  if (data.suspiciousScripts?.obfuscatedJS) {
    score += 15;
    factors.push('Obfuscated JavaScript detected');
  }
  if (data.suspiciousScripts?.macros) {
    score += 20;
    factors.push('Macro indicators detected');
  }

  score = Math.min(score, 100);

  let level = 'Low';
  if (score >= 70) {
    level = 'High';
  } else if (score >= 40) {
    level = 'Medium';
  }

  return {
    score: Math.round(score),
    level,
    factors
  };
}