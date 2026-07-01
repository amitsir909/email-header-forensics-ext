/**
 * Email Header Parser - Extracts headers, IPs, and metadata from raw email source
 */

class EmailParser {
  constructor(rawEmail) {
    this.rawEmail = rawEmail;
    this.headers = {};
    this.body = '';
    this.parseEmail();
  }

  parseEmail() {
    const parts = this.rawEmail.split(/\n\n/);
    const headerSection = parts[0];
    this.body = parts.slice(1).join('\n\n');

    const headerLines = headerSection.split(/\n(?=\S)/);
    headerLines.forEach(line => {
      const colonIndex = line.indexOf(':');
      if (colonIndex > -1) {
        const key = line.substring(0, colonIndex).trim();
        const value = line.substring(colonIndex + 1).trim();
        
        if (this.headers[key]) {
          if (!Array.isArray(this.headers[key])) {
            this.headers[key] = [this.headers[key]];
          }
          this.headers[key].push(value);
        } else {
          this.headers[key] = value;
        }
      }
    });
  }

  getSenderInfo() {
    const from = this.headers['From'] || '';
    const replyTo = this.headers['Reply-To'] || '';
    const returnPath = this.headers['Return-Path'] || '';

    return {
      from,
      replyTo,
      returnPath,
      displayName: this.extractDisplayName(from),
      email: this.extractEmail(from)
    };
  }

  extractDisplayName(headerValue) {
    const match = headerValue.match(/^"?([^<"]+)"?\s*</);
    return match ? match[1].trim() : '';
  }

  extractEmail(headerValue) {
    const match = headerValue.match(/<([^>]+)>/);
    return match ? match[1] : headerValue.trim();
  }

  getAuthenticationResults() {
    return {
      spf: this.extractAuthStatus('SPF'),
      dkim: this.extractAuthStatus('DKIM'),
      dmarc: this.extractAuthStatus('DMARC'),
      authResults: this.headers['Authentication-Results'] || ''
    };
  }

  extractAuthStatus(authType) {
    const authResults = this.headers['Authentication-Results'] || '';
    const regex = new RegExp(`${authType}\s*=\s*(\w+)`, 'i');
    const match = authResults.match(regex);
    return match ? match[1].toLowerCase() : 'unknown';
  }

  getOriginatingIP() {
    const receivedHeaders = Array.isArray(this.headers['Received']) 
      ? this.headers['Received'] 
      : [this.headers['Received']];

    if (!receivedHeaders || receivedHeaders.length === 0) {
      return null;
    }

    const lastReceived = receivedHeaders[receivedHeaders.length - 1];

    const ipPatterns = [
      /from\s+\S+\s+\((\d+\.\d+\.\d+\.\d+)\)/i,
      /from\s+\[(\d+\.\d+\.\d+\.\d+)\]/i,
      /\[(\d+\.\d+\.\d+\.\d+)\]/,
      /(\d+\.\d+\.\d+\.\d+)/
    ];

    for (const pattern of ipPatterns) {
      const match = lastReceived.match(pattern);
      if (match) {
        const ip = match[1];
        if (!this.isKnownRelay(ip)) {
          return {
            ip,
            source: 'Received header (last hop)',
            receivedHeader: lastReceived
          };
        }
      }
    }

    const xOriginatingIP = this.headers['X-Originating-IP'];
    if (xOriginatingIP) {
      const match = xOriginatingIP.match(/(\d+\.\d+\.\d+\.\d+)/);
      if (match) {
        return {
          ip: match[1],
          source: 'X-Originating-IP header',
          receivedHeader: xOriginatingIP
        };
      }
    }

    return null;
  }

  isKnownRelay(ip) {
    const knownRelays = [
      /^142\.251\./,
      /^40\.107\./,
      /^23\.103\./,
      /^127\./,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./
    ];

    return knownRelays.some(pattern => pattern.test(ip));
  }

  getURLs() {
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
    const matches = this.body.match(urlPattern) || [];
    return [...new Set(matches)];
  }

  getAttachments() {
    const attachments = [];
    const contentDisposition = this.headers['Content-Disposition'] || '';
    
    if (contentDisposition.includes('attachment')) {
      const filenameMatch = contentDisposition.match(/filename="?([^";\n]+)"?/i);
      if (filenameMatch) {
        attachments.push({
          filename: filenameMatch[1],
          contentType: this.headers['Content-Type'] || 'unknown'
        });
      }
    }

    return attachments;
  }

  detectSuspiciousScripts() {
    const suspicious = {
      scripts: [],
      obfuscatedJS: false,
      macros: false,
      suspiciousPatterns: []
    };

    const scriptRegex = /<script[^>]*>[\s\S]*?<\/script>/gi;
    const scripts = this.body.match(scriptRegex) || [];
    suspicious.scripts = scripts.map(s => s.substring(0, 200));

    if (/eval\s*\(|atob\s*\(|String\.fromCharCode|decodeURIComponent/i.test(this.body)) {
      suspicious.obfuscatedJS = true;
    }

    if (/VB\.NET|Sub\s+\w+\s*\(|Function\s+\w+|ActiveXObject/i.test(this.body)) {
      suspicious.macros = true;
    }

    const patterns = [
      { pattern: /onclick\s*=/i, name: 'onclick handler' },
      { pattern: /onerror\s*=/i, name: 'onerror handler' },
      { pattern: /onload\s*=/i, name: 'onload handler' },
      { pattern: /javascript:/i, name: 'javascript: protocol' },
      { pattern: /data:text\/html/i, name: 'data: URI' }
    ];

    patterns.forEach(({ pattern, name }) => {
      if (pattern.test(this.body)) {
        suspicious.suspiciousPatterns.push(name);
      }
    });

    return suspicious;
  }

  isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;

    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;

    return false;
  }

  getRawHeaders() {
    return Object.entries(this.headers)
      .map(([key, value]) => {
        if (Array.isArray(value)) {
          return value.map(v => `${key}: ${v}`).join('\n');
        }
        return `${key}: ${value}`;
      })
      .join('\n');
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = EmailParser;
}