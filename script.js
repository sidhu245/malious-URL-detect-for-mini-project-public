function initiateScan() {
    const urlInput = document.getElementById('urlInput');
    const resultContainer = document.getElementById('resultContainer');
    const errorMsg = document.getElementById('errorMsg');

    const url = urlInput.value.trim();

    // Reset UI
    errorMsg.textContent = '';
    resultContainer.classList.add('hidden');

    // Basic Validation
    if (!url) {
        errorMsg.textContent = 'Please enter a URL.';
        return;
    }

    if (!validateURL(url)) {
        errorMsg.textContent = 'Invalid URL format. Include http:// or https://';
        return;
    }

    // Simulate scanning delay for effect
    const btn = document.getElementById('scanBtn');
    const originalText = btn.textContent;
    btn.textContent = 'Scanning...';
    btn.disabled = true;

    setTimeout(() => {
        const result = analyzeURL(url);
        displayResult(result);

        btn.textContent = originalText;
        btn.disabled = false;
    }, 800); // 800ms "scanning" effect
}

function validateURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function analyzeURL(url) {
    // Convert to lowercase for checking
    const lowerUrl = url.toLowerCase();

    // 1. IP Address Check
    // Matches ipv4 patterns approx.
    const ipPattern = /^(http|https):\/\/(\d{1,3}\.){3}\d{1,3}/;
    if (ipPattern.test(lowerUrl)) {
        return {
            status: 'Malicious',
            reason: 'IP-based URL detected instead of domain name.',
            icon: '!',
            details: `<h3>Why is this dangerous?</h3>
            <p>Legitimate websites almost always use domain names (like google.com) to be user-friendly. Using a raw IP address is a common tactic for malware hosting or phishing sites to bypass domain blocklists.</p>
            <ul>
                <li><strong>Risk Level:</strong> High</li>
                <li><strong>Common Use:</strong> Hosting malware payloads directly.</li>
            </ul>`
        };
    }

    // 2. Excessive Special Characters
    // Arbitrary threshold: > 4 occurrences of suspicious chars in the query/path
    const specialChars = (url.match(/[-_?=&%]/g) || []).length;
    if (specialChars > 5) {
        return {
            status: 'Malicious',
            reason: 'High density of special characters detected (obfuscation risk).',
            icon: '!',
            details: `<h3>Obfuscation Checking</h3>
            <p>Attackers often use excessive special characters (like %, =, &, -) to hide the true destination of a URL or to confuse security filters. This "noise" creates a visual distraction.</p>
            <ul>
                <li><strong>Technique:</strong> URL Obfuscation</li>
                <li><strong>Advice:</strong> Do not click unless you trust the source explicitly.</li>
            </ul>`
        };
    }

    // 3. Suspicious Keywords
    const suspiciousKeywords = ['login', 'verify', 'bank', 'secure', 'update', 'account', 'signin', 'confirm', 'wallet', 'crypto'];
    const foundKeyword = suspiciousKeywords.find(kw => lowerUrl.includes(kw));
    if (foundKeyword) {
        return {
            status: 'Suspicious',
            reason: `Contains suspicious keyword: "${foundKeyword}".`,
            icon: '?',
            details: `<h3>Social Engineering Alert</h3>
            <p>Phishing sites often use urgent or trust-related words like 'login', 'secure', or 'bank' to trick you into believing they are legitimate service pages.</p>
            <ul>
                <li><strong>Detected Keyword:</strong> ${foundKeyword}</li>
                <li><strong>Advice:</strong> Check the domain name carefully. Does it match the official site?</li>
            </ul>`
        };
    }

    // 4. URL Shortening Services
    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'is.gd', 't.co', 'ow.ly'];
    // We check if the hostname matches, or if it's just in the string
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        if (shorteners.some(s => hostname.includes(s))) {
            return {
                status: 'Suspicious',
                reason: 'URL shortening service detected.',
                icon: '?',
                details: `<h3>Hidden Destination</h3>
                <p>URL shorteners mask the final destination of the link. Attackers use this to hide malicious URLs from users and initial security scans.</p>
                <ul>
                    <li><strong>Risk:</strong> You cannot see where you are going.</li>
                    <li><strong>Advice:</strong> Use a URL expander tool or be very cautious.</li>
                </ul>`
            };
        }
    } catch (e) {
        // Fallback simple check
        if (shorteners.some(s => lowerUrl.includes(s))) {
            return {
                status: 'Suspicious',
                reason: 'URL shortening service detected.',
                icon: '?',
                details: `<h3>Hidden Destination</h3>
                <p>URL shorteners mask the final destination of the link. Attackers use this to hide malicious URLs from users and initial security scans.</p>
                <ul>
                    <li><strong>Risk:</strong> You cannot see where you are going.</li>
                    <li><strong>Advice:</strong> Use a URL expander tool or be very cautious.</li>
                </ul>`
            };
        }
    }

    // 5. Length Check
    if (url.length > 75) {
        return {
            status: 'Suspicious',
            reason: 'URL is abnormally long.',
            icon: '?',
            details: `<h3>Abnormal Length</h3>
            <p>Extremely long URLs (>75 characters) can be used to hide malicious parameters or exploit buffer overflows in some older applications. They are also common in tracking and phishing links.</p>`
        };
    }

    // Default
    return {
        status: 'Safe',
        reason: 'No common threats detected.',
        icon: '✓',
        details: null
    };
}

function displayResult(result) {
    const resultContainer = document.getElementById('resultContainer');
    const resultCard = resultContainer.querySelector('.result-card');

    const statusTitle = document.getElementById('statusTitle');
    const statusReason = document.getElementById('statusReason');
    const statusIcon = document.getElementById('statusIcon');
    const viewDetailsBtn = document.getElementById('viewDetailsBtn');

    // Reset Classes
    resultCard.classList.remove('result-safe', 'result-suspicious', 'result-malicious');

    // Text Content
    statusTitle.textContent = result.status;
    statusReason.textContent = result.reason;
    statusIcon.textContent = result.icon;

    // Apply specific styling
    if (result.status === 'Safe') {
        resultCard.classList.add('result-safe');
        viewDetailsBtn.classList.add('hidden'); // No details for safe
    } else if (result.status === 'Suspicious') {
        resultCard.classList.add('result-suspicious');
        viewDetailsBtn.classList.remove('hidden');
    } else {
        resultCard.classList.add('result-malicious');
        viewDetailsBtn.classList.remove('hidden');
    }

    // Store details for modal
    if (result.details) {
        window.currentDetails = result.details;
    }

    resultContainer.classList.remove('hidden');
}

// Modal Functions
function openModal() {
    const modal = document.getElementById('analysisModal');
    const modalBody = document.getElementById('modalBody');

    if (window.currentDetails) {
        modalBody.innerHTML = window.currentDetails;
    } else {
        modalBody.innerHTML = '<p>No further details available.</p>';
    }

    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('analysisModal').classList.add('hidden');
}

// Close modal when clicking outside
window.onclick = function (event) {
    const modal = document.getElementById('analysisModal');
    if (event.target == modal) {
        closeModal();
    }
}

// Allow Enter key to submit
document.getElementById('urlInput').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        initiateScan();
    }
});
