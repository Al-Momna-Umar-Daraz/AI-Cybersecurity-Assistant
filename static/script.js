(function () {
    function byId(id) {
        return document.getElementById(id);
    }

    function getRiskClass(score) {
        if (score < 30) return 'safe';
        if (score < 70) return 'warning';
        return 'danger';
    }

    function safeText(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function safeHttpUrl(value) {
        const url = String(value || '').trim();
        return /^https?:\/\//i.test(url) ? url : '';
    }

    function toFaceThumbSrc(raw) {
        const value = String(raw || '').trim();
        if (!value) return '';
        if (value.indexOf('data:image') === 0) return value;
        if (value.indexOf('base64,') >= 0) return value;
        if (value.indexOf(' ') > 0) {
            const parts = value.split(' ');
            const last = parts[parts.length - 1].trim();
            if (last) return 'data:image/webp;base64,' + last;
        }
        return 'data:image/webp;base64,' + value;
    }

    function getCsrfToken() {
        const node = document.querySelector('meta[name="csrf-token"]');
        return node ? (node.getAttribute('content') || '') : '';
    }

    function jsonHeaders() {
        return {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        };
    }

    function buildApiError(message, status) {
        var err = new Error(String(message || 'Request failed.'));
        err.status = Number(status || 0);
        return err;
    }

    function looksLikeJson(text) {
        var t = String(text || '').trim();
        return t.indexOf('{') === 0 || t.indexOf('[') === 0;
    }

    function isLoginHtmlResponse(text) {
        var t = String(text || '').toLowerCase();
        if (t.indexOf('<!doctype') === -1 && t.indexOf('<html') === -1) return false;
        return t.indexOf('login') >= 0 || t.indexOf('/login') >= 0 || t.indexOf('name="email"') >= 0;
    }

    function parseApiJsonResponse(res) {
        return res.text().then(function (text) {
            var ct = (res.headers && res.headers.get('content-type') || '').toLowerCase();
            var data = {};
            var parsed = false;
            var shouldParseJson = ct.indexOf('application/json') >= 0 || looksLikeJson(text);
            if (shouldParseJson) {
                try {
                    data = text ? JSON.parse(text) : {};
                    parsed = true;
                } catch (_) {
                    if (ct.indexOf('application/json') >= 0) {
                        throw buildApiError('Invalid JSON response from server. Please retry.', res.status);
                    }
                }
            }

            if (!res.ok) {
                if (!parsed && (res.redirected || String(res.url || '').indexOf('/login') >= 0 || isLoginHtmlResponse(text) || res.status === 401 || res.status === 403)) {
                    throw buildApiError('Session expired. Please login again and retry.', res.status || 401);
                }
                if (!parsed) {
                    throw buildApiError('Server error (' + res.status + '). Please retry.', res.status);
                }
                throw buildApiError((data && (data.error || data.message)) || ('Request failed (' + res.status + ').'), res.status);
            }

            if (!parsed) {
                if (res.redirected || String(res.url || '').indexOf('/login') >= 0 || isLoginHtmlResponse(text)) {
                    throw buildApiError('Session expired. Please login again and retry.', res.status || 401);
                }
                throw buildApiError('Server returned unexpected response. Please refresh and try again.', res.status);
            }
            return data;
        });
    }

    function apiFetchJson(url, options) {
        return fetch(url, options).then(parseApiJsonResponse);
    }

    function showInvalidInput(message) {
        alert(String(message || 'Invalid input.') + ' Please retype and try again.');
    }

    function isValidEmail(value) {
        return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(value || '').trim());
    }

    function isValidHost(value) {
        return /^[a-zA-Z0-9.-]+$/.test(String(value || '').trim());
    }

    function normalizeHostForScan(value) {
        var raw = String(value || '').trim();
        if (!raw) return '';
        try {
            var withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw) ? raw : ('http://' + raw);
            var u = new URL(withScheme);
            var host = String(u.hostname || '').trim().toLowerCase();
            return host;
        } catch (_) {
            return raw.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
        }
    }

    function isLikelyUrl(value) {
        var v = String(value || '').trim();
        if (!v) return false;
        return /^(https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(v);
    }

    function isValidCommandText(value) {
        return /^[a-zA-Z0-9_ .\-\/\\|:;=,@*]+$/.test(String(value || '').trim());
    }

    var chatHistories = { assistant: [], chatbot: [], dashboard: [] };
    var MODULE_SUGGESTIONS = {
        '/features/command': ['rm -rf /tmp', 'net user hacker /add', 'dir /a'],
        '/features/password': ['password123', 'P@ssw0rd123!', 'MySecureVault2026!'],
        '/features/url': ['https://openai.com', 'http://free-gift-login-secure.tk', 'https://accounts.google.com'],
        '/features/breach': ['yourname@gmail.com', 'admin@company.com', 'security@company.com'],
        '/features/port-scan': ['8.8.8.8|21,22,80,443', 'example.com|80,443,8080'],
        '/features/network-scan': ['http://free-gift-login-secure.tk', 'https://secure-login.example'],
        '/features/encryption': ['encrypt_text:My confidential note', 'sha256:hello world', 'base64_encode:security test', 'base64_decode:U2VjdXJlIHRleHQ='],
        '/features/linux-lab': ['ls -la /var/log', 'chmod 777 /tmp/data', 'sudo rm -rf /'],
        '/features/chatbot': ['How do I harden a Linux server?', 'How can I improve password policy?', 'How to reduce phishing risk?'],
        '/features/attack': ['sql', 'xss', 'ddos'],
        '/features/face-intel': ['Upload a clear face photo and click Scan Face Match']
    };
    var MODULE_INPUT_IDS = {
        '/features/command': ['commandInput'],
        '/features/password': ['passwordInput'],
        '/features/url': ['urlInput'],
        '/features/breach': ['breachEmailInput'],
        '/features/port-scan': ['portHostInput', 'portListInput'],
        '/features/network-scan': ['networkTargetInput'],
        '/features/encryption': ['encryptionTextInput'],
        '/features/linux-lab': ['linuxCommandInput'],
        '/features/chatbot': ['chatInput'],
        '/features/attack': ['attackSearch'],
        '/features/face-intel': ['faceImageInput']
    };

    function getModulePathKey() {
        return String(window.location.pathname || '').toLowerCase();
    }

    function inferStatus(score) {
        const n = Number(score || 0);
        if (n < 30) return 'SAFE';
        if (n < 70) return 'WARNING';
        return 'DANGEROUS';
    }

    function getInsightHost() {
        if (document.querySelector('[data-disable-insight="1"]')) return null;
        return document.querySelector('.analyzer-container, .chat-container, .simulator-container');
    }

    function ensureModuleInsightCard() {
        const host = getInsightHost();
        if (!host) return null;
        function insightMarkup() {
            return (
                '<div class="module-insight-top">' +
                '  <span id="moduleRiskBadge" class="module-risk-badge safe">SAFE</span>' +
                '  <strong id="moduleRiskPercent">0%</strong>' +
                '</div>' +
                '<p id="moduleRiskMessage" class="module-risk-message">Module insights will appear here.</p>' +
                '<div class="module-graph-title">Risk Trend</div>' +
                '<div id="moduleRiskGraph" class="module-risk-graph"></div>' +
                '<div class="module-graph-title">Last Scan Output</div>' +
                '<ul id="moduleLastOutput" class="module-risk-suggestions"></ul>' +
                '<div class="module-graph-title">Auto Suggestions</div>' +
                '<ul id="moduleRiskSuggestions" class="module-risk-suggestions"></ul>'
            );
        }
        let card = byId('moduleInsightCard');
        if (card) {
            // Upgrade old in-session card markup so new output section appears without full reload.
            if (!byId('moduleLastOutput')) {
                card.innerHTML = insightMarkup();
            }
            return card;
        }

        card = document.createElement('div');
        card.id = 'moduleInsightCard';
        card.className = 'module-insight-card hidden';
        card.innerHTML = insightMarkup();
        host.appendChild(card);
        return card;
    }

    function readHistory(moduleKey) {
        try {
            const raw = sessionStorage.getItem('risk_history_' + moduleKey);
            const parsed = raw ? JSON.parse(raw) : [];
            return Array.isArray(parsed) ? parsed : [];
        } catch (_) {
            return [];
        }
    }

    function writeHistory(moduleKey, scores) {
        try {
            sessionStorage.setItem('risk_history_' + moduleKey, JSON.stringify(scores.slice(-16)));
        } catch (_) { }
    }

    function renderMiniRiskGraph(scores, statusClass) {
        const graph = byId('moduleRiskGraph');
        if (!graph) return;
        graph.innerHTML = '';
        const points = Array.isArray(scores) ? scores.slice(-12) : [];
        while (points.length < 12) points.unshift(0);
        points.forEach(function (value) {
            const bar = document.createElement('span');
            bar.className = 'risk-bar ' + statusClass;
            const numeric = Number(value);
            const safeNumeric = Number.isFinite(numeric) ? numeric : 0;
            const h = Math.max(12, Math.min(100, safeNumeric));
            bar.style.height = h + '%';
            bar.title = String(safeNumeric) + '%';
            graph.appendChild(bar);
        });
    }

    function buildAutoActions(score, status, moduleKey, extraSuggestions) {
        const suggestions = [];
        const key = String(moduleKey || '');
        const n = Number(score || 0);

        if (key === '/features/password') {
            suggestions.push('Use 12+ chars with upper, lower, number, and symbol.');
            suggestions.push('Avoid dictionary words and reused passwords.');
        } else if (key === '/features/url') {
            suggestions.push('Verify domain spelling and SSL certificate.');
            suggestions.push('Avoid shortened suspicious URLs before opening.');
        } else if (key === '/features/command' || key === '/features/linux-lab') {
            suggestions.push('Review command flags before execution on production.');
            suggestions.push('Run risky commands only in sandbox/test VM.');
        } else if (key === '/features/port-scan' || key === '/features/network-scan') {
            suggestions.push('Close unnecessary ports and enforce firewall rules.');
            suggestions.push('Monitor repeated scan activity in logs.');
        } else if (key === '/features/breach') {
            suggestions.push('Change breached passwords immediately.');
            suggestions.push('Enable MFA on critical accounts.');
        } else if (key === '/features/face-intel') {
            suggestions.push('Set account privacy controls on social platforms.');
            suggestions.push('Monitor impersonation reports regularly.');
        } else if (key === '/features/chatbot' || key === '/features/assistant') {
            suggestions.push('Ask module-specific questions for precise guidance.');
            suggestions.push('Follow least privilege and MFA baseline controls.');
        } else {
            suggestions.push('Review findings and apply recommended mitigations.');
        }

        if (n >= 70 || status === 'DANGEROUS') {
            suggestions.unshift('High risk detected: take corrective action immediately.');
        } else if (n >= 30 || status === 'WARNING') {
            suggestions.unshift('Moderate risk detected: harden configuration and re-check.');
        } else {
            suggestions.unshift('Low risk: keep monitoring and maintain best practices.');
        }

        if (Array.isArray(extraSuggestions)) {
            extraSuggestions.forEach(function (item) {
                if (item && suggestions.length < 5) suggestions.push(String(item));
            });
        }

        return suggestions.slice(0, 5);
    }

    function updateModuleInsight(payload) {
        const card = ensureModuleInsightCard();
        if (!card) return;

        const moduleKey = payload && payload.moduleKey ? String(payload.moduleKey) : getModulePathKey();
        const score = Number((payload && payload.score) || 0);
        const status = String((payload && payload.status) || inferStatus(score)).toUpperCase();
        const statusClass = getRiskClass(score);
        const message = String((payload && payload.message) || 'Module scan completed.');
        const actions = buildAutoActions(score, status, moduleKey, payload ? payload.suggestions : []);

        const badge = byId('moduleRiskBadge');
        const percent = byId('moduleRiskPercent');
        const msg = byId('moduleRiskMessage');
        const list = byId('moduleRiskSuggestions');
        const out = byId('moduleLastOutput');
        const outputLines = Array.isArray(payload && payload.output_lines) ? payload.output_lines : [];

        if (badge) {
            badge.className = 'module-risk-badge ' + statusClass;
            badge.textContent = status;
        }
        if (percent) percent.textContent = String(score) + '%';
        if (msg) {
            msg.textContent = message;
            msg.classList.remove('pulse');
            void msg.offsetWidth;
            msg.classList.add('pulse');
        }
        if (list) {
            list.innerHTML = actions.map(function (a) { return '<li>' + safeText(a) + '</li>'; }).join('');
        }
        if (out) {
            out.innerHTML = (outputLines.length ? outputLines : ['No scan output yet. Run a scan to populate details.'])
                .slice(0, 8)
                .map(function (line) { return '<li>' + safeText(line) + '</li>'; })
                .join('');
        }

        const history = readHistory(moduleKey);
        history.push(score);
        writeHistory(moduleKey, history);
        renderMiniRiskGraph(history.slice(-12), statusClass);

        card.classList.remove('hidden');
    }

    function applySuggestionValue(pathKey, value) {
        const ids = MODULE_INPUT_IDS[pathKey] || [];
        const nodes = ids.map(function (id) { return byId(id); }).filter(Boolean);
        if (!nodes.length) return;

        if (pathKey === '/features/port-scan') {
            const parts = String(value).split('|');
            if (nodes[0]) nodes[0].value = parts[0] || '';
            if (nodes[1]) nodes[1].value = parts[1] || '';
            return;
        }
        if (pathKey === '/features/encryption') {
            const parts = String(value).split(':');
            const action = parts[0];
            const text = parts.slice(1).join(':');
            const actionNode = byId('encryptionActionInput');
            if (actionNode && ['encrypt_text', 'decrypt_text', 'sha256', 'base64_encode', 'base64_decode'].indexOf(action) >= 0) {
                actionNode.value = action;
                if (typeof syncEncryptionActionUi === 'function') syncEncryptionActionUi();
            }
            if (nodes[0]) nodes[0].value = text || value;
            return;
        }
        if (pathKey === '/features/face-intel') {
            updateModuleInsight({
                moduleKey: pathKey,
                score: 10,
                status: 'SAFE',
                message: 'For face module, upload an image file and then click Scan Face Match.'
            });
            return;
        }
        nodes[0].value = value;
    }

    function initModuleSuggestions() {
        const pathKey = getModulePathKey();
        const items = MODULE_SUGGESTIONS[pathKey];
        if (!items || !items.length) return;

        const host = document.querySelector('.input-section, .chat-input, .toolbar-row');
        if (!host || byId('moduleSuggestionsPanel')) return;

        const panel = document.createElement('div');
        panel.id = 'moduleSuggestionsPanel';
        panel.className = 'module-suggestions-panel';
        panel.innerHTML = '<strong>Auto Suggestions</strong><div id="moduleSuggestionChips" class="module-suggestion-chips"></div>';
        host.appendChild(panel);

        const chips = byId('moduleSuggestionChips');
        if (!chips) return;
        items.forEach(function (item) {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'suggestion-chip';
            btn.textContent = item;
            btn.addEventListener('click', function () {
                applySuggestionValue(pathKey, item);
            });
            chips.appendChild(btn);
        });
    }

    window.updateModuleInsight = updateModuleInsight;

    function addChatMessage(messagesId, text, sender, metaLabel, metaBadge) {
        const messages = byId(messagesId);
        if (!messages) return;
        const div = document.createElement('div');
        div.className = 'message ' + (sender === 'user' ? 'user' : 'bot');
        if (metaLabel) {
            const meta = document.createElement('div');
            meta.className = 'message-meta';
            const metaText = document.createElement('span');
            metaText.textContent = String(metaLabel);
            meta.appendChild(metaText);
            if (metaBadge) {
                const badge = document.createElement('span');
                badge.className = 'message-source-badge ' + (sender === 'user' ? 'user' : 'bot');
                badge.textContent = String(metaBadge);
                meta.appendChild(badge);
            }
            div.appendChild(meta);
        }
        const content = document.createElement('div');
        content.className = 'message-content';
        content.textContent = String(text || '');
        div.appendChild(content);
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;
    }

    function setChatUiMeta(config, state) {
        const statusNode = byId(config.statusId || '');
        const detailNode = byId(config.detailId || '');
        const noticeNode = byId(config.noticeId || '');
        const modelNode = byId(config.modelId || '');
        const modeNode = byId(config.modeId || '');
        const next = state || {};

        if (statusNode && typeof next.statusText === 'string') {
            statusNode.textContent = next.statusText;
        }
        if (detailNode && typeof next.detailText === 'string') {
            detailNode.innerHTML = '<i class="fas fa-brain"></i> ' + safeText(next.detailText);
        }
        if (noticeNode) {
            const notice = String(next.noticeText || '').trim();
            noticeNode.textContent = notice;
            noticeNode.classList.toggle('hidden', !notice);
            noticeNode.classList.remove('live', 'fallback');
            noticeNode.classList.add(next.noticeClass === 'live' ? 'live' : 'fallback');
        }
        if (modelNode && next.modelLabel) {
            modelNode.textContent = String(next.modelLabel);
        }
        if (modeNode && next.modeLabel) {
            modeNode.textContent = String(next.modeLabel);
            modeNode.classList.remove('live', 'fallback');
            modeNode.classList.add(next.modeClass === 'live' ? 'live' : 'fallback');
        }
    }

    function formatChatModelLabel(modelName, fallbackLabel) {
        var raw = String(modelName || '').trim();
        if (!raw) return String(fallbackLabel || 'AI Assistant');
        if (raw === 'local-fallback') return 'Secure Fallback';
        return raw.toUpperCase();
    }

    function buildLegacyChatFallback(userMessage) {
        var text = String(userMessage || '').trim();
        var lowered = text.toLowerCase();
        if (lowered.indexOf('phishing') >= 0 || lowered.indexOf('gmail') >= 0 || lowered.indexOf('email') >= 0) {
            return 'Sorry, I could not use the old cached reply. Here is a better answer instead:\n\n- Enable MFA on the account.\n- Do not click login links from suspicious emails.\n- Review recent sign-ins, forwarding rules, and connected apps.\n- Change the password from a trusted browser if you already clicked a suspicious link.';
        }
        if (lowered.indexOf('website') >= 0 || lowered.indexOf('web') >= 0 || lowered.indexOf('app') >= 0) {
            return 'Sorry, I could not use the old cached reply. Here is a better answer instead:\n\n- Validate and sanitize input on frontend and backend.\n- Use parameterized queries and output encoding.\n- Protect sessions with CSRF defenses and secure cookies.\n- Log security events and test for common web vulnerabilities.';
        }
        if (lowered.indexOf('password') >= 0) {
            return 'Sorry, I could not use the old cached reply. Here is a better answer instead:\n\n- Use at least 12 to 16 characters.\n- Keep every password unique.\n- Store passwords in a password manager.\n- Enable MFA so password theft alone is not enough.';
        }
        return 'Sorry, I could not use the old cached reply. Please hard refresh the page with Ctrl + F5 and restart the server so the latest chatbot logic loads correctly.';
    }

    function normalizeLegacyChatReply(replyText, userMessage) {
        var reply = String(replyText || '').trim();
        var legacy = 'I can help with cybersecurity analysis. Try Command Analyzer, Password Checker, or URL Scanner.';
        if (reply === legacy) {
            return buildLegacyChatFallback(userMessage);
        }
        return reply;
    }

    function getAssistantInitialState() {
        const shell = byId('assistantProShell');
        if (!shell) {
            return {
                modelLabel: 'AI Assistant',
                modeLabel: 'Ready',
                modeClass: 'live',
                statusText: 'Ready for your next cybersecurity question.',
                detailText: 'Ask a cybersecurity question to begin.',
                noticeText: '',
                noticeClass: 'live',
                welcomeLabel: 'AI Assistant',
                welcomeText: 'Hello! I am your pro cybersecurity assistant. Ask me about phishing, Gmail security, Linux hardening, SOC checklists, password policy, incident response, or suspicious URLs.'
            };
        }

        const initModeClass = String(shell.dataset.initModeClass || 'live').trim() || 'live';
        return {
            modelLabel: String(shell.dataset.initModelLabel || 'AI Assistant').trim() || 'AI Assistant',
            modeLabel: String(shell.dataset.initModeLabel || 'Ready').trim() || 'Ready',
            modeClass: initModeClass,
            statusText: String(shell.dataset.initStatusText || 'Ready for your next cybersecurity question.').trim() || 'Ready for your next cybersecurity question.',
            detailText: String(shell.dataset.initStatusDetail || 'Ask a cybersecurity question to begin.').trim() || 'Ask a cybersecurity question to begin.',
            noticeText: String(shell.dataset.initNoticeText || '').trim(),
            noticeClass: initModeClass,
            welcomeLabel: String(shell.dataset.initWelcomeLabel || 'AI Assistant').trim() || 'AI Assistant',
            welcomeText: String(shell.dataset.initWelcomeText || 'Hello! I am your pro cybersecurity assistant. Ask me about phishing, Gmail security, Linux hardening, SOC checklists, password policy, incident response, or suspicious URLs.').trim()
        };
    }

    function getChatbotInitialState() {
        const shell = byId('chatbotProShell');
        if (!shell) {
            return {
                modelLabel: 'CyberBot',
                modeLabel: 'Ready',
                modeClass: 'live',
                statusText: 'CyberBot is ready for your next cybersecurity question.',
                detailText: 'Ask a cybersecurity question to begin.',
                noticeText: '',
                noticeClass: 'live',
                welcomeLabel: 'CyberBot',
                welcomeText: 'Hello! I am CyberBot. Ask cybersecurity questions, incident-response scenarios, and secure configuration topics.'
            };
        }

        const initModeClass = String(shell.dataset.initModeClass || 'live').trim() || 'live';
        return {
            modelLabel: String(shell.dataset.initModelLabel || 'CyberBot').trim() || 'CyberBot',
            modeLabel: String(shell.dataset.initModeLabel || 'Ready').trim() || 'Ready',
            modeClass: initModeClass,
            statusText: String(shell.dataset.initStatusText || 'CyberBot is ready for your next cybersecurity question.').trim() || 'CyberBot is ready for your next cybersecurity question.',
            detailText: String(shell.dataset.initStatusDetail || 'Ask a cybersecurity question to begin.').trim() || 'Ask a cybersecurity question to begin.',
            noticeText: String(shell.dataset.initNoticeText || '').trim(),
            noticeClass: initModeClass,
            welcomeLabel: String(shell.dataset.initWelcomeLabel || 'CyberBot').trim() || 'CyberBot',
            welcomeText: String(shell.dataset.initWelcomeText || 'Hello! I am CyberBot. Ask cybersecurity questions, incident-response scenarios, and secure configuration topics.').trim()
        };
    }

    function removeLastChatMessage(messagesId) {
        const messages = byId(messagesId);
        if (messages && messages.lastElementChild) {
            messages.removeChild(messages.lastElementChild);
        }
    }

    function getChatModuleConfig(moduleKey) {
        if (moduleKey === 'chatbot') {
            return {
                inputId: 'chatInput',
                messagesId: 'chatbotMessages',
                endpoint: '/api/chat',
                loadingText: 'Thinking...',
                successHint: 'Chat Bot response generated successfully.',
                suggestions: ['Ask focused questions for better answers.', 'Use scan modules to validate risky indicators.'],
                botLabel: 'CyberBot',
                sendButtonId: 'chatbotSendBtn',
                statusId: 'chatbotStatusText',
                detailId: 'chatbotStatusHint',
                noticeId: 'chatbotNotice',
                modelId: 'chatbotModelBadge',
                modeId: 'chatbotModeBadge'
            };
        }
        return {
            inputId: 'assistantInput',
            messagesId: 'assistantMessages',
            endpoint: '/api/chat',
            loadingText: 'Thinking...',
            successHint: 'Chat Bot response generated successfully.',
            suggestions: ['Ask focused questions for better answers.', 'Use scan modules to validate risky indicators.'],
            botLabel: 'AI Assistant',
            sendButtonId: 'assistantSendBtn',
            statusId: 'assistantStatusText',
            detailId: 'assistantStatusHint',
            noticeId: 'assistantNotice',
            modelId: 'assistantModelBadge',
            modeId: 'assistantModeBadge'
        };
    }

    function renderResult(data) {
        const scoreValue = byId('scoreValue');
        const threatStatus = byId('threatStatus');
        const scoreCircle = byId('scoreCircle');
        const resultSection = byId('resultSection');
        const threatList = byId('threatList');

        if (!scoreValue || !threatStatus || !scoreCircle || !resultSection) return;

        const score = Number(data.score || 0);
        scoreValue.textContent = String(score);
        threatStatus.textContent = data.status || 'UNKNOWN';
        scoreCircle.className = 'score-circle ' + getRiskClass(score);

        if (threatList) {
            const threats = Array.isArray(data.threats) ? data.threats : [];
            threatList.innerHTML = threats.length
                ? threats.map(function (t) { return '<li>' + safeText(t) + '</li>'; }).join('')
                : '<li>No major threat patterns detected.</li>';
            updateModuleInsight({
                score: score,
                status: data.status || inferStatus(score),
                message: threats[0] || 'Scan complete. Review auto suggestions below.',
                suggestions: threats.slice(1, 3)
            });
        }

        resultSection.classList.remove('hidden');
        return data;
    }

    function getPasswordImpactMessage(score, status) {
        const s = Number(score || 0);
        const st = String(status || '').toUpperCase();
        if (st === 'DANGEROUS' || s >= 70) {
            return 'High compromise risk: this password may be cracked quickly and can lead to account takeover, data theft, and credential stuffing across other platforms.';
        }
        if (st === 'WARNING' || s >= 30) {
            return 'Moderate risk: this password may resist basic attacks but remains vulnerable to targeted guessing or reuse-based attacks. Strengthening is recommended.';
        }
        return 'Low risk: this password appears strong against common attacks. Keep unique passwords per account and enable multi-factor authentication for best protection.';
    }

    function renderUrlScanResult(data) {
        const scoreValue = byId('urlScoreValue');
        const statusNode = byId('urlStatus');
        const scoreCircle = byId('urlScoreCircle');
        const resultSection = byId('urlResultSection');
        if (!scoreValue || !statusNode || !scoreCircle || !resultSection) return false;

        const score = Number(data.score || 0);
        const status = data.status || inferStatus(score);
        const threats = Array.isArray(data.threats) ? data.threats : [];
        const breachCount = (typeof data.breach_count === 'number') ? data.breach_count : 0;
        const safePercent = Number(data.safe_percent || (100 - score));
        const message = data.breach_message || data.message || 'URL scan completed.';

        const messageNode = byId('urlMessage');
        const safePercentNode = byId('urlSafePercent');
        const breachCountNode = byId('urlBreachCount');
        const domainNode = byId('urlDomainLabel');
        const threatListNode = byId('urlThreatList');

        scoreValue.textContent = String(score);
        statusNode.textContent = status;
        scoreCircle.className = 'score-circle ' + getRiskClass(score);
        if (messageNode) messageNode.textContent = message;
        if (safePercentNode) safePercentNode.textContent = String(safePercent) + '%';
        if (breachCountNode) breachCountNode.textContent = String(breachCount);
        if (domainNode) domainNode.textContent = String(data.domain || '-');
        if (threatListNode) {
            threatListNode.innerHTML = threats.length
                ? threats.map(function (t) { return '<li>' + safeText(t) + '</li>'; }).join('')
                : '<li>No major threat indicators detected.</li>';
        }

        updateModuleInsight({
            score: score,
            status: status,
            message: message,
            suggestions: threats.slice(0, 4)
        });

        resultSection.classList.remove('hidden');
        return true;
    }

    function analyzeInput(input, type) {
        var raw = String(input || '').trim();
        if (!raw) {
            showInvalidInput('Input is empty.');
            return Promise.resolve(null);
        }
        if (type === 'url' && !isLikelyUrl(raw)) {
            showInvalidInput('Invalid URL format.');
            return Promise.resolve(null);
        }
        if (type === 'command' && !isValidCommandText(raw)) {
            showInvalidInput('Invalid command format.');
            return Promise.resolve(null);
        }

        return apiFetchJson('/api/analyze', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ input: input, type: type })
        })
            .then(renderResult)
            .catch(function () {
                updateModuleInsight({
                    score: 50,
                    status: 'WARNING',
                    message: 'Analysis request failed. Please retry with valid input.'
                });
                alert('Analysis failed. Please retype and try again.');
            });
    }

    window.analyzeCommand = function analyzeCommand() {
        const field = byId('commandInput');
        const value = field ? field.value.trim() : '';
        if (!value) return alert('Please enter a command.');
        analyzeInput(value, 'command');
    };

    window.checkPassword = function checkPassword() {
        const field = byId('passwordInput');
        const value = field ? field.value : '';
        if (!value) return showInvalidInput('Password is empty.');
        analyzeInput(value, 'password').then(function (data) {
            if (!data) return;
            const node = byId('passwordImpactMessage');
            if (!node) return;
            node.textContent = getPasswordImpactMessage(data.score, data.status);
        });
    };

    window.scanURL = function scanURL() {
        const field = byId('urlInput');
        const value = field ? field.value.trim() : '';
        if (!value) return showInvalidInput('URL is empty.');
        if (!isLikelyUrl(value)) return showInvalidInput('Invalid URL format.');
        apiFetchJson('/api/url-scan', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ url: value })
        })
            .then(function (data) {
                const rendered = renderUrlScanResult(data);
                if (rendered) return;
                renderResult({
                    score: Number(data.score || 0),
                    status: data.status || 'UNKNOWN',
                    threats: Array.isArray(data.threats) ? data.threats : []
                });
            })
            .catch(function (err) {
                const msg = (err && err.message) ? err.message : 'URL scan failed. Please retype and try again.';
                const messageNode = byId('urlMessage');
                const resultSection = byId('urlResultSection');
                if (messageNode) messageNode.textContent = msg;
                if (resultSection) resultSection.classList.remove('hidden');
                updateModuleInsight({ score: 50, status: 'WARNING', message: msg });
                if (!messageNode) alert(msg);
            });
    };

    window.checkEmailBreach = function checkEmailBreach() {
        const field = byId('breachEmailInput');
        const email = field ? field.value.trim().toLowerCase() : '';
        if (!email) return showInvalidInput('Email is empty.');
        if (!isValidEmail(email)) return showInvalidInput('Invalid email format.');

        function buildLocalEmailFallback(emailValue, reason) {
            var domain = '';
            if (emailValue.indexOf('@') >= 0) {
                domain = emailValue.split('@')[1].toLowerCase();
            }
            var score = 22;
            if (/(gmail\.com|outlook\.com|hotmail\.com|yahoo\.com|icloud\.com|proton\.me|protonmail\.com)$/.test(domain)) score = 18;
            if (/(\.ru|\.tk|\.xyz|\.top|\.click)$/.test(domain)) score = 72;
            else if (domain.indexOf('-') >= 0 || (domain.match(/\./g) || []).length >= 2) score = 46;
            var status = score < 30 ? 'SAFE' : (score < 70 ? 'WARNING' : 'DANGEROUS');

            return {
                ok: true,
                score: score,
                status: status,
                mode: 'fallback',
                live_available: false,
                message: reason || 'Live breach check unavailable. Showing local safety estimate.',
                breaches: [],
                safety_notes: [
                    'Live breach API is unavailable right now; this is a local risk estimate.',
                    'Exact breach count cannot be confirmed without live lookup.',
                    status === 'SAFE'
                        ? 'Current email domain pattern appears lower risk, but keep MFA enabled.'
                        : (status === 'WARNING'
                            ? 'Moderate risk estimate: rotate password and monitor account activity.'
                            : 'Higher risk estimate: change password immediately and secure recovery options.'),
                    'Email domain analyzed: ' + (domain || 'unknown')
                ]
            };
        }

        function renderBreachResult(data) {
            const score = Number(data.score || 0);
            const status = data.status || 'UNKNOWN';
            const message = data.message || '';
            const breaches = Array.isArray(data.breaches) ? data.breaches : [];
            const safetyNotes = Array.isArray(data.safety_notes) ? data.safety_notes : [];
            const messageLower = String(message).toLowerCase();
            const isLiveMode = String(data.mode || 'live').toLowerCase() === 'live'
                && data.live_available !== false
                && messageLower.indexOf('api key is missing') === -1
                && messageLower.indexOf('unable to reach hibp') === -1;
            const mode = isLiveMode ? 'Live' : 'Fallback';

            const resultSection = byId('breachResultSection');
            const scoreValue = byId('breachScoreValue');
            const statusNode = byId('breachStatus');
            const messageNode = byId('breachMessage');
            const modeNode = byId('breachMode');
            const scoreCircle = byId('breachScoreCircle');
            const breachList = byId('breachList');
            const safetyList = byId('breachSafetyList');

            if (scoreValue) scoreValue.textContent = String(score);
            if (statusNode) statusNode.textContent = status;
            if (messageNode) messageNode.textContent = message;
            if (modeNode) modeNode.textContent = 'Mode: ' + mode;
            if (scoreCircle) scoreCircle.className = 'score-circle ' + getRiskClass(score);

            if (breachList) {
                breachList.innerHTML = breaches.length
                    ? breaches.map(function (b) {
                        const title = b.title || b.name || 'Unknown breach';
                        const date = b.breach_date || 'N/A';
                        const domain = b.domain || 'unknown';
                        return '<li><strong>' + safeText(title) + '</strong> - ' +
                            safeText(domain) + ' (' + safeText(date) + ')</li>';
                    }).join('')
                    : '<li>No breach records found in current response.</li>';
            }

            if (safetyList) {
                safetyList.innerHTML = safetyNotes.length
                    ? safetyNotes.map(function (item) { return '<li>' + safeText(item) + '</li>'; }).join('')
                    : '<li>Use a unique password and enable MFA for account safety.</li>';
            }

            updateModuleInsight({
                score: score,
                status: status,
                message: message || 'Breach check completed.',
                suggestions: breaches.length ? ['Enable MFA and reset affected passwords.', 'Monitor reused credentials in other services.'] : ['No breach found in current response, still rotate old passwords periodically.']
            });
            if (resultSection) resultSection.classList.remove('hidden');
        }

        apiFetchJson('/api/breach-check', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ email: email })
        })
            .then(function (data) {
                renderBreachResult(data || {});
            })
            .catch(function (err) {
                const msg = (err && err.message) ? err.message : 'Breach check failed. Please retype and try again.';
                const fallback = buildLocalEmailFallback(email, msg);
                renderBreachResult(fallback);
            });
    };

    window.runPortScan = function runPortScan() {
        const hostRaw = (byId('portHostInput') || {}).value || '';
        const host = normalizeHostForScan(hostRaw);
        const ports = (byId('portListInput') || {}).value || '';
        if (!host.trim()) return showInvalidInput('Host/IP is empty.');
        if (!isValidHost(host.trim())) return showInvalidInput('Invalid host/IP format.');
        if (ports.trim() && !/^[0-9,\-\s]+$/.test(ports.trim())) return showInvalidInput('Ports must be numbers, commas, and ranges.');

        const btn = byId('portScanBtn');
        if (btn) {
            btn.disabled = true;
            btn.dataset.originalText = btn.dataset.originalText || btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        }

        apiFetchJson('/api/port-scan', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ host: host.trim(), ports: ports.trim() })
        })
            .then(function (data) {
                const resultSection = byId('portResultSection');
                const score = Number(data.score || 0);
                byId('portScoreValue').textContent = String(score);
                byId('portStatus').textContent = data.status || 'UNKNOWN';
                byId('portMessage').textContent = (data.message || '') + (data.target_ip ? ' IP: ' + data.target_ip : '');
                byId('portScoreCircle').className = 'score-circle ' + getRiskClass(score);

                const list = byId('portListResult');
                const openItems = (data.results || []).filter(function (r) { return r.open; });
                list.innerHTML = openItems.length
                    ? openItems.map(function (r) {
                        return '<li>Port ' + r.port + ' (' + safeText(r.service) + ') - OPEN</li>';
                    }).join('')
                    : '<li>No open ports found in selected range.</li>';
                updateModuleInsight({
                    score: score,
                    status: data.status || inferStatus(score),
                    message: data.message || 'Port scan completed.',
                    suggestions: openItems.length ? ['Close unnecessary open ports.', 'Allow only trusted source IPs for admin ports.'] : ['No major exposure found in scanned range.']
                });

                if (resultSection) resultSection.classList.remove('hidden');
            })
            .catch(function (err) {
                updateModuleInsight({ score: 52, status: 'WARNING', message: (err && err.message) ? err.message : 'Port scan failed.' });
                alert((err && err.message) ? err.message : 'Port scan failed. Please retype and try again.');
            })
            .finally(function () {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = btn.dataset.originalText || '<i class="fas fa-search"></i> Start Port Scan';
                }
            });
    };

    window.runNetworkScan = function runNetworkScan() {
        function setText(id, value) {
            var node = byId(id);
            if (node) node.textContent = String(value || '');
        }
        function setHtml(id, value) {
            var node = byId(id);
            if (node) node.innerHTML = String(value || '');
        }
        function updateScoreClass(score) {
            var node = byId('networkScoreCircle');
            if (node) node.className = 'score-circle ' + getRiskClass(score);
        }
        function parseDomain(raw) {
            var value = String(raw || '').trim();
            if (!value) return '-';
            try {
                var withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value) ? value : ('https://' + value);
                return (new URL(withScheme).hostname || '-').toLowerCase();
            } catch (_) {
                return value.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase() || '-';
            }
        }

        var target = ((byId('networkTargetInput') || {}).value || '').trim();
        if (!target) return showInvalidInput('Target is empty.');
        if (!isLikelyUrl(target) && !isValidHost(target)) return showInvalidInput('Invalid target format.');

        var btn = byId('networkScanBtn');
        if (btn) {
            btn.disabled = true;
            btn.dataset.originalText = btn.dataset.originalText || btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        }

        setText('networkStatus', 'SCANNING');
        setText('networkMessage', 'Running live network scan...');
        setText('networkScanTime', 'Scan Time: ' + (new Date()).toLocaleString());
        var resultSection = byId('networkResultSection');
        if (resultSection) resultSection.classList.remove('hidden');

        var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        var timeout = setTimeout(function () {
            if (controller) controller.abort();
        }, 15000);

        fetch('/api/network-scan', {
            method: 'POST',
            headers: jsonHeaders(),
            credentials: 'same-origin',
            cache: 'no-store',
            body: JSON.stringify({ target: target }),
            signal: controller ? controller.signal : undefined
        })
            .then(parseApiJsonResponse)
            .then(function (data) {
                var score = Number(data.score || 0);
                var safePercent = Math.max(0, 100 - score);
                var findings = Array.isArray(data.findings) ? data.findings : [];
                var status = data.status || inferStatus(score);
                var domain = data.domain || parseDomain(data.target || target);

                setText('networkScoreValue', String(score));
                setText('networkStatus', status);
                setText('networkMessage', data.message || 'Network scan completed.');
                setText('networkRiskPercent', String(score) + '%');
                setText('networkSafePercent', String(safePercent) + '%');
                setText('networkDomain', domain);
                setText('networkTargetText', data.target || target);
                setText('networkIndicatorCount', String(findings.length));
                setText('networkModeLabel', 'Mode: ' + ((data.mode || 'live') === 'live' ? 'Live Scan' : 'Heuristic'));
                setText('networkScanTime', 'Scan Time: ' + (data.checked_at || (new Date()).toLocaleString()));
                updateScoreClass(score);

                setHtml('networkFindingsList', findings.length
                    ? findings.map(function (f) { return '<li>' + safeText(f) + '</li>'; }).join('')
                    : '<li>No high-risk indicators found.</li>');

                var rawNode = byId('networkRawOutput');
                if (rawNode) {
                    rawNode.textContent = JSON.stringify({
                        ok: data.ok,
                        status: status,
                        score_percent: String(score) + '%',
                        safe_percent: String(safePercent) + '%',
                        domain: domain,
                        target: data.target || target,
                        findings: findings,
                        mode: data.mode || 'live'
                    }, null, 2);
                }

                updateModuleInsight({
                    score: score,
                    status: status,
                    message: data.message || 'Network scan completed.',
                    output_lines: [
                        'Target: ' + (data.target || target),
                        'Domain: ' + domain,
                        'Risk Score: ' + score + '%',
                        'Safe Percentage: ' + safePercent + '%',
                        'Indicators Found: ' + findings.length
                    ].concat(findings.slice(0, 5).map(function (f) { return 'Indicator: ' + f; })),
                    suggestions: findings.length ? findings.slice(0, 3) : ['No major indicator found. Keep monitoring.']
                });
            })
            .catch(function (err) {
                var message = (err && err.name === 'AbortError')
                    ? 'Network scan timeout. Please retry.'
                    : ((err && err.message) ? err.message : 'Network scan failed.');
                setText('networkStatus', 'WARNING');
                setText('networkMessage', message);
                setText('networkRiskPercent', '55%');
                setText('networkSafePercent', '45%');
                setText('networkIndicatorCount', '0');
                setText('networkScanTime', 'Scan Time: ' + (new Date()).toLocaleString());
                updateScoreClass(55);
                setHtml('networkFindingsList', '<li>' + safeText(message) + '</li>');
                updateModuleInsight({ score: 55, status: 'WARNING', message: message });
                alert(message + ' Please retype and try again.');
            })
            .finally(function () {
                clearTimeout(timeout);
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = btn.dataset.originalText || '<i class="fas fa-brain"></i> Run AI Network Scan';
                }
            });
    };

    function getEncryptionActionMeta(action) {
        var key = String(action || '').trim().toLowerCase();
        if (key === 'encrypt_text') {
            return {
                label: 'Encrypt Text',
                inputLabel: 'Plain Text',
                placeholder: 'Example: My confidential note',
                hint: 'Encrypt converts plain text into a protected token using your secret key.',
                secretRequired: true
            };
        }
        if (key === 'decrypt_text') {
            return {
                label: 'Decrypt Text',
                inputLabel: 'Encrypted Token',
                placeholder: 'Example: v2.ABCD...XYZ',
                hint: 'Paste encrypted token and use the same secret key to decrypt.',
                secretRequired: true
            };
        }
        if (key === 'base64_encode') {
            return {
                label: 'Base64 Encode',
                inputLabel: 'Text to Encode',
                placeholder: 'Example: secure text',
                hint: 'Base64 is encoding, not encryption. Do not use it as security.',
                secretRequired: false
            };
        }
        if (key === 'base64_decode') {
            return {
                label: 'Base64 Decode',
                inputLabel: 'Base64 Text',
                placeholder: 'Example: U2VjdXJlIHRleHQ=',
                hint: 'Decode Base64 to original text. Validate source before decoding.',
                secretRequired: false
            };
        }
        return {
            label: 'SHA-256 Hash',
            inputLabel: 'Text to Hash',
            placeholder: 'Example: hello world',
            hint: 'SHA-256 is one-way hashing. It cannot be reversed.',
            secretRequired: false
        };
    }

    function syncEncryptionActionUi() {
        var actionNode = byId('encryptionActionInput');
        if (!actionNode) return;
        var textNode = byId('encryptionTextInput');
        var hintNode = byId('encryptionHintText');
        var secretWrap = byId('encryptionSecretWrap');
        var secretLabel = byId('encryptionSecretLabel');
        var textLabel = byId('encryptionTextLabel');
        var secretNode = byId('encryptionSecretInput');
        var meta = getEncryptionActionMeta(actionNode.value || 'sha256');

        if (textNode) textNode.placeholder = meta.placeholder;
        if (hintNode) hintNode.textContent = meta.hint;
        if (textLabel) textLabel.textContent = meta.inputLabel;

        if (secretWrap) secretWrap.classList.toggle('hidden', !meta.secretRequired);
        if (secretLabel) secretLabel.classList.toggle('hidden', !meta.secretRequired);
        if (secretNode) {
            if (!meta.secretRequired) secretNode.value = '';
            secretNode.required = !!meta.secretRequired;
        }
    }

    function setEncryptionBusy(isBusy) {
        var runBtn = byId('encryptionRunBtn');
        if (!runBtn) return;
        if (isBusy) {
            if (!runBtn.dataset.originalText) runBtn.dataset.originalText = runBtn.innerHTML;
            runBtn.disabled = true;
            runBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        } else {
            runBtn.disabled = false;
            runBtn.innerHTML = runBtn.dataset.originalText || '<i class="fas fa-cogs"></i> Run Tool';
        }
    }

    function getEncryptionOutputPlaceholder() {
        return 'Run Tool to generate output for the selected operation.';
    }

    function isEncryptionOutputPlaceholder(value) {
        return String(value || '').trim() === getEncryptionOutputPlaceholder();
    }

    function resetEncryptionOutputPlaceholder() {
        var outputNode = byId('encryptionOutput');
        if (!outputNode) return;
        outputNode.value = getEncryptionOutputPlaceholder();
    }

    function renderEncryptionNotes(notes) {
        var list = byId('encryptionNotesList');
        if (!list) return;
        var items = Array.isArray(notes) ? notes.filter(Boolean) : [];
        if (!items.length) items = ['No additional security notes for this operation.'];
        list.innerHTML = items.slice(0, 6).map(function (item) {
            return '<li>' + safeText(item) + '</li>';
        }).join('');
    }

    window.copyEncryptionOutput = function copyEncryptionOutput() {
        var outputNode = byId('encryptionOutput');
        var value = outputNode ? String(outputNode.value || '') : '';
        if (!value.trim() || isEncryptionOutputPlaceholder(value)) return showInvalidInput('Run Tool first to generate output.');

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(value).then(function () {
                alert('Output copied successfully.');
            }).catch(function () {
                showInvalidInput('Copy failed. Please copy manually.');
            });
            return;
        }

        if (outputNode) {
            outputNode.focus();
            outputNode.select();
        }
        try {
            document.execCommand('copy');
            alert('Output copied successfully.');
        } catch (_) {
            showInvalidInput('Copy failed. Please copy manually.');
        }
    };

    window.clearEncryptionForm = function clearEncryptionForm() {
        var actionNode = byId('encryptionActionInput');
        var textNode = byId('encryptionTextInput');
        var secretNode = byId('encryptionSecretInput');
        var outputNode = byId('encryptionOutput');

        if (actionNode) actionNode.value = 'encrypt_text';
        if (textNode) textNode.value = '';
        if (secretNode) secretNode.value = '';
        if (outputNode) outputNode.value = getEncryptionOutputPlaceholder();

        setText('encryptionScoreValue', '0');
        setText('encryptionStatus', 'READY');
        setText('encryptionMessage', 'Form cleared. Choose an operation and run again.');
        setText('encryptionOperation', '-');
        setText('encryptionOutputLength', '0');
        setText('encryptionSafePercent', '100%');
        setText('encryptionProcessedAt', '-');
        var circle = byId('encryptionScoreCircle');
        if (circle) circle.className = 'score-circle';
        renderEncryptionNotes(['Run Tool to load operation-specific security notes.']);
        syncEncryptionActionUi();
    };

    function initEncryptionToolUi() {
        var actionNode = byId('encryptionActionInput');
        if (!actionNode) return;
        syncEncryptionActionUi();
        resetEncryptionOutputPlaceholder();

        if (!actionNode.dataset.boundEncryptionAction) {
            actionNode.dataset.boundEncryptionAction = '1';
            actionNode.addEventListener('change', function () {
                syncEncryptionActionUi();
            });
        }

        var runBtn = byId('encryptionRunBtn');
        if (runBtn && !runBtn.dataset.boundEncryptionRun) {
            runBtn.dataset.boundEncryptionRun = '1';
            runBtn.addEventListener('click', function () {
                window.runEncryptionTool();
            });
        }

        var copyBtn = byId('encryptionCopyBtn');
        if (copyBtn && !copyBtn.dataset.boundEncryptionCopy) {
            copyBtn.dataset.boundEncryptionCopy = '1';
            copyBtn.addEventListener('click', function () {
                window.copyEncryptionOutput();
            });
        }

        var clearBtn = byId('encryptionClearBtn');
        if (clearBtn && !clearBtn.dataset.boundEncryptionClear) {
            clearBtn.dataset.boundEncryptionClear = '1';
            clearBtn.addEventListener('click', function () {
                window.clearEncryptionForm();
            });
        }

        var secretToggle = byId('encryptionSecretToggle');
        var secretInput = byId('encryptionSecretInput');
        if (secretToggle && secretInput && !secretToggle.dataset.boundEncryptionSecretToggle) {
            secretToggle.dataset.boundEncryptionSecretToggle = '1';
            secretToggle.addEventListener('click', function () {
                var visible = secretInput.type === 'text';
                secretInput.type = visible ? 'password' : 'text';
                secretToggle.innerHTML = visible ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
            });
        }
    }

    window.runEncryptionTool = function runEncryptionTool() {
        var action = (byId('encryptionActionInput') || {}).value || 'sha256';
        var text = (byId('encryptionTextInput') || {}).value || '';
        var secret = (byId('encryptionSecretInput') || {}).value || '';
        var meta = getEncryptionActionMeta(action);

        if (!String(text).trim()) return showInvalidInput('Input text is empty.');
        if (String(text).length > 20000) return showInvalidInput('Input is too long. Maximum allowed is 20,000 characters.');
        if (meta.secretRequired && !String(secret).trim()) return showInvalidInput('Secret key is required for this operation.');
        if (meta.secretRequired && String(secret).trim().length < 6) return showInvalidInput('Secret key must be at least 6 characters.');

        setEncryptionBusy(true);
        setText('encryptionStatus', 'PROCESSING');
        setText('encryptionMessage', 'Running ' + meta.label + '...');

        apiFetchJson('/api/encryption-tool', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ action: action, text: text, secret: secret })
        })
            .then(function (data) {
                var score = Number(data.score || 0);
                var status = data.status || inferStatus(score);
                var output = String(data.output || '');
                var safePercent = Number(data.safe_percent);
                if (!Number.isFinite(safePercent)) safePercent = Math.max(0, 100 - score);

                setText('encryptionScoreValue', String(score));
                setText('encryptionStatus', status);
                setText('encryptionMessage', data.message || 'Operation complete.');
                setText('encryptionOperation', data.operation_label || meta.label);
                setText('encryptionOutputLength', String(output.length));
                setText('encryptionSafePercent', String(safePercent) + '%');
                setText('encryptionProcessedAt', data.processed_at || (new Date()).toLocaleTimeString());

                var outputNode = byId('encryptionOutput');
                if (outputNode) outputNode.value = output || 'No textual output generated by this operation.';

                var circle = byId('encryptionScoreCircle');
                if (circle) circle.className = 'score-circle ' + getRiskClass(score);

                renderEncryptionNotes(data.notes || []);

                updateModuleInsight({
                    score: score,
                    status: status,
                    message: data.message || 'Encryption tool operation completed.',
                    output_lines: [
                        'Operation: ' + (data.operation_label || meta.label),
                        'Status: ' + status,
                        'Risk Score: ' + score + '%',
                        'Safe Percentage: ' + safePercent + '%',
                        'Output Length: ' + output.length
                    ],
                    suggestions: data.notes || []
                });

                var resultSection = byId('encryptionResultSection');
                if (resultSection) resultSection.classList.remove('hidden');
            })
            .catch(function (err) {
                var message = (err && err.message) ? err.message : 'Encryption tool failed.';
                setText('encryptionStatus', 'WARNING');
                setText('encryptionMessage', message);
                setText('encryptionOperation', meta.label);
                setText('encryptionProcessedAt', (new Date()).toLocaleTimeString());
                renderEncryptionNotes([message, 'Retype input and try again with valid format.']);
                updateModuleInsight({ score: 45, status: 'WARNING', message: message });
                alert(message + ' Please retype and try again.');
            })
            .finally(function () {
                setEncryptionBusy(false);
            });
    };

    window.runLinuxLab = function runLinuxLab() {
        const command = (byId('linuxCommandInput') || {}).value || '';
        if (!command.trim()) return showInvalidInput('Command is empty.');
        if (!isValidCommandText(command.trim())) return showInvalidInput('Invalid command format.');

        apiFetchJson('/api/linux-lab', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ command: command.trim() })
        })
            .then(function (data) {
                const score = Number(data.score || 0);
                byId('linuxScoreValue').textContent = String(score);
                byId('linuxStatus').textContent = data.status || 'UNKNOWN';
                byId('linuxMessage').textContent = data.message || '';
                byId('linuxScoreCircle').className = 'score-circle ' + getRiskClass(score);
                byId('linuxFeedbackList').innerHTML = (data.feedback || []).map(function (f) {
                    return '<li>' + safeText(f) + '</li>';
                }).join('');
                updateModuleInsight({
                    score: score,
                    status: data.status || inferStatus(score),
                    message: data.message || 'Linux command evaluation completed.',
                    suggestions: (data.feedback || []).slice(0, 3)
                });
                byId('linuxResultSection').classList.remove('hidden');
            })
            .catch(function (err) {
                updateModuleInsight({ score: 55, status: 'WARNING', message: (err && err.message) ? err.message : 'Linux lab evaluation failed.' });
                alert((err && err.message) ? err.message : 'Linux lab evaluation failed. Please retype and try again.');
            });
    };

    window.runFaceIntel = function runFaceIntel() {
        const input = byId('faceImageInput');
        const consent = byId('faceConsentCheck');
        const file = input && input.files ? input.files[0] : null;
        if (!file) return showInvalidInput('Image file is required.');
        if (!/\.(png|jpg|jpeg|webp)$/i.test(String(file.name || ''))) return showInvalidInput('Only png, jpg, jpeg, webp allowed.');
        if (!consent || !consent.checked) {
            return showInvalidInput('Consent is required for lawful image analysis.');
        }

        const formData = new FormData();
        formData.append('image', file);
        formData.append('consent', 'yes');

        apiFetchJson('/api/face-intel', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData
        })
            .then(function (data) {
                const score = Number(data.score || 0);
                byId('faceScoreValue').textContent = String(score);
                byId('faceStatus').textContent = data.status || 'UNKNOWN';
                byId('faceMessage').textContent = data.message || '';
                byId('faceScoreCircle').className = 'score-circle ' + getRiskClass(score);
                const matches = Array.isArray(data.matches) ? data.matches : [];
                const list = byId('faceMatchList');
                if (list) {
                    list.innerHTML = '';
                    if (!matches.length) {
                        list.innerHTML = '<li>No public matches found.</li>';
                    } else {
                        matches.slice(0, 10).forEach(function (m) {
                            const li = document.createElement('li');
                            li.className = 'face-match-item';

                            const thumbSrc = toFaceThumbSrc(m.base64 || '');
                            if (thumbSrc) {
                                const img = document.createElement('img');
                                img.className = 'face-thumb';
                                img.src = thumbSrc;
                                img.alt = 'Match thumbnail';
                                li.appendChild(img);
                            }

                            const info = document.createElement('div');
                            info.className = 'face-match-meta';
                            const scoreNode = document.createElement('strong');
                            scoreNode.textContent = 'Similarity: ' + safeText(m.score) + '%';
                            info.appendChild(scoreNode);

                            const rawUrl = safeHttpUrl(m.url || '');
                            if (rawUrl) {
                                const link = document.createElement('a');
                                link.href = rawUrl;
                                link.target = '_blank';
                                link.rel = 'noopener noreferrer';
                                link.textContent = rawUrl;
                                info.appendChild(document.createElement('br'));
                                info.appendChild(link);
                            } else {
                                const muted = document.createElement('div');
                                muted.className = 'muted-text';
                                muted.textContent = 'Source URL unavailable';
                                info.appendChild(muted);
                            }
                            li.appendChild(info);
                            list.appendChild(li);
                        });
                    }
                }
                updateModuleInsight({
                    score: score,
                    status: data.status || inferStatus(score),
                    message: data.message || 'Face intelligence scan completed.',
                    suggestions: matches.length ? ['Review matched links manually for impersonation.', 'Request takedown where identity misuse is found.'] : ['No public matches found in current scan.']
                });
                byId('faceResultSection').classList.remove('hidden');
            })
            .catch(function (err) {
                updateModuleInsight({ score: 50, status: 'WARNING', message: (err && err.message) ? err.message : 'Face search failed.' });
                alert((err && err.message) ? err.message : 'Face search failed. Please retry.');
            });
    };

    function sendChatMessage(moduleKey) {
        var key = moduleKey === 'chatbot' ? 'chatbot' : 'assistant';
        const config = getChatModuleConfig(moduleKey);
        const input = byId(config.inputId);
        const message = input ? String(input.value || '').trim() : '';
        if (!message) return showInvalidInput('Message is empty.');
        if (message.length < 2) return showInvalidInput('Message is too short.');
        if (message.length > 3000) return showInvalidInput('Message is too long. Maximum 3000 characters.');

        const history = chatHistories[key] || [];
        const runBtn = byId(config.sendButtonId || '') || (input && input.parentElement ? input.parentElement.querySelector('button') : null);
        const oldBtnHtml = runBtn ? runBtn.innerHTML : '';

        addChatMessage(config.messagesId, message, 'user', 'You');
        history.push({ role: 'user', content: message });
        chatHistories[key] = history;
        input.value = '';
        input.disabled = true;
        setChatUiMeta(config, {
            statusText: 'Generating response...',
            detailText: 'Generating your cybersecurity response right now.',
            noticeText: '',
            noticeClass: 'live',
            modeLabel: 'Thinking',
            modeClass: 'live'
        });

        if (runBtn) {
            runBtn.disabled = true;
            runBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        }

        addChatMessage(config.messagesId, config.loadingText, 'assistant', config.botLabel || 'Assistant');

        apiFetchJson(config.endpoint, {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ message: message, history: history })
        })
            .then(function (data) {
                removeLastChatMessage(config.messagesId);
                const reply = normalizeLegacyChatReply(data.reply || data.response || data.message || 'No response.', message);
                const formattedModelLabel = data.model_label || formatChatModelLabel(data.model, config.botLabel || 'Assistant');
                addChatMessage(config.messagesId, reply, 'assistant', config.botLabel || 'Assistant', data.status_label || formattedModelLabel);
                history.push({ role: 'assistant', content: reply });
                if (history.length > 30) {
                    chatHistories[key] = history.slice(-30);
                } else {
                    chatHistories[key] = history;
                }
                const modeIsLive = String(data.mode || 'ok') === 'ok';
                setChatUiMeta(config, {
                    statusText: data.status_text || (modeIsLive ? 'Live model responded successfully.' : 'Fallback assistant responded successfully.'),
                    detailText: data.status_detail || (modeIsLive ? 'Connected to the configured OpenAI model.' : 'Secure fallback answers are active right now.'),
                    noticeText: data.notice || (modeIsLive ? '' : (data.status_detail || '')),
                    noticeClass: data.status_class || (modeIsLive ? 'live' : 'fallback'),
                    modelLabel: formattedModelLabel,
                    modeLabel: data.status_label || (modeIsLive ? 'Connected' : 'Secure Fallback'),
                    modeClass: data.status_class || (modeIsLive ? 'live' : 'fallback')
                });
                updateModuleInsight({
                    score: 20,
                    status: 'SAFE',
                    message: config.successHint,
                    output_lines: [
                        'Module: Chat Bot',
                        'Status: Response generated',
                        'Characters: ' + String(reply.length),
                        'History window: ' + String(chatHistories[key].length)
                    ],
                    suggestions: config.suggestions
                });
            })
            .catch(function (err) {
                removeLastChatMessage(config.messagesId);
                const msg = (err && err.message) ? err.message : 'Chat request failed. Please retype and try again.';
                addChatMessage(config.messagesId, msg, 'assistant', config.botLabel || 'Assistant');
                setChatUiMeta(config, {
                    statusText: 'Response failed. Please retry.',
                    detailText: 'Secure fallback mode is recommended until the service issue is resolved.',
                    noticeText: msg,
                    noticeClass: 'fallback',
                    modeLabel: 'Secure Fallback',
                    modeClass: 'fallback'
                });
                updateModuleInsight({ score: 45, status: 'WARNING', message: msg });
            })
            .finally(function () {
                input.disabled = false;
                input.focus();
                if (runBtn) {
                    runBtn.disabled = false;
                    runBtn.innerHTML = oldBtnHtml || '<i class="fas fa-paper-plane"></i>';
                }
            });
    }

    window.sendAssistantMessage = function sendAssistantMessage() {
        sendChatMessage('assistant');
    };

    window.sendChatbotMessage = function sendChatbotMessage() {
        sendChatMessage('chatbot');
    };

    window.clearAssistantChat = function clearAssistantChat() {
        chatHistories.assistant = [];
        var messages = byId('assistantMessages');
        if (!messages) return;
        var initialState = getAssistantInitialState();
        messages.innerHTML = '' +
            '<div class="message bot">' +
            '  <div class="message-meta">' + safeText(initialState.welcomeLabel) + '</div>' +
            '  <div class="message-content">' +
            safeText(initialState.welcomeText) +
            '  </div>' +
            '</div>';
        setChatUiMeta(getChatModuleConfig('assistant'), {
            statusText: initialState.statusText,
            detailText: initialState.detailText,
            noticeText: initialState.noticeText,
            noticeClass: initialState.noticeClass,
            modelLabel: initialState.modelLabel,
            modeLabel: initialState.modeLabel,
            modeClass: initialState.modeClass
        });
        updateModuleInsight({
            score: 5,
            status: 'SAFE',
            message: 'Chat history cleared. Start a new conversation.',
            suggestions: ['Ask one focused question at a time.', 'Use real scenarios for better guidance.']
        });
    };

    window.clearChatbotChat = function clearChatbotChat() {
        chatHistories.chatbot = [];
        var messages = byId('chatbotMessages');
        if (!messages) return;
        var initialState = getChatbotInitialState();
        messages.innerHTML = '' +
            '<div class="message bot">' +
            '  <div class="message-meta">' + safeText(initialState.welcomeLabel) + '</div>' +
            '  <div class="message-content">' +
            safeText(initialState.welcomeText) +
            '  </div>' +
            '</div>';
        setChatUiMeta(getChatModuleConfig('chatbot'), {
            statusText: initialState.statusText,
            detailText: initialState.detailText,
            noticeText: initialState.noticeText,
            noticeClass: initialState.noticeClass,
            modelLabel: initialState.modelLabel,
            modeLabel: initialState.modeLabel,
            modeClass: initialState.modeClass
        });
        updateModuleInsight({
            score: 5,
            status: 'SAFE',
            message: 'Chat history cleared. Start a new conversation.',
            suggestions: ['Ask one focused question at a time.', 'Use real scenarios for better guidance.']
        });
    };

    window.useChatbotPrompt = function useChatbotPrompt(promptText) {
        var input = byId('chatInput');
        if (!input) return;
        input.value = String(promptText || '');
        input.focus();
    };

    window.useAssistantPrompt = function useAssistantPrompt(promptText) {
        var input = byId('assistantInput');
        if (!input) return;
        input.value = String(promptText || '');
        input.focus();
    };

    window.simulateAttack = function simulateAttack(type) {
        const simulationResult = byId('simulationResult');
        const attackDetails = byId('attackDetails');
        const preventionTips = byId('preventionTips');
        if (!simulationResult || !attackDetails || !preventionTips) {
            alert('Result panel not found on page. Please refresh and retry.');
            return;
        }

        const scenarios = {
            sql: {
                detail: 'Simulation: SQL Injection payload attempted against a vulnerable login form.',
                tips: [
                    'Use parameterized queries.',
                    'Validate and sanitize user input.',
                    'Apply least-privilege database access.'
                ]
            },
            xss: {
                detail: 'Simulation: Script payload injected into unsanitized comment field.',
                tips: [
                    'Escape user-generated content in HTML output.',
                    'Use a Content Security Policy (CSP).',
                    'Sanitize input on frontend and backend.'
                ]
            },
            ddos: {
                detail: 'Simulation: Traffic spike overwhelmed the service endpoint.',
                tips: [
                    'Use rate limiting and request throttling.',
                    'Enable autoscaling and CDN protection.',
                    'Configure WAF and anomaly detection.'
                ]
            }
        };

        const selected = scenarios[type];
        if (!selected) {
            attackDetails.textContent = 'Invalid attack type selected.';
            preventionTips.innerHTML = '<h4>Prevention Tips</h4><ul><li>Choose SQL, XSS, or DDoS card.</li></ul>';
            simulationResult.classList.remove('hidden');
            return;
        }

        attackDetails.textContent = selected.detail;
        preventionTips.innerHTML = '<h4>Prevention Tips</h4><ul>' +
            selected.tips.map(function (tip) { return '<li>' + safeText(tip) + '</li>'; }).join('') +
            '</ul>';
        simulationResult.classList.remove('hidden');
        simulationResult.scrollIntoView({ behavior: 'smooth', block: 'start' });
        const attackScore = type === 'sql' ? 86 : type === 'xss' ? 78 : 82;
        updateModuleInsight({
            score: attackScore,
            status: inferStatus(attackScore),
            message: selected.detail,
            suggestions: selected.tips
        });
    };

    function bindAttackCards() {
        var wrap = byId('attackTypes');
        if (!wrap || wrap.dataset.boundAttackCards) return;
        wrap.dataset.boundAttackCards = '1';
        var cards = wrap.querySelectorAll('.attack-card');
        cards.forEach(function (card) {
            card.addEventListener('click', function () {
                var type = String(card.getAttribute('data-attack-type') || '').trim().toLowerCase();
                window.simulateAttack(type);
            });
        });
    }

    window.filterAttackCards = function filterAttackCards() {
        const input = byId('attackSearch');
        const q = input ? input.value.trim().toLowerCase() : '';
        const cards = document.querySelectorAll('#attackTypes .attack-card');
        cards.forEach(function (card) {
            const name = (card.getAttribute('data-name') || '').toLowerCase();
            card.style.display = name.includes(q) ? '' : 'none';
        });
    };

    function setupSidebarToggle() {
        const openBtn = byId('menuToggle');
        const closeBtn = byId('sidebarClose');
        const body = document.body;
        
        function isMobile() {
            return window.matchMedia && window.matchMedia('(max-width: 900px)').matches;
        }

        function syncMenuState() {
            var expanded = isMobile() ? body.classList.contains('sidebar-open') : !body.classList.contains('sidebar-hidden');
            if (openBtn) {
                openBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
            }
        }

        if (openBtn) {
            openBtn.addEventListener('click', function () {
                if (isMobile()) {
                    body.classList.remove('sidebar-hidden');
                    body.classList.toggle('sidebar-open');
                } else {
                    body.classList.remove('sidebar-open');
                    body.classList.toggle('sidebar-hidden');
                }
                syncMenuState();
            });
        }

        if (closeBtn) {
            closeBtn.addEventListener('click', function () {
                if (isMobile()) {
                    body.classList.remove('sidebar-open');
                } else {
                    body.classList.add('sidebar-hidden');
                }
                syncMenuState();
            });
        }

        if (!window.__boundSidebarToggleResize) {
            window.__boundSidebarToggleResize = true;
            window.addEventListener('resize', function () {
                if (!isMobile()) {
                    body.classList.remove('sidebar-open');
                }
                syncMenuState();
            });
        }

        syncMenuState();
    }

    function setupHistoryNav() {
        var backBtn = byId('historyBackBtn');
        var forwardBtn = byId('historyForwardBtn');
        if (!backBtn && !forwardBtn) return;

        if (backBtn && !backBtn.dataset.boundHistory) {
            backBtn.dataset.boundHistory = '1';
            backBtn.addEventListener('click', function (e) {
                e.preventDefault();
                if (window.history.length > 1) {
                    window.history.back();
                } else {
                    window.location.href = '/';
                }
            });
        }

        if (forwardBtn && !forwardBtn.dataset.boundHistory) {
            forwardBtn.dataset.boundHistory = '1';
            forwardBtn.addEventListener('click', function (e) {
                e.preventDefault();
                window.history.forward();
            });
        }
    }

    function setupQuickToolsListToggle() {
        var sidebar = byId('sidebar');
        var list = byId('quickToolsList');
        var btn = byId('quickToolsToggle');
        if (!sidebar || !list || !btn) return;

        function applyState(collapsed) {
            sidebar.classList.toggle('list-collapsed', !!collapsed);
            btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
            var icon = btn.querySelector('i');
            if (icon) {
                icon.className = collapsed ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
            }
            try {
                sessionStorage.setItem('quickToolsCollapsed', collapsed ? '1' : '0');
            } catch (_) { }
        }

        var saved = '0';
        try { saved = sessionStorage.getItem('quickToolsCollapsed') || '0'; } catch (_) { }
        applyState(saved === '1');

        if (!btn.dataset.boundQuickToolsToggle) {
            btn.dataset.boundQuickToolsToggle = '1';
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                var collapsed = !sidebar.classList.contains('list-collapsed');
                applyState(collapsed);
            });
        }
    }

    var threatChart = null;
    var typeChart = null;
    var trendChart = null;

    function drawAnalysisCharts(data) {
        if (typeof Chart === 'undefined') return;

        const threatCanvas = byId('threatChart');
        const typeCanvas = byId('typeChart');
        const trendCanvas = byId('trendChart');
        if (!threatCanvas || !typeCanvas || !trendCanvas) return;

        if (threatChart) threatChart.destroy();
        if (typeChart) typeChart.destroy();
        if (trendChart) trendChart.destroy();

        threatChart = new Chart(threatCanvas, {
            type: 'doughnut',
            data: {
                labels: ['Safe', 'Warning', 'Dangerous'],
                datasets: [{
                    data: [data.status_counts.SAFE, data.status_counts.WARNING, data.status_counts.DANGEROUS],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444']
                }]
            }
        });

        typeChart = new Chart(typeCanvas, {
            type: 'bar',
            data: {
                labels: ['Commands', 'Passwords', 'URLs', 'Breach', 'Port Scan', 'Network AI', 'Encryption', 'Linux Lab', 'Face Intel'],
                datasets: [{
                    label: 'Avg Risk Score',
                    data: [
                        data.type_risk.command,
                        data.type_risk.password,
                        data.type_risk.url,
                        data.type_risk.breach || 0,
                        data.type_risk.portscan || 0,
                        data.type_risk.network || 0,
                        data.type_risk.encryption || 0,
                        data.type_risk.linux || 0,
                        data.type_risk.facecheck || 0
                    ],
                    backgroundColor: ['#5bc0eb','#22c55e','#9bc53d','#ff6f59','#f25f5c','#16a34a','#84dcc6','#c77dff','#4f46e5']
                }]
            },
            options: { scales: { y: { beginAtZero: true, max: 100 } } }
        });

        trendChart = new Chart(trendCanvas, {
            type: 'line',
            data: {
                labels: data.trend.labels,
                datasets: [{
                    label: 'Scans (Last 7 Days)',
                    data: data.trend.values,
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.15)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: { scales: { y: { beginAtZero: true } } }
        });
    }

    function updateAnalysisStats(summary) {
        const map = {
            totalScans: summary.total_scans,
            threatScore: summary.avg_threat_score,
            safePct: summary.safe_percent + '%',
            warningPct: summary.warning_percent + '%',
            dangerPct: summary.dangerous_percent + '%'
        };
        Object.keys(map).forEach(function (id) {
            const node = byId(id);
            if (node) node.textContent = String(map[id]);
        });
    }

    window.refreshAnalysisDashboard = function refreshAnalysisDashboard() {
        const filter = (byId('analysisFilter') || {}).value || 'all';
        const keyword = (byId('analysisSearch') || {}).value || '';

        apiFetchJson('/api/analysis-summary?filter=' + encodeURIComponent(filter) + '&q=' + encodeURIComponent(keyword))
            .then(function (summary) {
                updateAnalysisStats(summary);
                drawAnalysisCharts(summary);
            })
            .catch(function () {
                alert('Unable to refresh analysis right now. Please retry.');
            });
    };

    window.setDashboardChatPrompt = function setDashboardChatPrompt(prompt) {
        var input = byId('dashboardChatInput');
        if (!input) return;
        input.value = String(prompt || '');
        input.focus();
    };

    window.clearDashboardChatbot = function clearDashboardChatbot() {
        var input = byId('dashboardChatInput');
        var status = byId('dashboardChatStatus');
        var response = byId('dashboardChatResponse');
        if (input) input.value = '';
        if (status) status.textContent = 'Waiting for your question.';
        if (response) response.textContent = 'Ask Chatbot from here to get ChatGPT-style guidance.';
        chatHistories.dashboard = [];
    };

    window.runDashboardChatbot = function runDashboardChatbot() {
        var input = byId('dashboardChatInput');
        var sendBtn = byId('dashboardChatSendBtn');
        var status = byId('dashboardChatStatus');
        var response = byId('dashboardChatResponse');
        var message = input ? String(input.value || '').trim() : '';
        if (!message) return showInvalidInput('Question is empty.');
        if (message.length < 2) return showInvalidInput('Question is too short.');
        if (message.length > 3000) return showInvalidInput('Question is too long. Maximum 3000 characters.');

        var history = chatHistories.dashboard || [];
        history.push({ role: 'user', content: message });
        chatHistories.dashboard = history;

        if (status) status.textContent = 'Chatbot is thinking...';
        if (response) response.textContent = 'Generating response...';

        var oldBtnHtml = sendBtn ? sendBtn.innerHTML : '';
        if (sendBtn) {
            sendBtn.disabled = true;
            sendBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        }

        apiFetchJson('/api/chat', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ message: message, history: history })
        })
            .then(function (data) {
                var reply = String(data.reply || data.response || data.message || 'No response.').trim();
                if (!reply) reply = 'No response.';
                if (status) status.textContent = 'Response ready.';
                if (response) response.textContent = reply;
                history.push({ role: 'assistant', content: reply });
                chatHistories.dashboard = history.slice(-30);
                updateModuleInsight({
                    score: 15,
                    status: 'SAFE',
                    message: 'Chatbot responded successfully.',
                    output_lines: [
                        'Module: Chatbot',
                        'Status: Response generated',
                        'Characters: ' + String(reply.length),
                        'History window: ' + String(chatHistories.dashboard.length)
                    ],
                    suggestions: ['Ask focused questions for better quality responses.', 'Cross-check critical advice with live scans.']
                });
            })
            .catch(function (err) {
                var msg = (err && err.message) ? err.message : 'Chatbot request failed.';
                if (status) status.textContent = 'Request failed.';
                if (response) response.textContent = msg;
                updateModuleInsight({ score: 45, status: 'WARNING', message: msg });
            })
            .finally(function () {
                if (sendBtn) {
                    sendBtn.disabled = false;
                    sendBtn.innerHTML = oldBtnHtml || '<i class="fas fa-paper-plane"></i> Ask Chatbot';
                }
            });
    };

    window.applyReportFilter = function applyReportFilter() {
        const filter = (byId('reportFilter') || {}).value || 'all';
        const keyword = (byId('reportSearch') || {}).value || '';
        const url = '/reports?filter=' + encodeURIComponent(filter) + '&q=' + encodeURIComponent(keyword);
        window.location.href = url;
    };

    window.exportReport = function exportReport() {
        window.print();
    };

    window.filterSettings = function filterSettings() {
        const input = byId('settingsSearch');
        const q = input ? input.value.trim().toLowerCase() : '';
        const items = document.querySelectorAll('.setting-item');
        items.forEach(function (item) {
            const name = (item.getAttribute('data-name') || '').toLowerCase();
            item.style.display = name.includes(q) ? '' : 'none';
        });
    };

    window.saveSettings = function saveSettings() {
        const payload = {
            dark_mode: !!(byId('darkMode') && byId('darkMode').checked),
            threat_alerts: !!(byId('threatAlerts') && byId('threatAlerts').checked),
            scan_complete: !!(byId('scanComplete') && byId('scanComplete').checked),
            auto_refresh: !!(byId('autoRefresh') && byId('autoRefresh').checked)
        };

        apiFetchJson('/api/settings', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify(payload)
        })
            .then(function (data) {
                if (data.success) {
                    applyThemeState(payload.dark_mode, true);
                    alert('Settings saved successfully.');
                } else {
                    alert('Could not save settings.');
                }
            })
            .catch(function () {
                alert('Could not save settings.');
            });
    };

    window.requestPasswordCode = function requestPasswordCode() {
        const channel = ((byId('passwordCodeChannel') || {}).value || '').trim();
        if (!channel) return showInvalidInput('Choose code channel first.');

        apiFetchJson('/api/request-password-code', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ channel: channel })
        })
            .then(function (data) {
                alert(data.message || 'Verification code sent.');
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Could not send verification code.');
            });
    };

    window.changePasswordWithCode = function changePasswordWithCode() {
        const code = ((byId('passwordOtpCode') || {}).value || '').trim();
        const newPassword = (byId('newPasswordInput') || {}).value || '';
        const confirmPassword = (byId('confirmPasswordInput') || {}).value || '';

        if (!/^\d{6}$/.test(code)) return showInvalidInput('Enter 6-digit verification code.');
        if (newPassword.length < 8) return showInvalidInput('Password must be at least 8 characters.');
        if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
            return showInvalidInput('Password must include uppercase, lowercase, and number.');
        }
        if (newPassword !== confirmPassword) return showInvalidInput('New password and confirm password do not match.');

        apiFetchJson('/api/change-password-with-code', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({
                code: code,
                new_password: newPassword,
                confirm_password: confirmPassword
            })
        })
            .then(function (data) {
                alert(data.message || 'Password changed successfully.');
                if (byId('passwordOtpCode')) byId('passwordOtpCode').value = '';
                if (byId('newPasswordInput')) byId('newPasswordInput').value = '';
                if (byId('confirmPasswordInput')) byId('confirmPasswordInput').value = '';
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Unable to change password.');
            });
    };

    window.resetData = function resetData() {
        if (!confirm('Reset all reports data? This cannot be undone.')) return;

        apiFetchJson('/api/reports/reset', { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() } })
            .then(function (data) {
                if (data.success) {
                    alert('All reports reset successfully.');
                    if (window.location.pathname === '/reports') {
                        window.location.reload();
                    }
                }
            })
            .catch(function () {
                alert('Unable to reset reports.');
            });
    };

    window.clearCache = function clearCache() {
        localStorage.clear();
        sessionStorage.clear();
        alert('Browser cache cleared.');
    };

    function refreshCreditBalanceUi(balance) {
        var node = byId('creditBalanceValue');
        if (node && typeof balance !== 'undefined') {
            node.textContent = String(balance);
        }
    }

    window.buyCredits = function buyCredits(packKey) {
        if (!packKey) return;
        apiFetchJson('/api/create-payment', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ pack_key: packKey })
        })
            .then(function (data) {
                if (data.checkout_url) {
                    window.location.href = data.checkout_url;
                    return;
                }
                alert(data.message || 'Checkout URL not available.');
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Unable to start payment. Please retry.');
            });
    };

    window.simulateCreditPurchase = function simulateCreditPurchase(packKey) {
        if (!packKey) return;
        apiFetchJson('/api/simulate-payment', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ pack_key: packKey })
        })
            .then(function (data) {
                refreshCreditBalanceUi(data.balance || 0);
                alert(data.message || 'Credits updated.');
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Simulated payment failed.');
            });
    };

    window.buyViaBankTransfer = function buyViaBankTransfer(packKey) {
        if (!packKey) return;
        const transferRef = window.prompt('Enter bank transfer reference ID / transaction ID');
        if (!transferRef) return;
        if (!/^[a-zA-Z0-9\-_/]{4,60}$/.test(transferRef.trim())) return showInvalidInput('Invalid transfer reference.');

        apiFetchJson('/api/create-bank-transfer', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ pack_key: packKey, transfer_ref: transferRef.trim() })
        })
            .then(function (data) {
                if (typeof data.balance !== 'undefined') {
                    refreshCreditBalanceUi(data.balance);
                }
                alert(data.message || 'Bank transfer request submitted.');
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Unable to submit bank transfer.');
            });
    };

    function initMonetizationPage() {
        if (window.location.pathname !== '/monetization') return;
        apiFetchJson('/api/credit-packs')
            .then(function (data) {
                if (data && data.ok) {
                    refreshCreditBalanceUi(data.balance || 0);
                }
            })
            .catch(function () { });
    }

    function initAnalysisPage() {
        if (!window.analysisBootstrap) return;

        drawAnalysisCharts({
            status_counts: window.analysisBootstrap.statusCounts,
            type_counts: window.analysisBootstrap.typeCounts,
            type_risk: window.analysisBootstrap.typeRisk,
            trend: window.analysisBootstrap.trend
        });

        const filterSelect = byId('analysisFilter');
        const searchInput = byId('analysisSearch');
        const dashboardChatInput = byId('dashboardChatInput');
        if (filterSelect) filterSelect.addEventListener('change', window.refreshAnalysisDashboard);
        if (searchInput) {
            searchInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') window.refreshAnalysisDashboard();
            });
        }
        if (dashboardChatInput) {
            dashboardChatInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    if (typeof window.runDashboardChatbot === 'function') window.runDashboardChatbot();
                }
            });
        }
    }

    function applyThemeState(useDark, persistLocal) {
        var enabled = !!useDark;
        document.body.classList.toggle('dark-mode', enabled);
        document.body.setAttribute('data-dark-mode', enabled ? '1' : '0');
        if (persistLocal !== false) {
            try { localStorage.setItem('darkMode', enabled ? '1' : '0'); } catch (_) { }
        }
        var darkModeCheckbox = byId('darkMode');
        var quickDarkToggle = byId('quickDarkToggle');
        if (darkModeCheckbox) darkModeCheckbox.checked = enabled;
        if (quickDarkToggle) quickDarkToggle.checked = enabled;
    }

    function persistThemePreference(useDark) {
        return apiFetchJson('/api/theme', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ dark_mode: !!useDark })
        }).catch(function () { });
    }

    function initDarkMode() {
        const bodyDefaultDark = document.body.classList.contains('dark-mode') || String(document.body.getAttribute('data-dark-mode') || '') === '1';
        const stored = localStorage.getItem('darkMode');
        let useDark = true;
        if (stored === '1' || stored === '0') {
            useDark = stored === '1';
        } else {
            useDark = bodyDefaultDark || true;
        }
        applyThemeState(useDark, true);

        var darkModeCheckbox = byId('darkMode');
        if (darkModeCheckbox && !darkModeCheckbox.dataset.boundTheme) {
            darkModeCheckbox.dataset.boundTheme = '1';
            darkModeCheckbox.addEventListener('change', function () {
                applyThemeState(!!darkModeCheckbox.checked, true);
            });
        }
        var quickDarkToggle = byId('quickDarkToggle');
        if (quickDarkToggle && !quickDarkToggle.dataset.boundTheme) {
            quickDarkToggle.dataset.boundTheme = '1';
            quickDarkToggle.addEventListener('change', function () {
                applyThemeState(!!quickDarkToggle.checked, true);
                persistThemePreference(!!quickDarkToggle.checked);
            });
        }
    }

    function setupTopMoreMenu() {
        var btn = byId('topMoreBtn');
        var panel = byId('topMorePanel');
        var closeBtn = byId('topMoreClose');
        if (!btn || !panel) return;

        function openPanel() {
            panel.classList.remove('hidden');
            window.requestAnimationFrame(function () {
                panel.classList.add('open');
            });
            btn.setAttribute('aria-expanded', 'true');
            panel.setAttribute('aria-hidden', 'false');
        }

        function closePanel() {
            panel.classList.remove('open');
            btn.setAttribute('aria-expanded', 'false');
            panel.setAttribute('aria-hidden', 'true');
            window.setTimeout(function () {
                if (!panel.classList.contains('open')) panel.classList.add('hidden');
            }, 220);
        }

        if (!btn.dataset.boundMoreMenu) {
            btn.dataset.boundMoreMenu = '1';
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                if (panel.classList.contains('hidden') || !panel.classList.contains('open')) {
                    openPanel();
                } else {
                    closePanel();
                }
            });
        }
        if (closeBtn && !closeBtn.dataset.boundMoreMenu) {
            closeBtn.dataset.boundMoreMenu = '1';
            closeBtn.addEventListener('click', function (e) {
                e.preventDefault();
                closePanel();
            });
        }
        if (!document.body.dataset.boundMoreMenuClose) {
            document.body.dataset.boundMoreMenuClose = '1';
            document.addEventListener('click', function (e) {
                if (panel.classList.contains('hidden')) return;
                var target = e.target;
                if (panel.contains(target) || btn.contains(target)) return;
                closePanel();
            });
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && !panel.classList.contains('hidden')) closePanel();
            });
        }
    }

    function initPwaInstall() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker
                .register('/sw.js', { updateViaCache: 'none' })
                .then(function (reg) {
                    if (reg && typeof reg.update === 'function') reg.update();
                })
                .catch(function () { });
        }

        var deferredPrompt = null;
        var installBtn = byId('installAppBtn');
        window.addEventListener('beforeinstallprompt', function (e) {
            e.preventDefault();
            deferredPrompt = e;
            if (installBtn) installBtn.classList.remove('hidden');
        });

        if (installBtn) {
            installBtn.addEventListener('click', function () {
                if (!deferredPrompt) return;
                deferredPrompt.prompt();
                deferredPrompt.userChoice.finally(function () {
                    deferredPrompt = null;
                    installBtn.classList.add('hidden');
                });
            });
        }
    }

    function initButtonClickFlash() {
        document.addEventListener('click', function (e) {
            var target = e.target && e.target.closest
                ? e.target.closest('button, .btn-primary, .btn-secondary, .btn-analyze, .btn-export, .btn-danger, .install-btn, .chat-input button')
                : null;
            if (!target) return;
            if (target.disabled || target.classList.contains('disabled')) return;
            target.classList.remove('btn-click-flash');
            void target.offsetWidth;
            target.classList.add('btn-click-flash');
            window.setTimeout(function () {
                target.classList.remove('btn-click-flash');
            }, 320);
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        setupHistoryNav();
        setupSidebarToggle();
        setupQuickToolsListToggle();
        setupTopMoreMenu();
        initDarkMode();
        bindAttackCards();
        initEncryptionToolUi();
        initAnalysisPage();
        initMonetizationPage();
        initPwaInstall();
        initButtonClickFlash();
        initModuleSuggestions();
        if (
            window.location.pathname.indexOf('/features/') === 0 &&
            window.location.pathname.indexOf('/features/chatbot') !== 0 &&
            window.location.pathname.indexOf('/features/assistant') !== 0
        ) {
            updateModuleInsight({
                score: 0,
                status: 'SAFE',
                message: 'Enter input and run scan to see live risk message, percentage, and graph.'
            });
        }
        const assistantInput = byId('assistantInput');
        if (assistantInput) {
            assistantInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    window.sendAssistantMessage();
                }
            });
        }
        const assistantSendBtn = byId('assistantSendBtn');
        if (assistantSendBtn && !assistantSendBtn.dataset.boundSend) {
            assistantSendBtn.dataset.boundSend = '1';
            assistantSendBtn.addEventListener('click', function (e) {
                e.preventDefault();
                window.sendAssistantMessage();
            });
        }
        const chatInput = byId('chatInput');
        if (chatInput) {
            chatInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    window.sendChatbotMessage();
                }
            });
        }
        const chatbotSendBtn = byId('chatbotSendBtn');
        if (chatbotSendBtn && !chatbotSendBtn.dataset.boundSend) {
            chatbotSendBtn.dataset.boundSend = '1';
            chatbotSendBtn.addEventListener('click', function (e) {
                e.preventDefault();
                window.sendChatbotMessage();
            });
        }
        const chatbotComposerForm = byId('chatbotComposerForm');
        if (chatbotComposerForm && !chatbotComposerForm.dataset.boundSubmit) {
            chatbotComposerForm.dataset.boundSubmit = '1';
            chatbotComposerForm.addEventListener('submit', function (e) {
                e.preventDefault();
                window.sendChatbotMessage();
            });
        }
        const chatbotClearBtn = document.querySelector('.pro-chat-clear[onclick*="clearChatbotChat"]');
        if (chatbotClearBtn && !chatbotClearBtn.dataset.boundClear) {
            chatbotClearBtn.dataset.boundClear = '1';
            chatbotClearBtn.addEventListener('click', function (e) {
                e.preventDefault();
                window.clearChatbotChat();
            });
        }
        const assistantClearBtn = document.querySelector('.pro-chat-clear[onclick*="clearAssistantChat"]');
        if (assistantClearBtn && !assistantClearBtn.dataset.boundClear) {
            assistantClearBtn.dataset.boundClear = '1';
            assistantClearBtn.addEventListener('click', function (e) {
                e.preventDefault();
                window.clearAssistantChat();
            });
        }
        const urlScanBtn = byId('urlScanBtn');
        if (urlScanBtn && !urlScanBtn.dataset.boundUrlScanner) {
            urlScanBtn.dataset.boundUrlScanner = '1';
            urlScanBtn.addEventListener('click', function () {
                if (typeof window.scanURL === 'function') window.scanURL();
            });
        }
        const urlInput = byId('urlInput');
        if (urlInput && !urlInput.dataset.boundUrlScanner) {
            urlInput.dataset.boundUrlScanner = '1';
            urlInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (typeof window.scanURL === 'function') window.scanURL();
                }
            });
        }
        const reportSearch = byId('reportSearch');
        if (reportSearch && !reportSearch.dataset.boundReportEnter) {
            reportSearch.dataset.boundReportEnter = '1';
            reportSearch.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (typeof window.applyReportFilter === 'function') window.applyReportFilter();
                }
            });
        }

        var networkBtn = byId('networkScanBtn') || document.querySelector('button[onclick*="runNetworkScan"]');
        if (networkBtn && !networkBtn.dataset.boundNetworkScan) {
            networkBtn.dataset.boundNetworkScan = '1';
            networkBtn.removeAttribute('onclick');
            networkBtn.addEventListener('click', function (e) {
                e.preventDefault();
                if (typeof window.runNetworkScan === 'function') window.runNetworkScan();
            });
        }
        var networkInput = byId('networkTargetInput');
        if (networkInput && !networkInput.dataset.boundNetworkEnter) {
            networkInput.dataset.boundNetworkEnter = '1';
            networkInput.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (typeof window.runNetworkScan === 'function') window.runNetworkScan();
                }
            });
        }
    });
})();

