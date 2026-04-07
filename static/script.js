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

    function setFaceInputNotice(message, type) {
        var node = byId('faceInputNotice');
        if (!node) return;
        node.textContent = String(message || 'Upload one clear front-facing photo, tick consent, then run the scan.');
        node.className = 'face-input-notice' + (type ? (' ' + String(type)) : '');
    }

    function setForgotPasswordNotice(message, type) {
        var node = byId('forgotPasswordNotice');
        if (!node) return;
        var text = String(message || '').trim();
        node.textContent = text;
        node.className = 'auth-inline-notice' + (type ? (' ' + String(type)) : '');
        if (!text) {
            node.classList.add('hidden');
        } else {
            node.classList.remove('hidden');
        }
    }

    function resolveSiteSearchTarget(rawValue) {
        const value = String(rawValue || '').trim().toLowerCase();
        if (!value) return '/';

        const routes = [
            { keys: ['dashboard', 'analysis', 'summary'], target: '/analysis' },
            { keys: ['home', 'landing'], target: '/' },
            { keys: ['command', 'terminal', 'command analyzer'], target: '/features/command' },
            { keys: ['password', 'password checker', 'password strength'], target: '/features/password' },
            { keys: ['url', 'url scanner', 'phishing'], target: '/features/url' },
            { keys: ['email breach', 'breach', 'hibp', 'gmail'], target: '/features/breach' },
            { keys: ['port', 'port scanner', 'ports'], target: '/features/port-scan' },
            { keys: ['network', 'network scan', 'network ai'], target: '/features/network-scan' },
            { keys: ['encryption', 'encrypt', 'decrypt'], target: '/features/encryption' },
            { keys: ['face', 'face intel', 'face recognition'], target: '/features/face-intel' },
            { keys: ['reports', 'report'], target: '/reports' },
            { keys: ['settings', 'preferences'], target: '/settings' },
            { keys: ['profile', 'account'], target: '/profile' },
            { keys: ['chat', 'chatbot', 'assistant'], target: '/features/chatbot' }
        ];

        for (var i = 0; i < routes.length; i += 1) {
            var route = routes[i];
            if (route.keys.some(function (key) { return value.indexOf(key) >= 0; })) {
                return route.target;
            }
        }

        return '/analysis?q=' + encodeURIComponent(rawValue);
    }

    function submitSiteSearch(value) {
        const target = resolveSiteSearchTarget(value);
        if (!target) return;
        window.location.assign(target);
    }

    function bindQuickSearchForm(formId, inputId) {
        var form = byId(formId);
        var input = byId(inputId);
        if (!form || !input) return;

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var value = String(input.value || '').trim();
            if (!value) return showInvalidInput('Type what you want to open first.');
            submitSiteSearch(value);
        });
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
        if (window.location.pathname === '/features/attack') return null;
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
                welcomeText: 'Hello! I am your pro cybersecurity assistant. Ask me about phishing, email breach checks, Linux hardening, SOC checklists, password policy, incident response, or suspicious URLs.'
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
            welcomeText: String(shell.dataset.initWelcomeText || 'Hello! I am your pro cybersecurity assistant. Ask me about phishing, email breach checks, Linux hardening, SOC checklists, password policy, incident response, or suspicious URLs.').trim()
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

        const hibpUrl = 'https://haveibeenpwned.com/?Account=' + encodeURIComponent(email);
        window.location.assign(hibpUrl);
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
                hint: 'Type your message and a secret key. This will create cipher text.',
                secretRequired: true
            };
        }
        if (key === 'decrypt_text') {
            return {
                label: 'Decrypt Text',
                inputLabel: 'Cipher Text',
                placeholder: 'Example: v2.ABCD...XYZ',
                hint: 'Paste your cipher text and enter the same secret key to get your original message back.',
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
        var actionValue = String(actionNode.value || 'sha256').trim().toLowerCase();
        var textNode = byId('encryptionTextInput');
        var hintNode = byId('encryptionHintText');
        var secretWrap = byId('encryptionSecretWrap');
        var secretLabel = byId('encryptionSecretLabel');
        var textLabel = byId('encryptionTextLabel');
        var secretNode = byId('encryptionSecretInput');
        var outputLabel = byId('encryptionOutputLabel');
        var meta = getEncryptionActionMeta(actionValue);

        if (textNode) textNode.placeholder = meta.placeholder;
        if (hintNode) hintNode.textContent = meta.hint;
        if (textLabel) textLabel.textContent = meta.inputLabel;
        if (outputLabel) outputLabel.textContent = actionValue === 'decrypt_text' ? 'Your Message' : 'Output';

        if (secretWrap) secretWrap.classList.toggle('hidden', !meta.secretRequired);
        if (secretLabel) secretLabel.classList.toggle('hidden', !meta.secretRequired);
        if (secretLabel && meta.secretRequired) secretLabel.textContent = 'Secret Key';
        if (secretNode) {
            if (!meta.secretRequired) secretNode.value = '';
            secretNode.required = !!meta.secretRequired;
            if (meta.secretRequired) {
                secretNode.placeholder = actionValue === 'decrypt_text'
                    ? 'Enter the same secret key'
                    : 'Enter a secret key';
            }
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

    function setEncryptionText(id, value) {
        var node = byId(id);
        if (node) node.textContent = String(value || '');
    }

    function generateEncryptionKey() {
        var length = 24;
        var charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
        var chars = [];
        if (window.crypto && window.crypto.getRandomValues) {
            var bytes = new Uint32Array(length);
            window.crypto.getRandomValues(bytes);
            for (var i = 0; i < length; i += 1) {
                chars.push(charset.charAt(bytes[i] % charset.length));
            }
            return chars.join('');
        }
        while (chars.length < length) {
            chars.push(charset.charAt(Math.floor(Math.random() * charset.length)));
        }
        return chars.join('');
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

    function syncEncryptionDecryptPreview(value) {
        var wrap = byId('encryptionDecryptSourceWrap');
        var node = byId('encryptionDecryptSource');
        var text = String(value || '').trim();
        if (node) node.value = text;
        if (wrap) wrap.classList.toggle('hidden', !text);
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
        syncEncryptionDecryptPreview('');

        setEncryptionText('encryptionScoreValue', '0');
        setEncryptionText('encryptionStatus', 'READY');
        setEncryptionText('encryptionMessage', 'Form cleared. Choose an operation and run again.');
        setEncryptionText('encryptionOperation', '-');
        setEncryptionText('encryptionOutputLength', '0');
        setEncryptionText('encryptionSafePercent', '100%');
        setEncryptionText('encryptionProcessedAt', '-');
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
                if (String(actionNode.value || '').trim().toLowerCase() !== 'decrypt_text') {
                    syncEncryptionDecryptPreview('');
                }
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

        var generateKeyBtn = byId('encryptionGenerateKeyBtn');
        if (generateKeyBtn && !generateKeyBtn.dataset.boundEncryptionGenerate) {
            generateKeyBtn.dataset.boundEncryptionGenerate = '1';
            generateKeyBtn.addEventListener('click', function () {
                window.generateEncryptionKeyAndFill();
            });
        }

        var copyKeyBtn = byId('encryptionCopyKeyBtn');
        if (copyKeyBtn && !copyKeyBtn.dataset.boundEncryptionCopyKey) {
            copyKeyBtn.dataset.boundEncryptionCopyKey = '1';
            copyKeyBtn.addEventListener('click', function () {
                window.copyEncryptionKey();
            });
        }

        var useOutputBtn = byId('encryptionUseOutputBtn');
        if (useOutputBtn && !useOutputBtn.dataset.boundEncryptionUseOutput) {
            useOutputBtn.dataset.boundEncryptionUseOutput = '1';
            useOutputBtn.addEventListener('click', function () {
                window.useEncryptionOutputForDecrypt();
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

    window.generateEncryptionKeyAndFill = function generateEncryptionKeyAndFill() {
        var secretNode = byId('encryptionSecretInput');
        if (!secretNode) return;
        var key = generateEncryptionKey();
        secretNode.value = key;
        secretNode.type = 'text';
        var secretToggle = byId('encryptionSecretToggle');
        if (secretToggle) secretToggle.innerHTML = '<i class="fas fa-eye-slash"></i>';
        setEncryptionText('encryptionStatus', 'READY');
        setEncryptionText('encryptionMessage', 'New secret key generated. Save this key to decrypt your message later.');
    };

    window.copyEncryptionKey = function copyEncryptionKey() {
        var secretNode = byId('encryptionSecretInput');
        var value = secretNode ? String(secretNode.value || '').trim() : '';
        if (!value) return showInvalidInput('Secret key is empty. Generate or enter a key first.');

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(value).then(function () {
                setEncryptionText('encryptionStatus', 'READY');
                setEncryptionText('encryptionMessage', 'Secret key copied successfully.');
            }).catch(function () {
                showInvalidInput('Copy failed. Please copy the key manually.');
            });
            return;
        }

        if (secretNode) {
            secretNode.type = 'text';
            secretNode.focus();
            secretNode.select();
        }
        try {
            document.execCommand('copy');
            setEncryptionText('encryptionStatus', 'READY');
            setEncryptionText('encryptionMessage', 'Secret key copied successfully.');
        } catch (_) {
            showInvalidInput('Copy failed. Please copy the key manually.');
        }
    };

    window.useEncryptionOutputForDecrypt = function useEncryptionOutputForDecrypt() {
        var outputNode = byId('encryptionOutput');
        var actionNode = byId('encryptionActionInput');
        var textNode = byId('encryptionTextInput');
        var outputValue = outputNode ? String(outputNode.value || '').trim() : '';
        if (!outputValue || isEncryptionOutputPlaceholder(outputValue)) {
            return showInvalidInput('First generate encrypted output, then use this button for decryption.');
        }
        if (actionNode) actionNode.value = 'decrypt_text';
        if (textNode) textNode.value = outputValue;
        syncEncryptionDecryptPreview(outputValue);
        syncEncryptionActionUi();
        if (textNode) textNode.focus();
        setEncryptionText('encryptionStatus', 'READY');
        setEncryptionText('encryptionMessage', 'Cipher text loaded. Enter the same secret key and click Run Tool.');
    };

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
        setEncryptionText('encryptionStatus', 'PROCESSING');
        setEncryptionText('encryptionMessage', 'Running ' + meta.label + '...');

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

                setEncryptionText('encryptionScoreValue', String(score));
                setEncryptionText('encryptionStatus', status);
                setEncryptionText('encryptionMessage', data.message || 'Operation complete.');
                setEncryptionText('encryptionOperation', data.operation_label || meta.label);
                setEncryptionText('encryptionOutputLength', String(output.length));
                setEncryptionText('encryptionSafePercent', String(safePercent) + '%');
                setEncryptionText('encryptionProcessedAt', data.processed_at || (new Date()).toLocaleTimeString());

                var outputNode = byId('encryptionOutput');
                if (outputNode) outputNode.value = output || 'No textual output generated by this operation.';
                if (String(action).trim().toLowerCase() === 'decrypt_text') {
                    syncEncryptionDecryptPreview(text);
                } else {
                    syncEncryptionDecryptPreview('');
                }

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
                setEncryptionText('encryptionStatus', 'WARNING');
                setEncryptionText('encryptionMessage', message);
                setEncryptionText('encryptionOperation', meta.label);
                setEncryptionText('encryptionProcessedAt', (new Date()).toLocaleTimeString());
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

    function getFaceIntelState() {
        const input = byId('faceImageInput');
        const consent = byId('faceConsentCheck');
        const file = input && input.files ? input.files[0] : null;
        if (!file) return { ok: false, message: 'Please upload one face photo first.' };
        if (!/\.(png|jpg|jpeg|webp)$/i.test(String(file.name || ''))) return { ok: false, message: 'Please upload only PNG, JPG, JPEG, or WebP face photo.' };
        if (!consent || !consent.checked) return { ok: false, message: 'Please tick consent before running face analysis.' };
        return {
            ok: true,
            file: file,
            personName: ((byId('facePersonName') || {}).value || '').trim()
        };
    }

    function buildFaceIntelFormData(extraFields) {
        const state = getFaceIntelState();
        if (!state.ok) {
            setFaceInputNotice(state.message, 'warning');
            showInvalidInput(state.message);
            return null;
        }
        setFaceInputNotice('Face image accepted. Scan is ready to run.', 'safe');
        const formData = new FormData();
        formData.append('image', state.file);
        formData.append('consent', 'yes');
        Object.keys(extraFields || {}).forEach(function (key) {
            formData.append(key, String(extraFields[key] || ''));
        });
        return {
            formData: formData,
            personName: state.personName
        };
    }

    function renderPublicFaceResult(data) {
        const score = Number(data.score || 0);
        const mode = String(data.mode || '').trim().toLowerCase();
        const section = byId('faceResultSection');
        byId('faceScoreValue').textContent = String(score);
        byId('faceStatus').textContent = data.status || 'UNKNOWN';
        byId('faceMessage').textContent = data.message || '';
        byId('faceScoreCircle').className = 'score-circle ' + getRiskClass(score);
        const matches = Array.isArray(data.matches) ? data.matches : [];
        const list = byId('faceMatchList');
        if (list) {
            list.innerHTML = '';
            if (!matches.length) {
                if (mode === 'facecheck-live') {
                    list.innerHTML = '<li>No public matches found.</li>';
                }
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
        if (section) {
            if (!matches.length && mode !== 'facecheck-live') {
                section.classList.add('hidden');
            } else {
                section.classList.remove('hidden');
            }
        }
        return { score: score, matches: matches };
    }

    function renderFaceEmotionBadge(emotion) {
        const node = byId('faceEmotionBadge');
        if (!node) return;
        const data = emotion && typeof emotion === 'object' ? emotion : {};
        const label = String(data.display_label || data.label || '').trim();
        const confidence = Number(data.confidence || 0);
        if (!label) {
            node.textContent = 'Emotion: Waiting';
            node.className = 'face-emotion-badge';
            return;
        }
        node.textContent = confidence > 0
            ? ('Emotion: ' + label + ' (' + Math.round(confidence) + '%)')
            : ('Emotion: ' + label);
        node.className = 'face-emotion-badge ready';
    }

    function getFaceEmotionCategory(label) {
        const value = String(label || '').trim().toLowerCase();
        if (!value) return 'Neutral';
        if (['happy', 'joy'].includes(value)) return 'Positive';
        if (['sad', 'angry', 'anger', 'mad', 'fear', 'disgust'].includes(value)) return 'Negative';
        return 'Neutral';
    }

    function buildFaceSummaryHtml(data) {
        const payload = data && typeof data === 'object' ? data : {};
        const top = payload.top_match && typeof payload.top_match === 'object'
            ? payload.top_match
            : ((Array.isArray(payload.matches) && payload.matches.length) ? payload.matches[0] : null);
        const similarity = top ? Math.round(Number(top.score || 0)) : 0;
        const filename = top ? String(top.filename || top.id || top.name || 'N/A') : 'N/A';
        const emotion = payload.emotion && typeof payload.emotion === 'object' ? payload.emotion : {};
        const emotionLabel = String(emotion.display_label || emotion.label || '').trim();
        const emotionConfidence = Math.round(Number(emotion.confidence || 0));
        const category = getFaceEmotionCategory(emotionLabel);
        const faceIssue = String(payload.message || '').toLowerCase().includes('face')
            && String(payload.message || '').toLowerCase().includes('not')
            && !top;
        return [
            'Face Match:',
            '- Match Found: ' + (top ? 'Yes' : 'No'),
            '- Similarity: ' + similarity + '%',
            '- Matching Image: ' + filename,
            '',
            'Emotion Analysis:',
            '- Emotion: ' + (faceIssue ? 'Face not detected properly' : (emotionLabel || 'Face not detected properly')),
            '- Confidence: ' + (emotionLabel ? (emotionConfidence + '%') : '0%'),
            '- Category: ' + (emotionLabel ? category : 'Neutral')
        ].join('<br>');
    }

    function renderFaceSummary(nodeId, data) {
        const node = byId(nodeId);
        if (!node) return;
        node.innerHTML = buildFaceSummaryHtml(data);
    }

    function renderLiveStagePreview(nodeId, src, placeholderText, altText) {
        const node = byId(nodeId);
        if (!node) return;
        const safeSrc = String(src || '').trim();
        if (safeSrc) {
            node.innerHTML = '<img class="face-live-photo" src="' + safeText(safeSrc) + '" alt="' + safeText(altText || placeholderText || 'Face preview') + '">';
            node.classList.remove('face-live-placeholder');
        } else {
            node.innerHTML = '<span class="face-live-empty-mark"><i class="fas fa-image"></i></span>';
            node.classList.add('face-live-placeholder');
        }
    }

    function getMatchPreviewSrc(match) {
        const item = match && typeof match === 'object' ? match : {};
        return String(item.preview || item.preview_url || '').trim();
    }

    function getSelectedFacePreviewSrc() {
        const input = byId('faceImageInput');
        return input && input.dataset ? String(input.dataset.previewSrc || '').trim() : '';
    }

    function previewSelectedFaceFile(file) {
        const input = byId('faceImageInput');
        if (!input || !window.FileReader) return;
        if (!file) {
            input.dataset.previewSrc = '';
            renderLiveStagePreview('faceUploadedPreview', '', 'Your Pic', 'Your uploaded face');
            return;
        }
        const reader = new FileReader();
        reader.onload = function (event) {
            const result = String((event && event.target && event.target.result) || '').trim();
            input.dataset.previewSrc = result;
            renderLiveStagePreview('faceUploadedPreview', result, 'Your Pic', 'Your uploaded face');
        };
        reader.readAsDataURL(file);
    }

    function setFaceActionBusy(buttonId, busy, busyHtml) {
        const btn = byId(buttonId);
        if (!btn) return;
        if (busy) {
            if (!btn.dataset.originalHtml) btn.dataset.originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = busyHtml || '<i class="fas fa-spinner fa-spin"></i> Working...';
            return;
        }
        btn.disabled = false;
        if (btn.dataset.originalHtml) btn.innerHTML = btn.dataset.originalHtml;
    }

    function resolveBestPreviewMatch(data) {
        if (!data || typeof data !== 'object') return null;
        const top = data.top_match && typeof data.top_match === 'object' ? data.top_match : null;
        if (top && getMatchPreviewSrc(top)) return top;
        const matches = Array.isArray(data.matches) ? data.matches : [];
        for (let i = 0; i < matches.length; i += 1) {
            if (getMatchPreviewSrc(matches[i])) return matches[i];
        }
        return top || (matches.length ? matches[0] : null);
    }

    function pickBestFaceMatch(localData, galleryData) {
        const candidates = [];
        [localData, galleryData].forEach(function (data) {
            const top = resolveBestPreviewMatch(data);
            if (!top) return;
            candidates.push({
                source: data && data.mode === 'trained-gallery' ? 'Trained Gallery' : 'Local Database',
                data: data || {},
                match: top,
                score: Number(top.score || 0)
            });
        });
        candidates.sort(function (a, b) { return b.score - a.score; });
        return candidates.length ? candidates[0] : null;
    }

    function renderFaceLiveStage(bestCandidate, publicData) {
        const bestPercent = byId('faceBestPercent');
        const bestName = byId('faceBestName');
        const liveMessage = byId('faceLiveMessage');
        const publicEmotion = publicData && publicData.emotion ? publicData.emotion : {};
        const bestEmotion = bestCandidate && bestCandidate.data && bestCandidate.data.emotion ? bestCandidate.data.emotion : publicEmotion;
        const selectedPreview = getSelectedFacePreviewSrc();
        renderFaceEmotionBadge(bestEmotion);

        if (!bestCandidate) {
            renderLiveStagePreview('faceUploadedPreview', (publicData || {}).query_preview || selectedPreview, 'Your Pic', 'Your uploaded face');
            renderLiveStagePreview('faceMatchedPreview', '', 'DB Match', 'Matching database face');
            if (bestPercent) bestPercent.textContent = '0%';
            if (bestName) bestName.textContent = 'No strong database match found';
            if (liveMessage) liveMessage.textContent = 'Try a clearer front-facing photo or save more database faces first.';
            return;
        }

        renderLiveStagePreview('faceUploadedPreview', bestCandidate.data.query_preview || selectedPreview, 'Your Pic', 'Your uploaded face');
        renderLiveStagePreview('faceMatchedPreview', getMatchPreviewSrc(bestCandidate.match), 'DB Match', 'Best matching database face');
        if (bestPercent) bestPercent.textContent = String(Math.round(Number(bestCandidate.match.score || 0))) + '%';
        if (bestName) bestName.textContent = String(bestCandidate.match.name || 'Best match') + ' from ' + String(bestCandidate.source || 'database');
        if (liveMessage) liveMessage.textContent = String(bestCandidate.data.message || 'Comparison completed. Review your pic and the matching DB pic below.');
    }

    function renderLocalFaceList(data) {
        const list = byId('localFaceSavedList');
        if (!list) return;
        const items = Array.isArray((data || {}).items) ? data.items : [];
        if (!items.length) {
            list.innerHTML = '<li>No saved local face profiles yet.</li>';
            return;
        }
        list.innerHTML = items.map(function (item) {
            const preview = getMatchPreviewSrc(item);
            return '<li class="saved-face-item">' +
                (preview ? '<img class="face-thumb" src="' + safeText(preview) + '" alt="Saved face preview">' : '') +
                '<div class="saved-face-meta"><strong>' + safeText(item.name || 'Unnamed face') + '</strong> - ' +
                safeText(item.filename || 'image') + ' - ' +
                safeText(item.created_at || 'saved recently') + '</div>' +
                '<button type="button" class="btn-danger" onclick="deleteLocalFaceProfile(\'' + safeText(item.id || '') + '\')">Delete</button></li>';
        }).join('');
    }

    function renderFaceCompareCards(containerId, data, emptyMessage) {
        const container = byId(containerId);
        if (!container) return;
        const matches = Array.isArray((data || {}).matches) ? data.matches : [];
        const queryPreview = String((data || {}).query_preview || getSelectedFacePreviewSrc() || '').trim();
        const queryLabel = safeText((data || {}).query_label || 'Your Pic');
        const matchLabel = safeText((data || {}).match_label || 'Matching Pic');

        if (!matches.length) {
            container.innerHTML = '<div class="muted-text">' + safeText(emptyMessage || 'No face matches available.') + '</div>';
            return;
        }

        container.innerHTML = matches.slice(0, 3).map(function (item) {
            const matchPreview = getMatchPreviewSrc(item);
            return '<article class="face-compare-card">' +
                '<div class="face-compare-summary">' + queryLabel + ' vs ' + matchLabel + ': ' + safeText(String(item.score || 0)) + '% match</div>' +
                '<div class="face-compare-images">' +
                '<div class="face-compare-pane">' +
                (queryPreview ? '<img class="face-compare-image" src="' + safeText(queryPreview) + '" alt="Your pic">' : '<div class="face-compare-missing"><i class="fas fa-image"></i></div>') +
                '<div class="face-compare-label">' + queryLabel + '</div>' +
                '</div>' +
                '<div class="face-compare-pane">' +
                (matchPreview ? '<img class="face-compare-image" src="' + safeText(matchPreview) + '" alt="Matching pic">' : '<div class="face-compare-missing"><i class="fas fa-image"></i></div>') +
                '<div class="face-compare-label">' + matchLabel + '</div>' +
                '</div>' +
                '</div>' +
                '<div class="face-compare-meta"><strong>' + safeText(item.name || 'Unknown match') + '</strong>' +
                '<span>' + safeText(String(item.score || 0)) + '% match</span></div>' +
                '<p class="face-compare-note">' + safeText(item.source === 'trained-gallery' ? 'Matched from trained gallery database.' : 'Matched from your saved local database.') + '</p>' +
                '</article>';
        }).join('');
    }

    function renderLocalFaceCompare(data) {
        const score = Number(data.score || 0);
        const status = data.status || 'UNKNOWN';
        const matches = Array.isArray(data.matches) ? data.matches : [];
        const findings = Array.isArray(data.findings) ? data.findings : [];

        if (byId('localFaceScoreValue')) byId('localFaceScoreValue').textContent = String(score);
        if (byId('localFaceStatus')) byId('localFaceStatus').textContent = status;
        if (byId('localFaceMessage')) byId('localFaceMessage').textContent = data.message || '';
        if (byId('localFaceScoreCircle')) byId('localFaceScoreCircle').className = 'score-circle ' + getRiskClass(score);
        renderFaceSummary('localFaceSummary', data || {});
        renderFaceCompareCards('localFaceMatchCards', data || {}, 'No local face match previews available.');
        renderFaceEmotionBadge(data.emotion || {});
        const list = byId('localFaceMatchList');
        if (list) {
            if (matches.length) {
                list.innerHTML = matches.map(function (item) {
                    return '<li><strong>' + safeText(item.name || 'Unnamed face') + '</strong> - ' +
                        safeText(String(item.score || 0)) + '% similarity - ' +
                        safeText(item.filename || 'image') + '</li>';
                }).join('');
            } else {
                list.innerHTML = findings.length
                    ? findings.map(function (item) { return '<li>' + safeText(item) + '</li>'; }).join('')
                    : '<li>No local comparison results available.</li>';
            }
        }
        if (byId('localFaceCompareSection')) byId('localFaceCompareSection').classList.remove('hidden');
    }

    function renderGalleryFaceCompare(data) {
        const score = Number(data.score || 0);
        const status = data.status || 'UNKNOWN';
        const matches = Array.isArray(data.matches) ? data.matches : [];
        const findings = Array.isArray(data.findings) ? data.findings : [];

        if (byId('galleryFaceScoreValue')) byId('galleryFaceScoreValue').textContent = String(score);
        if (byId('galleryFaceStatus')) byId('galleryFaceStatus').textContent = status;
        if (byId('galleryFaceMessage')) byId('galleryFaceMessage').textContent = data.message || '';
        if (byId('galleryFaceScoreCircle')) byId('galleryFaceScoreCircle').className = 'score-circle ' + getRiskClass(score);
        renderFaceSummary('galleryFaceSummary', data || {});
        renderFaceCompareCards('galleryFaceMatchCards', data || {}, 'No trained gallery match previews available.');
        renderFaceEmotionBadge(data.emotion || {});
        const list = byId('galleryFaceMatchList');
        if (list) {
            list.innerHTML = findings.length
                ? findings.map(function (item) { return '<li>' + safeText(item) + '</li>'; }).join('')
                : '<li>No trained gallery comparison results available.</li>';
        }
        if (byId('galleryFaceCompareSection')) byId('galleryFaceCompareSection').classList.remove('hidden');
    }

    function getFaceStatusPriority(status) {
        const normalized = String(status || 'UNKNOWN').toUpperCase();
        if (normalized === 'DANGEROUS') return 3;
        if (normalized === 'WARNING') return 2;
        if (normalized === 'SAFE') return 1;
        return 0;
    }

    function mergeFaceInsight(publicData, publicRendered, localData, galleryData) {
        const publicScore = Number((publicRendered || {}).score || 0);
        const localScore = Number((localData || {}).score || 0);
        const galleryScore = Number((galleryData || {}).score || 0);
        const publicStatus = (publicData && publicData.status) || inferStatus(publicScore);
        const localStatus = (localData && localData.status) || inferStatus(localScore);
        const galleryStatus = (galleryData && galleryData.status) || inferStatus(galleryScore);
        let mergedStatus = publicStatus;
        if (getFaceStatusPriority(localStatus) > getFaceStatusPriority(mergedStatus)) mergedStatus = localStatus;
        if (getFaceStatusPriority(galleryStatus) > getFaceStatusPriority(mergedStatus)) mergedStatus = galleryStatus;
        const mergedScore = Math.max(publicScore, localScore, galleryScore);
        const suggestions = [];
        const publicMatches = Array.isArray((publicRendered || {}).matches) ? publicRendered.matches : [];
        const localFindings = Array.isArray((localData || {}).findings) ? localData.findings : [];
        const galleryFindings = Array.isArray((galleryData || {}).findings) ? galleryData.findings : [];

        if (publicMatches.length) {
            suggestions.push('Public face matches were found. Review each source carefully before taking action.');
        } else {
            suggestions.push('No strong public face matches were found in this scan.');
        }

        if (Array.isArray((localData || {}).matches) && localData.matches.length) {
            suggestions.push((localData.message || 'Local face comparison completed.').trim());
        } else if (localFindings.length) {
            suggestions.push(localFindings[0]);
        }

        if (Array.isArray((galleryData || {}).matches) && galleryData.matches.length) {
            suggestions.push((galleryData.message || 'Trained gallery comparison completed.').trim());
        } else if (galleryFindings.length) {
            suggestions.push(galleryFindings[0]);
        }

        return {
            score: mergedScore,
            status: mergedStatus,
            message: [
                (publicData && publicData.message) || 'Public face scan completed.',
                (localData && localData.message) || 'Local face comparison completed.',
                (galleryData && galleryData.message) || 'Trained gallery comparison completed.'
            ].filter(Boolean).join(' '),
            suggestions: suggestions.slice(0, 3),
            output_lines: [
                'Public face scan score: ' + publicScore + '%',
                'Local database score: ' + localScore + '%',
                'Trained gallery score: ' + galleryScore + '%'
            ]
        };
    }

    function executeLocalFaceCompare() {
        const payload = buildFaceIntelFormData();
        if (!payload) return Promise.reject(new Error('Face image and consent are required.'));

        return apiFetchJson('/api/face-intel/local-compare', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: payload.formData
        }).then(function (data) {
            renderLocalFaceCompare(data || {});
            return data || {};
        });
    }

    function executeGalleryFaceCompare() {
        const payload = buildFaceIntelFormData();
        if (!payload) return Promise.reject(new Error('Face image and consent are required.'));

        return apiFetchJson('/api/face-intel/gallery-compare', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: payload.formData
        }).then(function (data) {
            renderGalleryFaceCompare(data || {});
            return data || {};
        });
    }

    window.runFaceIntel = function runFaceIntel() {
        const payload = buildFaceIntelFormData();
        if (!payload) return;
        setFaceActionBusy('runFaceIntelBtn', true, '<i class="fas fa-spinner fa-spin"></i> Running...');
        setFaceInputNotice('Running face analysis now. Please wait for the match results.', 'safe');

        apiFetchJson('/api/face-intel', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: payload.formData
        })
            .then(function (data) {
                return { ok: true, data: data || {} };
            })
            .catch(function (err) {
                return {
                    ok: false,
                    data: {
                        score: 48,
                        status: 'WARNING',
                        message: (err && err.message) ? err.message : 'Public face scan is not available right now.',
                        matches: [],
                        findings: ['Public scan could not complete, but local database comparison will continue.']
                    }
                };
            })
            .then(function (publicState) {
                const publicData = publicState.data || {};
                const rendered = renderPublicFaceResult(publicData);
                return executeLocalFaceCompare()
                    .catch(function (err) {
                        const fallback = {
                            score: 52,
                            status: 'WARNING',
                            message: (err && err.message) ? err.message : 'Local face comparison failed.',
                            matches: [],
                            findings: ['Local face comparison could not finish in this run.']
                        };
                        renderLocalFaceCompare(fallback);
                        return fallback;
                    })
                    .then(function (localData) {
                        return executeGalleryFaceCompare()
                            .catch(function (err) {
                                const fallback = {
                                    score: 55,
                                    status: 'WARNING',
                                    message: (err && err.message) ? err.message : 'Trained gallery comparison failed.',
                                    matches: [],
                                    findings: ['Trained gallery comparison could not finish in this run.']
                                };
                                renderGalleryFaceCompare(fallback);
                                return fallback;
                            })
                            .then(function (galleryData) {
                                renderFaceLiveStage(pickBestFaceMatch(localData || {}, galleryData || {}), publicData || {});
                                setFaceInputNotice('Face analysis completed. Review your pic, the matched DB pic, and the emotion result below.', 'safe');
                                updateModuleInsight(mergeFaceInsight(publicData || {}, rendered, localData || {}, galleryData || {}));
                                return { publicData: publicData || {}, publicRendered: rendered, localData: localData || {}, galleryData: galleryData || {} };
                            });
                    });
            })
            .catch(function (err) {
                renderFaceLiveStage(null, {});
                setFaceInputNotice((err && err.message) ? err.message : 'Face search failed. Please retry with a clearer image.', 'warning');
                updateModuleInsight({
                    score: 50,
                    status: 'WARNING',
                    message: (err && err.message) ? err.message : 'Face search failed.'
                });
                alert((err && err.message) ? err.message : 'Face search failed. Please retry.');
            })
            .finally(function () {
                setFaceActionBusy('runFaceIntelBtn', false);
            });
    };

    window.refreshLocalFaceProfiles = function refreshLocalFaceProfiles() {
        apiFetchJson('/api/face-intel/local-faces')
            .then(function (data) {
                renderLocalFaceList(data || {});
            })
            .catch(function () { });
    };

    window.saveLocalFaceProfile = function saveLocalFaceProfile() {
        const payload = buildFaceIntelFormData({ person_name: ((byId('facePersonName') || {}).value || '').trim() });
        if (!payload) return;
        if (!payload.personName || payload.personName.length < 2) return showInvalidInput('Enter a known face name first.');
        setFaceActionBusy('saveFaceIntelBtn', true, '<i class="fas fa-spinner fa-spin"></i> Saving...');

        apiFetchJson('/api/face-intel/local-enroll', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: payload.formData
        })
            .then(function (data) {
                refreshLocalFaceProfiles();
                setFaceInputNotice(data.message || 'Known face saved successfully.', 'safe');
                updateModuleInsight({
                    score: 14,
                    status: 'SAFE',
                    message: data.message || 'Known face saved successfully.',
                    suggestions: ['Use a clear front-facing image for better local matching.', 'Save one face per person for clean results.']
                });
                alert(data.message || 'Known face saved successfully.');
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Could not save the known face.');
            })
            .finally(function () {
                setFaceActionBusy('saveFaceIntelBtn', false);
            });
    };

    window.compareLocalFaceProfile = function compareLocalFaceProfile() {
        setFaceActionBusy('compareFaceIntelBtn', true, '<i class="fas fa-spinner fa-spin"></i> Comparing...');
        executeLocalFaceCompare()
            .then(function (data) {
                const localData = data || {};
                const hasLocalPreview = !!resolveBestPreviewMatch(localData);
                if (hasLocalPreview) {
                    renderFaceLiveStage(pickBestFaceMatch(localData, {}), {});
                    setFaceInputNotice(localData.message || 'Local face comparison completed.', 'safe');
                    updateModuleInsight({
                        score: Number(localData.score || 0),
                        status: localData.status || inferStatus(Number(localData.score || 0)),
                        message: localData.message || 'Local face comparison completed.',
                        suggestions: (Array.isArray(localData.findings) ? localData.findings : []).slice(0, 3)
                    });
                    return null;
                }

                return executeGalleryFaceCompare()
                    .then(function (galleryData) {
                        renderFaceLiveStage(pickBestFaceMatch(localData, galleryData || {}), {});
                        setFaceInputNotice((galleryData && galleryData.message) || localData.message || 'Database comparison completed.', 'safe');
                        updateModuleInsight({
                            score: Math.max(Number(localData.score || 0), Number((galleryData || {}).score || 0)),
                            status: (galleryData && galleryData.status) || localData.status || 'WARNING',
                            message: ((galleryData && galleryData.message) || localData.message || 'Database comparison completed.'),
                            suggestions: ((Array.isArray((galleryData || {}).findings) ? galleryData.findings : []).concat(Array.isArray(localData.findings) ? localData.findings : [])).slice(0, 3)
                        });
                        return null;
                    })
                    .catch(function () {
                        renderFaceLiveStage(pickBestFaceMatch(localData, {}), {});
                        setFaceInputNotice(localData.message || 'Local face comparison completed.', localData.matches && localData.matches.length ? 'safe' : 'warning');
                        updateModuleInsight({
                            score: Number(localData.score || 0),
                            status: localData.status || inferStatus(Number(localData.score || 0)),
                            message: localData.message || 'Local face comparison completed.',
                            suggestions: (Array.isArray(localData.findings) ? localData.findings : []).slice(0, 3)
                        });
                        return null;
                    });
            })
            .catch(function () {
                return executeGalleryFaceCompare()
                    .then(function (galleryData) {
                        renderFaceLiveStage(pickBestFaceMatch({}, galleryData || {}), {});
                        setFaceInputNotice((galleryData && galleryData.message) ? galleryData.message : 'Gallery comparison completed.', 'safe');
                        updateModuleInsight({
                            score: Number((galleryData || {}).score || 0),
                            status: (galleryData && galleryData.status) || inferStatus(Number((galleryData || {}).score || 0)),
                            message: (galleryData && galleryData.message) || 'Gallery comparison completed.',
                            suggestions: (Array.isArray((galleryData || {}).findings) ? galleryData.findings : []).slice(0, 3)
                        });
                        return null;
                    });
            })
            .catch(function (err) {
                setFaceInputNotice((err && err.message) ? err.message : 'Face comparison failed.', 'warning');
                updateModuleInsight({
                    score: 50,
                    status: 'WARNING',
                    message: (err && err.message) ? err.message : 'Face comparison failed.'
                });
            })
            .finally(function () {
                setFaceActionBusy('compareFaceIntelBtn', false);
            });
    };

    window.deleteLocalFaceProfile = function deleteLocalFaceProfile(recordId) {
        const rid = String(recordId || '').trim();
        if (!rid) return;
        if (!window.confirm('Delete this saved face profile?')) return;

        apiFetchJson('/api/face-intel/local-delete', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ record_id: rid })
        })
            .then(function (data) {
                window.refreshLocalFaceProfiles();
                updateModuleInsight({
                    score: 12,
                    status: 'SAFE',
                    message: data.message || 'Saved face profile deleted successfully.',
                    suggestions: ['Save only the faces you still need for matching.']
                });
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Could not delete the saved face profile.');
            });
    };

    function initFaceIntelPage() {
        if (!byId('faceImageInput')) return;
        setFaceInputNotice('Upload one clear front-facing photo, tick consent, then run the scan.');
        renderFaceEmotionBadge({});
        renderFaceLiveStage(null, {});
        var runBtn = byId('runFaceIntelBtn');
        var saveBtn = byId('saveFaceIntelBtn');
        var compareBtn = byId('compareFaceIntelBtn');
        var refreshBtn = byId('refreshFaceIntelBtn');
        if (runBtn && !runBtn.dataset.boundFaceIntel) {
            runBtn.dataset.boundFaceIntel = '1';
            runBtn.addEventListener('click', function () {
                window.runFaceIntel();
            });
        }
        if (saveBtn && !saveBtn.dataset.boundFaceIntel) {
            saveBtn.dataset.boundFaceIntel = '1';
            saveBtn.addEventListener('click', function () {
                window.saveLocalFaceProfile();
            });
        }
        if (compareBtn && !compareBtn.dataset.boundFaceIntel) {
            compareBtn.dataset.boundFaceIntel = '1';
            compareBtn.addEventListener('click', function () {
                window.compareLocalFaceProfile();
            });
        }
        if (refreshBtn && !refreshBtn.dataset.boundFaceIntel) {
            refreshBtn.dataset.boundFaceIntel = '1';
            refreshBtn.addEventListener('click', function () {
                window.refreshLocalFaceProfiles();
            });
        }
        var fileInput = byId('faceImageInput');
        if (fileInput && !fileInput.dataset.boundPreview) {
            fileInput.dataset.boundPreview = '1';
            fileInput.addEventListener('change', function () {
                var file = (fileInput.files && fileInput.files[0]) ? fileInput.files[0] : null;
                previewSelectedFaceFile(file);
                if (file) {
                    setFaceInputNotice('Photo selected. Tick consent and click Run Full Face Check.', 'safe');
                } else {
                    setFaceInputNotice('Upload one clear front-facing photo, tick consent, then run the scan.');
                }
            });
        }
        window.refreshLocalFaceProfiles();
    }

    function initSiteSearch() {
        bindQuickSearchForm('siteQuickSearchForm', 'siteQuickSearch');
        bindQuickSearchForm('homeQuickSearchForm', 'homeQuickSearch');
        bindQuickSearchForm('dashboardQuickSearchForm', 'dashboardQuickSearch');

        document.querySelectorAll('[data-search-shortcut]').forEach(function (node) {
            node.addEventListener('click', function () {
                submitSiteSearch(node.getAttribute('data-search-shortcut') || '');
            });
        });
    }

    function initPasswordVisibilityToggles() {
        document.querySelectorAll('[data-toggle-password]').forEach(function (toggle) {
            if (toggle.dataset.boundPasswordToggle) return;
            toggle.dataset.boundPasswordToggle = '1';
            toggle.addEventListener('click', function () {
                var targetId = String(toggle.getAttribute('data-toggle-password') || '').trim();
                var input = targetId ? byId(targetId) : null;
                if (!input) return;
                var visible = input.type === 'text';
                input.type = visible ? 'password' : 'text';
                toggle.innerHTML = visible ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
                toggle.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
            });
        });
    }

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
    var analysisAutoRefreshTimer = null;

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
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderWidth: 0,
                    hoverOffset: 2
                }]
            },
            options: {
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { boxWidth: 10, usePointStyle: true }
                    }
                }
            }
        });

        typeChart = new Chart(typeCanvas, {
            type: 'bar',
            data: {
                labels: ['Commands', 'Passwords', 'URLs', 'Email Breach', 'Port Scan', 'Network AI', 'Encryption', 'Linux Lab', 'Face Intel'],
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
            options: {
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true, max: 100 } },
                plugins: { legend: { display: false } }
            }
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
            options: {
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: false } }
            }
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

    function setAnalysisRefreshStatus(message, isBusy) {
        var node = byId('analysisRefreshStatus');
        var btn = byId('analysisRefreshBtn');
        if (node) node.textContent = String(message || '');
        if (btn) {
            btn.disabled = !!isBusy;
            btn.innerHTML = isBusy
                ? '<i class="fas fa-spinner fa-spin"></i> Refreshing...'
                : '<i class="fas fa-sync"></i> Refresh';
        }
    }

    function formatDashboardRefreshTime() {
        try {
            return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch (_) {
            return '';
        }
    }

    function syncAnalysisUrl(filter, keyword) {
        if (!window.history || !window.history.replaceState) return;
        var nextUrl = '/analysis?filter=' + encodeURIComponent(filter || 'all') + '&q=' + encodeURIComponent(keyword || '');
        window.history.replaceState({}, '', nextUrl);
    }

    function applyAnalysisSummary(summary, filter, keyword) {
        updateAnalysisStats(summary);
        drawAnalysisCharts(summary);
        if (window.analysisBootstrap) {
            window.analysisBootstrap.filter = filter || 'all';
            window.analysisBootstrap.keyword = keyword || '';
            window.analysisBootstrap.statusCounts = summary.status_counts || { SAFE: 0, WARNING: 0, DANGEROUS: 0 };
            window.analysisBootstrap.typeCounts = summary.type_counts || {};
            window.analysisBootstrap.typeRisk = summary.type_risk || {};
            window.analysisBootstrap.trend = summary.trend || { labels: [], values: [] };
        }
        syncAnalysisUrl(filter, keyword);
        setAnalysisRefreshStatus('Dashboard updated at ' + formatDashboardRefreshTime() + '.', false);
    }

    function stopAnalysisAutoRefresh() {
        if (analysisAutoRefreshTimer) {
            window.clearInterval(analysisAutoRefreshTimer);
            analysisAutoRefreshTimer = null;
        }
    }

    function startAnalysisAutoRefresh() {
        stopAnalysisAutoRefresh();
        analysisAutoRefreshTimer = window.setInterval(function () {
            if (document.hidden) return;
            window.refreshAnalysisDashboard(true);
        }, 30000);
    }

    function loadDashboardRefreshPreference() {
        if (!window.analysisBootstrap) return;
        apiFetchJson('/api/settings')
            .then(function (settings) {
                if (settings && settings.auto_refresh) {
                    startAnalysisAutoRefresh();
                    setAnalysisRefreshStatus('Auto refresh is active. Last check at ' + formatDashboardRefreshTime() + '.', false);
                } else {
                    stopAnalysisAutoRefresh();
                }
            })
            .catch(function () {
                stopAnalysisAutoRefresh();
            });
    }

    window.refreshAnalysisDashboard = function refreshAnalysisDashboard(isSilent) {
        const filter = (byId('analysisFilter') || {}).value || 'all';
        const keyword = (byId('analysisSearch') || {}).value || '';
        if (!isSilent) {
            setAnalysisRefreshStatus('Refreshing dashboard data...', true);
        }

        apiFetchJson('/api/analysis-summary?filter=' + encodeURIComponent(filter) + '&q=' + encodeURIComponent(keyword))
            .then(function (summary) {
                applyAnalysisSummary(summary, filter, keyword);
            })
            .catch(function () {
                setAnalysisRefreshStatus(
                    isSilent
                        ? 'Auto refresh could not update dashboard right now.'
                        : 'Unable to refresh analysis right now. Please retry.',
                    false
                );
                if (!isSilent) {
                    alert('Unable to refresh analysis right now. Please retry.');
                }
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
        const filter = (byId('reportFilter') || {}).value || 'all';
        const keyword = (byId('reportSearch') || {}).value || '';
        const url = '/reports/export/pdf?filter=' + encodeURIComponent(filter) + '&q=' + encodeURIComponent(keyword);
        window.location.href = url;
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
                var msg = data.message || 'Verification code sent.';
                if (data.preview_code) {
                    msg += '\n\nTemporary code: ' + data.preview_code;
                }
                alert(msg);
            })
            .catch(function (err) {
                alert((err && err.message) ? err.message : 'Could not send verification code.');
            });
    };

    window.requestForgotPasswordCode = function requestForgotPasswordCode() {
        const email = ((byId('forgotEmailInput') || {}).value || '').trim();
        if (!email || email.indexOf('@') < 0) return showInvalidInput('Enter a valid Gmail or email address.');

        apiFetchJson('/api/public-request-password-code', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({ email: email })
        })
            .then(function (data) {
                setForgotPasswordNotice(data.message || 'Verification code sent.', data.delivery_mode === 'email' ? '' : 'warning');
            })
            .catch(function (err) {
                setForgotPasswordNotice((err && err.message) ? err.message : 'Could not send reset code.', 'warning');
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

    window.submitForgotPasswordChange = function submitForgotPasswordChange() {
        const email = ((byId('forgotEmailInput') || {}).value || '').trim();
        const code = ((byId('forgotOtpCode') || {}).value || '').trim();
        const newPassword = (byId('forgotNewPassword') || {}).value || '';
        const confirmPassword = (byId('forgotConfirmPassword') || {}).value || '';

        if (!email || email.indexOf('@') < 0) return showInvalidInput('Enter the same Gmail or email address first.');
        if (!/^\d{6}$/.test(code)) return showInvalidInput('Enter 6-digit verification code.');
        if (newPassword.length < 8) return showInvalidInput('Password must be at least 8 characters.');
        if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
            return showInvalidInput('Password must include uppercase, lowercase, and number.');
        }
        if (newPassword !== confirmPassword) return showInvalidInput('New password and confirm password do not match.');

        apiFetchJson('/api/public-change-password-with-code', {
            method: 'POST',
            headers: jsonHeaders(),
            body: JSON.stringify({
                email: email,
                code: code,
                new_password: newPassword,
                confirm_password: confirmPassword
            })
        })
            .then(function (data) {
                setForgotPasswordNotice(data.message || 'Password changed successfully.', '');
                window.location.href = '/login';
            })
            .catch(function (err) {
                setForgotPasswordNotice((err && err.message) ? err.message : 'Unable to change password.', 'warning');
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

        applyAnalysisSummary({
            status_counts: window.analysisBootstrap.statusCounts,
            type_counts: window.analysisBootstrap.typeCounts,
            type_risk: window.analysisBootstrap.typeRisk,
            trend: window.analysisBootstrap.trend
        }, window.analysisBootstrap.filter || 'all', window.analysisBootstrap.keyword || '');

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
        loadDashboardRefreshPreference();
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
        var installButtons = Array.prototype.slice.call(document.querySelectorAll('[data-install-app]'));
        var installCallout = byId('installCallout');

        function isStandaloneMode() {
            return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
        }

        function setInstallUiVisible(visible) {
            installButtons.forEach(function (btn) {
                btn.classList.toggle('hidden', !visible);
            });
            if (installCallout) {
                installCallout.classList.toggle('hidden', !visible);
            }
        }

        function showInstallFallbackHelp() {
            alert('To install this website, open your browser menu and choose "Install App" or "Add to Home Screen".');
        }

        if (isStandaloneMode()) {
            setInstallUiVisible(false);
            return;
        }

        setInstallUiVisible(true);

        window.addEventListener('beforeinstallprompt', function (e) {
            e.preventDefault();
            deferredPrompt = e;
            setInstallUiVisible(true);
        });

        installButtons.forEach(function (installBtn) {
            if (!installBtn || installBtn.dataset.boundInstallPrompt) return;
            installBtn.dataset.boundInstallPrompt = '1';
            installBtn.addEventListener('click', function () {
                if (!deferredPrompt) {
                    showInstallFallbackHelp();
                    return;
                }
                deferredPrompt.prompt();
                deferredPrompt.userChoice.finally(function () {
                    deferredPrompt = null;
                    setInstallUiVisible(false);
                });
            });
        });

        window.addEventListener('appinstalled', function () {
            setInstallUiVisible(false);
        });
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
        initFaceIntelPage();
        initSiteSearch();
        initPasswordVisibilityToggles();
        initMonetizationPage();
        initPwaInstall();
        initButtonClickFlash();
        initModuleSuggestions();
        if (
            window.location.pathname.indexOf('/features/') === 0 &&
            window.location.pathname.indexOf('/features/chatbot') !== 0 &&
            window.location.pathname.indexOf('/features/assistant') !== 0 &&
            window.location.pathname.indexOf('/features/attack') !== 0
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

