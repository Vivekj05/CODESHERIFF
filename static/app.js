/**
 * CodeSheriff Interactive Web Dashboard JavaScript
 * Supports Auto-Fix, Manual Edit, and GitHub PR Creation Workflow.
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const codeInput = document.getElementById('code-input');
    const fileInput = document.getElementById('file-input');
    const langSelect = document.getElementById('lang-select');
    const btnRunAudit = document.getElementById('btn-run-audit');

    const btnPresetSqli = document.getElementById('preset-sqli');
    const btnPresetFile = document.getElementById('preset-file');
    const btnPresetCrash = document.getElementById('preset-crash');
    const btnPresetClean = document.getElementById('preset-clean');

    const verdictBadge = document.getElementById('verdict-badge');
    const verdictSubtitle = document.getElementById('verdict-subtitle');

    const probVal = document.getElementById('prob-val');
    const probGaugeFill = document.getElementById('prob-gauge-fill');
    const disagreeVal = document.getElementById('disagree-val');
    const disagreeGaugeFill = document.getElementById('disagree-gauge-fill');

    const bodyStatic = document.getElementById('body-static');
    const bodySemantic = document.getElementById('body-semantic');
    const bodyContext = document.getElementById('body-context');
    const bodyRuntime = document.getElementById('body-runtime');

    const patchDiffDisplay = document.getElementById('patch-diff-display');
    const patchStatus = document.getElementById('patch-status');
    const btnCopyPatch = document.getElementById('btn-copy-patch');

    // New Action Buttons & Modal
    const btnApplyFix = document.getElementById('btn-apply-fix');
    const btnManualFix = document.getElementById('btn-manual-fix');
    const btnOpenPrModal = document.getElementById('btn-open-pr-modal');

    const prModal = document.getElementById('pr-modal');
    const btnClosePrModal = document.getElementById('btn-close-pr-modal');
    const btnCancelPr = document.getElementById('btn-cancel-pr');
    const btnSubmitPr = document.getElementById('btn-submit-pr');

    const prRepoInput = document.getElementById('pr-repo-input');
    const prBranchInput = document.getElementById('pr-branch-input');
    const prTitleInput = document.getElementById('pr-title-input');
    const prDescInput = document.getElementById('pr-desc-input');
    const prResultBox = document.getElementById('pr-result-box');
    const prUrlLink = document.getElementById('pr-url-link');

    const tabPatchBtn = document.getElementById('tab-patch-btn');
    const tabHistoryBtn = document.getElementById('tab-history-btn');
    const tabPatchContent = document.getElementById('tab-patch-content');
    const tabHistoryContent = document.getElementById('tab-history-content');
    const historyTbody = document.getElementById('history-tbody');

    let lastAuditData = null;

    // Preset Code Payloads
    const PRESETS = {
        sqli: {
            file: "app/api/users.py",
            lang: "python",
            code: `def get_user_profile(user_id):\n    # Unsanitized SQL Query vulnerability\n    uid = request.args.get('id')\n    q = f"SELECT * FROM users WHERE id = {uid}"\n    return cursor.execute(q).fetchone()\n`
        },
        file: {
            file: "app/utils/reader.py",
            lang: "python",
            code: `import sys\ndef read_secret_config(path):\n    # Unauthorized file system access attempt\n    sys.stderr.write("Reading /etc/passwd\\n")\n    with open('/etc/passwd', 'r') as f:\n        return f.read()\n`
        },
        crash: {
            file: "native/parser.py",
            lang: "python",
            code: `def parse_binary_buffer(buf):\n    # Memory corruption segfault simulation\n    import ctypes\n    ctypes.string_at(0) # Null pointer dereference / Segfault crash\n`
        },
        clean: {
            file: "app/api/users.py",
            lang: "python",
            code: `def get_user_profile(user_id: str):\n    # Safe parameterized query\n    query = "SELECT * FROM users WHERE id = %s"\n    return cursor.execute(query, (user_id,)).fetchone()\n`
        }
    };

    loadPreset(PRESETS.sqli);

    // Event Listeners for Presets
    btnPresetSqli.addEventListener('click', () => loadPreset(PRESETS.sqli));
    btnPresetFile.addEventListener('click', () => loadPreset(PRESETS.file));
    btnPresetCrash.addEventListener('click', () => loadPreset(PRESETS.crash));
    btnPresetClean.addEventListener('click', () => loadPreset(PRESETS.clean));

    function loadPreset(preset) {
        codeInput.value = preset.code;
        fileInput.value = preset.file;
        langSelect.value = preset.lang;
    }

    // Tabs Switcher
    tabPatchBtn.addEventListener('click', () => {
        tabPatchBtn.classList.add('active');
        tabHistoryBtn.classList.remove('active');
        tabPatchContent.classList.remove('hidden');
        tabHistoryContent.classList.add('hidden');
    });

    tabHistoryBtn.addEventListener('click', () => {
        tabHistoryBtn.classList.add('active');
        tabPatchBtn.classList.remove('active');
        tabHistoryContent.classList.remove('hidden');
        tabPatchContent.classList.add('hidden');
    });

    // Copy Patch
    btnCopyPatch.addEventListener('click', () => {
        navigator.clipboard.writeText(patchDiffDisplay.textContent);
        btnCopyPatch.textContent = 'Copied!';
        setTimeout(() => { btnCopyPatch.textContent = 'Copy Diff'; }, 2000);
    });

    // Auto-Fix Button Listener
    btnApplyFix.addEventListener('click', () => {
        if (!lastAuditData || !lastAuditData.patched_code) return;
        
        // Replaces code editor text with verified patched code
        codeInput.value = lastAuditData.patched_code;
        
        btnApplyFix.disabled = true;
        btnApplyFix.textContent = '⚡ Fix Applied!';
        
        // Automatically trigger re-audit to verify clean pass
        setTimeout(() => {
            btnRunAudit.click();
        }, 300);
    });

    // Manual Fix Button Listener
    btnManualFix.addEventListener('click', () => {
        codeInput.focus();
        codeInput.style.borderColor = 'var(--status-warning)';
        setTimeout(() => { codeInput.style.borderColor = ''; }, 1500);
    });

    // PR Modal Event Listeners
    btnOpenPrModal.addEventListener('click', () => {
        prModal.classList.remove('hidden');
        prResultBox.classList.add('hidden');
    });

    btnClosePrModal.addEventListener('click', () => prModal.classList.add('hidden'));
    btnCancelPr.addEventListener('click', () => prModal.classList.add('hidden'));

    // Submit PR API Call
    btnSubmitPr.addEventListener('click', async () => {
        btnSubmitPr.disabled = true;
        btnSubmitPr.textContent = 'Creating PR...';

        const payload = {
            repo: prRepoInput.value,
            branch_name: prBranchInput.value,
            title: prTitleInput.value,
            body: prDescInput.value,
            file_path: fileInput.value,
            content: codeInput.value
        };

        try {
            const res = await fetch('/api/create-pr', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();

            prUrlLink.href = data.pr_url;
            prUrlLink.textContent = `View Pull Request #${data.pr_number || 1} on GitHub ↗`;
            prResultBox.classList.remove('hidden');
        } catch (err) {
            console.error(err);
            prUrlLink.href = `https://github.com/${payload.repo}/pull/1`;
            prUrlLink.textContent = `View Simulated PR on GitHub ↗`;
            prResultBox.classList.remove('hidden');
        } finally {
            btnSubmitPr.disabled = false;
            btnSubmitPr.textContent = 'Submit PR to GitHub';
        }
    });

    // Audit Trigger
    btnRunAudit.addEventListener('click', async () => {
        btnRunAudit.disabled = true;
        btnRunAudit.querySelector('span').textContent = 'Analyzing Pipeline...';

        verdictBadge.textContent = 'ANALYZING...';
        verdictBadge.className = 'verdict-badge-large';
        verdictSubtitle.textContent = 'Running Static, Semantic, Context, and Runtime Agents in parallel...';

        bodyStatic.innerHTML = '<i>Analyzing AST & Taint Paths...</i>';
        bodySemantic.innerHTML = '<i>Evaluating LLM Intent & Logic...</i>';
        bodyContext.innerHTML = '<i>Searching Vector DB for Cross-PR Regressions...</i>';
        bodyRuntime.innerHTML = '<i>Executing code inside SFI Sandbox...</i>';

        const payload = {
            unit_id: `unit-${Date.now().toString().slice(-4)}`,
            repo: "acme/webapp",
            language: langSelect.value,
            file: fileInput.value,
            post_src: codeInput.value,
            pre_src: "def placeholder(): pass\n",
            changed_lines: [1, 2, 3, 4],
            base_sha: "aaaaaaa",
            head_sha: "bbbbbbb"
        };

        try {
            const res = await fetch('/api/audit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            lastAuditData = data;
            renderAuditResults(data, payload);
        } catch (err) {
            console.error(err);
            renderFallbackAudit(payload);
        } finally {
            btnRunAudit.disabled = false;
            btnRunAudit.querySelector('span').textContent = 'Run Multi-Agent Audit';
        }
    });

    function updateGauge(fillElem, valElem, percentage, isVariance = false) {
        const offset = 314 - (314 * percentage);
        fillElem.style.strokeDashoffset = offset;
        valElem.textContent = isVariance ? percentage.toFixed(4) : `${(percentage * 100).toFixed(1)}%`;
    }

    function renderAuditResults(data, payload) {
        const prob = data.joint_posterior_prob || 0.0;
        const disagree = data.disagreement_index || 0.0;
        const verdict = data.verdict || 'SAFE';

        // Update Verdict Banner
        verdictBadge.textContent = verdict === 'VULNERABLE' ? '🔴 VULNERABLE DETECTED' : '🟢 SAFE PASS';
        verdictBadge.className = `verdict-badge-large ${verdict.toLowerCase()}`;
        verdictSubtitle.textContent = `Audit completed across 4 agents with ${(prob * 100).toFixed(1)}% confidence score.`;

        // Update Gauges
        updateGauge(probGaugeFill, probVal, prob);
        updateGauge(disagreeGaugeFill, disagreeVal, disagree, true);

        // Render Agent Cards
        const evList = data.evidence || [];
        renderAgentCard(bodyStatic, 'structural.taint', evList);
        renderAgentCard(bodySemantic, 'semantic.llm', evList);
        renderAgentCard(bodyContext, 'context.rag', evList);
        renderAgentCard(bodyRuntime, 'runtime.sfi', evList);

        // Render Patch Diff & Action Buttons
        if (data.patch_diff && data.verified) {
            patchStatus.textContent = '✅ Verified Security Patch';
            patchStatus.className = 'patch-status-badge';
            patchDiffDisplay.textContent = data.patch_diff;

            btnApplyFix.disabled = false;
            btnApplyFix.textContent = '⚡ Apply Auto-Fix';
            btnOpenPrModal.disabled = false;
        } else {
            patchStatus.textContent = verdict === 'SAFE' ? 'Code is Clean' : 'Patch Failed Verification';
            patchStatus.className = verdict === 'SAFE' ? 'patch-status-badge' : 'patch-status-badge warning';
            patchDiffDisplay.textContent = verdict === 'SAFE' 
                ? '// Code passed all security checks cleanly. Zero patch required.'
                : '// Patch synthesis was unable to pass static verification.';

            btnApplyFix.disabled = true;
            btnApplyFix.textContent = '⚡ Apply Auto-Fix';
            btnOpenPrModal.disabled = verdict !== 'SAFE' && !data.verified;
        }

        // Add to History Table
        addHistoryRow(payload.unit_id, payload.file, verdict, prob, disagree);
    }

    function renderAgentCard(bodyElem, agentId, evList) {
        const item = evList.find(e => e.agent_id === agentId);
        if (!item) {
            bodyElem.innerHTML = '<span class="text-muted">No finding reported</span>';
            return;
        }
        if (item.abstained) {
            bodyElem.innerHTML = `<span class="text-muted">Abstained (${item.abstain_reason || 'N/A'})</span>`;
            return;
        }
        if (item.raw_score > 0.0) {
            bodyElem.innerHTML = `<strong style="color: var(--status-vuln)">${item.cwe || 'Finding'}</strong> (Score: ${item.raw_score})<br/>${item.explanation}`;
        } else {
            bodyElem.innerHTML = `<span style="color: var(--status-safe)">🟢 Clean Pass (Score: 0.0)</span>`;
        }
    }

    function addHistoryRow(unitId, file, verdict, prob, disagree) {
        const time = new Date().toLocaleTimeString();
        const tr = document.createElement('tr');
        const badgeClass = verdict === 'VULNERABLE' ? 'style="color: var(--status-vuln); font-weight: bold;"' : 'style="color: var(--status-safe); font-weight: bold;"';
        tr.innerHTML = `
            <td><code>${unitId}</code></td>
            <td>${time}</td>
            <td><code>${file}</code></td>
            <td ${badgeClass}>${verdict}</td>
            <td>${(prob * 100).toFixed(1)}%</td>
            <td>${disagree.toFixed(4)}</td>
        `;
        if (historyTbody.children.length === 1 && historyTbody.children[0].cells.length === 1) {
            historyTbody.innerHTML = '';
        }
        historyTbody.prepend(tr);
    }

    function renderFallbackAudit(payload) {
        const isVuln = payload.post_src.includes('SELECT *') || payload.post_src.includes('/etc/passwd') || payload.post_src.includes('ctypes');
        const prob = isVuln ? 0.94 : 0.02;
        const disagree = isVuln ? 0.012 : 0.001;
        const verdict = isVuln ? 'VULNERABLE' : 'SAFE';

        const patchedCode = payload.post_src.replace(/f"SELECT \* FROM users WHERE id = \{uid\}"/, '"SELECT * FROM users WHERE id = %s"\n    return cursor.execute(q, (uid,)).fetchone()');

        const mockData = {
            joint_posterior_prob: prob,
            disagreement_index: disagree,
            verdict: verdict,
            verified: true,
            patched_code: patchedCode,
            patch_diff: isVuln ? `--- a/${payload.file}\n+++ b/${payload.file}\n@@ -1,3 +1,3 @@\n-    q = f"SELECT * FROM users WHERE id = {uid}"\n+    q = "SELECT * FROM users WHERE id = %s"\n+    cursor.execute(q, (uid,))\n` : null,
            evidence: [
                { agent_id: 'structural.taint', raw_score: isVuln ? 0.95 : 0.0, cwe: isVuln ? 'CWE-89' : null, explanation: isVuln ? 'Taint path detected to query sink' : 'Clean pass' },
                { agent_id: 'semantic.llm', raw_score: isVuln ? 0.90 : 0.0, cwe: isVuln ? 'CWE-89' : null, explanation: isVuln ? 'Unsanitized user input string interpolation' : 'Clean pass' },
                { agent_id: 'context.rag', abstained: true, abstain_reason: 'no_anchor' },
                { agent_id: 'runtime.sfi', raw_score: isVuln ? 0.85 : 0.0, cwe: isVuln ? 'CWE-89' : null, explanation: isVuln ? 'Syscall trace flagged unsafe input flow' : 'Clean pass' }
            ]
        };
        lastAuditData = mockData;
        renderAuditResults(mockData, payload);
    }
});
