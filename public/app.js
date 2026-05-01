let allCves = [];
        let filteredCves = [];
        let allIocs = [];
        let filteredIocs = [];
        let progressItems = [];
        let filteredProgressItems = [];
        let companyAssets = [];
        let filteredCompanyAssets = [];
        let selectedItem = null;
        let selectedProgressItem = null;
        let selectedAsset = null;
        let selectedIocType = 'all';
        let selectedSeverity = 'all';
        let selectedCveProgress = 'all';
        let selectedCompanyAffected = false;
        let selectedCompanyAssetId = 'all';
        let selectedProgressStatus = 'all';
        let selectedCveTimeRange = 'all';
        let selectedIocTimeRange = 'all';
        let latestTriageStats = { needsReview: 0, open: 0, assigned: 0, closed: 0, feedErrors: 0 };
        let lastRefresh = null;
        let activeTab = 'cves';
        let autoRefreshEnabled = false;
        let autoRefreshTimer = null;
        let isRefreshing = false;
        let globalSearchResults = [];
        let progressImportCsvItems = [];
        let assetImportCsvItems = [];

        const API_BASE = '/api';
        const REQUEST_TIMEOUT_MS = 45000;
        const REFRESH_TIMEOUT_MS = 60000;

        async function fetchJson(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), timeoutMs);

            try {
                const res = await fetch(url, { ...options, signal: controller.signal });
                const data = await res.json().catch(() => ({}));
                if (!res.ok || data.success === false) {
                    throw new Error(data.error || `Request failed with status ${res.status}`);
                }
                return data;
            } catch (error) {
                if (error.name === 'AbortError') {
                    throw new Error('Request timed out. The server may still be working; try again in a moment.');
                }
                throw error;
            } finally {
                clearTimeout(timeout);
            }
        }

        async function fetchStats() {
            try {
                const data = await fetchJson(`${API_BASE}/stats`);

                const { cves, iocs, assets, recent24h, triage, lastRefresh, latestFeedAt } = data.data;
                document.getElementById('statTotalCves').textContent = cves.total || 0;
                document.getElementById('statCritical').textContent = cves.critical || 0;
                document.getElementById('statHigh').textContent = cves.high || 0;
                document.getElementById('statRecent24h').textContent = recent24h || 0;
                document.getElementById('statCompanyAssets').textContent = assets?.enabled || 0;
                document.getElementById('statCompanyMatches').textContent = assets?.matched_cves || 0;

                const iocMap = {};
                (iocs || []).forEach(i => { iocMap[i.type] = i.count; });
                document.getElementById('statUrls').textContent = iocMap.url || 0;
                document.getElementById('statHashes').textContent = iocMap.hash || 0;
                document.getElementById('statIps').textContent = iocMap.ip || 0;
                document.getElementById('statDomains').textContent = iocMap.domain || 0;

                latestTriageStats = triage || latestTriageStats;
                renderTriageOverview(latestTriageStats);
                applyLoadedState(lastRefresh, latestFeedAt);
            } catch (e) {
                document.getElementById('lastUpdated').textContent = 'Stats unavailable';
                console.error('Stats error:', e);
            }
        }

        async function fetchCves(search = '') {
            const params = new URLSearchParams({ limit: 200, offset: 0, sort: 'triage' });
            if (selectedSeverity !== 'all') params.set('severity', selectedSeverity);
            if (selectedCveProgress === 'needsReview') {
                params.set('needsReview', 'true');
            } else if (selectedCveProgress !== 'all') {
                params.set('progressStatus', selectedCveProgress);
            }
            const fromDate = getRangeStart(selectedCveTimeRange);
            if (fromDate) params.set('fromDate', fromDate);
            if (selectedCompanyAffected) params.set('companyAffected', 'true');
            if (selectedCompanyAssetId !== 'all') params.set('assetId', selectedCompanyAssetId);
            if (search) params.set('search', search);

            try {
                document.getElementById('cveList').innerHTML = '<div class="loader"><div class="spinner"></div></div>';
                const data = await fetchJson(`${API_BASE}/cves?${params}`);
                allCves = data.data || [];
                filteredCves = [...allCves];
                if (selectedItem?.id && !filteredCves.some(cve => cve.id === selectedItem.id)) {
                    selectedItem = null;
                    resetDetailPanel('detailPanel', 'Select an item to view details');
                }
                renderCveList();
            } catch (e) {
                document.getElementById('cveList').innerHTML = `<div class="error-state"><p>Failed to load CVEs</p><p>${escapeHtml(e.message)}</p></div>`;
            }
        }

        function renderCveList() {
            const container = document.getElementById('cveList');
            document.getElementById('cveCount').textContent = `${filteredCves.length} items`;

            if (filteredCves.length === 0) {
                container.innerHTML = '<div class="empty-state">No CVEs found. Click Refresh to fetch public feeds.</div>';
                return;
            }

            container.innerHTML = filteredCves.map((cve, index) => `
                <div class="list-item ${selectedItem?.id === cve.id ? 'selected' : ''}" onclick="selectCveByIndex(${index})">
                    <div class="item-header">
                        <a href="${sourceUrlForCve(cve)}" target="_blank" rel="noopener noreferrer" class="item-id" onclick="event.stopPropagation()">${escapeHtml(cve.id)}</a>
                        <div style="display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end;">
                            ${renderCompanyImpactBadge(cve)}
                            ${renderProgressBadge(cve.progress_status, cve)}
                            <span class="severity-badge ${escapeHtml(cve.severity || 'low')}">${escapeHtml(cve.severity || 'low')}</span>
                        </div>
                    </div>
                    <div class="item-desc">${escapeHtml(cve.description || '')}</div>
                    <div class="item-meta">
                        <span>CVSS: <span class="cvss-score">${(cve.cvss_score || 0).toFixed(1)}</span></span>
                        <span>${renderSourceSummary(cve)}</span>
                        ${cve.company_match_count ? `<span>${escapeHtml(renderCompanyAssetSummary(cve))}</span>` : ''}
                        <span>Notes: ${cve.progress_note_count || 0}</span>
                        <span>${formatDate(cve.published_at)}</span>
                    </div>
                </div>
            `).join('');
        }

        function selectCveByIndex(index) {
            const cve = filteredCves[index];
            if (cve) selectCve(cve);
        }

        async function selectCve(cve) {
            selectedItem = cve;
            renderCveList();
            renderCveDetail(cve);
            try {
                const data = await fetchJson(`${API_BASE}/cves/${encodeURIComponent(cve.id)}/progress`);
                if (selectedItem?.id === cve.id) {
                    selectedItem = data.data;
                    renderCveDetail(data.data);
                    applyProgressUpdate(data.data, { skipRenderDetail: true });
                }
            } catch (e) {
                setRefreshStatus(`Could not load CVE notes: ${e.message}`, 'error');
            }
        }

        function renderCveDetail(cve) {
            const panel = document.getElementById('detailPanel');
            panel.innerHTML = `
                <div class="detail-content">
                    <div class="detail-header">
                        <div class="detail-id">${escapeHtml(cve.id)}</div>
                        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px;">
                            <span class="severity-badge ${escapeHtml(cve.severity || 'low')}">${escapeHtml(cve.severity?.toUpperCase() || 'LOW')}</span>
                            ${renderCompanyImpactBadge(cve)}
                            ${renderProgressBadge(cve.progress_status, cve)}
                        </div>
                        <p class="detail-desc">${escapeHtml(cve.description || 'No description available')}</p>
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">CVSS Metrics</h3>
                        <div class="metrics-grid">
                            <div class="metric-item">
                                <div class="metric-label">Base Score</div>
                                <div class="metric-value" style="color: var(--severity-${escapeHtml(cve.severity || 'low')})">${(cve.cvss_score || 0).toFixed(1)}</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-label">Severity</div>
                                <div class="metric-value">${escapeHtml(cve.severity?.toUpperCase() || 'LOW')}</div>
                            </div>
                            ${cve.cvss_vector ? `
                            <div class="metric-item" style="grid-column: span 2;">
                                <div class="metric-label">Vector String</div>
                                <div class="metric-value" style="font-size: 11px; word-break: break-all;">${escapeHtml(cve.cvss_vector)}</div>
                            </div>` : ''}
                        </div>
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">Sources</h3>
                        ${renderSourceBadges(cve)}
                    </div>
                    ${renderCompanyMatches(cve)}
                    <div class="detail-section">
                        <h3 class="detail-section-title">Progress Tag</h3>
                        ${renderProgressControls(cve)}
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">Progress Notes</h3>
                        ${renderCveNoteWorkspace(cve)}
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">Actions</h3>
                        <a href="${sourceUrlForCve(cve)}" target="_blank" rel="noopener noreferrer" class="btn" style="display: inline-flex;">
                            View Source
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3"/></svg>
                        </a>
                    </div>
                </div>
            `;
        }

        function renderProgressBadge(status, cve = null) {
            if (!status && isNeedsReview(cve)) return '<span class="progress-badge needs-review">Needs Review</span>';
            if (!status) return '<span class="progress-badge untagged">Untagged</span>';
            return `<span class="progress-badge ${escapeHtml(status)}">${escapeHtml(status)}</span>`;
        }

        function renderCompanyImpactBadge(cve) {
            const count = Number(cve?.company_match_count || 0);
            if (!count) return '';
            const label = count === 1 ? 'Company Impact' : `Company Impact x${count}`;
            return `<span class="company-badge">${escapeHtml(label)}</span>`;
        }

        function renderCompanyAssetSummary(cve) {
            const matches = cve.company_matches || [];
            if (!matches.length) return `${cve.company_match_count || 0} company match(es)`;
            const names = matches.slice(0, 2).map(match => match.asset_name).filter(Boolean);
            return names.length
                ? `Assets: ${names.join(', ')}${matches.length > 2 ? ` +${matches.length - 2}` : ''}`
                : `${cve.company_match_count || 0} company match(es)`;
        }

        function renderCompanyMatches(cve) {
            const matches = cve.company_matches || [];
            if (!matches.length) return '';
            return `
                <div class="detail-section">
                    <h3 class="detail-section-title">Company Impact</h3>
                    <div class="asset-match-list">
                        ${matches.map(match => `
                            <div class="asset-match-item">
                                <div class="asset-match-title">
                                    <span>${escapeHtml(match.asset_name || 'Asset')}</span>
                                    <span class="asset-badge ${escapeHtml(match.criticality || 'medium')}">${escapeHtml(match.criticality || 'medium')}</span>
                                </div>
                                <div class="asset-match-reason">${escapeHtml(match.match_reason || '')}</div>
                                <div class="item-meta">
                                    <span>${escapeHtml(match.match_type || 'match')}</span>
                                    <span>Confidence: ${Math.round((match.confidence || 0) * 100)}%</span>
                                    <span>Score: ${match.score || 0}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        function renderSourceBadges(cve) {
            const sources = normalizeSources(cve);
            return `<div class="source-badges">${sources.map(source => `<span class="source-badge">${escapeHtml(formatSource(source))}</span>`).join('')}</div>`;
        }

        function renderSourceSummary(cve) {
            const sources = normalizeSources(cve);
            if (sources.length <= 2) return sources.map(formatSource).join(' + ');
            return `${formatSource(sources[0])} +${sources.length - 1}`;
        }

        function normalizeSources(cve) {
            const raw = Array.isArray(cve?.sources) && cve.sources.length ? cve.sources : [cve?.source || 'unknown'];
            return [...new Set(raw.map(source => String(source || 'unknown').toLowerCase()))];
        }

        function formatSource(source) {
            return String(source || 'unknown').replace(/_/g, ' ').toUpperCase();
        }

        function renderProgressControls(cve) {
            const current = cve.progress_status || 'none';
            const cveId = escapeJsArg(cve.id);
            return `
                <div class="progress-tag-controls">
                    <button class="progress-tag-btn none ${current === 'none' ? 'active' : ''}" onclick="updateCveProgress('${cveId}', null)">None</button>
                    <button class="progress-tag-btn open ${current === 'open' ? 'active' : ''}" onclick="updateCveProgress('${cveId}', 'open')">Open</button>
                    <button class="progress-tag-btn assigned ${current === 'assigned' ? 'active' : ''}" onclick="updateCveProgress('${cveId}', 'assigned')">Assigned</button>
                    <button class="progress-tag-btn closed ${current === 'closed' ? 'active' : ''}" onclick="updateCveProgress('${cveId}', 'closed')">Closed</button>
                </div>
            `;
        }

        function renderCveNoteWorkspace(cve) {
            if (!cve.progress_status) {
                return '<div class="empty-state" style="padding: 20px;">Set Open, Assigned, or Closed to add progress notes.</div>';
            }

            return `
                <textarea class="note-input" id="cveNoteInput" maxlength="2000" placeholder="Add progress note..."></textarea>
                <button class="btn" onclick="addProgressNote('${escapeJsArg(cve.id)}', 'cveNoteInput', 'cve')">Add Note</button>
                <div style="height: 12px;"></div>
                ${renderProgressNotes(cve.notes || [])}
            `;
        }

        async function updateCveProgress(cveId, status) {
            try {
                const data = await fetchJson(`${API_BASE}/cves/${encodeURIComponent(cveId)}/progress`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status })
                });

                applyProgressUpdate(data.data);
                const message = status ? `${cveId} marked ${status}.` : `${cveId} progress tag cleared.`;
                setRefreshStatus(message, 'success');
                await fetchStats();
                await fetchCves(document.getElementById('cveSearch')?.value || '');

                if (activeTab === 'progress') {
                    await fetchProgress(document.getElementById('progressSearch')?.value || '');
                    if (status && selectedProgressItem?.id === cveId) {
                        await fetchProgressDetail(cveId);
                    } else if (!status && selectedProgressItem?.id === cveId) {
                        selectedProgressItem = null;
                        resetDetailPanel('progressDetailPanel', 'Select a CVE to view progress');
                    }
                }
            } catch (e) {
                setRefreshStatus(`Progress update failed: ${e.message}`, 'error');
            }
        }

        function applyProgressUpdate(progress, options = {}) {
            if (!progress?.id) return;
            const fields = {
                progress_status: progress.progress_status || null,
                progress_created_at: progress.progress_created_at || null,
                progress_updated_at: progress.progress_updated_at || null,
                progress_note_count: progress.progress_note_count || 0,
                latest_note: progress.latest_note || null,
                latest_note_at: progress.latest_note_at || null
            };

            allCves = allCves.map(cve => cve.id === progress.id ? { ...cve, ...fields } : cve);
            filteredCves = filteredCves.map(cve => cve.id === progress.id ? { ...cve, ...fields } : cve);
            progressItems = progressItems.map(cve => cve.id === progress.id ? { ...cve, ...progress } : cve);
            filteredProgressItems = filteredProgressItems.map(cve => cve.id === progress.id ? { ...cve, ...progress } : cve);

            if (selectedItem?.id === progress.id) {
                selectedItem = { ...selectedItem, ...progress, ...fields };
                renderCveList();
                if (!options.skipRenderDetail) renderCveDetail(selectedItem);
            } else if (activeTab === 'cves') {
                renderCveList();
            }
        }

        async function fetchIocs(type = 'all', search = '') {
            const params = new URLSearchParams({ limit: 200, offset: 0 });
            if (type !== 'all') params.set('type', type);
            const fromDate = getRangeStart(selectedIocTimeRange);
            if (fromDate) params.set('fromDate', fromDate);
            if (search) params.set('search', search);

            try {
                document.getElementById('iocList').innerHTML = '<div class="loader"><div class="spinner"></div></div>';
                const data = await fetchJson(`${API_BASE}/iocs?${params}`);
                allIocs = data.data || [];
                filteredIocs = [...allIocs];
                renderIocList();
            } catch (e) {
                document.getElementById('iocList').innerHTML = `<div class="error-state"><p>Failed to load IOCs</p><p>${escapeHtml(e.message)}</p></div>`;
            }
        }

        function renderIocList() {
            const container = document.getElementById('iocList');
            document.getElementById('iocCount').textContent = `${filteredIocs.length} items`;

            if (filteredIocs.length === 0) {
                container.innerHTML = '<div class="empty-state">No IOCs found. Click Refresh to fetch public feeds.</div>';
                return;
            }

            container.innerHTML = filteredIocs.map((ioc, index) => `
                <div class="list-item ${selectedItem?.id === ioc.id ? 'selected' : ''}" onclick="selectIocByIndex(${index})">
                    <div class="item-header">
                        <span class="item-id" style="font-size: 12px;">${escapeHtml(ioc.value || '')}</span>
                        <div style="display: flex; gap: 6px;">
                            <span class="ioc-badge ${escapeHtml(ioc.type || 'domain')}">${escapeHtml(ioc.type || 'unknown')}</span>
                            <span class="source-badge">${escapeHtml(ioc.source?.toUpperCase() || 'UNKNOWN')}</span>
                        </div>
                    </div>
                    <div class="item-meta">
                        <span>Threat: ${escapeHtml(ioc.threat_type || 'unknown')}</span>
                        <span>Confidence: ${ioc.confidence || 0}%</span>
                        <span>${formatDate(ioc.last_seen)}</span>
                    </div>
                </div>
            `).join('');
        }

        function selectIocByIndex(index) {
            const ioc = filteredIocs[index];
            if (ioc) selectIoc(ioc);
        }

        function selectIoc(ioc) {
            selectedItem = ioc;
            renderIocList();
            renderIocDetail(ioc);
        }

        function renderIocDetail(ioc) {
            const panel = document.getElementById('iocDetailPanel');
            let metadata = {};
            try { metadata = ioc.metadata ? JSON.parse(ioc.metadata) : {}; } catch (e) {}

            panel.innerHTML = `
                <div class="detail-content">
                    <div class="detail-header">
                        <div class="detail-id" style="font-size: 14px; word-break: break-all;">${escapeHtml(ioc.value || '')}</div>
                        <div style="display: flex; gap: 6px; margin-bottom: 10px;">
                            <span class="ioc-badge ${escapeHtml(ioc.type || 'domain')}">${escapeHtml(ioc.type?.toUpperCase() || 'UNKNOWN')}</span>
                            <span class="severity-badge ${getThreatSeverity(ioc.threat_type)}">${escapeHtml(ioc.threat_type || 'unknown')}</span>
                        </div>
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">Classification</h3>
                        <div class="metrics-grid">
                            <div class="metric-item">
                                <div class="metric-label">Source</div>
                                <div class="metric-value">${escapeHtml(ioc.source?.toUpperCase() || 'UNKNOWN')}</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-label">Confidence</div>
                                <div class="metric-value">${ioc.confidence || 0}%</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-label">First Seen</div>
                                <div class="metric-value" style="font-size: 11px;">${formatDate(ioc.first_seen)}</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-label">Last Seen</div>
                                <div class="metric-value" style="font-size: 11px;">${formatDate(ioc.last_seen)}</div>
                            </div>
                        </div>
                    </div>
                    ${Object.keys(metadata).length > 0 ? `
                    <div class="detail-section">
                        <h3 class="detail-section-title">Metadata</h3>
                        <div class="tags-list">
                            ${Object.entries(metadata).filter(([k, v]) => v).slice(0, 10).map(([k, v]) => `
                                <span class="tag">${escapeHtml(k)}: ${escapeHtml(typeof v === 'string' ? v.substring(0, 50) : JSON.stringify(v))}</span>
                            `).join('')}
                        </div>
                    </div>` : ''}
                </div>
            `;
        }

        async function fetchProgress(search = '') {
            const params = new URLSearchParams({ limit: 200, offset: 0 });
            if (selectedProgressStatus !== 'all') params.set('status', selectedProgressStatus);
            if (search) params.set('search', search);

            try {
                document.getElementById('progressList').innerHTML = '<div class="loader"><div class="spinner"></div></div>';
                const data = await fetchJson(`${API_BASE}/cves/progress?${params}`);
                progressItems = data.data || [];
                filteredProgressItems = [...progressItems];
                if (selectedProgressItem?.id && !filteredProgressItems.some(cve => cve.id === selectedProgressItem.id)) {
                    selectedProgressItem = null;
                    resetDetailPanel('progressDetailPanel', 'Select a CVE to view progress');
                }
                renderProgressList();
            } catch (e) {
                document.getElementById('progressList').innerHTML = `<div class="error-state"><p>Failed to load progress</p><p>${escapeHtml(e.message)}</p></div>`;
            }
        }

        function renderProgressList() {
            const container = document.getElementById('progressList');
            document.getElementById('progressCount').textContent = `${filteredProgressItems.length} items`;

            if (filteredProgressItems.length === 0) {
                container.innerHTML = '<div class="empty-state">No tagged CVEs.</div>';
                return;
            }

            container.innerHTML = filteredProgressItems.map((cve, index) => `
                <div class="list-item ${selectedProgressItem?.id === cve.id ? 'selected' : ''}" onclick="selectProgressByIndex(${index})">
                    <div class="item-header">
                        <a href="${sourceUrlForCve(cve)}" target="_blank" rel="noopener noreferrer" class="item-id" onclick="event.stopPropagation()">${escapeHtml(cve.id)}</a>
                        <div style="display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end;">
                            ${renderCompanyImpactBadge(cve)}
                            ${renderProgressBadge(cve.progress_status, cve)}
                            <span class="severity-badge ${escapeHtml(cve.severity || 'low')}">${escapeHtml(cve.severity || 'low')}</span>
                        </div>
                    </div>
                    <div class="item-desc">${escapeHtml(cve.description || '')}</div>
                    ${cve.latest_note ? `<div class="progress-list-note">${escapeHtml(cve.latest_note)}</div>` : ''}
                    <div class="item-meta">
                        <span>${renderSourceSummary(cve)}</span>
                        <span>Notes: ${cve.progress_note_count || 0}</span>
                        <span>Updated: ${formatDate(cve.progress_updated_at)}</span>
                    </div>
                </div>
            `).join('');
        }

        function selectProgressByIndex(index) {
            const cve = filteredProgressItems[index];
            if (cve) {
                selectedProgressItem = cve;
                renderProgressList();
                fetchProgressDetail(cve.id);
            }
        }

        async function fetchProgressDetail(cveId) {
            try {
                const data = await fetchJson(`${API_BASE}/cves/${encodeURIComponent(cveId)}/progress`);
                selectedProgressItem = data.data;
                renderProgressDetail(data.data);
            } catch (e) {
                document.getElementById('progressDetailPanel').innerHTML = `<div class="error-state"><p>Failed to load progress</p><p>${escapeHtml(e.message)}</p></div>`;
            }
        }

        function renderProgressDetail(cve) {
            const panel = document.getElementById('progressDetailPanel');
            panel.innerHTML = `
                <div class="detail-content">
                    <div class="detail-header">
                        <div class="detail-id">${escapeHtml(cve.id)}</div>
                        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px;">
                            ${renderCompanyImpactBadge(cve)}
                            ${renderProgressBadge(cve.progress_status, cve)}
                            <span class="severity-badge ${escapeHtml(cve.severity || 'low')}">${escapeHtml(cve.severity?.toUpperCase() || 'LOW')}</span>
                        </div>
                        <p class="detail-desc">${escapeHtml(cve.description || 'No description available')}</p>
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">Sources</h3>
                        ${renderSourceBadges(cve)}
                    </div>
                    ${renderCompanyMatches(cve)}
                    <div class="detail-section">
                        <h3 class="detail-section-title">Progress Tag</h3>
                        ${renderProgressControls(cve)}
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">Add Note</h3>
                        <textarea class="note-input" id="progressNoteInput" maxlength="2000" placeholder="Add progress note..."></textarea>
                        <button class="btn" onclick="addProgressNote('${escapeJsArg(cve.id)}', 'progressNoteInput', 'progress')">Add Note</button>
                    </div>
                    <div class="detail-section">
                        <h3 class="detail-section-title">Notes</h3>
                        ${renderProgressNotes(cve.notes || [])}
                    </div>
                </div>
            `;
        }

        function renderProgressNotes(notes) {
            if (!notes.length) return '<div class="empty-state" style="padding: 20px;">No notes yet.</div>';

            return `
                <div class="notes-list">
                    ${notes.map(note => `
                        <div class="note-item">
                            <div class="note-meta">${formatDate(note.created_at)}</div>
                            <div class="note-body">${escapeHtml(note.note || '')}</div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        async function addProgressNote(cveId, inputId = 'progressNoteInput', context = 'progress') {
            const input = document.getElementById(inputId);
            const note = input?.value.trim() || '';
            if (!note) return;

            try {
                const data = await fetchJson(`${API_BASE}/cves/${encodeURIComponent(cveId)}/progress/notes`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ note })
                });
                input.value = '';
                applyProgressUpdate(data.data);
                if (context === 'progress' || selectedProgressItem?.id === cveId) {
                    selectedProgressItem = data.data;
                    renderProgressDetail(data.data);
                }
                if (context === 'cve' || selectedItem?.id === cveId) {
                    selectedItem = data.data;
                    renderCveDetail(data.data);
                }
                await fetchStats();
                await fetchCves(document.getElementById('cveSearch')?.value || '');
                await fetchProgress(document.getElementById('progressSearch')?.value || '');
                setRefreshStatus(`Note added to ${cveId}.`, 'success');
            } catch (e) {
                setRefreshStatus(`Note failed: ${e.message}`, 'error');
            }
        }

        async function handleImportCsvFile(event) {
            const file = event.target.files?.[0];
            progressImportCsvItems = [];
            if (!file) {
                updateImportPreview();
                return;
            }

            try {
                const text = await file.text();
                progressImportCsvItems = CtiDashboardUtils.parseProgressImportCsv(text);
                updateImportPreview(`${progressImportCsvItems.length} CSV row(s) loaded.`, progressImportCsvItems.length ? 'success' : '');
            } catch (e) {
                progressImportCsvItems = [];
                updateImportPreview(`CSV failed: ${e.message}`, 'error');
            }
        }

        function getProgressImportItems() {
            const pasted = CtiDashboardUtils.parseProgressImportText(document.getElementById('progressImportText')?.value || '');
            return [...pasted, ...progressImportCsvItems];
        }

        function updateImportPreview(message = null, type = '') {
            const preview = document.getElementById('progressImportPreview');
            if (!preview) return;

            const items = getProgressImportItems();
            const sample = items.slice(0, 5).map(item => item.id).join(', ');
            preview.className = `import-preview ${type || ''}`.trim();
            if (message) {
                preview.textContent = message;
            } else if (!items.length) {
                preview.textContent = 'No CVEs selected.';
            } else {
                preview.textContent = `${items.length} CVE row(s) ready${sample ? `: ${sample}${items.length > 5 ? ', ...' : ''}` : '.'}`;
            }
        }

        async function importProgressCves() {
            const items = getProgressImportItems();
            if (!items.length) {
                updateImportPreview('No valid CVE IDs found.', 'error');
                return;
            }

            const btn = document.getElementById('progressImportBtn');
            btn.disabled = true;
            btn.textContent = 'Importing...';
            updateImportPreview(`Importing ${items.length} CVE row(s)...`);

            try {
                const response = await fetchJson(`${API_BASE}/cves/progress/import`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ items })
                }, REFRESH_TIMEOUT_MS);
                const summary = response.data?.summary || {};
                const teams = response.notifications?.teams;
                const teamsMessage = teams?.sent
                    ? ' Teams notified.'
                    : teams?.attempted && !teams.sent
                        ? ` Teams: ${teams.error || 'not sent'}.`
                        : '';

                document.getElementById('progressImportText').value = '';
                document.getElementById('progressImportCsv').value = '';
                progressImportCsvItems = [];
                updateImportPreview(
                    `Imported ${summary.imported || 0}, updated ${summary.updated || 0}, placeholders ${summary.placeholders || 0}, failed ${summary.failed || 0}.${teamsMessage}`,
                    summary.failed ? 'error' : 'success'
                );
                setRefreshStatus(`Progress import completed: ${summary.imported || 0} imported, ${summary.updated || 0} updated.`, summary.failed ? '' : 'success');

                await fetchStats();
                await fetchCves(document.getElementById('cveSearch')?.value || '');
                await fetchProgress(document.getElementById('progressSearch')?.value || '');
                const globalQuery = document.getElementById('globalSearch')?.value || '';
                if (globalQuery.trim()) await fetchGlobalSearch(globalQuery);
            } catch (e) {
                updateImportPreview(`Import failed: ${e.message}`, 'error');
                setRefreshStatus(`Progress import failed: ${e.message}`, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Import CVEs';
            }
        }

        async function fetchCompanyAssets(search = '') {
            const params = new URLSearchParams({ limit: 500, offset: 0 });
            if (search) params.set('search', search);

            try {
                const list = document.getElementById('assetList');
                if (list) list.innerHTML = '<div class="loader"><div class="spinner"></div></div>';
                const data = await fetchJson(`${API_BASE}/company-assets?${params}`);
                companyAssets = data.data || [];
                filteredCompanyAssets = [...companyAssets];
                if (selectedAsset?.id) {
                    selectedAsset = filteredCompanyAssets.find(asset => asset.id === selectedAsset.id) || null;
                }
                renderAssetList();
                updateAssetFilterOptions();
                if (activeTab === 'assets') renderAssetEditor(selectedAsset);
            } catch (e) {
                const list = document.getElementById('assetList');
                if (list) list.innerHTML = `<div class="error-state"><p>Failed to load assets</p><p>${escapeHtml(e.message)}</p></div>`;
            }
        }

        function renderAssetList() {
            const container = document.getElementById('assetList');
            const count = document.getElementById('assetCount');
            if (!container || !count) return;
            count.textContent = `${filteredCompanyAssets.length} items`;

            if (filteredCompanyAssets.length === 0) {
                container.innerHTML = '<div class="empty-state">No company assets yet.</div>';
                return;
            }

            container.innerHTML = filteredCompanyAssets.map((asset, index) => `
                <div class="list-item ${selectedAsset?.id === asset.id ? 'selected' : ''}" onclick="selectAssetByIndex(${index})">
                    <div class="item-header">
                        <span class="item-id">${escapeHtml(asset.name || '')}</span>
                        <div style="display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end;">
                            <span class="asset-badge ${asset.enabled ? escapeHtml(asset.criticality || 'medium') : 'disabled'}">${asset.enabled ? escapeHtml(asset.criticality || 'medium') : 'disabled'}</span>
                            <span class="source-badge">${escapeHtml(asset.type || 'application')}</span>
                        </div>
                    </div>
                    <div class="item-desc">${escapeHtml([asset.vendor, asset.product, asset.version].filter(Boolean).join(' / ') || 'No product metadata')}</div>
                    <div class="item-meta">
                        <span>Matches: ${asset.match_count || 0}</span>
                        <span>Aliases: ${(asset.aliases || []).length}</span>
                        <span>CPEs: ${(asset.cpe_uris || []).length}</span>
                        <span>Packages: ${(asset.packages || []).length}</span>
                    </div>
                </div>
            `).join('');
        }

        function selectAssetByIndex(index) {
            const asset = filteredCompanyAssets[index];
            if (asset) {
                selectedAsset = asset;
                renderAssetList();
                renderAssetEditor(asset);
            }
        }

        function renderAssetEditor(asset = null) {
            selectedAsset = asset || null;
            const panel = document.getElementById('assetDetailPanel');
            if (!panel) return;
            const active = selectedAsset || {
                type: 'application',
                criticality: 'medium',
                enabled: true,
                aliases: [],
                cpe_uris: [],
                packages: []
            };

            panel.innerHTML = `
                <div class="detail-content">
                    <div class="detail-header">
                        <div class="detail-id">${selectedAsset ? escapeHtml(selectedAsset.name) : 'New Asset'}</div>
                        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px;">
                            <span class="asset-badge ${active.enabled ? escapeHtml(active.criticality || 'medium') : 'disabled'}">${active.enabled ? escapeHtml(active.criticality || 'medium') : 'disabled'}</span>
                            ${selectedAsset ? `<span class="company-badge">${active.match_count || 0} matched CVEs</span>` : ''}
                        </div>
                    </div>
                    <div class="asset-form">
                        <div class="form-grid">
                            <div class="field">
                                <label for="assetName">Name</label>
                                <input id="assetName" value="${escapeHtml(active.name || '')}" maxlength="160">
                            </div>
                            <div class="field">
                                <label for="assetType">Type</label>
                                <select id="assetType">
                                    <option value="application" ${active.type === 'application' ? 'selected' : ''}>Application</option>
                                    <option value="service" ${active.type === 'service' ? 'selected' : ''}>Service</option>
                                </select>
                            </div>
                            <div class="field">
                                <label for="assetVendor">Vendor</label>
                                <input id="assetVendor" value="${escapeHtml(active.vendor || '')}" maxlength="120">
                            </div>
                            <div class="field">
                                <label for="assetProduct">Product</label>
                                <input id="assetProduct" value="${escapeHtml(active.product || '')}" maxlength="160">
                            </div>
                            <div class="field">
                                <label for="assetVersion">Version</label>
                                <input id="assetVersion" value="${escapeHtml(active.version || '')}" maxlength="120">
                            </div>
                            <div class="field">
                                <label for="assetCriticality">Criticality</label>
                                <select id="assetCriticality">
                                    <option value="high" ${active.criticality === 'high' ? 'selected' : ''}>High</option>
                                    <option value="medium" ${active.criticality === 'medium' ? 'selected' : ''}>Medium</option>
                                    <option value="low" ${active.criticality === 'low' ? 'selected' : ''}>Low</option>
                                </select>
                            </div>
                            <div class="field full">
                                <label for="assetAliases">Aliases</label>
                                <textarea id="assetAliases">${escapeHtml((active.aliases || []).join('\n'))}</textarea>
                            </div>
                            <div class="field full">
                                <label for="assetCpes">CPE URIs</label>
                                <textarea id="assetCpes">${escapeHtml((active.cpe_uris || []).join('\n'))}</textarea>
                            </div>
                            <div class="field full">
                                <label for="assetPackages">Packages</label>
                                <textarea id="assetPackages">${escapeHtml(formatAssetPackages(active.packages || []))}</textarea>
                            </div>
                            <div class="field full">
                                <label for="assetNotes">Notes</label>
                                <textarea id="assetNotes">${escapeHtml(active.notes || '')}</textarea>
                            </div>
                            <label class="field checkbox-row full" for="assetEnabled">
                                <input type="checkbox" id="assetEnabled" ${active.enabled ? 'checked' : ''}>
                                <span>Enabled</span>
                            </label>
                        </div>
                        <div class="asset-actions">
                            <button class="btn primary" onclick="saveCompanyAsset()">${selectedAsset ? 'Save Asset' : 'Create Asset'}</button>
                            <button class="btn" onclick="clearAssetEditor()">Clear</button>
                            ${selectedAsset ? '<button class="btn" onclick="deleteSelectedCompanyAsset()">Delete</button>' : ''}
                        </div>
                    </div>
                </div>
            `;
        }

        function clearAssetEditor() {
            selectedAsset = null;
            renderAssetList();
            renderAssetEditor(null);
        }

        async function saveCompanyAsset() {
            const payload = collectCompanyAssetForm();
            if (!payload.name) {
                setRefreshStatus('Asset name is required.', 'error');
                return;
            }

            try {
                const url = selectedAsset?.id
                    ? `${API_BASE}/company-assets/${encodeURIComponent(selectedAsset.id)}`
                    : `${API_BASE}/company-assets`;
                const method = selectedAsset?.id ? 'PATCH' : 'POST';
                const response = await fetchJson(url, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                selectedAsset = response.data;
                setRefreshStatus(`${selectedAsset.name} saved.`, 'success');
                await fetchCompanyAssets(document.getElementById('assetSearch')?.value || '');
                await fetchCves(document.getElementById('cveSearch')?.value || '');
                await fetchStats();
            } catch (e) {
                setRefreshStatus(`Asset save failed: ${e.message}`, 'error');
            }
        }

        async function deleteSelectedCompanyAsset() {
            if (!selectedAsset?.id) return;
            if (!confirm(`Delete ${selectedAsset.name}?`)) return;

            try {
                await fetchJson(`${API_BASE}/company-assets/${encodeURIComponent(selectedAsset.id)}`, { method: 'DELETE' });
                setRefreshStatus(`${selectedAsset.name} deleted.`, 'success');
                selectedAsset = null;
                await fetchCompanyAssets(document.getElementById('assetSearch')?.value || '');
                await fetchCves(document.getElementById('cveSearch')?.value || '');
                await fetchStats();
                renderAssetEditor();
            } catch (e) {
                setRefreshStatus(`Asset delete failed: ${e.message}`, 'error');
            }
        }

        function collectCompanyAssetForm() {
            return {
                name: document.getElementById('assetName')?.value || '',
                type: document.getElementById('assetType')?.value || 'application',
                vendor: document.getElementById('assetVendor')?.value || '',
                product: document.getElementById('assetProduct')?.value || '',
                version: document.getElementById('assetVersion')?.value || '',
                criticality: document.getElementById('assetCriticality')?.value || 'medium',
                aliases: parseTextList(document.getElementById('assetAliases')?.value || ''),
                cpe_uris: parseTextList(document.getElementById('assetCpes')?.value || ''),
                packages: parsePackageLines(document.getElementById('assetPackages')?.value || ''),
                notes: document.getElementById('assetNotes')?.value || '',
                enabled: Boolean(document.getElementById('assetEnabled')?.checked)
            };
        }

        async function handleAssetImportCsvFile(event) {
            const file = event.target.files?.[0];
            assetImportCsvItems = [];
            if (!file) {
                updateAssetImportPreview();
                return;
            }

            try {
                const text = await file.text();
                assetImportCsvItems = CtiDashboardUtils.parseCompanyAssetCsv(text);
                updateAssetImportPreview(`${assetImportCsvItems.length} CSV row(s) loaded.`, assetImportCsvItems.length ? 'success' : '');
            } catch (e) {
                assetImportCsvItems = [];
                updateAssetImportPreview(`CSV failed: ${e.message}`, 'error');
            }
        }

        function getAssetImportItems() {
            const text = document.getElementById('assetImportText')?.value || '';
            const pasted = text.trim() ? CtiDashboardUtils.parseCompanyAssetCsv(text) : [];
            return [...pasted, ...assetImportCsvItems];
        }

        function updateAssetImportPreview(message = null, type = '') {
            const preview = document.getElementById('assetImportPreview');
            if (!preview) return;

            const items = getAssetImportItems();
            const sample = items.slice(0, 4).map(item => item.name).join(', ');
            preview.className = `import-preview ${type || ''}`.trim();
            if (message) {
                preview.textContent = message;
            } else if (!items.length) {
                preview.textContent = 'No assets selected.';
            } else {
                preview.textContent = `${items.length} asset row(s) ready${sample ? `: ${sample}${items.length > 4 ? ', ...' : ''}` : '.'}`;
            }
        }

        async function importCompanyAssetRows() {
            const items = getAssetImportItems();
            if (!items.length) {
                updateAssetImportPreview('No valid asset rows found.', 'error');
                return;
            }

            const btn = document.getElementById('assetImportBtn');
            btn.disabled = true;
            btn.textContent = 'Importing...';
            updateAssetImportPreview(`Importing ${items.length} asset row(s)...`);

            try {
                const response = await fetchJson(`${API_BASE}/company-assets/import`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ items })
                }, REFRESH_TIMEOUT_MS);
                const summary = response.data?.summary || {};
                document.getElementById('assetImportText').value = '';
                document.getElementById('assetImportCsv').value = '';
                assetImportCsvItems = [];
                updateAssetImportPreview(
                    `Imported ${summary.imported || 0}, updated ${summary.updated || 0}, failed ${summary.failed || 0}.`,
                    summary.failed ? 'error' : 'success'
                );
                setRefreshStatus(`Asset import completed: ${summary.imported || 0} imported, ${summary.updated || 0} updated.`, summary.failed ? '' : 'success');
                await fetchCompanyAssets(document.getElementById('assetSearch')?.value || '');
                await fetchCves(document.getElementById('cveSearch')?.value || '');
                await fetchStats();
            } catch (e) {
                updateAssetImportPreview(`Import failed: ${e.message}`, 'error');
                setRefreshStatus(`Asset import failed: ${e.message}`, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Import Assets';
            }
        }

        async function recalculateCompanyAssets() {
            try {
                setRefreshStatus('Recalculating company impact matches...', '');
                const response = await fetchJson(`${API_BASE}/company-assets/recalculate`, { method: 'POST' }, REFRESH_TIMEOUT_MS);
                const result = response.data || {};
                setRefreshStatus(`Company impact recalculated: ${result.matches || 0} matches across ${result.cves || 0} CVEs.`, 'success');
                await fetchCompanyAssets(document.getElementById('assetSearch')?.value || '');
                await fetchCves(document.getElementById('cveSearch')?.value || '');
                await fetchStats();
            } catch (e) {
                setRefreshStatus(`Recalculation failed: ${e.message}`, 'error');
            }
        }

        function updateAssetFilterOptions() {
            const select = document.getElementById('cveAssetFilter');
            if (!select) return;
            const enabledAssets = companyAssets.filter(asset => asset.enabled);
            const hasSelected = selectedCompanyAssetId === 'all' || enabledAssets.some(asset => String(asset.id) === String(selectedCompanyAssetId));
            if (!hasSelected) selectedCompanyAssetId = 'all';
            select.innerHTML = [
                '<option value="all">All Assets</option>',
                ...enabledAssets.map(asset => `<option value="${asset.id}" ${String(asset.id) === String(selectedCompanyAssetId) ? 'selected' : ''}>${escapeHtml(asset.name)}</option>`)
            ].join('');
        }

        function filterCompanyAffected() {
            selectedCompanyAffected = !selectedCompanyAffected;
            updateCompanyFilterControls();
            fetchCves(document.getElementById('cveSearch')?.value || '');
        }

        function filterCveAsset(assetId) {
            selectedCompanyAssetId = assetId || 'all';
            if (selectedCompanyAssetId !== 'all') selectedCompanyAffected = true;
            updateCompanyFilterControls();
            fetchCves(document.getElementById('cveSearch')?.value || '');
        }

        function updateCompanyFilterControls() {
            document.getElementById('companyAffectedBtn')?.classList.toggle('active', selectedCompanyAffected);
            const select = document.getElementById('cveAssetFilter');
            if (select) select.value = selectedCompanyAssetId;
        }

        function formatAssetPackages(packages) {
            return (packages || []).map(pkg => pkg.ecosystem ? `${pkg.ecosystem}:${pkg.name}` : pkg.name).filter(Boolean).join('\n');
        }

        function parseTextList(text) {
            return String(text || '')
                .split(/[\n;|,]+/)
                .map(value => value.trim())
                .filter(Boolean);
        }

        function parsePackageLines(text) {
            return parseTextList(text).map(value => {
                const separator = value.indexOf(':');
                if (separator > 0) {
                    return {
                        ecosystem: value.slice(0, separator).trim(),
                        name: value.slice(separator + 1).trim()
                    };
                }
                return { name: value };
            }).filter(pkg => pkg.name);
        }

        async function fetchFeedStatus() {
            try {
                const data = await fetchJson(`${API_BASE}/stats/feeds`);
                renderFeedStatus(data.data || []);
            } catch (e) {
                document.getElementById('feedStatusContent').innerHTML = `<div class="error-state"><p>Failed to load feed status</p><p>${escapeHtml(e.message)}</p></div>`;
            }
        }

        function renderFeedStatus(feeds) {
            const container = document.getElementById('feedStatusContent');
            if (feeds.length === 0) {
                container.innerHTML = '<div class="empty-state">No feed data yet. Click Refresh to fetch data.</div>';
                return;
            }

            const sortedFeeds = [...feeds].sort((a, b) => {
                const order = { error: 0, running: 1, pending: 2, skipped: 3, success: 4 };
                return (order[a.status] ?? 4) - (order[b.status] ?? 4) || String(a.source || '').localeCompare(String(b.source || ''));
            });

            container.innerHTML = `
                <div class="detail-section">
                    <div class="metrics-grid" style="grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));">
                        ${sortedFeeds.map(feed => `
                            <div class="metric-item feed-card ${escapeHtml(feed.status || 'pending')}">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <span style="font-family: 'JetBrains Mono', monospace; font-weight: 600;">${escapeHtml(feed.source?.toUpperCase() || 'UNKNOWN')}</span>
                                    <span class="feed-dot ${escapeHtml(feed.status || 'pending')}"></span>
                                </div>
                                <div style="font-size: 12px; color: var(--text-muted);">
                                    <div>Status: ${escapeHtml(feed.status || 'pending')}</div>
                                    <div>Last attempt: ${formatDate(feed.last_fetch)}</div>
                                    <div>Last attempt items: ${feed.last_count || 0}</div>
                                    <div>Last success: ${feed.last_successful_fetch ? `${formatDate(feed.last_successful_fetch)} (${feed.last_successful_count || 0} items)` : 'Not available yet'}</div>
                                    ${feed.error_message ? `<div class="feed-error">Error: ${escapeHtml(feed.error_message)}</div>` : ''}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        function switchMainTab(tab, button) {
            activeTab = tab;
            document.querySelectorAll('.main-tab').forEach(t => t.classList.remove('active'));
            const activeButton = button || document.querySelector(`.main-tab[data-tab="${tab}"]`);
            activeButton?.classList.add('active');

            document.getElementById('cvesPanel').style.display = tab === 'cves' ? 'grid' : 'none';
            document.getElementById('iocsPanel').style.display = tab === 'iocs' ? 'grid' : 'none';
            document.getElementById('progressPanel').style.display = tab === 'progress' ? 'grid' : 'none';
            document.getElementById('assetsPanel').style.display = tab === 'assets' ? 'grid' : 'none';
            document.getElementById('feedsPanel').style.display = tab === 'feeds' ? 'block' : 'none';

            if (tab === 'cves' && allCves.length === 0) fetchCves();
            if (tab === 'iocs' && allIocs.length === 0) fetchIocs();
            if (tab === 'progress') fetchProgress(document.getElementById('progressSearch')?.value || '');
            if (tab === 'assets') {
                fetchCompanyAssets(document.getElementById('assetSearch')?.value || '');
                renderAssetEditor(selectedAsset);
            }
            if (tab === 'feeds') fetchFeedStatus();
        }

        function filterCves(filter) {
            selectedSeverity = filter;
            document.querySelectorAll('#cveSeverityFilters .filter-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.filter === filter);
            });
            fetchCves(document.getElementById('cveSearch')?.value || '');
        }

        function filterCveProgress(status) {
            selectedCveProgress = status;
            document.querySelectorAll('#cveProgressFilters .filter-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.cveProgress === status);
            });
            fetchCves(document.getElementById('cveSearch')?.value || '');
        }

        function filterIocs(type) {
            selectedIocType = type;
            document.querySelectorAll('#iocFilters .filter-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.iocType === type);
            });
            fetchIocs(type, document.getElementById('iocSearch')?.value || '');
        }

        function filterProgress(status) {
            selectedProgressStatus = status;
            document.querySelectorAll('#progressStatusFilters .filter-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.progressStatus === status);
            });
            fetchProgress(document.getElementById('progressSearch')?.value || '');
        }

        function filterTimeRange(scope, range) {
            if (scope === 'cves') {
                selectedCveTimeRange = range;
                document.querySelectorAll('#cveTimeFilters .filter-btn').forEach(b => {
                    b.classList.toggle('active', b.dataset.timeRange === range);
                });
                fetchCves(document.getElementById('cveSearch')?.value || '');
                return;
            }

            selectedIocTimeRange = range;
            document.querySelectorAll('#iocTimeFilters .filter-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.timeRange === range);
            });
            fetchIocs(selectedIocType, document.getElementById('iocSearch')?.value || '');
        }

        let searchTimeout;
        function debounceSearch() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                fetchCves(document.getElementById('cveSearch')?.value || '');
            }, 300);
        }

        function debounceSearchIocs() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                fetchIocs(selectedIocType, document.getElementById('iocSearch')?.value || '');
            }, 300);
        }

        function debounceSearchProgress() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                fetchProgress(document.getElementById('progressSearch')?.value || '');
            }, 300);
        }

        function debounceSearchAssets() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                fetchCompanyAssets(document.getElementById('assetSearch')?.value || '');
            }, 300);
        }

        function debounceGlobalSearch() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                fetchGlobalSearch(document.getElementById('globalSearch')?.value || '');
            }, 250);
        }

        async function manualRefresh() {
            if (isRefreshing) {
                setRefreshStatus('Refresh already running. Waiting for the current run to finish...', '');
                return;
            }
            isRefreshing = true;
            const btn = document.getElementById('refreshBtn');
            btn.classList.add('loading');
            btn.disabled = true;
            btn.innerHTML = '<div class="spinner" style="width:14px;height:14px;border-width:2px;"></div> Refreshing...';
            setRefreshStatus('Fetching public CTI feeds. This can take a little while...', '');

            try {
                const data = await fetchJson(`${API_BASE}/stats/feeds/refresh`, { method: 'POST' }, REFRESH_TIMEOUT_MS);
                const finalResult = data.data?.running ? await pollManualRefresh() : data.data;

                lastRefresh = new Date();
                document.getElementById('lastUpdated').textContent = `Updated: ${formatDate(lastRefresh)}`;
                renderLastRefreshSummary(finalResult?.summary);
                setRefreshStatus(refreshSummary(finalResult), finalResult?.summary?.feeds?.failed ? '' : 'success');
            } catch (e) {
                setRefreshStatus(`Refresh failed: ${e.message}`, 'error');
                console.error('Refresh error:', e);
            } finally {
                btn.classList.remove('loading');
                btn.disabled = false;
                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Refresh';
                isRefreshing = false;

                fetchStats();
                if (activeTab === 'cves') fetchCves(document.getElementById('cveSearch')?.value || '');
                if (activeTab === 'iocs') fetchIocs(selectedIocType, document.getElementById('iocSearch')?.value || '');
                if (activeTab === 'progress') fetchProgress(document.getElementById('progressSearch')?.value || '');
                if (activeTab === 'assets') fetchCompanyAssets(document.getElementById('assetSearch')?.value || '');
                if (activeTab === 'feeds') fetchFeedStatus();
            }
        }

        async function pollManualRefresh() {
            for (;;) {
                await sleep(3000);
                const status = await fetchJson(`${API_BASE}/stats/feeds/refresh/status`, {}, REQUEST_TIMEOUT_MS);
                const state = status.data || {};
                if (activeTab === 'feeds') fetchFeedStatus();
                if (!state.running) {
                    if (state.last_error) throw new Error(state.last_error);
                    return state.last_result;
                }
                const started = state.started_at ? ` since ${formatDate(state.started_at)}` : '';
                setRefreshStatus(`Refresh still running${started}. Feed cards update as each source finishes.`, '');
            }
        }

        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        function toggleAutoRefresh() {
            if (autoRefreshTimer) clearInterval(autoRefreshTimer);
            autoRefreshTimer = null;
            autoRefreshEnabled = false;
            setRefreshStatus('Feed refresh is manual only.', '');
        }

        function exportData() {
            if (activeTab === 'progress') {
                exportCsv(filteredProgressItems, 'cve-progress-export', ['id', 'progress_status', 'severity', 'cvss_score', 'latest_note', 'progress_updated_at']);
            } else if (activeTab === 'assets') {
                exportCsv(companyAssetCsvRows(filteredCompanyAssets), 'company-assets-export', ['name', 'type', 'vendor', 'product', 'version', 'aliases', 'cpe_uris', 'packages', 'criticality', 'enabled', 'notes']);
            } else if (activeTab === 'iocs') {
                exportCsv(filteredIocs, 'ioc-export', ['type', 'value', 'source', 'threat_type', 'confidence', 'first_seen', 'last_seen']);
            } else {
                exportCsv(filteredCves, 'cve-export', ['id', 'source', 'severity', 'cvss_score', 'description', 'published_at', 'company_match_count', 'company_priority_score']);
            }
        }

        function companyAssetCsvRows(assets) {
            return (assets || []).map(asset => ({
                ...asset,
                aliases: (asset.aliases || []).join('; '),
                cpe_uris: (asset.cpe_uris || []).join('; '),
                packages: formatAssetPackages(asset.packages || []).replace(/\n/g, '; '),
                enabled: asset.enabled ? 'true' : 'false'
            }));
        }

        function exportCsv(data, filename, fields) {
            const csv = CtiDashboardUtils.buildCsv(data, fields);
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${filename}-${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function escapeJsArg(text) {
            return String(text || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        }

        function sourceUrlForCve(cve) {
            if (/^CVE-\d{4}-\d+$/i.test(cve.id || '')) {
                return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`;
            }
            if (/^GHSA-/i.test(cve.id || '')) {
                return `https://github.com/advisories/${encodeURIComponent(cve.id)}`;
            }
            return `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(cve.id || '')}`;
        }

        function resetDetailPanel(panelId, message) {
            document.getElementById(panelId).innerHTML = `
                <div class="detail-placeholder">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12h6M12 9v6M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    <p>${escapeHtml(message)}</p>
                </div>
            `;
        }

        function setRefreshStatus(message, type) {
            const status = document.getElementById('refreshStatus');
            status.className = `status-line ${type || ''}`;
            status.textContent = message || '';
        }

        function renderTriageOverview(triage) {
            const safe = {
                needsReview: triage?.needsReview || 0,
                open: triage?.open || 0,
                assigned: triage?.assigned || 0,
                closed: triage?.closed || 0,
                feedErrors: triage?.feedErrors || 0
            };

            document.getElementById('triageNeedsReview').textContent = safe.needsReview;
            document.getElementById('triageOpen').textContent = safe.open;
            document.getElementById('triageAssigned').textContent = safe.assigned;
            document.getElementById('triageClosed').textContent = safe.closed;
            document.getElementById('triageFeedErrors').textContent = safe.feedErrors;
            renderProgressStatusCounts(safe);
        }

        function renderProgressStatusCounts(triage) {
            const total = (triage.open || 0) + (triage.assigned || 0) + (triage.closed || 0);
            const counts = {
                all: total,
                open: triage.open || 0,
                assigned: triage.assigned || 0,
                closed: triage.closed || 0
            };

            document.querySelectorAll('#progressStatusFilters .filter-btn').forEach(button => {
                const key = button.dataset.progressStatus;
                const label = button.dataset.label || button.textContent;
                button.textContent = `${label} (${counts[key] || 0})`;
            });
        }

        async function fetchGlobalSearch(query) {
            const container = document.getElementById('globalSearchResults');
            if (!container) return;
            const trimmed = String(query || '').trim();
            if (trimmed.length < 2) {
                globalSearchResults = [];
                container.classList.remove('active');
                container.innerHTML = '';
                return;
            }

            try {
                const params = new URLSearchParams({ q: trimmed, limit: 25, offset: 0 });
                const data = await fetchJson(`${API_BASE}/search?${params}`);
                globalSearchResults = data.data || [];
                renderGlobalSearchResults();
            } catch (e) {
                container.classList.add('active');
                container.innerHTML = `<div class="error-state"><p>Search failed</p><p>${escapeHtml(e.message)}</p></div>`;
            }
        }

        function renderGlobalSearchResults() {
            const container = document.getElementById('globalSearchResults');
            if (!container) return;
            container.classList.add('active');

            if (globalSearchResults.length === 0) {
                container.innerHTML = '<div class="empty-state">No matches found.</div>';
                return;
            }

            container.innerHTML = globalSearchResults.map((result, index) => `
                <div class="search-result" onclick="openSearchResult(${index})">
                    <div class="search-result-header">
                        <span class="search-result-title">${escapeHtml(result.title || result.name || result.id || '')}</span>
                        <span class="search-result-type">${escapeHtml(result.type || 'result')} - ${escapeHtml(result.source || 'unknown')}</span>
                    </div>
                    <div class="search-result-summary">${escapeHtml(result.summary || result.threat_type || result.severity || '')}</div>
                </div>
            `).join('');
        }

        async function openSearchResult(index) {
            const result = globalSearchResults[index];
            if (!result) return;

            if (result.type === 'cve') {
                switchMainTab('cves', document.querySelector('.main-tab[data-tab="cves"]'));
                document.getElementById('cveSearch').value = result.title || result.id || '';
                await fetchCves(result.title || result.id || '');
                const cve = filteredCves.find(item => item.id === result.entity_id || item.id === result.id) || { id: result.entity_id || result.id };
                if (cve?.id) await selectCve(cve);
                return;
            }

            if (result.type === 'ioc') {
                switchMainTab('iocs', document.querySelector('.main-tab[data-tab="iocs"]'));
                document.getElementById('iocSearch').value = result.title || '';
                await fetchIocs('all', result.title || '');
                const ioc = filteredIocs.find(item => String(item.id) === String(result.entity_id)) || await fetchIocById(result.entity_id);
                if (ioc) {
                    selectedItem = ioc;
                    renderIocDetail(ioc);
                }
            }
        }

        async function fetchIocById(id) {
            if (!id) return null;
            const data = await fetchJson(`${API_BASE}/iocs/${encodeURIComponent(id)}`);
            return data.data || null;
        }

        function isNeedsReview(cve) {
            return !cve?.progress_status && ['critical', 'high'].includes(String(cve?.severity || '').toLowerCase());
        }

        function applyLoadedState(lastRefreshSummary, latestFeedAt) {
            if (lastRefreshSummary?.finished_at) {
                lastRefresh = new Date(lastRefreshSummary.finished_at);
                document.getElementById('lastUpdated').textContent = `Updated: ${formatDate(lastRefreshSummary.finished_at)}`;
                renderLastRefreshSummary(lastRefreshSummary);
                return;
            }

            if (latestFeedAt) {
                document.getElementById('lastUpdated').textContent = `Loaded: ${formatDate(latestFeedAt)}`;
                renderNoRefreshSummary(latestFeedAt);
                return;
            }

            document.getElementById('lastUpdated').textContent = 'Loaded';
            renderNoRefreshSummary(null);
        }

        function renderNoRefreshSummary(latestFeedAt) {
            const container = document.getElementById('lastRefreshSummary');
            if (!container) return;

            const latest = latestFeedAt ? formatDate(latestFeedAt) : 'No feed run yet';
            container.innerHTML = `
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">Latest Feed Data</div>
                    <div class="refresh-summary-value">${escapeHtml(latest)}</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">New CVEs</div>
                    <div class="refresh-summary-value">Refresh to calculate</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">Updated CVEs</div>
                    <div class="refresh-summary-value">Refresh to calculate</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">New IOCs</div>
                    <div class="refresh-summary-value">Refresh to calculate</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">Feeds</div>
                    <div class="refresh-summary-value">Ready</div>
                </div>
            `;
        }

        function renderLastRefreshSummary(summary) {
            const container = document.getElementById('lastRefreshSummary');
            if (!container || !summary) return;

            const failed = summary.feeds?.failed || 0;
            const feedText = `${summary.feeds?.successful || 0}/${summary.feeds?.total || 0}`;
            container.innerHTML = `
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">Last Refresh</div>
                    <div class="refresh-summary-value">${formatDate(summary.finished_at)}</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">New CVEs</div>
                    <div class="refresh-summary-value good">${summary.cves?.new || 0}</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">Updated CVEs</div>
                    <div class="refresh-summary-value">${summary.cves?.updated || 0}</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">New IOCs</div>
                    <div class="refresh-summary-value good">${summary.iocs?.new || 0}</div>
                </div>
                <div class="refresh-summary-item">
                    <div class="refresh-summary-label">Feeds</div>
                    <div class="refresh-summary-value ${failed ? 'warn' : 'good'}">${feedText}${failed ? ` (${failed} failed)` : ''}</div>
                </div>
            `;
        }

        function refreshSummary(results) {
            if (results?.summary) {
                const summary = results.summary;
                return `Refresh completed: ${summary.feeds.successful}/${summary.feeds.total} configured feeds succeeded, ${summary.cves.new || 0} new CVEs, ${summary.iocs.new || 0} new IOCs.`;
            }

            const feeds = Object.entries(results || {}).filter(([key]) => !['alerts', 'summary'].includes(key));
            if (feeds.length === 0) return 'Refresh completed.';

            const successful = feeds.filter(([, result]) => result?.success).length;
            const totalItems = feeds.reduce((sum, [, result]) => sum + (result?.count || 0), 0);
            return `Refresh completed: ${successful}/${feeds.length} feeds succeeded, ${totalItems} items processed.`;
        }

        function formatDate(dateStr) {
            if (!dateStr) return 'N/A';
            const d = new Date(dateStr);
            if (isNaN(d)) return 'N/A';
            return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        }

        function getRangeStart(range) {
            const daysByRange = {
                '1d': 1,
                '7d': 7,
                '14d': 14,
                '30d': 30
            };
            const days = daysByRange[range];
            if (!days) return null;

            const start = new Date();
            start.setDate(start.getDate() - days);
            return start.toISOString();
        }

        function getThreatSeverity(threatType) {
            const high = ['malware', 'ransomware', 'c2', 'botnet', 'trojan', 'backdoor'];
            const med = ['phishing', 'spam'];
            if (high.some(t => threatType?.toLowerCase().includes(t))) return 'high';
            if (med.some(t => threatType?.toLowerCase().includes(t))) return 'medium';
            return 'low';
        }

        fetchStats();
        fetchCompanyAssets();
        fetchCves();

        setInterval(() => {
            fetchStats();
        }, 60000);
    
