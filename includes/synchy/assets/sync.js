(function () {
	const config = window.synchySyncConfig;

	if (!config) {
		return;
	}

	const form = document.querySelector("[data-synchy-sync-form]");
	const saveButton = document.querySelector("[data-synchy-save-sync]");
	const testButton = document.querySelector("[data-synchy-test-sync]");
	const previewButton = document.querySelector("[data-synchy-preview-sync]");
	const runButton = document.querySelector("[data-synchy-run-sync]");
	const fullSyncButton = document.querySelector("[data-synchy-run-full-sync]");
	const pauseSyncButton = document.querySelector("[data-synchy-pause-sync]");
	const resumeSyncButton = document.querySelector("[data-synchy-resume-sync]");
	const resetSyncButton = document.querySelector("[data-synchy-reset-sync]");
	const manualBaselineButton = document.querySelector("[data-synchy-mark-baseline]");
	const destinationUrlInput = document.querySelector("[data-synchy-sync-url]");
	const usernameInput = document.querySelector("[data-synchy-sync-username]");
	const passwordInput = document.querySelector("[data-synchy-sync-password]");
	const verifySslInput = document.querySelector("[data-synchy-sync-verify-ssl]");
	const inlineConnectionStatus = document.querySelector("[data-synchy-sync-inline-status]");
	const progress = document.querySelector("[data-synchy-sync-progress]");
	const progressBar = document.querySelector("[data-synchy-sync-progress-bar]");
	const progressPhase = document.querySelector("[data-synchy-sync-progress-phase]");
	const progressPercent = document.querySelector("[data-synchy-sync-progress-percent]");
	const progressMessage = document.querySelector("[data-synchy-sync-progress-message]");
	const progressDetail = document.querySelector("[data-synchy-sync-progress-detail]");
	const stages = document.querySelector("[data-synchy-sync-stages]");
	const connectionPanel = document.querySelector("[data-synchy-sync-connection-result]");
	const connectionBadge = document.querySelector("[data-synchy-sync-connection-badge]");
	const connectionMessage = document.querySelector("[data-synchy-sync-connection-message]");
	const connectionMeta = document.querySelector("[data-synchy-sync-connection-meta]");
	const updateRemoteButton = document.querySelector("[data-synchy-update-remote-synchy]");
	const updateRemoteNote = document.querySelector("[data-synchy-update-remote-note]");
	const previewBadge = document.querySelector("[data-synchy-sync-preview-badge]");
	const previewMessage = document.querySelector("[data-synchy-sync-preview-message]");
	const previewBatchCounter = document.querySelector("[data-synchy-sync-batch-counter]");
	const previewTreeContainer = document.querySelector("[data-synchy-sync-preview-tree]");
	const statusBadge = document.querySelector("[data-synchy-sync-status-badge]");
	const statusSummary = document.querySelector("[data-synchy-sync-status-summary]");
	const targetNote = document.querySelector("[data-synchy-sync-target-note]");
	const scopeInputs = Array.from(document.querySelectorAll("[data-synchy-sync-scope]"));

	if (
		!form ||
		!testButton ||
		!previewButton ||
		!runButton ||
		!fullSyncButton ||
		!pauseSyncButton ||
		!resumeSyncButton ||
		!resetSyncButton ||
		!manualBaselineButton ||
		!saveButton ||
		!destinationUrlInput ||
		!usernameInput ||
		!passwordInput ||
		!previewBadge ||
		!previewMessage ||
		!previewBatchCounter ||
		!statusBadge ||
		!statusSummary
	) {
		return;
	}

	let latestPreview = null;
	let latestPreviewMode = "delta";
	let latestFullSyncPlan = null;
	let busy = false;
	let pendingBaselineScopeIds = new Set((config.scopeStatus?.pendingBaselineScopeIds || []).map(String));
	let changedScopeIds = new Set();
	let currentJob = config.currentJob || null;
	let currentStatus = config.currentStatus || null;
	let currentConnectionState = config.connectionState || null;
	let autoConnectionCheckStarted = false;
	let browserFullSyncDriverActive = false;
	// Require a live connection test in the current page session before trusting the destination.
	let connectionVerified = false;
	const initialConnectionState = {
		destinationUrl: destinationUrlInput.value.trim(),
		username: usernameInput.value.trim(),
		verifySsl: verifySslInput?.checked ? "1" : "0",
	};

	const escapeHtml = (value) =>
		String(value)
			.replace(/&/g, "&amp;")
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;")
			.replace(/"/g, "&quot;")
			.replace(/'/g, "&#039;");

	const formatDateTime = (value) => {
		if (value === null || value === undefined || value === "") {
			return config.strings.never || "Never";
		}

		let date = null;

		if (typeof value === "number") {
			date = new Date(value * 1000);
		} else if (/^\d+$/.test(String(value))) {
			date = new Date(Number(value) * 1000);
		} else {
			date = new Date(String(value));
		}

		return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
	};

	const formatDuration = (seconds) => {
		const numeric = Number(seconds || 0);

		if (!Number.isFinite(numeric) || numeric <= 0) {
			return config.strings.na || "N/A";
		}

		const rounded = Math.max(1, Math.round(numeric));
		const hours = Math.floor(rounded / 3600);
		const minutes = Math.floor((rounded % 3600) / 60);
		const secs = rounded % 60;

		if (hours > 0) {
			return `${hours}h ${minutes}m`;
		}

		if (minutes > 0) {
			return `${minutes}m ${secs}s`;
		}

		return `${secs}s`;
	};

	const formatBytes = (bytes) => {
		const numeric = Number(bytes || 0);

		if (!Number.isFinite(numeric) || numeric <= 0) {
			return "0 B";
		}

		const units = ["B", "KB", "MB", "GB"];
		let value = numeric;
		let unitIndex = 0;

		while (value >= 1024 && unitIndex < units.length - 1) {
			value /= 1024;
			unitIndex += 1;
		}

		return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
	};

	const compareVersions = (left, right) => {
		const normalize = (value) =>
			String(value || "")
				.replace(/^[^0-9]*/, "")
				.split(".")
				.map((part) => Number.parseInt(part, 10) || 0);

		const leftParts = normalize(left);
		const rightParts = normalize(right);
		const length = Math.max(leftParts.length, rightParts.length);

		for (let index = 0; index < length; index += 1) {
			const leftPart = leftParts[index] || 0;
			const rightPart = rightParts[index] || 0;

			if (leftPart === rightPart) {
				continue;
			}

			return leftPart > rightPart ? 1 : -1;
		}

		return 0;
	};

	const getRemotePluginVersion = (remoteSite) =>
		String(remoteSite?.sentinelVersion || remoteSite?.pluginVersion || "");

	const getSiteVersion = (source) => {
		const version = source?.siteVersion || {};

		return {
			siteId: String(version.siteId || ""),
			number: Number(version.number || 0),
			syncId: String(version.syncId || ""),
			sourceUrl: String(version.sourceUrl || ""),
			destinationUrl: String(version.destinationUrl || ""),
			updatedAt: String(version.updatedAt || ""),
			updatedBy: String(version.updatedBy || ""),
			mode: String(version.mode || ""),
		};
	};

	const formatSiteVersion = (version) => {
		const normalized = getSiteVersion({ siteVersion: version });
		const label = normalized.number > 0 ? `v${normalized.number}` : "unversioned";
		const detail = normalized.updatedAt ? ` (${formatDateTime(normalized.updatedAt)})` : "";

		return `${label}${detail}`;
	};

	const getSiteVersionRelationship = (remoteSite) => {
		const local = getSiteVersion({ siteVersion: config.localSiteVersion || {} });
		const remote = getSiteVersion(remoteSite || {});

		if (local.number <= 0 && remote.number <= 0) {
			return "No site sync version has been recorded yet.";
		}

		if (local.siteId !== "" && remote.siteId !== "" && local.siteId !== remote.siteId) {
			return "Different site version lineage. Run a baseline/full sync before trusting reverse sync.";
		}

		if (local.number === remote.number) {
			return `Same site version (${formatSiteVersion(local)}).`;
		}

		if (local.number > remote.number) {
			return `Local is ahead (${formatSiteVersion(local)} vs live ${formatSiteVersion(remote)}).`;
		}

		return `Live is newer (${formatSiteVersion(remote)} vs local ${formatSiteVersion(local)}). Reverse sync can bring live changes back.`;
	};

	const refreshRemoteVersionUntilCurrent = (attempt = 0) => {
		const maxAttempts = 6;
		const localVersion = String(config.localPluginVersion || "");
		const remoteVersion = getRemotePluginVersion(currentConnectionState?.remoteSite || {});

		if (
			localVersion !== ""
			&& remoteVersion !== ""
			&& compareVersions(remoteVersion, localVersion) >= 0
		) {
			updateRemoteUpdateControls();
			return;
		}

		if (attempt >= maxAttempts) {
			updateRemoteUpdateControls();
			return;
		}

		window.setTimeout(async () => {
			try {
				await performConnectionTest();
			} catch (error) {
				// Keep retrying briefly in case the destination is still reloading the plugin.
			}

			refreshRemoteVersionUntilCurrent(attempt + 1);
		}, attempt === 0 ? 1500 : 2000);
	};

	const renderMeta = (container, items) => {
		if (!container) {
			return;
		}

		const filtered = items.filter((item) => item && item.value !== undefined && item.value !== null && item.value !== "");

		if (filtered.length === 0) {
			container.innerHTML = "";
			return;
		}

		container.innerHTML = filtered
			.map(
				(item) =>
					`<div${item.className ? ` class="${escapeHtml(item.className)}"` : ""}><span class="synchy-export-meta__label">${escapeHtml(item.label)}</span><strong>${item.html ? item.value : escapeHtml(item.value)}</strong></div>`
			)
			.join("");
	};

	const isTerminalSyncStatus = (status) =>
		["success", "complete", "completed", "done", "error", "failed"].includes(String(status || ""));

	const clearFullSyncDisplay = () => {
		currentJob = null;
		latestFullSyncPlan = null;
		browserFullSyncDriverActive = false;

		if (previewBatchCounter) {
			previewBatchCounter.textContent = "";
			previewBatchCounter.classList.add("is-hidden");
		}

		if (previewTreeContainer) {
			previewTreeContainer.innerHTML = "";
			previewTreeContainer.classList.add("is-hidden");
		}

		if (previewBadge) {
			previewBadge.textContent = "";
		}

		if (previewMessage) {
			previewMessage.textContent = config.strings.previewDefault || "Run Preview to load the pending file sections and database tables.";
		}

		renderProgress(null);
		updateActionButtons();
	};

	const renderPreviewBatchCounter = (preview) => {
		if (!previewBatchCounter) {
			return;
		}

		const jobStatus = String(currentJob?.status || "");
		const savedStatus = String(currentStatus?.status || "");
		const syncFinished = isTerminalSyncStatus(savedStatus) && jobStatus !== "running";

		const batches = Array.isArray(currentJob?.batches) && currentJob.batches.length > 0
			? currentJob.batches
			: Array.isArray(preview?.batches) && preview.batches.length > 0
				? preview.batches
				: Array.isArray(latestFullSyncPlan?.batches) ? latestFullSyncPlan.batches : [];
		const totalBatchesSource = currentJob?.totalBatches ?? preview?.totalBatches ?? latestFullSyncPlan?.totalBatches ?? batches.length ?? 0;
		const totalBatches = Number(totalBatchesSource);

		if (totalBatches <= 0) {
			previewBatchCounter.textContent = "";
			previewBatchCounter.classList.add("is-hidden");
			return;
		}

		const completedBatchesSource = currentJob?.completedBatches ?? batches.filter((batch) => String(batch?.status || "") === "complete").length ?? 0;
		const completedBatches = syncFinished ? totalBatches : Number(completedBatchesSource);
		const messageBatchMatch = String(currentJob?.message || currentStatus?.message || "").match(/batch\s+(\d+)\s+of\s+(\d+)/i);
		const currentBatchIndex = Number(currentJob?.currentBatchIndex || (messageBatchMatch ? messageBatchMatch[1] : 0));
		const runningBatches = syncFinished ? 0 : batches.filter((batch) => String(batch?.status || "") === "running").length
			|| (currentJob?.runMode === "full" && currentJob?.status === "running" && (currentBatchIndex > completedBatches || String(currentJob?.message || "").toLowerCase().includes("syncing batch")) ? 1 : 0)
			|| (String(currentStatus?.status || "") === "running" && String(currentStatus?.message || "").toLowerCase().includes("syncing batch") ? 1 : 0);

		previewBatchCounter.textContent = `${completedBatches.toLocaleString()} / ${totalBatches.toLocaleString()} ${config.strings.batchesComplete || "batches complete"}${runningBatches > 0 ? ` | ${runningBatches.toLocaleString()} running${currentBatchIndex > 0 ? ` (${currentBatchIndex.toLocaleString()} of ${totalBatches.toLocaleString()})` : ""}` : ""}`;
		previewBatchCounter.classList.remove("is-hidden");
	};

	const parseFullSyncStatusMessage = (message) => {
		const plannedMatch = String(message || "").match(/Full Sync is running:\s*([\d,]+)\s*files,\s*([\d,]+)\s*DB rows,\s*([\d,]+)\s*batches planned/i);

		if (!plannedMatch) {
			return null;
		}

		return {
			filesCount: Number(String(plannedMatch[1] || "0").replace(/,/g, "")),
			dbRows: Number(String(plannedMatch[2] || "0").replace(/,/g, "")),
			totalBatches: Number(String(plannedMatch[3] || "0").replace(/,/g, "")),
		};
	};

	const buildSyntheticFullSyncJob = () => {
		if (String(currentStatus?.status || "") !== "running") {
			return null;
		}

		const parsed = parseFullSyncStatusMessage(currentStatus?.message || "") || {};
		const totalBatches = Number(parsed.totalBatches || latestFullSyncPlan?.totalBatches || currentJob?.totalBatches || 0);

		return {
			...(currentJob || {}),
			status: "running",
			runMode: "full",
			phase: currentJob?.phase || "sending_package",
			phaseLabel: currentJob?.phaseLabel || (config.strings.syncRunning || "Sync running"),
			progress: Number(currentJob?.progress || 1),
			message: currentJob?.message || currentStatus?.message || "Full Sync is running.",
			filesCount: Number(currentJob?.filesCount || parsed.filesCount || 0),
			dbRows: Number(currentJob?.dbRows || parsed.dbRows || 0),
			totalBatches,
			completedBatches: Number(currentJob?.completedBatches || 0),
			currentBatchLabel: currentJob?.currentBatchLabel || "",
			batches: Array.isArray(currentJob?.batches) && currentJob.batches.length > 0
				? currentJob.batches
				: Array.isArray(latestFullSyncPlan?.batches) ? latestFullSyncPlan.batches : [],
			stages: Array.isArray(currentJob?.stages) ? currentJob.stages : Array.isArray(config.defaultStages) ? config.defaultStages : [],
		};
	};

	const renderFullSyncPendingHeader = () => {
		const jobStatus = String(currentJob?.status || "");
		const savedStatus = String(currentStatus?.status || "");

		if (isTerminalSyncStatus(savedStatus) && !["running", "paused", "failed_partial"].includes(jobStatus)) {
			return;
		}

		const hasFullSyncContext = currentJob?.runMode === "full"
			|| latestPreviewMode === "full"
			|| latestPreviewMode === "baseline-full";
		const hasBatchPlan = hasFullSyncContext && (Number(currentJob?.totalBatches || latestFullSyncPlan?.totalBatches || 0) > 0
			|| (Array.isArray(currentJob?.batches) && currentJob.batches.length > 0)
			|| (Array.isArray(latestFullSyncPlan?.batches) && latestFullSyncPlan.batches.length > 0));

		if (
			(currentJob?.runMode !== "full" || !["running", "paused", "failed_partial"].includes(jobStatus))
			&& !(savedStatus === "running")
			&& !hasBatchPlan
		) {
			return;
		}

		const effectiveStatus = jobStatus || savedStatus || "running";
		previewBadge.textContent = effectiveStatus === "running"
			? (config.strings.syncRunning || "Sync running")
			: effectiveStatus === "paused"
				? (config.strings.paused || "Paused")
				: (config.strings.resumeReady || "Resume ready");
		previewMessage.textContent = currentJob?.message || currentStatus?.message || "Full Sync batches are in progress.";
		renderPreviewBatchCounter(latestPreview);
	};

	const hasFullSyncDisplayContext = () =>
		currentJob?.runMode === "full"
		|| String(currentStatus?.status || "") === "running"
		|| Number(latestFullSyncPlan?.totalBatches || 0) > 0
		|| (Array.isArray(latestFullSyncPlan?.batches) && latestFullSyncPlan.batches.length > 0);

	const mergeJobResponse = (incoming) => {
		if (!incoming || !incoming.status) {
			return null;
		}

		const previousBatches = Array.isArray(currentJob?.batches) && currentJob.batches.length > 0
			? currentJob.batches
			: Array.isArray(latestFullSyncPlan?.batches) ? latestFullSyncPlan.batches : [];
		const incomingBatches = Array.isArray(incoming.batches) ? incoming.batches : [];

		if (incoming.runMode === "full" && incomingBatches.length === 0 && previousBatches.length > 0) {
			return {
				...incoming,
				batches: previousBatches,
				totalBatches: Number(incoming.totalBatches || latestFullSyncPlan?.totalBatches || previousBatches.length),
			};
		}

		return incoming;
	};

	const getFileBucketLabel = (scopeId, path) => {
		const normalized = String(path || "").replace(/^\/+/, "");
		const segments = normalized.split("/").filter(Boolean);

		if (segments.length === 0) {
			return config.strings.other || "Other";
		}

		if (scopeId === "files_plugins") {
			return segments[1] || segments[0];
		}

		if (scopeId === "files_themes") {
			return segments[1] || segments[0];
		}

		if (scopeId === "files_uploads") {
			return segments[1] || segments[0];
		}

		return segments[0];
	};

	const buildFileBuckets = (scopeId, files) => {
		const buckets = new Map();

		files.forEach((file) => {
			const path = String(file?.path || "");
			const size = Number(file?.size || 0);
			const bucketLabel = getFileBucketLabel(scopeId, path);

			if (!buckets.has(bucketLabel)) {
				buckets.set(bucketLabel, {
					label: bucketLabel,
					count: 0,
					bytes: 0,
					files: [],
				});
			}

			const bucket = buckets.get(bucketLabel);
			bucket.count += 1;
			bucket.bytes += size;
			bucket.files.push({ path, size });
		});

		return Array.from(buckets.values()).sort((left, right) => left.label.localeCompare(right.label));
	};

	const renderStages = (job) => {
		if (!stages) {
			return;
		}

		const items = Array.isArray(job?.stages) ? job.stages : Array.isArray(config.defaultStages) ? config.defaultStages : [];

		stages.innerHTML = items
			.map(
				(stage) => `
					<div class="synchy-export-stage is-${escapeHtml(stage.state || "pending")}">
						<span class="synchy-export-stage__indicator" aria-hidden="true"></span>
						<div class="synchy-export-stage__content">
							<strong>${escapeHtml(stage.label || "")}</strong>
						</div>
					</div>
				`
			)
			.join("");
	};

	const renderProgress = (job) => {
		if (!progress) {
			renderStages(job);
			return;
		}

		if (!job || !job.status) {
			progress.classList.add("is-hidden");
			renderStages(null);
			return;
		}

		progress.classList.remove("is-hidden");

		if (progressBar) {
			progressBar.style.width = `${job.progress || 0}%`;
		}

		if (progressPhase) {
			progressPhase.textContent = job.phaseLabel || (config.strings.syncRunning || "Sync running");
		}

		if (progressPercent) {
			progressPercent.textContent = `${job.progress || 0}%`;
		}

		if (progressMessage) {
			progressMessage.textContent = job.message || "";
		}

		if (progressDetail) {
			if (job?.runMode === "full" && Number(job.totalBatches || 0) > 0) {
				progressDetail.textContent = `${config.strings.batches || "Batches"}: ${Number(job.completedBatches || 0).toLocaleString()} / ${Number(job.totalBatches || 0).toLocaleString()}${job.currentBatchLabel ? ` | ${config.strings.currentBatch || "Current batch"}: ${job.currentBatchLabel}` : ""}`;
			} else {
				progressDetail.textContent = `${config.strings.selectedChanges || "Selected changes"}: ${Number(job.filesCount || 0).toLocaleString()} files, ${Number(job.dbRows || 0).toLocaleString()} DB rows`;
			}
		}

		renderPreviewBatchCounter(latestPreview);
		renderStages(job);
	};

	const getSelectedScopeIds = () =>
		scopeInputs
			.filter((input) => String(input.value || "") === "1")
			.map((input) => String(input.dataset.scopeId || ""));

	const getSelectedScopeLabels = () =>
		getSelectedScopeIds()
			.map((scopeId) => document.querySelector(`[data-synchy-sync-scope-row][data-scope-id="${scopeId}"] strong`)?.textContent?.trim() || "")
			.filter(Boolean);

	const getHasSelection = () => getSelectedScopeIds().length > 0;

	const getPreviewSelectionInputs = () => Array.from(form.querySelectorAll("[data-synchy-preview-selection]"));

	const getHasSelectedPreviewItems = () => {
		if (latestPreviewMode === "full" || Array.isArray(latestPreview?.batches)) {
			return getHasPreviewChanges();
		}

		const inputs = getPreviewSelectionInputs().filter((input) => input.type === "checkbox");

		if (inputs.length === 0) {
			return false;
		}

		return inputs.some((input) => input.checked);
	};

	const getHasPreviewChanges = () =>
		latestPreview !== null
		&& ((Number(latestPreview.filesCount || 0) > 0) || (Number(latestPreview.dbRows || 0) > 0));

	const getHasPendingBaselineSelection = () =>
		getSelectedScopeIds().some((scopeId) => pendingBaselineScopeIds.has(String(scopeId)));

	const getIsBatchedBaselinePreview = () =>
		latestPreview !== null && latestPreviewMode === "baseline-full";

	const getIsRunningFullSync = () => currentJob?.runMode === "full" && currentJob?.status === "running";
	const getHasResumableFullSync = () =>
		currentJob?.runMode === "full" && ["paused", "failed_partial"].includes(String(currentJob?.status || ""));

	const getRunActionLabel = () =>
		getHasPendingBaselineSelection()
			? (config.strings.startBaseline || "Start Baseline")
			: (config.strings.pushChanges || "Push");

	const updateTargetNote = () => {
		if (!targetNote) {
			return;
		}

		const destination = destinationUrlInput?.value?.trim() || "the destination URL above";
		targetNote.textContent = `Sync sends changes only to ${destination}.`;
	};

	const getSelectedScopeIdSet = () => new Set(getSelectedScopeIds().map(String));

	const updateScopeRows = () => {
		scopeInputs.forEach((input) => {
			const row = document.querySelector(`[data-synchy-sync-scope-row][data-scope-id="${String(input.dataset.scopeId || "")}"]`);
			const status = row?.querySelector("[data-synchy-sync-scope-status]");
			const scopeId = String(input.dataset.scopeId || "");
			const pending = pendingBaselineScopeIds.has(scopeId);
			const changed = changedScopeIds.has(scopeId);

			if (!row || !status) {
				return;
			}

			row.classList.toggle("is-pending", pending);
			row.classList.toggle("is-complete", !pending && !changed);
			row.classList.toggle("is-changed", !pending && changed);
			status.classList.remove("synchy-badge--muted", "synchy-badge--warning", "synchy-badge--connected");

			if (pending) {
				status.textContent = config.strings.needsBaseline || "Needs baseline";
				status.classList.add("synchy-badge--warning");
				return;
			}

			if (changed) {
				status.textContent = config.strings.pendingChanges || "Pending changes";
				status.classList.add("synchy-badge--warning");
				return;
			}

			status.textContent = latestPreview
				? (config.strings.noChangesInScope || "No changes")
				: (config.strings.readyForPreview || "Ready for preview");
			status.classList.add("synchy-badge--muted");
		});
	};

	const hasSavedPassword = () => passwordInput.dataset.hasSavedPassword === "1";

	const getConnectionDirty = () =>
		destinationUrlInput.value.trim() !== initialConnectionState.destinationUrl
		|| usernameInput.value.trim() !== initialConnectionState.username
		|| (verifySslInput?.checked ? "1" : "0") !== initialConnectionState.verifySsl
		|| passwordInput.value.trim() !== "";

	const hasConnectionCoreValues = () =>
		destinationUrlInput.value.trim() !== ""
		&& usernameInput.value.trim() !== ""
		&& (passwordInput.value.trim() !== "" || hasSavedPassword());

	const hasConfirmedConnection = () =>
		!getConnectionDirty()
		&& connectionVerified;

	const updateConnectionControls = () => {
		const dirty = getConnectionDirty();

		saveButton.disabled = busy || !dirty;
		testButton.disabled = busy || !hasConnectionCoreValues() || hasConfirmedConnection();

		if (!inlineConnectionStatus) {
			return;
		}

		inlineConnectionStatus.classList.remove("synchy-badge--muted", "synchy-badge--warning", "synchy-badge--connected");

		if (hasConfirmedConnection()) {
			inlineConnectionStatus.textContent = config.strings.connected || "Connected";
			inlineConnectionStatus.classList.add("synchy-badge--connected");
			return;
		}

		if (!dirty && currentConnectionState?.status === "error" && hasConnectionCoreValues()) {
			inlineConnectionStatus.textContent = config.strings.failed || "Failed";
			inlineConnectionStatus.classList.add("synchy-badge--warning");
			return;
		}

		if (dirty && hasConnectionCoreValues()) {
			inlineConnectionStatus.textContent = config.strings.needsRetest || "Needs retest";
			inlineConnectionStatus.classList.add("synchy-badge--warning");
			return;
		}

		inlineConnectionStatus.textContent = hasConnectionCoreValues()
			? (config.strings.notChecked || "Not checked")
			: (config.strings.incomplete || "Incomplete");
		inlineConnectionStatus.classList.add("synchy-badge--muted");
	};

	const updateActionButtons = () => {
		const hasSelection = getHasSelection();
		const runLabel = getRunActionLabel();
		const hasPreviewChanges = getHasPreviewChanges();
		const hasSelectedPreviewItems = getHasSelectedPreviewItems();
		const hasFullSyncPreview = latestPreview !== null && latestPreviewMode === "full";
		const hasBatchedBaselinePreview = getIsBatchedBaselinePreview();
		const runningFullSync = getIsRunningFullSync();
		const resumableFullSync = getHasResumableFullSync();

		previewButton.disabled = busy || !hasSelection;
		runButton.disabled = busy || !hasSelection || (hasFullSyncPreview && !hasBatchedBaselinePreview) || !hasPreviewChanges || !hasSelectedPreviewItems || runningFullSync || resumableFullSync;
		fullSyncButton.disabled = (busy && !runningFullSync) || !hasSelection || runningFullSync || resumableFullSync || (hasFullSyncPreview && (!hasPreviewChanges || !hasSelectedPreviewItems));
		pauseSyncButton.disabled = !runningFullSync;
		resumeSyncButton.disabled = runningFullSync || !resumableFullSync;
		resetSyncButton.disabled = busy;
		runButton.textContent = busy ? (config.strings.syncingAction || "Syncing...") : runLabel;
		fullSyncButton.textContent = hasFullSyncPreview
			? (busy ? (config.strings.syncingAction || "Syncing...") : (config.strings.startFullSync || "Run Full Sync"))
			: (config.strings.fullSync || "Full Sync");
		pauseSyncButton.textContent = currentJob?.pauseRequested ? (config.strings.pausePending || "Pause requested") : (config.strings.pauseSync || "Pause Sync");
		resumeSyncButton.textContent = config.strings.resumeSync || "Resume Sync";
		resetSyncButton.textContent = config.strings.resetSync || "Cancel";

		if (manualBaselineButton) {
			manualBaselineButton.disabled = busy || !hasSelection;
		}
	};

	const setBusy = (isBusy) => {
		busy = isBusy;
		updateConnectionControls();
		updateRemoteUpdateControls();
		updateActionButtons();
	};

	const applyScopeStatus = (scopeStatus) => {
		if (!scopeStatus || !Array.isArray(scopeStatus.pendingBaselineScopeIds)) {
			return;
		}

		pendingBaselineScopeIds = new Set(scopeStatus.pendingBaselineScopeIds.map(String));
		updateScopeRows();
		updateActionButtons();
	};

	const renderConnectionResult = (payload, isError = false) => {
		if (!connectionPanel || !connectionBadge || !connectionMessage || !connectionMeta) {
			return;
		}

		const remoteVersion = getRemotePluginVersion(payload);
		const localVersion = String(config.localPluginVersion || "");
		const remoteIsOlder = !isError && remoteVersion !== "" && localVersion !== "" && compareVersions(remoteVersion, localVersion) < 0;
		const localSiteVersion = getSiteVersion({ siteVersion: config.localSiteVersion || {} });
		const remoteSiteVersion = getSiteVersion(payload || {});

		connectionPanel.classList.remove("is-hidden");
		connectionBadge.textContent = isError
			? (config.strings.connectionError || "Connection failed")
			: (remoteIsOlder ? `Live Sentinel ${remoteVersion}` : (config.strings.connectionReady || "Connection ready"));
		connectionMessage.textContent = isError
			? payload.message || config.strings.unknownError || "Backup & Restore hit an unexpected Sync error."
			: payload.message || "Destination site is ready for Sync.";

		if (isError) {
			renderMeta(connectionMeta, []);
			return;
		}

		renderMeta(connectionMeta, [
			{ label: config.strings.localSiteVersion || "Local site version", value: formatSiteVersion(localSiteVersion) },
			{ label: config.strings.liveSiteVersion || "Live site version", value: formatSiteVersion(remoteSiteVersion) },
			{ label: config.strings.versionState || "Version state", value: getSiteVersionRelationship(payload || {}), className: "synchy-detail-grid__wide" },
		]);
	};

	const updateRemoteUpdateControls = () => {
		if (!updateRemoteButton || !updateRemoteNote) {
			return;
		}

		const remoteVersion = getRemotePluginVersion(currentConnectionState?.remoteSite || {});
		const localVersion = String(config.localPluginVersion || "");
		const canCompare = remoteVersion !== "" && localVersion !== "";
		const remoteIsOlder = canCompare && compareVersions(remoteVersion, localVersion) < 0;

		updateRemoteButton.classList.toggle("is-hidden", !remoteIsOlder);
		updateRemoteButton.disabled = busy || !remoteIsOlder;
		updateRemoteNote.classList.toggle("is-hidden", !remoteIsOlder && canCompare);
		updateRemoteNote.textContent = remoteIsOlder
			? `${config.strings.updateAvailable || "Destination update available"} ${remoteVersion} -> ${localVersion}`
			: (canCompare
				? (config.strings.destinationUpToDate || "Destination Sentinel is up to date.")
				: (config.strings.updateCheckPending || "Run or wait for the connection check to compare Sentinel versions."));
	};

	const performConnectionTest = async () => {
		try {
			const data = await sendAjax("synchy_test_sync_connection");
			if (data.localSiteVersion) {
				config.localSiteVersion = data.localSiteVersion;
			}
			currentConnectionState = {
				status: "connected",
				message: config.strings.connectionReady || "Connection ready",
				remoteSite: data.remoteSite || {},
			};
			connectionVerified = true;
			renderConnectionResult(data.remoteSite || {}, false);
			updateConnectionControls();
			updateRemoteUpdateControls();
			return { ok: true, remoteSite: data.remoteSite || {} };
		} catch (error) {
			currentConnectionState = {
				status: "error",
				message: error.message,
				remoteSite: {},
			};
			connectionVerified = false;
			renderConnectionResult({ message: error.message }, true);
			updateConnectionControls();
			updateRemoteUpdateControls();
			return { ok: false, message: error.message };
		}
	};

	const updateRemoteSynchy = async (confirmFirst = true) => {
		if (confirmFirst && !window.confirm(config.strings.confirmUpdateRemoteSynchy || "Update Sentinel on the destination site from this local plugin copy now?")) {
			return { ok: false, cancelled: true };
		}

		setBusy(true);
		updateRemoteButton.disabled = true;
		updateRemoteNote.textContent = config.strings.updatingDestination || "Updating destination Sentinel...";
		previewBadge.textContent = config.strings.updatingDestination || "Updating destination Sentinel...";
		previewMessage.textContent = config.strings.updatingDestinationDetail || "Building a plugin package locally and sending it to the destination site.";

		try {
			const data = await sendAjax("synchy_update_remote_synchy");
			const successMessage = data.message || config.strings.destinationUpdated || "Destination Sentinel updated.";

			updateRemoteNote.textContent = successMessage;
			previewBadge.textContent = config.strings.success || "Success";
			previewMessage.textContent = successMessage;

			if (data.remoteSite) {
				currentConnectionState = {
					status: "connected",
					message: successMessage,
					remoteSite: data.remoteSite,
				};
				connectionVerified = true;
				renderConnectionResult(data.remoteSite, false);
				updateConnectionControls();
				updateRemoteUpdateControls();
				refreshRemoteVersionUntilCurrent();
			}

			return { ok: true, remoteSite: data.remoteSite || {}, message: successMessage };
		} catch (error) {
			updateRemoteNote.textContent = error.message;
			previewBadge.textContent = config.strings.error || "Error";
			previewMessage.textContent = error.message;
			renderConnectionResult({ message: error.message }, true);
			updateRemoteUpdateControls();
			return { ok: false, message: error.message };
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	const renderPreviewTree = (preview) => {
		if (!previewTreeContainer) {
			return;
		}

		const activeBatchSource = Array.isArray(currentJob?.batches) && currentJob.batches.length > 0
			? currentJob.batches
			: Array.isArray(preview?.batches) && preview.batches.length > 0
				? preview.batches
				: Array.isArray(latestFullSyncPlan?.batches) ? latestFullSyncPlan.batches : [];

		if (activeBatchSource.length > 0) {
			changedScopeIds = new Set(activeBatchSource.map((batch) => String(batch.scopeId || "")).filter(Boolean));
			updateScopeRows();
			previewTreeContainer.innerHTML = `
				<div class="synchy-sync-tree__section">
					<h4>${escapeHtml(config.strings.batches || "Batches")}</h4>
					${activeBatchSource.map((batch) => {
						const status = String(batch?.status || "pending");
						const marker = status === "complete" ? "[x]" : status === "running" ? "[>]" : status === "failed" ? "[!]" : status === "paused" ? "[|]" : "[ ]";
						const detail = Number(batch?.fileCount || 0) > 0
							? `${Number(batch.fileCount || 0).toLocaleString()} files • ${formatBytes(batch.workUnits || 0)}`
							: `${Number(batch?.dbRows || 0).toLocaleString()} rows`;

						return `
							<div class="synchy-sync-tree__node">
								<div class="synchy-sync-tree__toggle">
									<span>
										<strong>${escapeHtml(`${marker} ${batch?.label || ""}`)}</strong>
										<small>${escapeHtml(detail)}</small>
									</span>
								</div>
								${batch?.error ? `<p class="synchy-sync-tree__sample">${escapeHtml(batch.error)}</p>` : ""}
							</div>
						`;
					}).join("")}
				</div>
			`;
			previewTreeContainer.classList.remove("is-hidden");
			renderPreviewBatchCounter(preview);
			renderFullSyncPendingHeader();
			updateActionButtons();
			return;
		}

		const plannedBatchTotal = Number(currentJob?.totalBatches || preview?.totalBatches || latestFullSyncPlan?.totalBatches || 0);

		if (plannedBatchTotal > 0 || hasFullSyncDisplayContext()) {
			const displayTotal = plannedBatchTotal > 0 ? plannedBatchTotal : Number(String(currentStatus?.message || "").match(/(\d+)\s+batches\s+planned/i)?.[1] || 0);
			previewTreeContainer.innerHTML = `
				<div class="synchy-sync-tree__section">
					<h4>${escapeHtml(config.strings.batches || "Batches")}</h4>
					<div class="synchy-sync-tree__node">
						<div class="synchy-sync-tree__toggle">
							<span>
								<strong>${escapeHtml(displayTotal > 0 ? `${Number(currentJob?.completedBatches || 0).toLocaleString()} / ${displayTotal.toLocaleString()} ${config.strings.batchesComplete || "batches complete"}` : "Full Sync status")}</strong>
								<small>${escapeHtml(currentJob?.message || currentStatus?.message || "Waiting for batch details to refresh.")}</small>
							</span>
						</div>
					</div>
				</div>
			`;
			previewTreeContainer.classList.remove("is-hidden");
			renderPreviewBatchCounter(preview);
			renderFullSyncPendingHeader();
			updateActionButtons();
			return;
		}

		const tree = preview?.previewTree || null;
		const fileGroups = Array.isArray(tree?.fileGroups) ? tree.fileGroups : [];
		const databaseTables = Array.isArray(tree?.databaseTables) ? tree.databaseTables : [];
		const nextChangedScopeIds = new Set();

		fileGroups.forEach((group) => {
			if (group?.id) {
				nextChangedScopeIds.add(String(group.id));
			}
		});

		databaseTables.forEach((table) => {
			if (table?.scopeId) {
				nextChangedScopeIds.add(String(table.scopeId));
			}
		});

		changedScopeIds = nextChangedScopeIds;
		updateScopeRows();

		if (fileGroups.length === 0 && databaseTables.length === 0) {
			previewTreeContainer.innerHTML = "";
			previewTreeContainer.classList.add("is-hidden");
			renderPreviewBatchCounter(preview);
			updateActionButtons();
			return;
		}

		const existingFileSelection = new Set(
			Array.from(form.querySelectorAll('input[name="synchy_sync_selected_file_scopes[]"]:checked')).map((input) => String(input.value || ""))
		);
		const existingTableSelection = new Set(
			Array.from(form.querySelectorAll('input[name="synchy_sync_selected_db_tables[]"]:checked')).map((input) => String(input.value || ""))
		);
		const hasExistingSelection = existingFileSelection.size > 0 || existingTableSelection.size > 0;
		const isChecked = (value, set) => (!hasExistingSelection ? true : set.has(String(value)));
		const selectedScopeIds = getSelectedScopeIdSet();

		const fileGroupHtml = fileGroups
			.map((group) => {
				const files = Array.isArray(group.files) ? group.files : [];
				const buckets = buildFileBuckets(String(group.id || ""), files);

				return `
					<div class="synchy-sync-tree__node">
						<label class="synchy-sync-tree__toggle">
							<input
								type="checkbox"
								name="synchy_sync_selected_file_scopes[]"
								value="${escapeHtml(group.id || "")}"
								data-synchy-preview-selection
								data-scope-id="${escapeHtml(group.id || "")}"
								${isChecked(group.id || "", existingFileSelection) ? "checked" : ""}
								${selectedScopeIds.has(String(group.id || "")) ? "" : "disabled"}
							/>
							<span>
								<strong>${escapeHtml(group.label || "")}</strong>
								<small>${escapeHtml(String(group.count || 0))} files • ${escapeHtml(formatBytes(group.bytes || 0))}</small>
							</span>
						</label>
						<div class="synchy-sync-tree__groups">
							${buckets.map((bucket) => {
								const visibleFiles = bucket.files.slice(0, 100);
								return `
									<details class="synchy-sync-tree__details">
										<summary>${escapeHtml(bucket.label)} <span>${escapeHtml(String(bucket.count))} files • ${escapeHtml(formatBytes(bucket.bytes))}</span></summary>
										<ul class="synchy-sync-tree__list">
											${visibleFiles.map((file) => `<li><span>${escapeHtml(file.path)}</span><small>${escapeHtml(formatBytes(file.size))}</small></li>`).join("")}
											${bucket.files.length > visibleFiles.length ? `<li><span>${escapeHtml(`... and ${bucket.files.length - visibleFiles.length} more files`)}</span></li>` : ""}
										</ul>
									</details>
								`;
							}).join("")}
						</div>
					</div>
				`;
			})
			.join("");

		const dbTableHtml = databaseTables
			.map((table) => {
				const rowIds = Array.isArray(table.rowIds) ? table.rowIds : [];

				return `
					<div class="synchy-sync-tree__node">
						<label class="synchy-sync-tree__toggle">
							<input
								type="checkbox"
								name="synchy_sync_selected_db_tables[]"
								value="${escapeHtml(table.table || "")}"
								data-synchy-preview-selection
								data-scope-id="${escapeHtml(table.scopeId || "")}"
								${isChecked(table.table || "", existingTableSelection) ? "checked" : ""}
								${selectedScopeIds.has(String(table.scopeId || "")) ? "" : "disabled"}
							/>
							<span>
								<strong>${escapeHtml(table.label || "")}</strong>
								<small>${escapeHtml(String(table.rowCount || 0))} rows${table.scopeLabel ? ` • ${escapeHtml(table.scopeLabel)}` : ""}</small>
							</span>
						</label>
						${rowIds.length > 0 ? `<p class="synchy-sync-tree__sample">${escapeHtml(config.strings.sampleRowIds || "Sample row IDs")}: ${escapeHtml(rowIds.join(", "))}</p>` : ""}
					</div>
				`;
			})
			.join("");

		previewTreeContainer.innerHTML = `
			<input type="hidden" name="synchy_sync_preview_selection_present" value="1" data-synchy-preview-selection-marker />
			${fileGroups.length > 0 ? `
				<div class="synchy-sync-tree__section">
					<h4>${escapeHtml(config.strings.files || "Files")}</h4>
					${fileGroupHtml}
				</div>
			` : ""}
			${databaseTables.length > 0 ? `
				<div class="synchy-sync-tree__section">
					<h4>${escapeHtml(config.strings.dbTables || "Database tables")}</h4>
					${dbTableHtml}
				</div>
			` : ""}
		`;
		previewTreeContainer.classList.remove("is-hidden");
		renderPreviewBatchCounter(preview);
		updateActionButtons();
	};

	const renderPreview = (preview) => {
		if (!preview) {
			if (hasFullSyncDisplayContext()) {
				renderPreviewTree(latestFullSyncPlan);
				renderFullSyncPendingHeader();
				updateActionButtons();
				return;
			} else if (getIsRunningFullSync() || getHasResumableFullSync()) {
				previewBadge.textContent = config.strings.fullSync || "Full Sync";
				previewMessage.textContent = currentJob?.message || (config.strings.previewDefault || "Run Preview to load the pending file sections and database tables.");
			} else {
				previewBadge.textContent = "";
				previewMessage.textContent = config.strings.previewDefault || "Run Preview to load the pending file sections and database tables.";
			}
			renderPreviewBatchCounter(null);
			renderPreviewTree(null);
			renderFullSyncPendingHeader();
			return;
		}

		const mode = String(preview.mode || "delta").toLowerCase() === "baseline"
			? (config.strings.baseline || "Baseline")
			: (config.strings.delta || "Delta");
		const filesCount = Number(preview.filesCount || 0);
		const dbRows = Number(preview.dbRows || 0);
		const dryRunSummary = [
			`Source: ${preview.sourcePath || "Unknown"}`,
			`Destination: ${preview.destinationPath || destinationUrlInput?.value?.trim() || "Not set"}`,
			`Files included: ${filesCount.toLocaleString()}`,
			`Files excluded: ${Number(preview.excludedFilesCount || 0).toLocaleString()}`,
			`DB sync: ${preview.dbSyncDisabled ? "disabled" : "enabled"}`,
			`Protected options: ${Number(preview.protectedOptionsCount || 0).toLocaleString()}`,
			`Protected tables: ${Number(preview.protectedTablesCount || 0).toLocaleString()}`,
		];
		previewBadge.textContent = mode;

		if (filesCount === 0 && dbRows === 0) {
			previewMessage.textContent = ["No pending changes detected since the last successful Sync.", ...dryRunSummary].join(" | ");
		} else if (Array.isArray(preview?.batches) && preview.batches.length > 0) {
			previewMessage.textContent = [`Full Sync will run ${Number(preview.totalBatches || 0).toLocaleString()} logical batches for the selected scopes.`, ...dryRunSummary].join(" | ");
		} else {
			previewMessage.textContent = [config.strings.previewSelectionHelp || "Review the pending file sections and database tables, then uncheck anything you do not want to send.", ...dryRunSummary].join(" | ");
		}

		renderPreviewTree(preview);
	};

	const getStatusBadge = (status) => {
		switch (String(status?.status || "")) {
			case "success":
				return config.strings.success || "Success";
			case "paused":
				return config.strings.paused || "Paused";
			case "running":
				return config.strings.syncingAction || "Syncing...";
			case "error":
				return config.strings.error || "Error";
			case "idle":
				return config.strings.noChanges || "No changes";
			default:
				return config.strings.awaitingBaseline || "Awaiting baseline";
		}
	};

	const getStatusMessage = (status) => {
		if (status && status.message) {
			return status.message;
		}

		return "No Sync has completed yet.";
	};

	const buildStatusSummary = (status) => {
		if (["error", "paused", "running"].includes(String(status?.status || ""))) {
			return getStatusMessage(status);
		}

		if (String(status?.status || "") === "idle" && status?.message) {
			return status.message;
		}

		const lastSync = formatDateTime(status?.lastSyncTime || "");
		const destination = status?.destinationUrl || "";
		const files = Number(status?.filesSynced || 0).toLocaleString();
		const dbRows = Number(status?.dbRowsSynced || 0).toLocaleString();
		const mode = String(status?.mode || "").toLowerCase() === "baseline"
			? (config.strings.baseline || "Baseline")
			: String(status?.mode || "") === ""
				? (config.strings.delta || "Delta")
				: (config.strings.delta || "Delta");
		const duration = formatDuration(status?.durationSeconds || 0);

		return `Last Sync: ${lastSync} | ${destination || "Not set"} | ${files} files | ${dbRows} DB rows | ${mode} | ${duration}`;
	};

	const renderStatus = (status) => {
		currentStatus = status || currentStatus;
		if (currentStatus?.siteVersion) {
			config.localSiteVersion = currentStatus.siteVersion;
		}
		statusBadge.textContent = getStatusBadge(status);
		statusSummary.textContent = buildStatusSummary(status);

		if (isTerminalSyncStatus(currentStatus?.status) && currentJob?.status !== "running") {
			clearFullSyncDisplay();
		}
	};

	const clearPreview = () => {
		const keepFullSyncPlan = hasFullSyncDisplayContext();

		latestPreview = null;
		latestPreviewMode = "delta";
		if (!keepFullSyncPlan) {
			latestFullSyncPlan = null;
		}
		changedScopeIds = new Set();
		renderPreview(null);
		updateScopeRows();
		updateActionButtons();
	};

	const collectFormData = (action, extraFields = {}) => {
		const formData = new FormData(form);
		formData.append("action", action);
		formData.append("nonce", config.nonce);

		Object.entries(extraFields).forEach(([key, value]) => {
			formData.append(key, value);
		});

		return formData;
	};

	const sendAjax = async (action, extraFields = {}) => {
		const response = await fetch(config.ajaxUrl, {
			method: "POST",
			body: collectFormData(action, extraFields),
			credentials: "same-origin",
		});

		const raw = await response.text();
		let payload = null;

		try {
			payload = raw ? JSON.parse(raw) : null;
		} catch (error) {
			payload = null;
		}

		if (!response.ok || !payload || payload.success !== true) {
			const message = payload?.data?.message || payload?.message || config.strings.unknownError || "Backup & Restore hit an unexpected Sync error.";
			throw new Error(message);
		}

		return payload.data || {};
	};

	const pollSyncJob = async () => {
		if (!busy && !(currentJob?.runMode === "full" && currentJob?.status === "running")) {
			return;
		}

		try {
			const data = await sendAjax("synchy_get_sync_job_status");
			if (data.status) {
				currentStatus = data.status;
				renderStatus(data.status);
			}
			currentJob = mergeJobResponse(data.job) || buildSyntheticFullSyncJob() || currentJob;
			if (isTerminalSyncStatus(currentStatus?.status) && currentJob?.status !== "running") {
				clearFullSyncDisplay();
			}
			renderProgress(currentJob);
			renderPreviewTree(latestPreview || latestFullSyncPlan);

			if (currentJob && currentJob.status === "running") {
				if (currentJob.runMode === "full") {
					window.setTimeout(driveFullSyncFromBrowser, 50);
				}
				window.setTimeout(pollSyncJob, 250);
				return;
			}

			setBusy(false);
		} catch (error) {
			if (busy) {
				window.setTimeout(pollSyncJob, 500);
			}
		}
	};

	const driveFullSyncFromBrowser = async () => {
		if (browserFullSyncDriverActive || currentJob?.runMode !== "full" || currentJob?.status !== "running") {
			return;
		}

		browserFullSyncDriverActive = true;

		try {
			const data = await sendAjax("synchy_continue_full_sync");
			if (data.status) {
				currentStatus = data.status;
			}
			currentJob = mergeJobResponse(data.job) || buildSyntheticFullSyncJob() || currentJob;
			renderProgress(currentJob);
			renderPreviewTree(latestPreview || latestFullSyncPlan);
			if (currentJob?.runMode === "full" && currentJob?.status === "running") {
				statusBadge.textContent = config.strings.syncingAction || "Syncing...";
				statusSummary.textContent = currentJob.message || "Full Sync is running. Keep this tab open while the batches run.";
			} else {
				renderStatus(data.status || {});
			}
			applyScopeStatus(data.scopeStatus || null);
		} catch (error) {
			previewBadge.textContent = config.strings.error || "Error";
			previewMessage.textContent = error.message;
			if (currentJob?.runMode === "full" && currentJob?.status === "running") {
				statusBadge.textContent = config.strings.syncingAction || "Syncing...";
				statusSummary.textContent = "Full Sync is still running. Retrying status refresh after: " + error.message;
				window.setTimeout(pollSyncJob, 1000);
			} else {
				renderStatus({
					status: "error",
					message: error.message,
					at: new Date().toISOString(),
				});
			}
		} finally {
			browserFullSyncDriverActive = false;

			if (currentJob?.runMode === "full" && currentJob?.status === "running") {
				window.setTimeout(driveFullSyncFromBrowser, 250);
			}
		}
	};

	const requireSelection = () => {
		if (getHasSelection()) {
			return true;
		}

		previewBadge.textContent = config.strings.previewError || "Preview failed";
		previewMessage.textContent = config.strings.selectAtLeastOneScope || "Select at least one file or database scope first.";
		return false;
	};

	const runTestConnection = async () => {
		setBusy(true);

		try {
			const connectionCheck = await performConnectionTest();

			if (connectionCheck.ok) {
				const updateCheck = await updateRemoteSynchy(false);

				if (!updateCheck.ok) {
					return;
				}

				await runPreview("delta");
				return;
			}
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	const runPreview = async (mode = "delta") => {
		if (!requireSelection()) {
			updateActionButtons();
			return;
		}

		setBusy(true);

		try {
			if (!hasConfirmedConnection()) {
				const connectionCheck = await performConnectionTest();

				if (!connectionCheck.ok) {
					previewBadge.textContent = config.strings.previewError || "Preview failed";
					previewMessage.textContent = connectionCheck.message || config.strings.connectionError || "Connection failed";
					clearPreview();
					return;
				}
			}

			const baselinePreview = mode !== "full" && getHasPendingBaselineSelection();
			const effectiveMode = mode === "full" || baselinePreview ? "full" : "delta";
			const data = await sendAjax("synchy_preview_sync_changes", {
				synchy_sync_run_mode: effectiveMode,
			});
			latestPreview = data.preview || null;
			latestPreviewMode = baselinePreview ? "baseline-full" : effectiveMode;
			latestFullSyncPlan = effectiveMode === "full" ? latestPreview : null;
			currentJob = mergeJobResponse(data.job) || currentJob;
			applyScopeStatus(data.scopeStatus || null);
			if (data.remoteSite) {
				currentConnectionState = {
					status: "connected",
					message: config.strings.connectionReady || "Connection ready",
					remoteSite: data.remoteSite,
				};
				connectionVerified = true;
				renderConnectionResult(data.remoteSite || {}, false);
			}
			renderPreview(latestPreview);
			if (effectiveMode === "full" && latestPreview !== null) {
				statusBadge.textContent = config.strings.previewReady || "Preview ready";
				statusSummary.textContent = getHasPreviewChanges()
					? (baselinePreview ? "Baseline preview is ready. Click Start Baseline to begin the batched sync." : "Full Sync preview is ready. Click Run Full Sync to begin.")
					: (baselinePreview ? "Baseline preview found nothing to send for the selected scopes." : "Full Sync preview found nothing to send for the selected scopes.");
			}
		} catch (error) {
			clearPreview();
			previewBadge.textContent = config.strings.previewError || "Preview failed";
			previewMessage.textContent = error.message;
		} finally {
			setBusy(false);
		}
	};

	const resetSyncState = async () => {
		if (!window.confirm(config.strings.confirmResetSync || "Cancel the saved Sync job and clear local Sync baseline state? This does not change the destination site.")) {
			return;
		}

		setBusy(true);
		const resetMessage = config.strings.resetComplete || "Sync state reset. Run Full Sync to start fresh.";

		try {
			const data = await sendAjax("synchy_reset_sync_state");
			currentJob = data.job || null;
			latestPreview = null;
			latestPreviewMode = "delta";
			latestFullSyncPlan = null;
			currentStatus = data.status || { status: "idle", message: data.message || resetMessage };
			changedScopeIds = new Set();
			applyScopeStatus(data.scopeStatus || null);
			renderProgress(null);
			renderPreview(null);
			renderStatus(currentStatus);
			previewBadge.textContent = config.strings.success || "Success";
			previewMessage.textContent = data.message || resetMessage;
		} catch (error) {
			previewBadge.textContent = config.strings.error || "Error";
			previewMessage.textContent = error.message;
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
			});
		} finally {
			setBusy(false);
		}
	};

	const runManualBaseline = async () => {
		if (!requireSelection()) {
			updateActionButtons();
			return;
		}

		const destinationUrl = destinationUrlInput?.value?.trim() || "";
		const scopeLabels = getSelectedScopeLabels();
		const confirmMessage = [
			config.strings.confirmBaseline || "Mark the selected scopes as already baselined after a successful manual full restore to the destination site?",
			"",
			`Destination: ${destinationUrl || "Not set"}`,
			`Scopes: ${scopeLabels.join(", ") || "None"}`,
		].join("\n");

		if (!window.confirm(confirmMessage)) {
			return;
		}

		setBusy(true);
		statusBadge.textContent = config.strings.syncingAction || "Syncing...";
		statusSummary.textContent = "Saving the selected manual baseline state.";

		try {
			const data = await sendAjax("synchy_mark_sync_baseline_complete");
			renderStatus(data.status || {});
			applyScopeStatus(data.scopeStatus || null);
			clearPreview();
		} catch (error) {
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
				lastSyncTime: "",
				filesSynced: 0,
				dbRowsSynced: 0,
				durationSeconds: 0,
				destinationUrl: destinationUrl || "",
				mode: "",
			});
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	const runSync = async () => {
		if (latestPreview === null) {
			return;
		}

		const destinationUrl = destinationUrlInput?.value?.trim() || "";
		const scopeLabels = getSelectedScopeLabels();
		const selectedFileSections = form.querySelectorAll('input[name="synchy_sync_selected_file_scopes[]"]:checked').length;
		const selectedDbTables = form.querySelectorAll('input[name="synchy_sync_selected_db_tables[]"]:checked').length;
		const isFullSync = latestPreviewMode === "full" || getIsBatchedBaselinePreview() || Boolean(latestPreview?.forceFull);
		const dbSyncEnabled = latestPreview?.dbSyncDisabled === false;
		const confirmMessage = [
			isFullSync
				? (config.strings.confirmFullSync || "Run a full Sync for the selected scopes and send all tracked files and rows to the destination site now?")
				: (config.strings.confirmSync || "Sync the previewed changes to the destination site now?"),
			"",
			`Destination: ${destinationUrl || "Not set"}`,
			`Scopes: ${scopeLabels.join(", ") || "None"}`,
			`Files included: ${Number(latestPreview?.filesCount || 0).toLocaleString()}`,
			`Files excluded: ${Number(latestPreview?.excludedFilesCount || 0).toLocaleString()}`,
			`DB sync: ${dbSyncEnabled ? "enabled" : "disabled"}`,
			`Protected AJ Core options: ${Number(latestPreview?.protectedOptionsCount || 0).toLocaleString()}`,
			`Protected AJ Core tables: ${Number(latestPreview?.protectedTablesCount || 0).toLocaleString()}`,
			dbSyncEnabled ? "Database Sync requires this explicit confirmation. Protected AJ Core options and runtime tables will still be excluded." : "",
			isFullSync
				? `Planned batches: ${Number(latestPreview?.totalBatches || 0).toLocaleString()}`
				: `Selected preview items: ${selectedFileSections} file sections, ${selectedDbTables} DB tables`,
		].filter(Boolean).join("\n");

		if (!window.confirm(confirmMessage)) {
			return;
		}

		setBusy(true);
		currentJob = {
			status: "running",
			runMode: isFullSync ? "full" : "delta",
			phase: "building_package",
			phaseLabel: config.strings.syncRunning || "Sync running",
			progress: 5,
			message: "Starting Sync...",
			filesCount: Number(latestPreview?.filesCount || 0),
			dbRows: Number(latestPreview?.dbRows || 0),
			totalBatches: Number(latestPreview?.totalBatches || 0),
			completedBatches: 0,
			currentBatchLabel: "",
			batches: Array.isArray(latestPreview?.batches) ? latestPreview.batches : [],
			stages: Array.isArray(config.defaultStages) ? config.defaultStages : [],
		};
		renderProgress(currentJob);
		renderPreviewTree(latestPreview);
		window.setTimeout(pollSyncJob, 100);
		statusBadge.textContent = config.strings.syncingAction || "Syncing...";
		statusSummary.textContent = isFullSync
			? "Full Sync is starting. Keep this tab open while the batches run."
			: "Sync is running. Keep this tab open until it finishes.";

		try {
			const data = await sendAjax("synchy_run_sync_changes", {
				synchy_sync_run_mode: isFullSync ? "full" : "delta",
				synchy_sync_confirm_db: dbSyncEnabled ? "1" : "",
			});
			if (data.status) {
				currentStatus = data.status;
			}
			currentJob = mergeJobResponse(data.job) || (isFullSync ? currentJob : null);
			renderProgress(currentJob);
			renderPreviewTree(latestPreview || latestFullSyncPlan);
			if (!isFullSync || String(currentJob?.status || "") !== "running") {
				renderStatus(data.status || {});
			}
			applyScopeStatus(data.scopeStatus || null);
			if (currentJob?.runMode === "full" && currentJob?.status === "running") {
				setBusy(true);
				statusBadge.textContent = config.strings.syncingAction || "Syncing...";
				statusSummary.textContent = "Full Sync is running. Keep this tab open while the batches run.";
				renderProgress(currentJob);
				window.setTimeout(driveFullSyncFromBrowser, 50);
				return;
			}
			if (!getHasResumableFullSync()) {
				clearPreview();
			}
		} catch (error) {
			if (!getHasResumableFullSync()) {
				currentJob = null;
				browserFullSyncDriverActive = false;
				renderProgress(null);
				renderPreviewTree(latestPreview || latestFullSyncPlan);
			}
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
				lastSyncTime: "",
				filesSynced: 0,
				dbRowsSynced: 0,
				durationSeconds: 0,
				destinationUrl: destinationUrl || "",
				mode: "",
			});
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
			} else {
				setBusy(false);
			}
		}
	};

	const pauseFullSync = async () => {
		try {
			const data = await sendAjax("synchy_pause_full_sync");
			if (data.status) {
				currentStatus = data.status;
			}
			currentJob = mergeJobResponse(data.job) || null;
			renderProgress(currentJob);
			renderPreviewTree(latestPreview || latestFullSyncPlan);
			updateActionButtons();
		} catch (error) {
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
			});
		}
	};

	const resumeFullSync = async () => {
		if (!window.confirm(config.strings.confirmResumeSync || "Resume the remaining full Sync batches now?")) {
			return;
		}

		setBusy(true);
		currentJob = {
			...(currentJob || {}),
			status: "running",
			runMode: "full",
			pauseRequested: false,
			phase: "sending_package",
			phaseLabel: config.strings.syncRunning || "Sync running",
			message: "Resuming Sync...",
		};
		renderProgress(currentJob);
		renderPreviewTree(latestPreview);
		renderFullSyncPendingHeader();
		window.setTimeout(pollSyncJob, 100);

		try {
			const data = await sendAjax("synchy_resume_full_sync");
			if (data.status) {
				currentStatus = data.status;
			}
			currentJob = mergeJobResponse(data.job) || currentJob;
			renderProgress(currentJob);
			renderPreviewTree(latestPreview || latestFullSyncPlan);
			renderFullSyncPendingHeader();
			if (currentJob?.runMode !== "full" || currentJob?.status !== "running") {
				renderStatus(data.status || {});
			} else {
				statusBadge.textContent = config.strings.syncingAction || "Syncing...";
				statusSummary.textContent = currentJob.message || "Full Sync is running. Keep this tab open while the batches run.";
			}
			applyScopeStatus(data.scopeStatus || null);
			if (currentJob?.runMode === "full" && currentJob?.status === "running") {
				window.setTimeout(driveFullSyncFromBrowser, 50);
			}
		} catch (error) {
			renderStatus({
				status: "error",
				message: error.message,
				at: new Date().toISOString(),
			});
		} finally {
			if (currentJob?.status === "running") {
				setBusy(true);
				window.setTimeout(pollSyncJob, 100);
			} else {
				setBusy(false);
			}
		}
	};

	form.addEventListener("input", (event) => {
		if (event.target?.matches("[data-synchy-preview-selection]")) {
			updateActionButtons();
			return;
		}

		if (
			event.target === destinationUrlInput
			|| event.target === usernameInput
			|| event.target === passwordInput
		) {
			connectionVerified = false;
		}

		updateTargetNote();
		updateConnectionControls();
		updateActionButtons();
	});
	form.addEventListener("change", (event) => {
		if (event.target?.matches("[data-synchy-preview-selection]")) {
			updateActionButtons();
			return;
		}

		if (
			event.target === destinationUrlInput
			|| event.target === usernameInput
			|| event.target === passwordInput
			|| event.target === verifySslInput
		) {
			connectionVerified = false;
		}

		updateTargetNote();
		updateConnectionControls();
		updateActionButtons();
	});
	testButton.addEventListener("click", runTestConnection);
	if (updateRemoteButton) {
		updateRemoteButton.addEventListener("click", updateRemoteSynchy);
	}
	previewButton.addEventListener("click", () => runPreview("delta"));
	fullSyncButton.addEventListener("click", () => {
		if (latestPreview !== null && (latestPreviewMode === "full" || Boolean(latestPreview?.forceFull))) {
			runSync();
			return;
		}

		runPreview("full");
	});
	runButton.addEventListener("click", runSync);
	pauseSyncButton.addEventListener("click", pauseFullSync);
	resumeSyncButton.addEventListener("click", resumeFullSync);
	resetSyncButton.addEventListener("click", resetSyncState);
	manualBaselineButton.addEventListener("click", runManualBaseline);

	updateTargetNote();
	updateScopeRows();
	currentJob = mergeJobResponse(currentJob) || buildSyntheticFullSyncJob() || currentJob;
	if (currentStatus) {
		renderStatus(currentStatus);
	}
	renderProgress(currentJob);
	renderPreviewTree(latestPreview || latestFullSyncPlan);
	renderFullSyncPendingHeader();
	updateRemoteUpdateControls();
	if (currentConnectionState?.status === "connected") {
		renderConnectionResult(currentConnectionState.remoteSite || {}, false);
	} else if (currentConnectionState?.status === "error") {
		renderConnectionResult({ message: currentConnectionState.message || (config.strings.connectionError || "Connection failed") }, true);
	}

	if (
		!autoConnectionCheckStarted
		&& destinationUrlInput.value.trim() !== ""
		&& usernameInput.value.trim() !== ""
		&& passwordInput.dataset.hasSavedPassword === "1"
	) {
		autoConnectionCheckStarted = true;
		window.setTimeout(runTestConnection, 50);
	}

	if (currentJob && currentJob.status === "running") {
		setBusy(true);
		window.setTimeout(pollSyncJob, 100);
		if (currentJob.runMode === "full") {
			window.setTimeout(driveFullSyncFromBrowser, 150);
		}
		return;
	}

	if (!currentJob?.status && String(currentStatus?.status || "") === "running") {
		setBusy(true);
		window.setTimeout(pollSyncJob, 1000);
		return;
	}

	if (getHasResumableFullSync()) {
		renderStatus({
			status: "paused",
			message: currentJob.message || "Full Sync stopped before all batches completed. Resume Sync to continue.",
			at: currentJob.updatedAt || currentJob.createdAt || new Date().toISOString(),
		});
	}

	updateConnectionControls();
	updateActionButtons();
})();
