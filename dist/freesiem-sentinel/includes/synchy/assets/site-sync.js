(function () {
	const config = window.synchySiteSyncConfig;

	if (!config) {
		return;
	}

	const form = document.querySelector("[data-synchy-site-sync-form]");
	const saveButton = document.querySelector("[data-synchy-save-site-sync]");
	const testButton = document.querySelector("[data-synchy-test-site-sync]");
	const pushButton = document.querySelector("[data-synchy-run-site-sync]");
	const progress = document.querySelector("[data-synchy-site-sync-progress]");
	const progressBar = document.querySelector("[data-synchy-site-sync-bar]");
	const progressPhase = document.querySelector("[data-synchy-site-sync-phase]");
	const progressPercent = document.querySelector("[data-synchy-site-sync-percent]");
	const progressMessage = document.querySelector("[data-synchy-site-sync-message]");
	const progressDetail = document.querySelector("[data-synchy-site-sync-detail]");
	const progressTiming = document.querySelector("[data-synchy-site-sync-timing]");
	const progressWarning = document.querySelector("[data-synchy-site-sync-warning]");
	const stages = document.querySelector("[data-synchy-site-sync-stages]");
	const resultPanel = document.querySelector("[data-synchy-site-sync-result]");
	const resultBadge = document.querySelector("[data-synchy-site-sync-result-badge]");
	const resultMessage = document.querySelector("[data-synchy-site-sync-result-message]");
	const resultMeta = document.querySelector("[data-synchy-site-sync-result-meta]");
	const pushActionLabel = config.strings?.pushAction || "Upload to Live";

	if (!form || !testButton || !pushButton) {
		return;
	}

	let currentJob = config.currentJob || null;
	let pushInProgress = false;
	let uploadEstimate = {
		key: "",
		lastBytes: 0,
		lastTimestamp: 0,
		bytesPerSecond: 0,
	};

	const escapeHtml = (value) =>
		String(value)
			.replace(/&/g, "&amp;")
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;")
			.replace(/"/g, "&quot;")
			.replace(/'/g, "&#039;");

	const setBusyState = (isBusy) => {
		pushInProgress = isBusy;

		if (saveButton) {
			saveButton.disabled = isBusy;
		}

		testButton.disabled = isBusy;
		pushButton.disabled = isBusy;
		pushButton.textContent = isBusy ? "Pushing..." : pushActionLabel;
	};

	const handleBeforeUnload = (event) => {
		if (!pushInProgress) {
			return undefined;
		}

		event.preventDefault();
		event.returnValue = "";

		return "";
	};

	window.addEventListener("beforeunload", handleBeforeUnload);

	const formatDuration = (seconds) => {
		if (!Number.isFinite(seconds) || seconds <= 0) {
			return "";
		}

		const rounded = Math.max(1, Math.round(seconds));
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

	const updateUploadEstimate = (job) => {
		if (job.phase !== "uploading_archive" && job.phase !== "uploading_installer") {
			uploadEstimate = {
				key: "",
				lastBytes: 0,
				lastTimestamp: 0,
				bytesPerSecond: 0,
			};
			return "";
		}

		const artifactBytesUploaded = Number(job.artifactBytesUploaded || 0);
		const artifactBytesTotal = Number(job.artifactBytesTotal || 0);
		const estimateKey = `${job.phase}:${job.currentArtifact || ""}:${artifactBytesTotal}`;
		const now = Date.now();

		if (
			uploadEstimate.key !== estimateKey ||
			artifactBytesUploaded < uploadEstimate.lastBytes
		) {
			uploadEstimate = {
				key: estimateKey,
				lastBytes: artifactBytesUploaded,
				lastTimestamp: now,
				bytesPerSecond: 0,
			};
			return "";
		}

		const elapsedSeconds = uploadEstimate.lastTimestamp > 0
			? (now - uploadEstimate.lastTimestamp) / 1000
			: 0;
		const deltaBytes = artifactBytesUploaded - uploadEstimate.lastBytes;

		if (deltaBytes > 0 && elapsedSeconds > 0.25) {
			const instantRate = deltaBytes / elapsedSeconds;
			uploadEstimate.bytesPerSecond = uploadEstimate.bytesPerSecond > 0
				? (uploadEstimate.bytesPerSecond * 0.7) + (instantRate * 0.3)
				: instantRate;
			uploadEstimate.lastBytes = artifactBytesUploaded;
			uploadEstimate.lastTimestamp = now;
		}

		if (uploadEstimate.bytesPerSecond <= 0 || artifactBytesUploaded <= 0 || artifactBytesUploaded >= artifactBytesTotal) {
			return "";
		}

		return formatDuration((artifactBytesTotal - artifactBytesUploaded) / uploadEstimate.bytesPerSecond);
	};

	const getElapsedSeconds = (job) => {
		const createdAt = job && job.createdAt ? Date.parse(job.createdAt) : NaN;

		if (!Number.isFinite(createdAt)) {
			return 0;
		}

		return Math.max(0, Math.floor((Date.now() - createdAt) / 1000));
	};

	const setProgressTiming = (job, timeRemaining = "") => {
		if (!progressTiming) {
			return;
		}

		const elapsedSeconds = getElapsedSeconds(job);
		const elapsedText = elapsedSeconds > 0
			? `${config.strings.timeSpent} ${formatDuration(elapsedSeconds)}`
			: "";

		if (job.status === "complete") {
			progressTiming.textContent = elapsedText === ""
				? ""
				: `${config.strings.completedIn} ${formatDuration(elapsedSeconds)}`;
			return;
		}

		if (elapsedText !== "" && timeRemaining !== "") {
			progressTiming.textContent = `${elapsedText} • ${config.strings.timeRemaining} ${timeRemaining}`;
			return;
		}

		progressTiming.textContent = elapsedText;
	};

	const setProgressWarning = (job) => {
		if (!progressWarning) {
			return;
		}

		progressWarning.style.display = job.status === "running" ? "" : "none";
	};

	const getPollDelay = (job) => {
		if (!job || job.status !== "running") {
			return 0;
		}

		if (job.phase === "uploading_archive" || job.phase === "uploading_installer") {
			return 25;
		}

		if (job.phase === "finalizing_remote_package") {
			return 50;
		}

		return 150;
	};

	const setProgressDetail = (job) => {
		if (!progressDetail) {
			return;
		}

		const artifactUploaded = Number(job.artifactBytesUploaded || 0);
		const artifactTotal = Number(job.artifactBytesTotal || 0);

		if (
			(job.phase === "uploading_archive" || job.phase === "uploading_installer") &&
			artifactTotal > 0
		) {
			const artifactLabel = job.currentArtifact === "installer" ? "installer.php" : "archive";
			const uploaded = artifactUploaded.toLocaleString();
			const total = artifactTotal.toLocaleString();
			const artifactPercent = Number(job.artifactProgress || 0);
			const timeRemaining = updateUploadEstimate(job);
			progressDetail.textContent = `${artifactLabel} ${artifactPercent}% • ${config.strings.uploaded} ${uploaded} / ${total}`;
			setProgressTiming(job, timeRemaining);
			return;
		}

		updateUploadEstimate(job);

		const uploaded = Number(job.bytesUploaded || 0).toLocaleString();
		const total = Number(job.bytesTotal || 0).toLocaleString();
		progressDetail.textContent = `${config.strings.uploaded} ${uploaded} / ${total}`;
		setProgressTiming(job, "");
	};

	const renderStages = (job) => {
		if (!stages) {
			return;
		}

		const items = Array.isArray(job && job.stages) ? job.stages : Array.isArray(config.defaultStages) ? config.defaultStages : [];

		stages.innerHTML = items
			.map(
				(stage) => `
					<div class="synchy-export-stage is-${escapeHtml(stage.state || "pending")}">
						<span class="synchy-export-stage__indicator" aria-hidden="true"></span>
						<div class="synchy-export-stage__content">
							<strong>${escapeHtml(stage.label || "")}</strong>
							<span>${escapeHtml(stage.description || "")}</span>
						</div>
					</div>
				`
			)
			.join("");
	};

	const renderProgress = (job) => {
		if (!progress || !job) {
			return;
		}

		progress.classList.remove("is-hidden");

		if (progressBar) {
			progressBar.style.width = `${job.progress || 0}%`;
		}

		if (progressPhase) {
			progressPhase.textContent = job.phaseLabel || "Preparing";
		}

		if (progressPercent) {
			progressPercent.textContent = job.progressLabel || `${job.progress || 0}%`;
		}

		if (progressMessage) {
			progressMessage.textContent = job.message || "";
		}

		renderStages(job);
		setProgressDetail(job);
		setProgressWarning(job);
	};

	const renderConnectionResult = (payload, isError = false) => {
		if (!resultPanel || !resultBadge || !resultMessage || !resultMeta) {
			return;
		}

		resultPanel.classList.remove("is-hidden");
		resultBadge.textContent = isError ? config.strings.connectionError : config.strings.connectionReady;
		resultMessage.textContent = payload.message || (isError ? config.strings.unknownError : "");

		if (isError) {
			resultMeta.innerHTML = "";
			return;
		}

		const fields = [
			["Site", payload.name || payload.remoteSiteName || "Unknown"],
			["URL", payload.siteUrl || payload.remoteSiteUrl || ""],
			["Synchy", payload.pluginVersion || ""],
			["WordPress", payload.wordpressVersion || ""],
			["User", payload.authenticatedAs || ""],
			["Deploy", payload.deployStatus || ""],
			["Installer URL", payload.installerUrl || ""],
			["Installer Path", payload.installerPath || ""],
			["Archive Path", payload.archivePath || ""],
			["Root Path", payload.rootPath || ""],
			["Staged Path", payload.stagedPath || ""],
		].filter(([, value]) => value);

		resultMeta.innerHTML = fields
			.map(
				([label, value]) =>
					`<div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div>`
			)
			.join("");
	};

	const request = async (payload) => {
		const body = new FormData();

		Object.entries(payload).forEach(([key, value]) => {
			if (value !== undefined && value !== null) {
				body.append(key, value);
			}
		});

		const response = await fetch(config.ajaxUrl, {
			method: "POST",
			credentials: "same-origin",
			body,
		});

		const json = await response.json();

		if (!response.ok || !json.success) {
			const message = json && json.data && json.data.message ? json.data.message : config.strings.unknownError;
			throw new Error(message);
		}

		return json.data;
	};

	const serializeSyncOptions = () => {
		const formData = new FormData(form);
		const payload = {};

		formData.forEach((value, key) => {
			payload[key] = value;
		});

		payload.nonce = config.nonce;

		return payload;
	};

	const pollJob = async (jobId) => {
		try {
			const data = await request({
				action: "synchy_continue_site_sync_push",
				nonce: config.nonce,
				job_id: jobId,
			});
			currentJob = data.job;
			renderProgress(currentJob);

			if (currentJob.status === "running") {
				window.setTimeout(() => pollJob(jobId), getPollDelay(currentJob));
				return;
			}

			setBusyState(false);

			if (currentJob.status === "complete") {
				renderConnectionResult(
					{
						message: currentJob.message,
						remoteSiteName: currentJob.remoteSiteName,
						remoteSiteUrl: currentJob.remoteSiteUrl,
						deployStatus: currentJob.deployStatus,
						installerUrl: currentJob.installerUrl,
						installerPath: currentJob.installerPath,
						archivePath: currentJob.archivePath,
						rootPath: currentJob.rootPath,
						stagedPath: currentJob.stagedPath,
					},
					false
				);
				return;
			}

			renderConnectionResult({ message: currentJob.message }, true);
		} catch (error) {
			setBusyState(false);
			if (progressMessage) {
				progressMessage.textContent = error.message;
			}
			renderConnectionResult({ message: error.message }, true);
		}
	};

	testButton.addEventListener("click", async () => {
		try {
			testButton.disabled = true;
			renderConnectionResult({ message: "Testing the destination Synchy receiver..." }, false);
			const data = await request({
				...serializeSyncOptions(),
				action: "synchy_test_site_sync_connection",
			});
			const remoteSite = data.remoteSite || {};
			renderConnectionResult(
				{
					...remoteSite,
					message: `Connected to ${remoteSite.siteUrl || "the destination site"} as ${remoteSite.authenticatedAs || "the selected user"}.`,
				},
				false
			);
		} catch (error) {
			renderConnectionResult({ message: error.message }, true);
		} finally {
			testButton.disabled = false;
		}
	});

	pushButton.addEventListener("click", async () => {
		try {
			setBusyState(true);
			renderProgress({
				phaseLabel: "Preparing",
				progress: 1,
				message: "Starting live upload...",
				bytesUploaded: 0,
				bytesTotal: 0,
				createdAt: new Date().toISOString(),
				status: "running",
			});

			const data = await request({
				...serializeSyncOptions(),
				action: "synchy_start_site_sync_push",
			});
			currentJob = data.job;
			renderProgress(currentJob);
			pollJob(currentJob.id);
		} catch (error) {
			setBusyState(false);
			renderProgress({
				phaseLabel: "Error",
				progress: 100,
				message: error.message,
				bytesUploaded: 0,
				bytesTotal: 0,
				status: "error",
			});
			renderConnectionResult({ message: error.message }, true);
		}
	});

	if (currentJob && currentJob.status === "running" && currentJob.id) {
		setBusyState(true);
		renderProgress(currentJob);
		pollJob(currentJob.id);
	} else {
		renderStages(currentJob);
	}
})();
