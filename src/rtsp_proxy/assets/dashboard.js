(() => {
  "use strict";

  const boundedInterval = (raw) => {
    const value = Number.parseInt(raw || "", 10);
    return Number.isInteger(value) && value >= 5000 && value <= 30000 ? value : 10000;
  };

  const bitrate = (value) => {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      return "—";
    }
    if (value >= 1000000) {
      return `${(value / 1000000).toFixed(2)} Мбит/с`;
    }
    if (value >= 1000) {
      return `${(value / 1000).toFixed(1)} Кбит/с`;
    }
    return `${value.toFixed(0)} бит/с`;
  };

  const setText = (root, selector, value) => {
    const element = root.querySelector(selector);
    if (element instanceof HTMLElement) {
      element.textContent = String(value);
    }
  };

  const fetchSnapshot = async (url) => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(url, {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (response.status === 401 || response.status === 403) {
        window.location.reload();
        return null;
      }
      if (!response.ok) {
        throw new Error("snapshot_unavailable");
      }
      return await response.json();
    } finally {
      window.clearTimeout(timeout);
    }
  };

  const overview = document.querySelector("[data-dashboard-poll-ms]");
  if (overview instanceof HTMLElement) {
    const interval = boundedInterval(overview.dataset.dashboardPollMs);
    const url = overview.dataset.dashboardSnapshotUrl;
    if (url && overview.dataset.dashboardGeneratedAt) {
      let overviewFailures = 0;
      let overviewTimer = null;
      const refreshOverview = async () => {
        try {
          const snapshot = await fetchSnapshot(url);
          if (!snapshot || !Array.isArray(snapshot.nodes)) {
            return;
          }
          const rows = Array.from(overview.querySelectorAll("[data-node-id]"));
          const currentIds = rows.map((row) => row.getAttribute("data-node-id"));
          const nextIds = snapshot.nodes.map((node) => node.node_id);
          if (currentIds.join(",") !== nextIds.join(",")) {
            window.location.reload();
            return;
          }
          setText(overview, "[data-summary-nodes]", `${snapshot.configured_nodes} / ${snapshot.max_nodes}`);
          const capacity = snapshot.nodes.reduce(
            (total, node) => total + (Number.isInteger(node.camera_capacity) ? node.camera_capacity : 0),
            0,
          );
          setText(overview, "[data-summary-cameras]", `${snapshot.registered_cameras} / ${capacity}`);
          setText(overview, "[data-summary-ports]", snapshot.external_ports_used);
          setText(overview, "[data-summary-ports-free]", `свободно ${snapshot.external_ports_free}`);
          setText(overview, "[data-dashboard-node-count]", snapshot.configured_nodes);
          const updated = overview.querySelector("[data-dashboard-updated]");
          if (updated instanceof HTMLTimeElement && typeof snapshot.generated_at === "string") {
            const timestamp = new Date(snapshot.generated_at);
            updated.dateTime = snapshot.generated_at;
            if (!Number.isNaN(timestamp.valueOf())) {
              updated.textContent = timestamp.toLocaleString("ru-RU", { timeZone: "UTC" }) + " UTC";
            }
          }
          snapshot.nodes.forEach((node, index) => {
            const row = rows[index];
            if (!(row instanceof HTMLElement)) {
              return;
            }
            const health = row.querySelector("[data-node-health]");
            if (health instanceof HTMLElement && typeof node.health === "string") {
              health.textContent = node.health;
              health.className = /^[a-z_]+$/.test(node.health)
                ? `status status-${node.health}`
                : "status status-unknown";
            }
            setText(row, "[data-node-runtime]", `${node.runtime_state} · ${node.scrape_status}`);
            setText(row, "[data-node-cameras]", `${node.registered_cameras} / ${node.camera_capacity}`);
            const metricsFresh =
              node.metrics && (node.scrape_status === "fresh" || node.scrape_status === "idle");
            setText(
              row,
              "[data-node-metric-state]",
              node.scrape_status === "stale"
                ? "Метрики устарели"
                : metricsFresh
                  ? "Метрики"
                  : "Метрики недоступны",
            );
            setText(row, "[data-node-sources]", metricsFresh ? node.metrics.active_sources : "—");
            setText(row, "[data-node-occupied]", metricsFresh ? node.metrics.occupied_streams : "—");
            setText(row, "[data-node-received]", metricsFresh ? bitrate(node.received_bitrate_bps) : "—");
            setText(row, "[data-node-sent]", metricsFresh ? bitrate(node.sent_bitrate_bps) : "—");
            const observed = row.querySelector("[data-node-metric-observed]");
            if (observed instanceof HTMLTimeElement) {
              if (typeof node.metric_observed_at === "string") {
                const timestamp = new Date(node.metric_observed_at);
                observed.dateTime = node.metric_observed_at;
                observed.textContent = Number.isNaN(timestamp.valueOf())
                  ? "—"
                  : timestamp.toLocaleString("ru-RU", { timeZone: "UTC" }) + " UTC";
              } else {
                observed.removeAttribute("datetime");
                observed.textContent = "—";
              }
            }
            setText(
              row,
              "[data-node-counter-state]",
              node.counters_reset === true
                ? "Счётчики перезапущены"
                : metricsFresh
                  ? "Счётчики непрерывны"
                  : "Состояние счётчиков неизвестно",
            );
          });
          overview.dataset.dashboardGeneratedAt = snapshot.generated_at;
          overviewFailures = 0;
        } catch (_error) {
          // The server-rendered snapshot remains visible as the degraded fallback.
          overviewFailures += 1;
        } finally {
          const delay = Math.min(30000, interval * (2 ** Math.min(overviewFailures, 2)));
          overviewTimer = window.setTimeout(() => void refreshOverview(), delay);
        }
      };
      overviewTimer = window.setTimeout(() => void refreshOverview(), interval);
      window.addEventListener("pagehide", () => {
        if (overviewTimer !== null) {
          window.clearTimeout(overviewTimer);
        }
      });
    }
  }

  const live = document.querySelector("[data-camera-live]");
  if (!(live instanceof HTMLElement)) {
    return;
  }

  const connection = live.querySelector("[data-live-connection]");
  const sourceState = live.querySelector("[data-live-source]");
  const occupied = live.querySelector("[data-live-occupied]");
  const received = live.querySelector("[data-live-received]");
  const sent = live.querySelector("[data-live-sent]");
  const observed = live.querySelector("[data-live-observed]");
  const probeResult = live.querySelector("[data-live-probe-result]");
  const probeDetail = live.querySelector("[data-live-probe-detail]");
  const probeCompleted = live.querySelector("[data-live-probe-completed]");
  const note = live.querySelector("[data-live-note]");
  const streamUrl = live.dataset.liveUrl;
  const snapshotUrl = live.dataset.snapshotUrl;
  const pollInterval = boundedInterval(live.dataset.pollIntervalMs);
  let eventSource = null;
  let fallbackTimer = null;
  let fallbackFailures = 0;
  let streamFailures = 0;

  const setConnection = (label, state) => {
    if (!(connection instanceof HTMLElement)) {
      return;
    }
    connection.textContent = label;
    connection.className = `status status-${state}`;
  };

  const applyState = (state) => {
    if (!state || typeof state !== "object") {
      return;
    }
    if (sourceState instanceof HTMLElement) {
      const labels = {
        ready: "готов",
        idle: "ожидает клиента",
        stale: "данные устарели",
        unavailable: "недоступен",
        unknown: "нет per-path state",
      };
      sourceState.textContent = labels[state.source_state] || "—";
    }
    if (occupied instanceof HTMLElement) {
      occupied.textContent = state.occupied === true ? "занят" : state.occupied === false ? "свободен" : "—";
    }
    if (received instanceof HTMLElement) {
      received.textContent = bitrate(state.received_bitrate_bps);
    }
    if (sent instanceof HTMLElement) {
      sent.textContent = bitrate(state.sent_bitrate_bps);
    }
    if (observed instanceof HTMLTimeElement) {
      if (typeof state.observed_at === "string") {
        const timestamp = new Date(state.observed_at);
        observed.dateTime = state.observed_at;
        observed.textContent = Number.isNaN(timestamp.valueOf())
          ? "—"
          : timestamp.toLocaleString("ru-RU");
      } else {
        observed.removeAttribute("datetime");
        observed.textContent = "—";
      }
    }
    if (note instanceof HTMLElement) {
      note.textContent = state.counters_reset === true
        ? "Счётчики медианоды были сброшены; bitrate появится после следующего непрерывного интервала."
        : state.metric_gap === true
          ? "Между измерениями обнаружен разрыв; bitrate временно не рассчитывается."
          : "Данные поступают из агрегированного снимка collector; браузер не обращается к API медианоды.";
    }
  };

  const applyProbe = (probe) => {
    if (!probe || typeof probe !== "object") {
      return;
    }
    if (probeResult instanceof HTMLElement) {
      const failureLabels = {
        authentication: "ошибка авторизации",
        codec: "неподдерживаемый codec",
        connect_timeout: "таймаут подключения",
        executor: "ошибка исполнителя",
        output: "некорректный ответ",
        transport: "ошибка транспорта",
      };
      const failure = failureLabels[probe.failure_class] || "ошибка";
      probeResult.textContent = probe.outcome === "healthy"
        ? "успешно"
        : probe.outcome === "inconclusive"
          ? `проверка не выполнена: ${failure}`
          : failure;
    }
    if (probeDetail instanceof HTMLElement) {
      const method = probe.method === "source" ? "источник" : probe.method === "path" ? "путь ноды" : "—";
      const codecs = [probe.video_codec, probe.audio_codec]
        .filter((codec) => typeof codec === "string")
        .join(" + ");
      const duration = Number.isInteger(probe.duration_ms) && probe.duration_ms >= 0
        ? `${(probe.duration_ms / 1000).toLocaleString("ru-RU")} с`
        : "—";
      probeDetail.textContent = `${method} / ${codecs || "—"} / ${duration}`;
    }
    if (probeCompleted instanceof HTMLTimeElement) {
      if (typeof probe.completed_at === "string") {
        const timestamp = new Date(probe.completed_at);
        probeCompleted.dateTime = probe.completed_at;
        probeCompleted.textContent = Number.isNaN(timestamp.valueOf())
          ? "—"
          : timestamp.toLocaleString("ru-RU");
      } else {
        probeCompleted.removeAttribute("datetime");
        probeCompleted.textContent = "—";
      }
    }
  };

  const clearProbe = () => {
    if (probeResult instanceof HTMLElement) {
      probeResult.textContent = "—";
    }
    if (probeDetail instanceof HTMLElement) {
      probeDetail.textContent = "—";
    }
    if (probeCompleted instanceof HTMLTimeElement) {
      probeCompleted.removeAttribute("datetime");
      probeCompleted.textContent = "—";
    }
  };

  const pollOnce = async () => {
    if (!snapshotUrl) {
      return;
    }
    try {
      const snapshot = await fetchSnapshot(snapshotUrl);
      if (snapshot) {
        applyState(snapshot);
        setConnection("Polling", "unknown");
        fallbackFailures = 0;
      }
    } catch (_error) {
      fallbackFailures += 1;
      setConnection("Нет данных", "failed");
    } finally {
      if (fallbackTimer !== null) {
        const delay = Math.min(30000, pollInterval * (2 ** Math.min(fallbackFailures, 2)));
        fallbackTimer = window.setTimeout(() => void pollOnce(), delay);
      }
    }
  };

  const startFallback = () => {
    if (fallbackTimer !== null) {
      return;
    }
    if (note instanceof HTMLElement) {
      note.textContent = "SSE недоступен; включён ограниченный polling агрегированного снимка.";
    }
    fallbackTimer = window.setTimeout(() => void pollOnce(), 0);
  };

  if (!streamUrl || !snapshotUrl || typeof window.EventSource !== "function") {
    startFallback();
    return;
  }

  eventSource = new EventSource(streamUrl, { withCredentials: true });
  eventSource.addEventListener("state", (event) => {
    try {
      applyState(JSON.parse(event.data));
      streamFailures = 0;
      setConnection("Live", "healthy");
    } catch (_error) {
      setConnection("Некорректные данные", "failed");
    }
  });
  eventSource.addEventListener("probe_completed", (event) => {
    try {
      applyProbe(JSON.parse(event.data));
      streamFailures = 0;
      setConnection("Live", "healthy");
    } catch (_error) {
      setConnection("Некорректные данные", "failed");
    }
  });
  eventSource.addEventListener("probe_cleared", () => {
    clearProbe();
    streamFailures = 0;
    setConnection("Live", "healthy");
  });
  eventSource.addEventListener("heartbeat", () => {
    setConnection("Live", "healthy");
  });
  eventSource.addEventListener("resync_required", () => {
    void pollOnce();
  });
  eventSource.addEventListener("authz_epoch", () => {
    eventSource.close();
    window.location.reload();
  });
  eventSource.onerror = () => {
    streamFailures += 1;
    setConnection("Переподключение…", "unknown");
    if (streamFailures >= 3 && eventSource !== null) {
      eventSource.close();
      startFallback();
    }
  };
  window.addEventListener("pagehide", () => {
    if (eventSource !== null) {
      eventSource.close();
    }
    if (fallbackTimer !== null) {
      window.clearTimeout(fallbackTimer);
      fallbackTimer = null;
    }
  });
})();
