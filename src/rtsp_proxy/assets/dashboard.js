(() => {
  "use strict";

  const root = document.documentElement;
  const themeToggle = document.querySelector("[data-theme-toggle]");
  const themeLabel = document.querySelector("[data-theme-label]");
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const savedTheme = (() => {
    try {
      return window.localStorage.getItem("rtsp-proxy-theme");
    } catch (_error) {
      return null;
    }
  })();
  const applyTheme = (theme) => {
    const dark = theme === "dark";
    root.dataset.theme = theme;
    if (themeToggle instanceof HTMLButtonElement) {
      themeToggle.setAttribute("aria-pressed", String(dark));
    }
    if (themeLabel instanceof HTMLElement) {
      themeLabel.textContent = dark ? "Светлая тема" : "Тёмная тема";
    }
  };
  applyTheme(savedTheme === "dark" || savedTheme === "light"
    ? savedTheme
    : systemTheme.matches ? "dark" : "light");
  if (themeToggle instanceof HTMLButtonElement) {
    themeToggle.addEventListener("click", () => {
      const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
      applyTheme(nextTheme);
      try {
        window.localStorage.setItem("rtsp-proxy-theme", nextTheme);
      } catch (_error) {
        // Theme persistence is optional in locked-down browsers.
      }
    });
  }

  const activeNavigation = document.querySelector(
    document.body.classList.contains("dashboard-cameras") ? ".nav-cameras" : ".nav-overview",
  );
  if (activeNavigation instanceof HTMLAnchorElement) {
    activeNavigation.setAttribute("aria-current", "page");
  }

  const placementInputs = Array.from(document.querySelectorAll('input[name="placement_mode"]'));
  const manualPlacement = document.querySelector("[data-manual-placement]");
  if (placementInputs.length > 0 && manualPlacement instanceof HTMLElement) {
    const updatePlacement = () => {
      const selected = placementInputs.find((input) => input instanceof HTMLInputElement && input.checked);
      manualPlacement.hidden = selected instanceof HTMLInputElement && selected.value !== "manual";
    };
    placementInputs.forEach((input) => input.addEventListener("change", updatePlacement));
    updatePlacement();
  }

  document.querySelectorAll("form.mutation-form").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const submit = form.querySelector('button[type="submit"]');
      if (submit instanceof HTMLButtonElement) {
        window.setTimeout(() => {
          if (event.defaultPrevented) {
            return;
          }
          form.setAttribute("aria-busy", "true");
          submit.disabled = true;
          submit.textContent = "Выполняем…";
        }, 0);
      }
    });
  });

  const tabList = document.querySelector("[data-camera-tabs]");
  if (tabList instanceof HTMLElement) {
    const tabs = Array.from(tabList.querySelectorAll("[role=tab]"));
    const panels = Array.from(document.querySelectorAll("[data-camera-panel]"));
    const panelNames = new Set(panels.map((panel) => panel.getAttribute("data-camera-panel")));
    const activateTab = (tab, moveFocus = false) => {
      const name = tab.getAttribute("data-camera-tab");
      if (!name || !panelNames.has(name)) {
        return;
      }
      tabs.forEach((candidate) => {
        const active = candidate === tab;
        candidate.setAttribute("aria-selected", String(active));
        candidate.setAttribute("tabindex", active ? "0" : "-1");
        candidate.classList.toggle("active", active);
      });
      panels.forEach((panel) => {
        panel.hidden = panel.getAttribute("data-camera-panel") !== name;
      });
      if (moveFocus) {
        tab.focus();
      }
    };
    document.body.classList.add("tabs-ready");
    const requestedName = window.location.hash.slice(1);
    const initial = tabs.find((tab) => tab.getAttribute("data-camera-tab") === requestedName)
      || tabs.find((tab) => tab.getAttribute("aria-selected") === "true")
      || tabs[0];
    if (initial instanceof HTMLElement) {
      activateTab(initial);
    }
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", (event) => {
        const name = tab.getAttribute("data-camera-tab");
        if (!name || !panelNames.has(name)) {
          return;
        }
        event.preventDefault();
        window.history.replaceState(null, "", `#${name}`);
        activateTab(tab);
      });
      tab.addEventListener("keydown", (event) => {
        let nextIndex = index;
        if (event.key === "ArrowRight") {
          nextIndex = (index + 1) % tabs.length;
        } else if (event.key === "ArrowLeft") {
          nextIndex = (index - 1 + tabs.length) % tabs.length;
        } else if (event.key === "Home") {
          nextIndex = 0;
        } else if (event.key === "End") {
          nextIndex = tabs.length - 1;
        } else {
          return;
        }
        event.preventDefault();
        const next = tabs[nextIndex];
        if (next instanceof HTMLElement && panelNames.has(next.getAttribute("data-camera-tab"))) {
          const name = next.getAttribute("data-camera-tab");
          window.history.replaceState(null, "", `#${name}`);
          activateTab(next, true);
        } else if (next instanceof HTMLAnchorElement) {
          next.focus();
        }
      });
    });
  }

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const targetId = button.getAttribute("data-copy-target");
      const target = targetId ? document.getElementById(targetId) : null;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      try {
        await navigator.clipboard.writeText(target.textContent || "");
        button.textContent = "Скопировано";
      } catch (_error) {
        button.textContent = "Выделите адрес вручную";
      }
    });
  });

  document.querySelectorAll("form[data-raw-source-credentials]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!(form instanceof HTMLFormElement) || form.dataset.encodedCredentialConfirmed === "true") {
        return;
      }
      const values = ["source_username", "source_password"].map((name) => {
        const field = form.elements.namedItem(name);
        return field instanceof HTMLInputElement ? field.value : "";
      });
      if (!values.some((value) => /%[0-9a-f]{2}/i.test(value))) {
        return;
      }
      if (!window.confirm("Credentials должны быть исходными. Продолжить и сохранить %HH буквально?")) {
        event.preventDefault();
        return;
      }
      form.dataset.encodedCredentialConfirmed = "true";
    });
  });

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
  const loginForm = document.querySelector("[data-login-form]");
  if (loginForm instanceof HTMLFormElement) {
    const password = loginForm.querySelector("#password");
    const toggle = loginForm.querySelector("[data-password-toggle]");
    const submit = loginForm.querySelector("[data-login-submit]");
    const label = loginForm.querySelector("[data-login-label]");
    if (password instanceof HTMLInputElement && toggle instanceof HTMLButtonElement) {
      toggle.addEventListener("click", () => {
        const visible = password.type === "text";
        password.type = visible ? "password" : "text";
        toggle.textContent = visible ? "Показать" : "Скрыть";
        toggle.setAttribute("aria-label", visible ? "Показать пароль" : "Скрыть пароль");
      });
    }
    loginForm.addEventListener("submit", () => {
      if (submit instanceof HTMLButtonElement) {
        submit.setAttribute("aria-busy", "true");
        window.setTimeout(() => {
          submit.disabled = true;
        }, 0);
      }
      if (label instanceof HTMLElement) {
        label.textContent = "Входим…";
      }
    });
  }
  if (!(live instanceof HTMLElement)) {
    return;
  }

  const connection = live.querySelector("[data-live-connection]");
  const sourceState = live.querySelector("[data-live-source]");
  const sourceReason = live.querySelector("[data-live-source-reason]");
  const sourceIcon = live.querySelector("[data-live-icon]");
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
        ready: "Готов",
        idle: "Ожидает клиента",
        connecting: "Подключается к источнику",
        stale: "Данные устарели",
        unavailable: "Недоступен",
        unknown: "Нет per-path state",
      };
      sourceState.textContent = labels[state.source_state] || "—";
    }
    if (sourceIcon instanceof HTMLElement) {
      const icons = { ready: "●", idle: "Ⅱ", connecting: "…", stale: "!", unavailable: "!", unknown: "?" };
      sourceIcon.textContent = icons[state.source_state] || "?";
    }
    if (sourceReason instanceof HTMLElement) {
      const reasons = {
        source_start_pending: "Авторизованный клиент запустил on-demand подключение; ожидаем источник.",
        source_start_failed: "Источник не стал доступен после авторизованной попытки. Проверьте endpoint, сеть и credentials; глубокая проверка ниже уточнит причину, если она разрешена профилем камеры.",
      };
      const stateReasons = {
        ready: "Источник подключён и готов к передаче.",
        idle: "Источник подключится по запросу downstream-клиента.",
        connecting: "Нода устанавливает соединение с источником.",
        stale: "Показано последнее известное состояние; данные устарели.",
        unavailable: "Collector не смог получить состояние источника.",
        unknown: "Per-path состояние источника пока недоступно.",
      };
      sourceReason.textContent = reasons[state.source_reason] || stateReasons[state.source_state] || "—";
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

  const loadInitialSnapshot = async () => {
    if (!snapshotUrl) {
      return;
    }
    try {
      const snapshot = await fetchSnapshot(snapshotUrl);
      if (snapshot) {
        applyState(snapshot);
      }
    } catch (_error) {
      // SSE remains authoritative; its error path starts bounded polling.
    }
  };

  if (!streamUrl || !snapshotUrl || typeof window.EventSource !== "function") {
    startFallback();
    return;
  }

  void loadInitialSnapshot();
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
