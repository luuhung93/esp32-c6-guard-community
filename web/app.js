import { t, text, locale, translate, wireLanguage, apiError } from "./i18n.js";
import { searchCatalog, clearCatalogCache } from "./catalog.js";
import { wireFirmware } from "./firmware.js";
import { wireNetwork } from "./network.js";
"use strict";
let editSetupWifi = false;
const $ = (s) => document.querySelector(s);
let csrf = sessionStorage.getItem("csrf") || "",
  tab = "dashboard",
  offset = 0,
  filters = [],
  installed = [],
  rules = [],
  queries = [];
let filterJob = {};
let discovery = [], discoveryError = "", discoveryBusy = false, searchSequence = 0;
let pendingFilter, filterNotice = "", filterLimit = 5;
let countryNames = typeof Intl.DisplayNames === "function" ? new Intl.DisplayNames([locale()], {type: "region"}) : null;
const retiredFilters = new Map([["adguard-dns", "AdGuard DNS filter"], ["hagezi-light", "HaGeZi Light"]]);
function message(value, error = false) {
  text($("#message"), value);
  $("#message").classList.toggle("error", error);
}
async function api(path, method = "GET", body) {
  const headers = {};
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  if (body && !(body instanceof Blob) && typeof body !== "string") {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  const response = await fetch(path, { method, headers, body,
    signal: method === "GET" ? AbortSignal.timeout(25000) : undefined })
    .catch(() => { throw Error(t("cannotReachTheDeviceOr")); });
  const type = response.headers.get("content-type") || "";
  const data = type.includes("json")
    ? await response.json()
    : await response.text();
  if (response.status === 401 && path !== "/api/auth/login") {
    $("#app").hidden = true;
    $("#mainNav").hidden = true;
    $("#login-panel").hidden = false;
    $("#logout").hidden = true;
    throw Error(t("yourSessionHasExpiredPlease"));
  }
  if (!response.ok)
    throw Error(apiError(data.error));
  return data;
}
function button(label, fn) {
  const b = document.createElement("button");
  text(b, label);
  b.onclick = () => run(fn, b);
  return b;
}
async function run(fn, b) {
  if (b) b.disabled = true;
  try {
    await fn();
  } catch (e) {
    message(e.message, true);
  } finally {
    if (b) b.disabled = false;
  }
}
function data(form) {
  return Object.fromEntries(new FormData(form));
}
function cell(row, text) {
  const td = document.createElement("td");
  td.textContent = text;
  row.append(td);
  return td;
}
async function session() {
  const s = await api("/api/auth/session");
  text($("#connection-status"), ["connectedToEsp"]);
  const wizard = s.setup && s.authenticated;
  $("#wifi-panel").hidden = !wizard || (s.wifi && !editSetupWifi);
  $("#connected-panel").hidden = !wizard || !s.wifi || editSetupWifi;
  if (wizard && s.wifi) {
    const link = $("#lan-link");
    link.href = `http://${s.ip}`;
    link.textContent = s.ip;
    sessionStorage.removeItem("wifiAttempt");
  } else if (wizard) {
    const since = Number(sessionStorage.getItem("wifiAttempt") || 0);
    text($("#wifi-progress"), since
      ? Date.now() - since < 30000
        ? ["connectingToTheRouterThis"]
        : ["notConnectedYetCheckThe"]
      : s.wifiConfigured
        ? ["tryingSavedWiFiYou"]
        : "");
  }
  $("#setup-panel").hidden = !(s.setup && !s.configured);
  $("#login-panel").hidden = s.authenticated || (s.setup && !s.configured);
  $("#app").hidden = !s.authenticated || wizard;
  $("#mainNav").hidden = $("#app").hidden;
  $("#logout").hidden = !s.authenticated;
  if (s.authenticated) {
    await refresh();
    const pending = sessionStorage.getItem("otaPending");
    if (pending) {
      const expected = JSON.parse(pending);
      const current = await api("/api/status");
      if (current.bootId !== expected.oldBoot) {
        if (current.build === expected.build && current.dns && current.store) {
          message(t("newFirmwareConfirmedAfterRestart"));
          sessionStorage.removeItem("otaPending");
        } else
          message(
            t("theDeviceRestartedButFirmware"),
            true,
          );
      } else
        message(t("restartNotObservedUpdateNot"), true);
    }
  }
}
$("#login").onsubmit = (e) => {
  e.preventDefault();
  const submit = e.target.querySelector('button[type="submit"]');
  if (submit.disabled) return;
  run(async () => {
    const r = await api("/api/auth/login", "POST", data(e.target));
    csrf = r.csrf;
    sessionStorage.setItem("csrf", csrf);
    e.target.reset();
    networkForm.reset();
    message("");
    await session();
  }, submit);
};
$("#show-password").onclick = () => {
  const input = $("#adminPassword");
  input.type = input.type === "password" ? "text" : "password";
  $("#show-password").setAttribute("data-i18n-aria-label", input.type === "password" ? "showPassword" : "hidePassword");
  translate();
};
$("#copy-ip").onclick = () => {
  const range = document.createRange();
  range.selectNodeContents($("#dns-ip"));
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
  message(t("dnsAddressSelectedUseCopy"));
};
$("#setup-admin").onsubmit = (e) => {
  e.preventDefault();
  run(async () => {
    const b = data(e.target);
    if (b.password !== b.confirm) throw Error(t("thePasswordsDoNotMatch"));
    const r = await api("/api/setup/admin", "POST", { password: b.password });
    csrf = r.csrf;
    sessionStorage.setItem("csrf", csrf);
    e.target.reset();
    message(t("adminPasswordSetNextConnect"));
    await session();
  }, e.target.querySelector("button"));
};
$("#scan-wifi").onclick = () =>
  run(async () => {
    text($("#wifi-progress"), ["scanningWiFi"]);
    const result = await api("/api/setup/scan", "POST", {});
    const list = $("#wifi-networks");
    list.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    text(placeholder, result.networks.length
      ? ["chooseHomeWiFi"]
      : ["noNetworksFoundScanAgain"]);
    list.append(placeholder);
    for (const item of result.networks) {
      const option = document.createElement("option");
      option.value = item.ssid;
      if (item.secured) option.textContent = item.ssid;
      else text(option, ["openNetwork", item.ssid]);
      list.append(option);
    }
    text($("#wifi-progress"), ["selectANetworkEnterIts"]);
  }, $("#scan-wifi"));
$("#wifi-networks").onchange = (e) => {
  if (e.target.value) {
    $("#setup").elements.ssid.value = e.target.value;
    $("#setup").elements.password.value = "";
    $("#setup").elements.password.focus();
  }
};
$("#setup").onsubmit = (e) => {
  e.preventDefault();
  run(async () => {
    const b = data(e.target);
    b.dhcp = true;
    await api("/api/setup", "POST", b);
    editSetupWifi = false;
    sessionStorage.setItem("wifiAttempt", String(Date.now()));
    e.target.elements.password.value = "";
    message(t("wiFiSavedWaitingFor"));
    await session();
  }, $("#connect-wifi"));
};
$("#change-wifi").onclick = () =>
  run(async () => {
    editSetupWifi = true;
    await session();
  });
setInterval(() => {
  if (
    !document.hidden &&
    (!$("#wifi-panel").hidden || !$("#connected-panel").hidden)
  )
    run(session);
}, 2000);
$("#logout").onclick = () =>
  run(async () => {
    await api("/api/auth/logout", "POST");
    csrf = "";
    sessionStorage.removeItem("csrf");
    await session();
  });
for (const b of document.querySelectorAll("[data-tab]"))
  b.onclick = () =>
    run(async () => {
      tab = b.dataset.tab;
      for (const t of document.querySelectorAll(".tab"))
        t.hidden = t.id !== tab;
      for (const x of document.querySelectorAll("[data-tab]")) {
        if (x === b) x.setAttribute("aria-current", "page");
        else x.removeAttribute("aria-current");
      }
      await refresh();
    });
let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  const requestedTab = tab;
  try {
    await refreshTab(requestedTab);
  } finally {
    refreshing = false;
  }
  if (tab !== requestedTab) await refresh();
}
async function refreshTab(tab) {
  if ($("#app").hidden || document.hidden) return;
  if (tab === "dashboard") {
    const s = await api("/api/status");
    const m = await api("/api/stats");
    $("#dns-ip").textContent = s.ip;
    $("#version").textContent = `v${s.firmware} · heap ${s.heap} B`;
    for (const key of ["total", "blocked", "cacheHits", "errors"]) {
      $("#metric-" + key).dataset.number = m[key];
      $("#metric-" + key).textContent = Number(m[key]).toLocaleString(locale());
    }
    text($("#connection-status"), s.wifi && s.dns && s.store ? ["running"] : ["needsAttention"]);
  } else if (tab === "queries") {
    const r = await api("/api/queries?limit=300");
    queries = r.queries;
    drawQueries();
  } else if (tab === "filters") {
    const r = await api("/api/filters");
    filters = r.filters || [];
    installed = r.installed || [];
    filterJob = r.job || {};
    filterLimit = Number.isInteger(r.maxInstalled) && r.maxInstalled > 0 ? r.maxInstalled : 5;
    if (pendingFilter && !pendingFilter.requesting) {
      if (pendingFilter.removing) {
        if (!installed.some(item => item.id === pendingFilter.id)) {
          filterNotice = ["disabledAndRemovedItsData", pendingFilter.name];
          pendingFilter = undefined;
        } else if (Date.now() - pendingFilter.startedAt > 120000) {
          filterNotice = ["removalNotConfirmedRefreshTo"];
          pendingFilter = undefined;
        }
      } else if (installed.some(item => item.id === pendingFilter.id && item.enabled !== false)) {
        filterNotice = ["enabled", pendingFilter.name];
        pendingFilter = undefined;
      } else if (pendingFilter.jobId === filterJob.id && !filterJob.busy &&
          ["error", "succeeded"].includes(filterJob.state)) {
        filterNotice = filterJob.message === "ESP_ERR_NO_MEM"
          ? ["couldNotAddStorageOr", pendingFilter.name]
          : ["addingIsNotConfirmedRefresh", pendingFilter.name];
        pendingFilter = undefined;
      } else if (Number(filterJob.id) > Number(pendingFilter.jobId) ||
          Date.now() - pendingFilter.startedAt > 120000) {
        filterNotice = ["addingIsNotConfirmedCheck", pendingFilter.name];
        pendingFilter = undefined;
      }
    }
    updateFilterStatus();
    drawFilters();
  } else if (tab === "rules") await loadRules();
  else if (tab === "settings") {
    const r = await api("/api/settings");
    const f = $("#settings-form");
    for (const [k, v] of Object.entries(r)) {
      if (!f.elements[k]) continue;
      if (f.elements[k].type === "checkbox") f.elements[k].checked = v;
      else f.elements[k].value = v;
    }
    networkForm.sync(r.currentNetwork);
    await refreshFirmware();
  }
}
function updateFilterStatus() {
    const pending = pendingFilter;
    const received = pending && pending.jobId === filterJob.id ? Number(filterJob.receivedBytes || 0) : 0;
    const progress = pending?.bytes > 0 && received > 0
      ? ` ${Math.min(100, Math.floor(received * 100 / pending.bytes))}%` : "";
    text($("#update-status"), pending?.removing
      ? ["disablingAndRemovingFromThe", pending.name]
      : pending ? pending.requesting ? ["requestingInstallationOf", pending.name]
        : received >= pending.bytes && pending.bytes > 0
          ? ["verifyingAndSaving", pending.name]
          : ["adding", pending.name, progress]
      : filterJob.busy
      ? ["downloadingListsAndUpdates"]
      : filterNotice ? filterNotice
      : filterJob.state === "error"
        ? ["couldNotDownloadTheUpdate"]
        : filterJob.state === "succeeded"
            ? ["doneTheListsBelowHave"]
            : ["chooseListsThatSuitYour"]);
    $("#check-updates").disabled = !!filterJob.busy || !!pending;
    $("#apply-updates").disabled = !!filterJob.busy || !!pending || !installed.length;
}
function drawQueries() {
    $("#query-rows").replaceChildren();
    for (const q of queries) {
      if (!`${q.domain} ${q.client}`.toLowerCase().includes($("#query-search").value.toLowerCase())) continue;
      const row = document.createElement("tr");
      row.className = ["", "outcome-blocked", "outcome-cached", ""][q.outcome];
      for (const v of [
        q.domain,
        q.client,
        ({1: "A", 28: "AAAA"})[q.type] || q.type,
        ["Allowed", "Blocked", "Cached", "Error"][q.outcome],
      ])
        cell(row, v);
      $("#query-rows").append(row);
    }
}
$("#query-search").oninput = drawQueries;
$("#refresh-queries").onclick = () => run(refresh, $("#refresh-queries"));
function searchText(value) {
  return value.normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/đ/g, "d").replace(/[^a-z0-9]/g, "");
}
function filterRegion(region = "Global") {
  if (region.toUpperCase() === "VN") return t("vietnam");
  if (region.toLowerCase() === "global") return t("global");
  if (countryNames && /^[a-z]{2}$/i.test(region)) return countryNames.of(region.toUpperCase());
  return region;
}
function drawFilters() {
  const term = searchText($("#filter-search").value);
  const activeList = $("#filter-active"), resultList = $("#filter-results");
  activeList.replaceChildren();
  resultList.replaceChildren();
  const all = [];
  for (const item of [...discovery, ...filters, ...(pendingFilter?.source ? [pendingFilter.source] : [])])
    if (!retiredFilters.has(item.id) && !all.some(source => source.id === item.id)) all.push(item);
  for (const item of installed)
    if (!all.some(source => source.id === item.id)) {
      const code = item.id === "hostsvn" ? "VN" : /^country-[a-z]{2}$/.test(item.id) ? item.id.slice(-2).toUpperCase() : "Global";
      all.push({...item, region: code, name: item.id === "guard-starter" ? t("adawayCompactDefault") : item.id === "hostsvn" ? "hostsVN" : code === "Global" ? retiredFilters.get(item.id) || item.id : t("filter", filterRegion(code))});
    }
  const countryCodeSearch = term.length === 2 && all.some(item => item.region?.toLowerCase() === term);
  let count = 0;
  for (const item of all) {
    const region = filterRegion(item.region);
    const keywords = `${item.name || item.id} ${item.id} ${item.region || "Global"} ${region} ${item.region === "Global" ? "global toan cau quoc te" : ""}`;
    const local = installed.find(x => x.id === item.id);
    if (!local && pendingFilter?.id !== item.id && (!term || (!discovery.some(f => f.id === item.id) && (countryCodeSearch ? item.region?.toLowerCase() !== term : !searchText(keywords).includes(term))))) continue;
    if (!local) count++;
    const available = discovery.some(x => x.id === item.id) || filters.some(x => x.id === item.id);
    const card = document.createElement("article");
    card.className = "filter-card";
    const info = document.createElement("div");
    const h = document.createElement("h3");
    h.textContent = item.name || retiredFilters.get(item.id) || item.id;
    const p = document.createElement("p");
    const rules = local?.ruleCount ?? item.ruleCount;
    p.textContent = region + (rules === undefined ? "" : t("domains", Number(rules).toLocaleString(locale())));
    if (retiredFilters.has(item.id)) p.textContent += t("retired");
    const badge = document.createElement("span");
    badge.className = local ? "filter-badge added" : pendingFilter?.id === item.id ? "filter-badge pending" : "filter-badge";
    text(badge, local ? local.enabled ? ["enabled2"] : ["oldDataDisabled"] : pendingFilter?.id === item.id ? ["adding2"] : ["notEnabled"]);
    const labels = document.createElement("div");
    labels.className = "filter-labels";
    labels.append(badge);
    info.append(h, p, labels);
    const actions = document.createElement("div");
    actions.className = "filter-actions";
    card.append(info, actions);
    if (local) {
      const remove = button(t("disableAndRemove"), async () => {
        pendingFilter = {id: item.id, name: h.textContent, removing: true, requesting: true, startedAt: Date.now()};
        filterNotice = "";
        updateFilterStatus();
        drawFilters();
        let accepted = false;
        try {
          await api(`/api/filters/${item.id}`, "DELETE");
          accepted = true;
          pendingFilter.requesting = false;
          await refresh();
        } catch (error) {
          if (!accepted) {
            pendingFilter = undefined;
            filterNotice = ["disablingAndRemovingIsIncomplete", h.textContent];
            updateFilterStatus();
            drawFilters();
          }
          throw error;
        }
      });
      remove.className = "filter-remove";
      actions.append(remove);
    } else {
      const full = installed.length >= filterLimit;
      const add = button(pendingFilter?.id === item.id ? t("adding2") : full
        ? t("limitOfReached", filterLimit) : available ? t("enable") : t("notAvailableToDownload"), async () => {
        if (pendingFilter || full) return;
        pendingFilter = {source: item, id: item.id, name: item.name || item.id, bytes: item.binaryBytes || 0, requesting: true, startedAt: Date.now()};
        filterNotice = "";
        updateFilterStatus();
        drawFilters();
        let accepted = false;
        try {
          const job = await api("/api/filters/install", "POST", { id: item.id });
          accepted = true;
          pendingFilter.requesting = false;
          pendingFilter.jobId = job.id;
          filterJob = job;
          updateFilterStatus();
          drawFilters();
          await refresh();
        } catch (error) {
          if (!accepted) {
            pendingFilter = undefined;
            filterNotice = ["noConfirmationReceivedForAdding", item.name || item.id];
            updateFilterStatus();
            drawFilters();
          }
          throw error;
        }
      });
      add.className = "filter-add";
      add.disabled = !available || full;
      actions.append(add);
    }
    if (filterJob.busy || pendingFilter)
      for (const action of actions.querySelectorAll("button")) action.disabled = true;
    (local ? activeList : resultList).append(card);
  }
  text($("#filter-count"), ["filtersOnThisDevice2", installed.length, filterLimit]);
  if (!installed.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    text(empty, ["noFiltersEnabledSearchBelow"]);
    activeList.append(empty);
  }
  if (!count) {
    const empty = document.createElement("p");
    empty.className = "empty";
    text(empty, discoveryBusy ? ["searchingTheOnlineCatalog"] : discoveryError || (term ? ["noMatchingInactiveFiltersFound"] : ["enterACountryOrName"]));
    resultList.append(empty);
  }
}
async function discoverFilters() {
  const sequence = ++searchSequence;
  const term = $("#filter-search").value.trim();
  discovery = [];
  discoveryError = "";
  discoveryBusy = !!term;
  drawFilters();
  if (!term) { discoveryBusy = false; return; }
  try {
    const found = await searchCatalog(term);
    if (sequence === searchSequence) discovery = found;
  } catch (error) {
    if (sequence === searchSequence) discoveryError = error.message;
  } finally {
    if (sequence === searchSequence) {
      discoveryBusy = false;
      drawFilters();
    }
  }
}
$("#filter-search").oninput = () => { drawFilters(); discoverFilters(); };
$("#check-updates").onclick = () =>
  run(async () => {
    filterNotice = "";
    clearCatalogCache();
    discoverFilters();
    await api("/api/filters/check-updates", "POST");
    await refresh();
  });
$("#apply-updates").onclick = () =>
  run(async () => {
    filterNotice = "";
    await api("/api/filters/apply-updates", "POST");
    await refresh();
  });
async function loadRules() {
  rules = [];
  let total = 1;
  for (let start = 0; start < total; start += 100) {
    const page = await api(`/api/my-rules?offset=${start}&limit=100`);
    total = page.total;
    rules.push(...page.rules);
    if (!page.rules.length) break;
  }
  $("#rule-total").textContent = `${total}/1000`;
  drawRules();
}
function drawRules() {
  $("#rule-rows").replaceChildren();
  const term = $("#rule-search").value.toLowerCase();
  const matches = rules.filter((r) => r.domain.includes(term));
  offset = Math.min(
    offset,
    Math.max(0, Math.floor((matches.length - 1) / 100) * 100),
  );
  $("#rules-prev").disabled = offset === 0;
  $("#rules-next").disabled = offset + 100 >= matches.length;
  text($("#rules-page"), ["page", offset / 100 + 1, Math.max(1, Math.ceil(matches.length / 100))]);
  for (const r of matches.slice(offset, offset + 100)) {
    const row = document.createElement("tr");
    cell(row, r.domain);
    cell(row, r.action);
    const actions = cell(row, "");
    actions.append(
      button(t("edit"), async () => {
        const name = prompt("Domain", r.domain);
        if (name === null) return;
        const action = prompt(t("actionAllowOrBlock"), r.action);
        if (action === null) return;
        if (!["allow", "block"].includes(action))
          throw Error(t("actionMustBeAllowOr"));
        await api(`/api/my-rules/${r.domain}`, "PUT", { domain: name, action });
        await loadRules();
      }),
      button(t("delete"), async () => {
        await api(`/api/my-rules/${r.domain}`, "DELETE");
        await loadRules();
      }),
    );
    $("#rule-rows").append(row);
  }
}
$("#rule-search").oninput = () => {
  offset = 0;
  drawRules();
};
$("#rules-prev").onclick = () =>
  run(async () => {
    offset = Math.max(0, offset - 100);
    drawRules();
  });
$("#rules-next").onclick = () =>
  run(async () => {
    offset += 100;
    drawRules();
  });
$("#rule-form").onsubmit = (e) => {
  e.preventDefault();
  run(async () => {
    await api("/api/my-rules", "POST", data(e.target));
    e.target.reset();
    await loadRules();
  });
};
$("#export-rules").onclick = () =>
  run(async () => {
    const text = await api("/api/my-rules/export");
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "my-rules.txt";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
$("#import-rules").onclick = () =>
  run(async () => {
    const f = $("#import-file").files[0];
    if (!f) throw Error(t("selectAFileFirst"));
    if (!confirm(t("replaceAllMyRulesWith"))) return;
    await api(
      `/api/my-rules/import?action=${$("#import-action").value}`,
      "POST",
      f,
    );
    offset = 0;
    await loadRules();
    message(t("rulesImported"));
  });
$("#reboot").onclick = () =>
  run(async () => {
    if (confirm(t("restartTheDevice"))) {
      await api("/api/system/reboot", "POST");
      message(t("restarting"));
    }
  });
$("#upload-firmware").onclick = () =>
  run(async () => {
    const f = $("#firmware-file").files[0];
    if (!f) throw Error(t("selectASignedBinFile"));
    if (!confirm(t("updateFirmwareAndRestart"))) return;
    const before = await api("/api/status");
    const result = await api("/api/ota/firmware", "POST", f);
    sessionStorage.setItem(
      "otaPending",
      JSON.stringify({ oldBoot: before.bootId, build: result.expectedBuild }),
    );
    message(
      t("imageVerifiedWaitingForRestart"),
    );
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      try {
        const s = await api("/api/auth/session");
        if (!s.authenticated) {
          await session();
          message(
            t("theDeviceIsBackLog"),
          );
          return;
        }
      } catch {}
    }
    message(
      t("restartNotConfirmedReconnectAnd"),
      true,
    );
  });
const networkForm = wireNetwork(api, message);
const refreshFirmware = wireFirmware(api, run, message, session);
wireLanguage(() => {
  countryNames = typeof Intl.DisplayNames === "function" ? new Intl.DisplayNames([locale()], {type: "region"}) : null;
  drawFilters();
  drawRules();
  for (const element of document.querySelectorAll("[data-number]"))
    element.textContent = Number(element.dataset.number).toLocaleString(locale());
});
setInterval(() => {
  if (tab !== "settings" && tab !== "rules") run(refresh);
}, 5000);
run(session);
