import { t, text } from "./i18n.js";
export function wireFirmware(api, run, message, session) {
  const status = document.querySelector('#firmware-release-status');
  const install = document.querySelector('#install-online-firmware');
  const check = document.querySelector('#check-firmware');
  const confirmation = document.querySelector('#firmware-confirm');
  const confirmInstall = document.querySelector('#confirm-online-firmware');
  const cancelInstall = document.querySelector('#cancel-online-firmware');
  let selected;
  let release, polling = false, reading = false, started = 0, rebooting = false;
  async function refreshFirmware() {
    if (reading) return;
    reading = true;
    try {
      const result = await api('/api/ota/release');
      release = result;
      text(document.querySelector('#firmware-current-version'), result.currentVersion
        ? ["runningV", result.currentVersion] : ["couldNotReadTheCurrent"]);
      const job = result.job || {};
      install.disabled = !!job.busy || !result.available;
      check.disabled = !!job.busy;
      polling = !!job.busy;
      if (job.action === 'ota-install' && job.state === 'rebooting') {
        text(status, ["firmwareVerifiedRestarting"]);
        polling = rebooting = true;
      } else if (job.busy) {
        if (!started) started = Date.now();
        if (job.action === 'ota-install') rebooting = true;
        text(status, job.action === 'ota-install'
          ? ["downloadingFirmware", Math.min(100, Math.floor((result.receivedBytes || 0) * 100 / (result.bytes || 1)))]
          : job.action === 'ota-check' ? ["checkingForUpdates"] : ["theDeviceIsProcessingAnother"]);
      } else if (job.action?.startsWith('ota-') && job.state === 'error') {
        text(status, job.action === 'ota-check'
          ? ["couldNotCheckForUpdates"]
          : ["updateUnsuccessfulPleaseRetry"]);
        rebooting = false;
      } else if (result.checked) {
        text(status, result.available
          ? ["versionMbIsAvailableYou", result.version, result.bytes / 1048576]
          : ["theDeviceIsUsingThe", result.version]);
      } else text(status, ["checkForSignedFirmwareFrom"]);
    } finally { reading = false; }
  }
  check.onclick = () => run(async () => {
    if (check.disabled) return;
    check.disabled = install.disabled = true;
    try {
      await api('/api/ota/check', 'POST', {});
      polling = true;
      started = Date.now();
      await refreshFirmware();
    } finally {
      if (!polling) { check.disabled = false; install.disabled = !release?.available; }
    }
  });
  install.onclick = () => {
    if (install.disabled || !release?.available) return;
    selected = release;
    text(document.querySelector('#firmware-confirm-text'), ["updateToVTheDevice", selected.version]);
    confirmation.hidden = false;
    confirmInstall.focus();
  };
  cancelInstall.onclick = () => {
    confirmation.hidden = true;
    selected = undefined;
    install.focus();
  };
  confirmInstall.onclick = () => run(async () => {
    if (confirmInstall.disabled || !selected) return;
    const chosen = selected;
    confirmInstall.disabled = cancelInstall.disabled = true;
    install.disabled = check.disabled = true;
    text(status, ["sendingTheUpdateRequestTo"]);
    let accepted = false;
    try {
      const before = await api('/api/status');
      await api('/api/ota/install', 'POST', {build: chosen.build});
      accepted = true;
      confirmation.hidden = true;
      selected = undefined;
      polling = rebooting = true;
      sessionStorage.setItem('otaPending', JSON.stringify({oldBoot: before.bootId, build: chosen.build}));
      started = Date.now();
      message(t("downloadingFirmwareKeepPowerConnected"));
      await refreshFirmware();
    } catch (error) {
      text(status, accepted ? ["waitingForTheDeviceTo"]
        : ["couldNotSendTheUpdate"]);
      throw error;
    } finally {
      confirmInstall.disabled = cancelInstall.disabled = false;
      if (!polling) { check.disabled = false; install.disabled = !release?.available; }
    }
  });
  setInterval(() => {
    if (!polling || reading || document.hidden) return;
    if (started && Date.now() - started > 360000) {
      polling = false;
      text(status, ["updateNotConfirmedLogIn"]);
      return;
    }
    refreshFirmware().catch(async error => {
      if (!rebooting) {
        polling = false; check.disabled = false; install.disabled = !release?.available;
        message(error.message, true); return;
      }
      try {
        const s = await api('/api/auth/session');
        if (!s.authenticated) {
          polling = false;
          await session();
          message(t("theDeviceIsBackLog2"));
        }
      } catch { /* Reboot may briefly disconnect the LAN connection. */ }
    });
  }, 2000);
  return refreshFirmware;
}
