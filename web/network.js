import { t, text } from "./i18n.js";
function ipv4(value) {
  if (typeof value !== "string" || !/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) return null;
  const parts = value.split(".").map(Number);
  if (parts.some(n => n > 255)) return null;
  return parts.reduce((address, n) => (address * 256 + n) >>> 0, 0);
}
function unicast(address) {
  const a = address >>> 24, b = (address >>> 16) & 255;
  return a > 0 && a < 224 && a !== 127 && !(a === 169 && b === 254);
}
export function networkSettingsError(values) {
  const upstream = ipv4(values.upstream);
  const a = upstream >>> 24, b = (upstream >>> 16) & 255;
  if (upstream === null || !unicast(upstream) || a === 10 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && [168, 0, 2].includes(b)) || (a === 198 && [18, 19, 51].includes(b)) || (a === 203 && b === 0))
    return t("upstreamDnsMustBeA");
  if (values.dhcp) return "";
  const ip = ipv4(values.ip), gateway = ipv4(values.gateway), mask = ipv4(values.netmask);
  if (ip === null || gateway === null || mask === null)
    return t("enterAValidStaticIpv");
  const host = (~mask) >>> 0;
  if (!mask || host < 3 || (host & (host + 1)) !== 0)
    return t("invalidSubnetMaskForExample");
  if (!unicast(ip) || !unicast(gateway) || !(ip & host) || (ip & host) === host ||
      !(gateway & host) || (gateway & host) === host || ip === gateway)
    return t("ipAndGatewayMustBe");
  if ((ip & mask) !== (gateway & mask)) return t("gatewayMustBeOnThe");
  if ((upstream & mask) === (ip & mask)) return t("upstreamDnsMustBeOutside");
  return "";
}
export function wireNetwork(api, message) {
  const form = document.querySelector("#settings-form");
  const group = document.querySelector("#staticIpFields");
  const status = document.querySelector("#settings-status");
  const link = document.querySelector("#settings-address");
  const submit = form.querySelector('[type="submit"]');
  const addressFields = ["ip", "gateway", "netmask"];
  let saving = false, applied = false;
  function sync(currentNetwork) {
    if (form.elements.dhcp.checked && currentNetwork)
      for (const key of addressFields)
        if (ipv4(currentNetwork[key]) !== null && currentNetwork[key] !== "0.0.0.0")
          form.elements[key].value = currentNetwork[key];
    group.hidden = form.elements.dhcp.checked;
    for (const key of addressFields) {
      form.elements[key].disabled = group.hidden;
      form.elements[key].required = !group.hidden;
    }
  }
  form.elements.dhcp.onchange = () => sync();
  form.onsubmit = async event => {
    event.preventDefault();
    if (saving || applied) return;
    const values = Object.fromEntries(new FormData(form));
    values.dhcp = form.elements.dhcp.checked;
    values.history = form.elements.history.checked;
    if (!values.password) delete values.password;
    const error = networkSettingsError(values);
    if (error) { message(error, true); return; }
    saving = true;
    submit.disabled = true;
    status.hidden = false;
    link.hidden = true;
    text(status, ["savingNetworkSettings"]);
    message("");
    try {
      await api("/api/settings", "PUT", values);
      applied = true;
      text(status, values.dhcp
        ? ["savedTheEspIsRestarting"]
        : ["savedTheEspIsRestarting2", values.ip]);
      if (!values.dhcp) {
        link.href = `http://${values.ip}/`;
        text(link, ["openHttp", values.ip]);
        link.hidden = false;
      }
    } catch (error) {
      text(status, ["settingsSaveNotConfirmedIf"]);
      message(error.message, true);
    } finally {
      saving = false;
      submit.disabled = applied;
    }
  };
  sync();
  return {sync, reset() {
    applied = false;
    submit.disabled = saving;
    form.elements.password.value = "";
    status.hidden = link.hidden = true;
    sync();
  }};
}
