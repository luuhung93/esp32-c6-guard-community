import { t } from "./i18n.js";
const catalogBase = "https://luuhung93.github.io/esp32-c6-guard-filters/catalog/v2/";
const fold = value => String(value).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/đ/g, "d").replace(/[^a-z0-9]/g, "");
let regionIndex;
const countryCache = new Map();
const labels = ["vi", "en"].map(language => typeof Intl.DisplayNames === "function" ? new Intl.DisplayNames([language], {type: "region"}) : null);
export function clearCatalogCache() {
  regionIndex = undefined;
  countryCache.clear();
}
async function readCatalog(path) {
  const response = await fetch(catalogBase + path, {cache: "no-cache", credentials: "omit", signal: AbortSignal.timeout(15000)})
    .catch(() => { throw Error(t("couldNotLoadTheOnline")); });
  if (!response.ok) throw Error(t("couldNotLoadTheOnline"));
  const data = await response.json();
  if (data.schemaVersion !== 2) throw Error(t("theOnlineCatalogIsIncompatible"));
  return data;
}
async function regions() {
  if (!regionIndex) regionIndex = readCatalog("index.json").then(data => {
    if (!Array.isArray(data.regions) || data.regions.length > 256 || data.regions.some(r =>
      !/^(Global|[A-Z]{2})$/.test(r.code) || !Array.isArray(r.names) || r.names.length > 8 || r.names.some(n => typeof n !== "string" || n.length > 160)))
      throw Error(t("invalidCountryCatalog"));
    return data.regions;
  }).catch(error => {regionIndex = undefined; throw error;});
  return regionIndex;
}
export async function searchCatalog(query) {
  const term = fold(query);
  if (!term) return [];
  const index = await regions();
  const exact = index.some(r => fold(r.code) === term);
  const matches = index.filter(r => exact ? fold(r.code) === term : fold([r.code, ...r.names,
    ...(r.code === "Global" ? ["Toàn cầu", "quốc tế", "global", "AdAway"] : labels.map(l => l?.of(r.code) || r.code))].join(" ")).includes(term));
  if (matches.length > 8) throw Error(t("enterAMoreSpecificCountry"));
  const results = await Promise.all(matches.map(async r => {
    if (!countryCache.has(r.code)) {
      const pending = readCatalog(`countries/${r.code}.json`).then(data => {
        if (!Array.isArray(data.filters) || data.filters.length > 8 || data.filters.some(f =>
          !/^[a-zA-Z0-9_-]{1,63}$/.test(f.id) || f.region !== r.code || typeof f.name !== "string" || f.name.length > 160 ||
          !Number.isInteger(f.ruleCount) || f.ruleCount < 1 || !Number.isInteger(f.binaryBytes) || f.binaryBytes < 152 || f.binaryBytes > 4000144))
          throw Error(t("invalidFilterListTryRefreshing"));
        return data.filters;
      }).catch(error => {
        if (countryCache.get(r.code) === pending) countryCache.delete(r.code);
        throw error;
      });
      countryCache.set(r.code, pending);
    }
    return countryCache.get(r.code);
  }));
  return results.flat();
}
