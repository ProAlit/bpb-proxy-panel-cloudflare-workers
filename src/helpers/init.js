import { isValidUUID } from "./helpers";

export function initializeParams(request, env) {
    const url = new URL(request.url);
    const searchParams = new URLSearchParams(url.search);
    globalThis.panelVersion = __PV__;
    globalThis.defaultHttpPorts = [80, 8080, 2052, 2082, 2086, 2095, 8880];
    globalThis.defaultHttpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
    globalThis.userID = env.U;
    globalThis.TRPassword = env.P;
    globalThis.proxyIPs = env.PIP || `tool.exifit.eu.org`;
    globalThis.hostName = request.headers.get('Host');
    globalThis.pathName = url.pathname;
    globalThis.client = searchParams.get('app');
    globalThis.urlOrigin = url.origin;
    globalThis.dohURL = env.D || 'hhttps://freedns.controld.com/p2';
    globalThis.fallbackDomain = env.FB || 'wikipedia.org';
    globalThis.subPath = env.SP || globalThis.userID;
    if (!['/problem', '/encrypted', '/file.ico'].includes(globalThis.pathName)) {
        if (!globalThis.userID || !globalThis.TRPassword) throw new Error(`Please set U and P first. Go <a href="${globalThis.urlOrigin}/encrypted" target="_blank">Here!</a>`, { cause: "init" });
        if (globalThis.userID && !isValidUUID(globalThis.userID)) throw new Error(`Invalid U: ${globalThis.userID}`, { cause: "init" });
        if (typeof env.S !== 'object') throw new Error('S Dataset is not properly set!', { cause: "init" });
    }
}