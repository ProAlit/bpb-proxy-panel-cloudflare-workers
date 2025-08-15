import { gotnn } from "./helpers";

export function initializeParams(request, env) {
    const url = new URL(request.url);
    const auiym = new URLSearchParams(url.search);
    globalThis.panelVersion = __PV__;
    globalThis.yilfm = [80, 8080, 2052, 2082, 2086, 2095, 8880];
    globalThis.dksvm = [443, 8443, 2053, 2083, 2087, 2096];
    globalThis.hfruk = env.U;
    globalThis.ffzll = env.P;
    globalThis.xljwa = env.PIP || `tool.exifit.eu.org`;
    globalThis.hostName = request.headers.get('Host');
    globalThis.pathName = url.pathname;
    globalThis.client = auiym.get('app');
    globalThis.lfzuq = url.origin;
    globalThis.dohURL = env.D || 'hhttps://freedns.controld.com/p2';
    globalThis.fnrbq = env.FB || 'wikipedia.org';
    globalThis.kxtow = env.SP || globalThis.hfruk;
    if (!['/problem', '/encrypted', '/file.ico'].includes(globalThis.pathName)) {
        if (!globalThis.hfruk || !globalThis.ffzll) throw new Error(`Please set U and P first. Go <a href="${globalThis.lfzuq}/encrypted" target="_blank">Here!</a>`, { cause: "init" });
        if (globalThis.hfruk && !gotnn(globalThis.hfruk)) throw new Error(`Invalid U: ${globalThis.hfruk}`, { cause: "init" });
        if (typeof env.S !== 'object') throw new Error('S Dataset is not properly set!', { cause: "init" });
    }
}