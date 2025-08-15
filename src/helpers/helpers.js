import { Authenticate, generateJWTToken, resetPassword } from "../idetify/auth";
import { getClashNormalConfig, getClashWarpConfig } from "../clients/c";
import { extractWireguardParams } from "../clients/helpers";
import { getHiddifyWarpConfigs, getNormalConfigs } from "../clients/n";
import { getSingBoxCustomConfig, getSingBoxWarpConfig } from "../clients/s";
import { getXrayCustomConfigs, getXrayWarpConfigs } from "../clients/x";
import { getDataset, updateDataset } from "../storage/handlers";
import JSZip from "jszip";
import { fetchWarpConfigs } from "../types/w";

export function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

export async function handlePanel(request, env) {

    switch (globalThis.pathName) {
        case '/app':
            return await renderPanel(request, env);
        case '/app/setup':
            return await getSettings(request, env);
        case '/app/u-setup':
            return await updateSettings(request, env);
        case '/app/r-setup':
            return await resetSettings(request, env);
        case '/app/r-pwd':
            return await resetPassword(request, env);
        case '/app/info':
            return await getMyIP(request);
        case '/app/u-w':
            return await updateWarpConfigs(request, env);
        case '/app/g-w':
            return await getWarpConfigs(request, env);
        default:
            return await fallback(request);
    }
}

export async function handleError(error) {
    const message = encodeURIComponent(error.message);
    return Response.redirect(`${globalThis.urlOrigin}/problem?message=${message}`, 302);
}

export async function handleLogin(request, env) {
    if (globalThis.pathName === '/sign') return await renderLogin(request, env);
    if (globalThis.pathName === '/sign/authenticate') return await generateJWTToken(request, env);
    return await fallback(request);
}

export async function handleSubscriptions(request, env) {
    const { proxySettings: settings } = await getDataset(request, env);
    globalThis.settings = settings;
    const { pathName, client, subPath } = globalThis;

    switch (decodeURIComponent(pathName)) {
        case `/link/n/${subPath}`:
            return await getNormalConfigs(false);

        case `/link/f-n/${subPath}`:
            switch (client) {
                case 's':
                    return await getSingBoxCustomConfig(env, false);
                case 'c':
                    return await getClashNormalConfig(env);
                case 'x':
                    return await getXrayCustomConfigs(env, false);
                default:
                    break;
            }

        case `/link/frg/${subPath}`:
            switch (client) {
                case 's':
                    return await getSingBoxCustomConfig(env, true);
                case 'h-f':
                    return await getNormalConfigs(true);
                default:
                    return await getXrayCustomConfigs(env, true);
            }

        case `/link/w/${subPath}`:
            switch (client) {
                case 'c':
                    return await getClashWarpConfig(request, env, false);
                case 's':
                    return await getSingBoxWarpConfig(request, env);
                case 'h':
                    return await getHiddifyWarpConfigs(false);
                case 'x':
                    return await getXrayWarpConfigs(request, env, false);
                default:
                    break;
            }

        case `/link/w-pro/${subPath}`:
            switch (client) {
                case 'c-pro':
                    return await getClashWarpConfig(request, env, true);
                case 'h-pro':
                    return await getHiddifyWarpConfigs(true);
                case 'x-k':
                case 'x-pro':
                    return await getXrayWarpConfigs(request, env, true);
                default:
                    break;
            }

        default:
            return await fallback(request);
    }
}

async function updateSettings(request, env) {
    if (request.method === 'POST') {
        const auth = await Authenticate(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized!');
        const proxySettings = await updateDataset(request, env);
        return await respond(true, 200, null, proxySettings);
    }

    return await respond(false, 405, 'Method not allowed.');
}

async function resetSettings(request, env) {
    if (request.method === 'POST') {
        const auth = await Authenticate(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized!');
        const proxySettings = await updateDataset(request, env);
        return await respond(true, 200, null, proxySettings);
    }

    return await respond(false, 405, 'Method Not Allowed!');
}

async function getSettings(request, env) {
    try {
        const isPassSet = await env.S.get('pwd') ? true : false;
        const auth = await Authenticate(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized!', { isPassSet });
        const { proxySettings } = await getDataset(request, env);
        const settings = {
            proxySettings,
            isPassSet,
            subPath: globalThis.subPath
        };

        return await respond(true, 200, null, settings);
    } catch (error) {
        throw new Error(error);
    }
}

export async function fallback(request) {
    const url = new URL(request.url);
    url.hostname = globalThis.fallbackDomain;
    url.protocol = 'https:';
    const newRequest = new Request(url.toString(), {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: 'manual'
    });

    return await fetch(newRequest);
}

async function getMyIP(request) {
    const ip = await request.text();
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?nocache=${Date.now()}`);
        const geoLocation = await response.json();
        return await respond(true, 200, null, geoLocation);
    } catch (error) {
        console.error('Error fetching IP address:', error);
        return await respond(false, 500, `Error fetching IP address: ${error}`)
    }
}

async function getWarpConfigs(request, env) {
    const isPro = globalThis.client === 'amnezia';
    const auth = await Authenticate(request, env);
    if (!auth) return new Response('Unauthorized!', { status: 401 });
    const { warpConfigs, proxySettings } = await getDataset(request, env);
    const warpConfig = extractWireguardParams(warpConfigs, false);
    const { warpIPv6, publicKey, privateKey } = warpConfig;
    const { warpEndpoints, amneziaNoiseCount, amneziaNoiseSizeMin, amneziaNoiseSizeMax } = proxySettings;
    const zip = new JSZip();
    const trimLines = (string) => string.split("\n").map(line => line.trim()).join("\n");
    const amneziaNoise = isPro
        ?
        `Jc = ${amneziaNoiseCount}
        Jmin = ${amneziaNoiseSizeMin}
        Jmax = ${amneziaNoiseSizeMax}
        S1 = 0
        S2 = 0
        H1 = 0
        H2 = 0
        H3 = 0
        H4 = 0`
        : '';

    try {
        warpEndpoints.forEach((endpoint, index) => {
            zip.file(`${atob('QlBC')}-W-${index + 1}.conf`, trimLines(
                `[Interface]
                PrivateKey = ${privateKey}
                Address = 172.16.0.2/32, ${warpIPv6}
                DNS = 1.1.1.1, 1.0.0.1
                MTU = 1280
                ${amneziaNoise}
                [Peer]
                PublicKey = ${publicKey}
                AllowedIPs = 0.0.0.0/0, ::/0
                Endpoint = ${endpoint}
                PersistentKeepalive = 25`
            ));
        });

        const zipBlob = await zip.generateAsync({ type: "blob" });
        const arrayBuffer = await zipBlob.arrayBuffer();
        return new Response(arrayBuffer, {
            headers: {
                "Content-Type": "application/zip",
                "Content-Disposition": `attachment; filename="${atob('QlBC')}-W-${isPro ? "Pro-" : ""}configs.zip"`,
            },
        });
    } catch (error) {
        return new Response(`Error generating ZIP file: ${error}`, { status: 500 });
    }
}

export async function serveIcon() {
    const faviconBase64 = __ICON__;
    return new Response(Uint8Array.from(atob(faviconBase64), c => c.charCodeAt(0)), {
        headers: {
            'Content-Type': 'image/x-icon',
            'Cache-Control': 'public, max-age=86400',
        }
    });
}

async function renderPanel(request, env) {
    const pwd = await env.S.get('pwd');
    if (pwd) {
        const auth = await Authenticate(request, env);
        if (!auth) return Response.redirect(`${globalThis.urlOrigin}/sign`, 302);
    }

    const encodedHtml = __PANEL_HTML_CONTENT__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

async function renderLogin(request, env) {
    const auth = await Authenticate(request, env);
    if (auth) return Response.redirect(`${urlOrigin}/app`, 302);

    const encodedHtml = __LOGIN_HTML_CONTENT__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

export async function renderSecrets() {
    const encodedHtml = __SECRETS_HTML_CONTENT__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' },
    });
}

export async function renderError() {
    const encodedHtml = __ERROR_HTML_CONTENT__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
    });
}

async function updateWarpConfigs(request, env) {
    if (request.method === 'POST') {
        const auth = await Authenticate(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized.');
        try {
            await fetchWarpConfigs(env);
            return await respond(true, 200, 'W Updated!');
        } catch (error) {
            console.log(error);
            return await respond(false, 500, `Err W Update: ${error}`);
        }
    }

    return await respond(false, 405, 'Method Not Allowd!');
}

export async function respond(success, status, message, body, customHeaders) {
    return new Response(JSON.stringify({
        success,
        status,
        message: message || '',
        body: body || ''
    }), {
        headers: customHeaders || {
            'Content-Type': message ? 'text/plain' : 'application/json'
        }
    });
}