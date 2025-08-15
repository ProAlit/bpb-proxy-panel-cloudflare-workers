import { jekni, generateJWTToken, qwctb } from "../identify/auth";
import { fqyts, yzldz } from "../clients/c";
import { moume } from "../clients/helpers";
import { zuyvo, zlxxw } from "../clients/n";
import { fdybn, absit } from "../clients/s";
import { htplv, casaf } from "../clients/x";
import { nfmif, wmbcn } from "../storage/handlers";
import JSZip from "jszip";
import { dnupd } from "../types/w";

export function gotnn(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

export async function handlePanel(request, env) {

    switch (globalThis.pathName) {
        case '/app':
            return await aqrzz(request, env);
        case '/app/setup':
            return await nwujt(request, env);
        case '/app/u-setup':
            return await kuwty(request, env);
        case '/app/r-setup':
            return await wiipf(request, env);
        case '/app/r-pwd':
            return await qwctb(request, env);
        case '/app/info':
            return await dbdgc(request);
        case '/app/u-w':
            return await pzfgb(request, env);
        case '/app/g-w':
            return await aszrv(request, env);
        default:
            return await ydmzk(request);
    }
}

export async function handleError(error) {
    const message = encodeURIComponent(error.message);
    return Response.redirect(`${globalThis.lfzuq}/problem?message=${message}`, 302);
}

export async function handleLogin(request, env) {
    if (globalThis.pathName === '/sign') return await jvynn(request, env);
    if (globalThis.pathName === '/sign/authenticate') return await generateJWTToken(request, env);
    return await ydmzk(request);
}

export async function handleSubscriptions(request, env) {
    const { fkvzd: settings } = await nfmif(request, env);
    globalThis.settings = settings;
    const { pathName, client, kxtow } = globalThis;

    switch (decodeURIComponent(pathName)) {
        case `/link/n/${kxtow}`:
            return await zlxxw(false);

        case `/link/f-n/${kxtow}`:
            switch (client) {
                case 's':
                    return await fdybn(env, false);
                case 'c':
                    return await fqyts(env);
                case 'x':
                    return await htplv(env, false);
                default:
                    break;
            }

        case `/link/frg/${kxtow}`:
            switch (client) {
                case 's':
                    return await fdybn(env, true);
                case 'h-f':
                    return await zlxxw(true);
                default:
                    return await htplv(env, true);
            }

        case `/link/w/${kxtow}`:
            switch (client) {
                case 'c':
                    return await yzldz(request, env, false);
                case 's':
                    return await absit(request, env);
                case 'h':
                    return await zuyvo(false);
                case 'x':
                    return await casaf(request, env, false);
                default:
                    break;
            }

        case `/link/w-pro/${kxtow}`:
            switch (client) {
                case 'c-pro':
                    return await yzldz(request, env, true);
                case 'h-pro':
                    return await zuyvo(true);
                case 'x-k':
                case 'x-pro':
                    return await casaf(request, env, true);
                default:
                    break;
            }

        default:
            return await ydmzk(request);
    }
}

async function kuwty(request, env) {
    if (request.method === 'POST') {
        const auth = await jekni(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized!');
        const fkvzd = await wmbcn(request, env);
        return await respond(true, 200, null, fkvzd);
    }

    return await respond(false, 405, 'Method not allowed.');
}

async function wiipf(request, env) {
    if (request.method === 'POST') {
        const auth = await jekni(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized!');
        const fkvzd = await wmbcn(request, env);
        return await respond(true, 200, null, fkvzd);
    }

    return await respond(false, 405, 'Method Not Allowed!');
}

async function nwujt(request, env) {
    try {
        const isPassSet = await env.S.get('pwd') ? true : false;
        const auth = await jekni(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized!', { isPassSet });
        const { fkvzd } = await nfmif(request, env);
        const settings = {
            fkvzd,
            isPassSet,
            kxtow: globalThis.kxtow
        };

        return await respond(true, 200, null, settings);
    } catch (error) {
        throw new Error(error);
    }
}

export async function ydmzk(request) {
    const url = new URL(request.url);
    url.hostname = globalThis.fnrbq;
    url.protocol = 'https:';
    const newRequest = new Request(url.toString(), {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: 'manual'
    });

    return await fetch(newRequest);
}

async function dbdgc(request) {
    const ip = await request.text();
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?nocache=${Date.now()}`);
        const pejyn = await response.json();
        return await respond(true, 200, null, pejyn);
    } catch (error) {
        console.error('Error fetching IP address:', error);
        return await respond(false, 500, `Error fetching IP address: ${error}`)
    }
}

async function aszrv(request, env) {
    const aojtx = globalThis.client === 'amn';
    const auth = await jekni(request, env);
    if (!auth) return new Response('Unauthorized!', { status: 401 });
    const { ucdin, fkvzd } = await nfmif(request, env);
    const qptdt = moume(ucdin, false);
    const { anqse, bwgqa, qhjno } = qptdt;
    const { nfbjf, muanl, cubtg, bbdwc } = fkvzd;
    const zip = new JSZip();
    const trimLines = (string) => string.split("\n").map(line => line.trim()).join("\n");
    const roctv = aojtx
        ?
        `Jc = ${muanl}
        Jmin = ${cubtg}
        Jmax = ${bbdwc}
        S1 = 0
        S2 = 0
        H1 = 0
        H2 = 0
        H3 = 0
        H4 = 0`
        : '';

    try {
        nfbjf.forEach((sbvwg, index) => {
            zip.file(`${atob('QlBC')}-W-${index + 1}.conf`, trimLines(
                `[Interface]
                PrivateKey = ${qhjno}
                Address = 172.16.0.2/32, ${anqse}
                DNS = 76.76.2.2, 76.76.10.2
                MTU = 1280
                ${roctv}
                [Peer]
                PublicKey = ${bwgqa}
                AllowedIPs = 0.0.0.0/0, ::/0
                Endpoint = ${sbvwg}
                PersistentKeepalive = 25`
            ));
        });

        const rwoov = await zip.generateAsync({ type: "blob" });
        const arrayBuffer = await rwoov.arrayBuffer();
        return new Response(arrayBuffer, {
            headers: {
                "Content-Type": "application/zip",
                "Content-Disposition": `attachment; filename="${atob('QlBC')}-W-${aojtx ? "Pro-" : ""}configs.zip"`,
            },
        });
    } catch (error) {
        return new Response(`Error generating ZIP file: ${error}`, { status: 500 });
    }
}

export async function bkcez() {
    const kmtmg = __ICON__;
    return new Response(Uint8Array.from(atob(kmtmg), c => c.charCodeAt(0)), {
        headers: {
            'Content-Type': 'image/x-icon',
            'Cache-Control': 'public, max-age=86400',
        }
    });
}

async function aqrzz(request, env) {
    const pwd = await env.S.get('pwd');
    if (pwd) {
        const auth = await jekni(request, env);
        if (!auth) return Response.redirect(`${globalThis.lfzuq}/sign`, 302);
    }

    const encodedHtml = __AHC__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

async function jvynn(request, env) {
    const auth = await jekni(request, env);
    if (auth) return Response.redirect(`${lfzuq}/app`, 302);

    const encodedHtml = __LHC__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

export async function slymt() {
    const encodedHtml = __EHC__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' },
    });
}

export async function mfdkx() {
    const encodedHtml = __PHC__;
    const html = new TextDecoder('utf-8').decode(Uint8Array.from(atob(encodedHtml), c => c.charCodeAt(0)));
    return new Response(html, {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
    });
}

async function pzfgb(request, env) {
    if (request.method === 'POST') {
        const auth = await jekni(request, env);
        if (!auth) return await respond(false, 401, 'Unauthorized.');
        try {
            await dnupd(env);
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