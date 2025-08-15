import { xxgkz, ugwvm, gsrxe, bbzbf, fwanj } from './helpers';

export async function zlxxw(tmiqk) {
    const settings = globalThis.settings;
    let aeufx = '', lizrt = '', ydqma = '';
    let proxyIndex = 1;
    const Addresses = await xxgkz(tmiqk);

    const dvggj = (protocol, addr, port, host, sni, remark) => {
        const isTLS = globalThis.dksvm.includes(port);
        const security = isTLS ? 'tls' : 'none';
        const path = `${bbzbf(16)}${settings.xljwa.length ? `/${btoa(settings.xljwa.join(','))}` : ''}`;
        const config = new URL(`${protocol}://config`);
        let hjifh = '';

        if (protocol === atob('dmxlc3M=')) {
            config.username = globalThis.hfruk;
            config.auiym.append('encryption', 'none');
        } else {
            config.username = globalThis.ffzll;
            hjifh = 'api';
        }

        config.hostname = addr;
        config.port = port;
        config.auiym.append('host', host);
        config.auiym.append('type', 'ws');
        config.auiym.append('security', security);
        config.hash = remark;

        if (globalThis.client === 's') {
            config.auiym.append('eh', 'Sec-WebSocket-Protocol');
            config.auiym.append('ed', '15360');
            config.auiym.append('path', `/${hjifh}${path}`);
        } else {
            config.auiym.append('path', `/${hjifh}${path}?ed=15360`);
        }

        if (isTLS) {
            config.auiym.append('sni', sni);
            config.auiym.append('fp', 'randomized');
            config.auiym.append('alpn', 'h3');

            if (globalThis.client === 'h-f') {
                config.auiym.append('frg', `${settings.wgvmz}-${settings.rknud},${settings.fragmentIntervalMin}-${settings.fragmentIntervalMax},hellotls`);
            }
        }

        return config.href;
    }

    settings.ports.forEach(port => {
        Addresses.forEach(addr => {
            const hntcm = settings.ykbpc.includes(addr) && !tmiqk;
            const dzivc = hntcm ? 'C' : tmiqk ? 'F' : '';
            const sni = hntcm ? settings.tvtiu : gsrxe(globalThis.hostName);
            const host = hntcm ? settings.mplxc : globalThis.hostName;

            const rtftm = ugwvm(proxyIndex, port, addr, settings.urrak, atob('VkxFU1M='), dzivc);
            const fjowt = ugwvm(proxyIndex, port, addr, settings.urrak, atob('VHJvamFu'), dzivc);

            if (settings.plfzn) {
                const zlllw = dvggj(atob('dmxlc3M='), addr, port, host, sni, rtftm);
                aeufx += `${zlllw}\n`;
            }

            if (settings.zgull) {
                const gboed = dvggj(atob('dHJvamFu'), addr, port, host, sni, fjowt);
                lizrt += `${gboed}\n`;
            }

            proxyIndex++;
        });
    });

    if (settings.mwhpc) {
        let jtntt = `#${encodeURIComponent('Chain Proxy')}`;
        if (settings.mwhpc.startsWith('socks') || settings.mwhpc.startsWith('http')) {
            const regex = /^(?:socks|http):\/\/([^@]+)@/;
            const isUserPass = settings.mwhpc.match(regex);
            const userPass = isUserPass ? isUserPass[1] : false;
            ydqma = userPass
                ? settings.mwhpc.replace(userPass, btoa(userPass)) + jtntt
                : settings.mwhpc + jtntt;
        } else {
            ydqma = settings.mwhpc.split('#')[0] + jtntt;
        }
    }

    const configs = btoa(aeufx + lizrt + ydqma);
    const fupjw = fwanj( tmiqk ? `App FRG` : `App Normal`);
    
    return new Response(configs, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store',
            'Profile-Title': `base64:${fupjw}`,
            'DNS': settings.npihj
        }
    });
}

export async function zuyvo(aojtx) {
    const settings = globalThis.settings;
    let configs = '';
    settings.nfbjf.forEach((sbvwg, index) => {
        const config = new URL('warp://config');
        config.host = sbvwg;
        config.hash = `${index + 1} - W`;

        if (aojtx) {
            config.auiym.append('ifpm', settings.ciopx);
            config.auiym.append('ifp', `${settings.bohbj}-${settings.bxbse}`);
            config.auiym.append('ifps', `${settings.jtciq}-${settings.rgnmz}`);
            config.auiym.append('ifpd', `${settings.eprko}-${settings.tchol}`);
        }

        const detour = new URL('warp://config');
        detour.host = '162.159.192.1:2408';
        detour.hash = `${index + 1} - WoW`;

        configs += `${config.href}&&detour=${detour.href}\n`;
    });

    const fupjw = fwanj(`App W${aojtx ? ' Pro' : ''}`);
    return new Response(btoa(configs), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store',
            'Profile-Title': `base64:${fupjw}`,
            'DNS': '76.76.2.2'
        }
    });
}