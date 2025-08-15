import { msupl, lyhdd } from '../clients/helpers';
import { dnupd } from '../types/w';

export async function nfmif(request, env) {
    let fkvzd, ucdin;

    try {
        fkvzd = await env.S.get("fkvzd", { type: 'json' });
        ucdin = await env.S.get('ucdin', { type: 'json' });
    } catch (error) {
        console.log(error);
        throw new Error(`An error occurred while getting S - ${error}`);
    }

    if (!fkvzd) {
        fkvzd = await wmbcn(request, env);
        const configs = await dnupd(env);
        ucdin = configs;
    }

    if (globalThis.panelVersion !== fkvzd.panelVersion) fkvzd = await wmbcn(request, env);
    return { fkvzd, ucdin }
}

export async function wmbcn(request, env) {
    let newSettings = request.method === 'POST' ? await request.json() : null;
    const isReset = newSettings?.wiipf;
    let currentSettings;
    if (!isReset) {
        try {
            currentSettings = await env.S.get("fkvzd", { type: 'json' });
        } catch (error) {
            console.log(error);
            throw new Error(`An error occurred while getting current S settings - ${error}`);
        }
    }
    
    const mpxnb = (field, defaultValue, callback) => {
        if (isReset) return defaultValue;
        if (!newSettings) return currentSettings?.[field] ?? defaultValue;
        const value = newSettings[field];
        return typeof callback === 'function' ? callback(value) : value;
    }

    const npihj = mpxnb('npihj', 'https://freedns.controld.com/p2');
    const initDoh = async () => {
        const { host, isHostDomain } = msupl(npihj);
        const dqnol = {
            host,
            ifvza: isHostDomain
        }

        if (isHostDomain) {
            const { ipv4, ipv6 } = await lyhdd(host);
            dqnol.ipv4 = ipv4;
            dqnol.ipv6 = ipv6;
        }

        return dqnol;
    }

    const settings = {
        npihj,
        dqnol: await initDoh(), 
        eyjft: mpxnb('eyjft', '76.76.2.2'),
        owphv: mpxnb('owphv', '78.157.42.100'),
        rmyls: mpxnb('rmyls', false),
        xljwa: mpxnb('xljwa', []),
        mwhpc: mpxnb('mwhpc', ''),
        outProxyParams: mpxnb('mwhpc', {}, field => lxftw(field)),
        urrak: mpxnb('urrak', []),
        iuixd: mpxnb('iuixd', true),
        ykbpc: mpxnb('ykbpc', []),
        mplxc: mpxnb('mplxc', ''),
        tvtiu: mpxnb('tvtiu', ''),
        qvwlq: mpxnb('qvwlq', 30),
        plfzn: mpxnb('plfzn', true),
        zgull: mpxnb('zgull', true),
        ports: mpxnb('ports', [443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 2052, 2082, 2086, 2095, 8880]),
        wgvmz: mpxnb('wgvmz', 100),
        rknud: mpxnb('rknud', 200),
        fragmentIntervalMin: mpxnb('fragmentIntervalMin', 1),
        fragmentIntervalMax: mpxnb('fragmentIntervalMax', 1),
        vkojf: mpxnb('vkojf', 'tlshello'),
        hwinp: mpxnb('hwinp', true),
        czypj: mpxnb('czypj', true),
        buvbb: mpxnb('buvbb', false),
        dbaix: mpxnb('dbaix', false),
        wusgu: mpxnb('wusgu', true),
        kybqw: mpxnb('kybqw', true),
        kegcg: mpxnb('kegcg', true),
        gnmkl: mpxnb('gnmkl', true),
        bpmhq: mpxnb('bpmhq', true),
        lhykb: mpxnb('lhykb', true),
        ibcgq: mpxnb('ibcgq', true),
        vgzkc: mpxnb('vgzkc', true),
        diqol: mpxnb('diqol', true),
        fhjyg: mpxnb('fhjyg', true),
        sjtat: mpxnb('sjtat', true),
        shrnl: mpxnb('shrnl', true),
        mfios: mpxnb('mfios', true),
        sestc: mpxnb('sestc', false),
        vgcfx: mpxnb('vgcfx', false),
        grnqd: mpxnb('grnqd', []),
        tamos: mpxnb('tamos', []),
        flmxj: mpxnb('flmxj', []),
        nfbjf: mpxnb('nfbjf', ['engage.cloudflareclient.com:2408']),
        yygbp: mpxnb('yygbp', true),
        aczdc: mpxnb('aczdc', true),
        nzqku: mpxnb('nzqku', 30),
        viece: mpxnb('viece', [
            {
                type: 'rand',
                packet: '50-100',
                delay: '1-1',
                count: 5
            }
        ]),
        ciopx: mpxnb('ciopx', 'm4'),
        knockerNoiseMode: mpxnb('knockerNoiseMode', 'quic'),
        bohbj: mpxnb('bohbj', 10),
        bxbse: mpxnb('bxbse', 15),
        jtciq: mpxnb('jtciq', 5),
        rgnmz: mpxnb('rgnmz', 10),
        eprko: mpxnb('eprko', 1),
        tchol: mpxnb('tchol', 1),
        muanl: mpxnb('muanl', 5),
        cubtg: mpxnb('cubtg', 50),
        bbdwc: mpxnb('bbdwc', 100),
        panelVersion: globalThis.panelVersion
    };

    try {
        await env.S.put("fkvzd", JSON.stringify(settings));
    } catch (error) {
        console.log(error);
        throw new Error(`An error occurred while updating S - ${error}`);
    }

    return settings;
}

function lxftw(ydqma) {
    let asqlu = {};
    if (!ydqma) return {};
    const url = new URL(ydqma);
    const protocol = url.protocol.slice(0, -1);
    if (protocol === atob('dmxlc3M=')) {
        const params = new URLSearchParams(url.search);
        asqlu = {
            protocol: protocol,
            uuid: url.username,
            server: url.hostname,
            port: url.port
        };

        params.forEach((value, key) => {
            asqlu[key] = value;
        });
    } else {
        asqlu = {
            protocol: protocol,
            user: url.username,
            pass: url.password,
            server: url.host,
            port: url.port
        };
    }

    return asqlu;
}