import { xxgkz, moume, ugwvm, gsrxe, bbzbf, uxwpo, dcmlm, ifvza, msupl } from './helpers';
import { nfmif } from '../storage/handlers';

async function vzvnd(xpazn, oidgx) {
    const settings = globalThis.settings;
    const oejgb = settings.eyjft === 'localhost' ? 'system' : `${settings.eyjft}#DIRECT`;
    const uxwpo = (settings.iuixd && !oidgx) || (settings.aczdc && oidgx);
    const eoivz = {
        "enable": true,
        "listen": "0.0.0.0:1053",
        "ipv6": uxwpo,
        "respect-rules": true,
        "use-system-hosts": false,
        "nameserver": [`${oidgx ? '76.76.2.2' : settings.npihj}#Selector`],
        "proxy-server-nameserver": [oejgb],
        "nameserver-policy": {
            "raw.githubusercontent.com": oejgb,
            "time.apple.com": oejgb
        }
    };

    if (settings.dqnol.ifvza && !oidgx) {
        const { ipv4, ipv6, host } = settings.dqnol;
        eoivz["hosts"] = {
            [host]: settings.iuixd ? [...ipv4, ...ipv6] : ipv4
        }
    }

    const dnsHost = msupl(settings.owphv);
    if (dnsHost.isHostDomain) {
        eoivz["nameserver-policy"][dnsHost.host] = oejgb;
    }

    if (xpazn && !oidgx) {
        const zlutm = settings.outProxyParams.server;
        if (ifvza(zlutm)) {
            eoivz["nameserver-policy"][zlutm] = `${settings.npihj}#proxy-1`;
        }
    }

    const routingRules = ntlth();

    settings.tamos.filter(ifvza).forEach(domain => {
        if (!eoivz["hosts"]) eoivz["hosts"] = {};
        eoivz["hosts"][`+.${domain}`] = "127.0.0.1";
    });

    settings.grnqd.filter(ifvza).forEach(domain => {
        eoivz["nameserver-policy"][`+.${domain}`] = `${settings.eyjft}#DIRECT`;
    });

    settings.flmxj.filter(ifvza).forEach(domain => {
        eoivz["nameserver-policy"][`+.${domain}`] = `${settings.owphv}#DIRECT`;
    });

    routingRules
        .filter(({ rule, ruleProvider }) => rule && ruleProvider?.geosite)
        .forEach(({ type, dns, ruleProvider }) => {
            if (type === 'DIRECT') {
                eoivz["nameserver-policy"][`rule-set:${ruleProvider.geosite}`] = dns;
            } else {
                if (!eoivz["hosts"]) eoivz["hosts"] = {};
                eoivz["hosts"][`rule-set:${ruleProvider.geosite}`] = "127.0.0.1";
            }
        });

    const uzrpy = (settings.rmyls && !oidgx) || (settings.yygbp && oidgx);
    if (uzrpy) Object.assign(eoivz, {
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": ["*", "+.lan", "+.local"]
    });

    return eoivz;
}

function nvves(oidgx) {
    const settings = globalThis.settings;
    const routingRules = ntlth();

    settings.tamos.forEach(value => {
        const isDomainValue = ifvza(value);
        routingRules.push({
            rule: true,
            type: 'REJECT',
            domain: isDomainValue ? value : null,
            ip: isDomainValue ? null : value
        });
    });

    const fnoru = [
        ...settings.grnqd,
        ...settings.flmxj
    ];

    fnoru.forEach(value => {
        const isDomainValue = ifvza(value);
        routingRules.push({
            rule: true,
            type: 'DIRECT',
            domain: isDomainValue ? value : null,
            ip: isDomainValue ? null : value
        });
    });

    const ruleProviders = {};
    function addRuleProvider(ruleProvider) {
        const { geosite, geoip, geositeURL, geoipURL, format } = ruleProvider;
        const fileExtension = format === 'text' ? 'txt' : format;

        const defineProvider = (type, behavior, url) => {
            if (!type) return;
            ruleProviders[type] = {
                type: "http",
                format,
                behavior,
                url,
                path: `./ruleset/${type}.${fileExtension}`,
                interval: 86400
            };
        };

        defineProvider(geosite, 'domain', geositeURL);
        defineProvider(geoip, 'ipcidr', geoipURL);
    }

    const groupedRules = new Map();
    routingRules.filter(({ rule }) => rule).forEach(routingRule => {
        const { type, domain, ip, ruleProvider } = routingRule;
        const { geosite, geoip } = ruleProvider || {};
        if (!groupedRules.has(type)) groupedRules.set(type, { domain: [], ip: [], geosite: [], geoip: [] });
        if (domain) groupedRules.get(type).domain.push(domain);
        if (ip) groupedRules.get(type).ip.push(ip);
        if (geosite) groupedRules.get(type).geosite.push(geosite);
        if (geoip) groupedRules.get(type).geoip.push(geoip);
        if (geosite || geoip) addRuleProvider(ruleProvider);
    });

    let rules = [];

    if (settings.hwinp) rules.push(`GEOIP,lan,DIRECT,no-resolve`);

    function eblyk(geosites, geoips, domains, ips, type) {
        if(domains) domains.forEach(domain => rules.push(`DOMAIN-SUFFIX,${domain},${type}`));
        if(geosites) geosites.forEach(geosite => rules.push(`RULE-SET,${geosite},${type}`));
        if (ips) ips.forEach(value => {
            const ipType = dcmlm(value) ? 'IP-CIDR' : 'IP-CIDR6';
            const ip = uxwpo(value) ? value.replace(/\[|\]/g, '') : value;
            const cidr = value.includes('/') ? '' : dcmlm(value) ? '/32' : '/128';
            rules.push(`${ipType},${ip}${cidr},${type},no-resolve`);
        });

        if (geoips) geoips.forEach(geoip => rules.push(`RULE-SET,${geoip},${type}`));
    }

    if (oidgx && settings.vgcfx) rules.push("AND,((NETWORK,udp),(DST-PORT,443)),REJECT");
    if (!oidgx) rules.push("NETWORK,udp,REJECT");

    for (const [type, rule] of groupedRules) {
        const { domain, ip, geosite, geoip } = rule;

        if (domain.length) eblyk(null, null, domain, null, type);
        if (geosite.length) eblyk(geosite, null, null, null, type);
        if (ip.length) eblyk(null, null, null, ip, type);
        if (geoip.length) eblyk(null, geoip, null, null, type);
    }

    rules.push("MATCH,Selector");
    return { rules, ruleProviders };
}

function xrvws(remark, address, port, host, sni, xljwa, allowInsecure) {
    const settings = globalThis.settings;
    const tls = globalThis.dksvm.includes(port) ? true : false;
    const addr = uxwpo(address) ? address.replace(/\[|\]/g, '') : address;
    const path = `/${bbzbf(16)}${xljwa.length ? `/${btoa(xljwa.join(','))}` : ''}`;
    const ipVersion = settings.iuixd ? "dual" : "ipv4";

    const outbound = {
        "name": remark,
        "type": atob('dmxlc3M='),
        "server": addr,
        "port": port,
        "uuid": globalThis.hfruk,
        "packet-encoding": "packetaddr",
        "ip-version": ipVersion,
        "tls": tls,
        "network": "ws",
        "tfo": true,
        "mptcp": true,
        "ws-opts": {
            "path": path,
            "headers": { "Host": host },
            "max-early-data": 15360,
            "early-data-header-name": "Sec-WebSocket-Protocol"
        }
    };

    if (tls) {
        Object.assign(outbound, {
            "servername": sni,
            "alpn": ["h3"],
            "client-fingerprint": "random",
            "skip-cert-verify": allowInsecure
        });
    }

    return outbound;
}

function lmnnl(remark, address, port, host, sni, xljwa, allowInsecure) {
    const settings = globalThis.settings;
    const addr = uxwpo(address) ? address.replace(/\[|\]/g, '') : address;
    const path = `/api${bbzbf(16)}${xljwa.length ? `/${btoa(xljwa.join(','))}` : ''}`;
    const ipVersion = settings.iuixd ? "dual" : "ipv4";

    return {
        "name": remark,
        "type": atob('dHJvamFu'),
        "server": addr,
        "port": port,
        "password": globalThis.ffzll,
        "ip-version": ipVersion,
        "tls": true,
        "network": "ws",
        "tfo": true,
        "mptcp": true,
        "ws-opts": {
            "path": path,
            "headers": { "Host": host },
            "max-early-data": 15360,
            "early-data-header-name": "Sec-WebSocket-Protocol"
        },
        "sni": sni,
        "alpn": ["h3"],
        "client-fingerprint": "random",
        "skip-cert-verify": allowInsecure
    };
}

function tjxkc(ucdin, remark, sbvwg, chain, aojtx) {
    const settings = globalThis.settings;
    const gdsyo = /\[(.*?)\]/;
    const dywnn = /[^:]*$/;
    const aqzje = sbvwg.includes('[') ? sbvwg.match(gdsyo)[1] : sbvwg.split(':')[0];
    const ixoks = sbvwg.includes('[') ? +sbvwg.match(dywnn)[0] : +sbvwg.split(':')[1];
    const ipVersion = settings.aczdc ? "dual" : "ipv4";

    const {
        anqse,
        reserved,
        bwgqa,
        qhjno
    } = moume(ucdin, chain);

    let outbound = {
        "name": remark,
        "type": "wireguard",
        "ip": "172.16.0.2/32",
        "ipv6": anqse,
        "ip-version": ipVersion,
        "private-key": qhjno,
        "server": chain ? "162.159.192.1" : aqzje,
        "port": chain ? 2408 : ixoks,
        "public-key": bwgqa,
        "allowed-ips": ["0.0.0.0/0", "::/0"],
        "reserved": reserved,
        "udp": true,
        "mtu": 1280
    };

    if (chain) outbound["dialer-proxy"] = chain;
    if (aojtx) outbound["amn-wg-option"] = {
        "jc": String(settings.muanl),
        "jmin": String(settings.cubtg),
        "jmax": String(settings.bbdwc)
    }
    return outbound;
}

function uaxsa(chainProxyParams) {
    if (["socks", "http"].includes(chainProxyParams.protocol)) {
        const { protocol, server, port, user, pass } = chainProxyParams;
        const proxyType = protocol === 'socks' ? 'socks5' : protocol;
        return {
            "name": "",
            "type": proxyType,
            "server": server,
            "port": +port,
            "dialer-proxy": "",
            "username": user,
            "password": pass
        };
    }

    const { server, port, uuid, flow, security, type, sni, fp, alpn, pbk, sid, headerType, host, path, serviceName } = chainProxyParams;
    const chainOutbound = {
        "name": "Chain BP",
        "type": atob('dmxlc3M='),
        "server": server,
        "port": +port,
        "udp": true,
        "uuid": uuid,
        "flow": flow,
        "network": type,
        "dialer-proxy": "BP"
    };

    if (security === 'tls') {
        const tofdy = alpn ? alpn?.split(',') : [];
        Object.assign(chainOutbound, {
            "tls": true,
            "servername": sni,
            "alpn": tofdy,
            "client-fingerprint": fp
        });
    }

    if (security === 'reality') Object.assign(chainOutbound, {
        "tls": true,
        "servername": sni,
        "client-fingerprint": fp,
        "reality-opts": {
            "public-key": pbk,
            "short-id": sid
        }
    });

    if (headerType === 'http') {
        const httpPaths = path?.split(',');
        chainOutbound["http-opts"] = {
            "method": "GET",
            "path": httpPaths,
            "headers": {
                "Connection": ["keep-alive"],
                "Content-Type": ["application/octet-stream"]
            }
        };
    }

    if (type === 'ws') {
        const dgqev = path?.split('?ed=')[0];
        const azync = +path?.split('?ed=')[1];
        chainOutbound["ws-opts"] = {
            "path": dgqev,
            "headers": {
                "Host": host
            },
            "max-early-data": azync,
            "early-data-header-name": "Sec-WebSocket-Protocol"
        };
    }

    if (type === 'grpc') chainOutbound["grpc-opts"] = {
        "grpc-service-name": serviceName
    };

    return chainOutbound;
}

async function nchcc(gzgoc, urlTestTags, secondUrlTestTags, xpazn, oidgx, aojtx) {
    const settings = globalThis.settings;
    const config = structuredClone(ffdeh);
    config['dns'] = await vzvnd(xpazn, oidgx);

    const { rules, ruleProviders } = nvves(oidgx);
    config['rules'] = rules;
    config['rule-providers'] = ruleProviders;

    const selector = {
        "name": "Selector",
        "type": "select",
        "proxies": gzgoc
    };

    const urlTest = {
        "name": oidgx ? `W ${aojtx ? 'Pro ' : ''}- BP` : 'BP',
        "type": "url-test",
        "url": "https://www.google.com/generate_204",
        "interval": oidgx ? settings.nzqku : settings.qvwlq,
        "tolerance": 50,
        "proxies": urlTestTags
    };

    config['proxy-groups'].push(selector, urlTest);

    if (oidgx) {
        const secondUrlTest = structuredClone(urlTest);
        secondUrlTest["name"] = `WoW ${aojtx ? 'Pro ' : ''}- BP`;
        secondUrlTest["proxies"] = secondUrlTestTags;
        config['proxy-groups'].push(secondUrlTest);
    }

    return config;
}

export async function yzldz(request, env, aojtx) {
    const { ucdin } = await nfmif(request, env);
    const settings = globalThis.settings;
    const yexar = [], vbyiis = [];
    const outbounds = {
        proxies: [],
        chains: []
    }

    settings.nfbjf.forEach((sbvwg, index) => {
        const fzjat = `${index + 1} - W ${aojtx ? 'Pro ' : ''}`;
        yexar.push(fzjat);

        const vbyii = `${index + 1} - WoW ${aojtx ? 'Pro ' : ''}`;
        vbyiis.push(vbyii);

        const ekbdx = tjxkc(ucdin, fzjat, sbvwg, '', aojtx);
        outbounds.proxies.push(ekbdx);

        const yyfsr = tjxkc(ucdin, vbyii, sbvwg, fzjat);
        outbounds.chains.push(yyfsr);

    });

    const gzgoc = [
        `W ${aojtx ? 'Pro ' : ''}- BP`,
        `WoW ${aojtx ? 'Pro ' : ''}- BP`,
        ...yexar,
        ...vbyiis
    ];

    const config = await nchcc(gzgoc, yexar, vbyiis, true, true, aojtx);
    config['proxies'].push(...outbounds.proxies, ...outbounds.chains);

    return new Response(JSON.stringify(config, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

export async function fqyts(env) {
    const { settings, hostName } = globalThis;
    let ydqma;
    if (settings.mwhpc) {
        try {
            ydqma = uaxsa(settings.outProxyParams);
        } catch (error) {
            console.log('An error occured while parsing chain proxy: ', error);
            ydqma = undefined;
            const fkvzd = await env.S.get("fkvzd", { type: 'json' });
            await env.S.put("fkvzd", JSON.stringify({
                ...fkvzd,
                mwhpc: '',
                outProxyParams: {}
            }));
        }
    }

    let proxyIndex = 1;
    const protocols = [];
    if(settings.plfzn) protocols.push(atob('VkxFU1M='));
    if(settings.zgull) protocols.push(atob('VHJvamFu'));
    const Addresses = await xxgkz(false);
    const tags = [];
    const outbounds = {
        proxies: [],
        chains: []
    };

    protocols.forEach(protocol => {
        let protocolIndex = 1;
        settings.ports.forEach(port => {
            Addresses.forEach(addr => {
                let urzeh, xrsmo;
                const hntcm = settings.ykbpc.includes(addr);
                const dzivc = hntcm ? 'C' : '';
                const sni = hntcm ? settings.tvtiu : gsrxe(hostName);
                const host = hntcm ? settings.mplxc : hostName;
                const tag = ugwvm(protocolIndex, port, addr, settings.urrak, protocol, dzivc).replace(' : ', ' - ');

                if (protocol === atob('VkxFU1M=')) {
                    urzeh = xrvws(
                        ydqma ? `proxy-${proxyIndex}` : tag,
                        addr,
                        port,
                        host,
                        sni,
                        settings.xljwa,
                        hntcm
                    );

                    outbounds.proxies.push(urzeh);
                    tags.push(tag);
                }

                if (protocol === atob('VHJvamFu') && globalThis.dksvm.includes(port)) {
                    xrsmo = lmnnl(
                        ydqma ? `proxy-${proxyIndex}` : tag,
                        addr,
                        port,
                        host,
                        sni,
                        settings.xljwa,
                        hntcm
                    );

                    outbounds.proxies.push(xrsmo);
                    tags.push(tag);
                }


                if (ydqma) {
                    let chain = structuredClone(ydqma);
                    chain['name'] = tag;
                    chain['dialer-proxy'] = `proxy-${proxyIndex}`;
                    outbounds.chains.push(chain);
                }

                proxyIndex++;
                protocolIndex++;
            });
        });
    });

    const gzgoc = ['BP', ...tags];
    const config = await nchcc(gzgoc, tags, null, ydqma, false, false);
    config['proxies'].push(...outbounds.chains, ...outbounds.proxies);

    return new Response(JSON.stringify(config, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

const ffdeh = {
    "mixed-port": 7890,
    "ipv6": true,
    "allow-lan": true,
    "mode": "rule",
    "log-level": "warning",
    "disable-keep-alive": false,
    "keep-alive-idle": 10,
    "keep-alive-interval": 15,
    "unified-delay": false,
    "geo-auto-update": true,
    "geo-update-interval": 168,
    "external-controller": "127.0.0.1:9090",
    "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
    "external-ui": "ui",
    "external-controller-cors": {
        "allow-origins": ["*"],
        "allow-private-network": true
    },
    "profile": {
        "store-selected": true,
        "store-fake-ip": true
    },
    "dns": {},
    "tun": {
        "enable": true,
        "stack": "mixed",
        "auto-route": true,
        "strict-route": true,
        "auto-detect-interface": true,
        "dns-hijack": [
            "any:53",
            "tcp://any:53"
        ],
        "mtu": 9000
    },
    "sniffer": {
        "enable": true,
        "force-dns-mapping": true,
        "parse-pure-ip": true,
        "override-destination": false,
        "sniff": {
            "HTTP": {
                "ports": [80, 8080, 8880, 2052, 2082, 2086, 2095]
            },
            "TLS": {
                "ports": [443, 8443, 2053, 2083, 2087, 2096]
            }
        }
    },
    "proxies": [],
    "proxy-groups": [],
    "rule-providers": {},
    "rules": [],
    "ntp": {
        "enable": true,
        "server": "time.cloudflare.com",
        "port": 123,
        "interval": 30
    }
};

function ntlth() {
    const settings = globalThis.settings;
    const oejgb = settings.eyjft === 'localhost' ? 'system' : `${settings.eyjft}#DIRECT`;
    return [
        {
            rule: true,
            type: 'REJECT',
            ruleProvider: {
                format: "text",
                geosite: "malware",
                geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.txt",
                geoip: "malware-cidr",
                geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware-ip.txt",
            }
        },
        {
            rule: true,
            type: 'REJECT',
            ruleProvider: {
                format: "text",
                geosite: "phishing",
                geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt",
                geoip: "phishing-cidr",
                geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing-ip.txt",
            }
        },
        {
            rule: true,
            type: 'REJECT',
            ruleProvider: {
                format: "text",
                geosite: "cryptominers",
                geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.txt"
            }
        },
        {
            rule: settings.mfios,
            type: 'REJECT',
            ruleProvider: {
                format: "text",
                geosite: "category-ads-all",
                geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt"
            }
        },
        {
            rule: settings.sestc,
            type: 'REJECT',
            ruleProvider: {
                format: "text",
                geosite: "nsfw",
                geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/nsfw.txt",
            }
        },
        // {
        //     rule: hwinp,
        //     type: 'DIRECT',
        //     noResolve: true,
        //     ruleProvider: {
        //         format: "yaml",
        //         geosite: "private",
        //         geoip: "private-cidr",
        //         geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.yaml",
        //         geoipURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.yaml"
        //     }
        // },
        {
            rule: settings.czypj,
            type: 'DIRECT',
            dns: oejgb,
            ruleProvider: {
                format: "text",
                geosite: "ir",
                geoip: "ir-cidr",
                geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
                geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt"
            }
        },
        {
            rule: settings.buvbb,
            type: 'DIRECT',
            dns: oejgb,
            ruleProvider: {
                format: "yaml",
                geosite: "cn",
                geoip: "cn-cidr",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.yaml",
                geoipURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.yaml"
            }
        },
        {
            rule: settings.dbaix,
            type: 'DIRECT',
            dns: oejgb,
            ruleProvider: {
                format: "yaml",
                geosite: "ru",
                geoip: "ru-cidr",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.yaml",
                geoipURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ru.yaml"
            }
        },
        {
            rule: settings.wusgu,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "openai",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml"
            }
        },
        {
            rule: settings.kybqw,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "microsoft",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.yaml"
            }
        },
        {
            rule: settings.kegcg,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "oracle",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/oracle.yaml"
            }
        },
        {
            rule: settings.gnmkl,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "docker",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/docker.yaml"
            }
        },
        {
            rule: settings.bpmhq,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "adobe",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/adobe.yaml"
            }
        },
        {
            rule: settings.lhykb,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "epicgames",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/epicgames.yaml"
            }
        },
        {
            rule: settings.ibcgq,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "intel",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/intel.yaml"
            }
        },
        {
            rule: settings.vgzkc,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "amd",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/amd.yaml"
            }
        },
        {
            rule: settings.diqol,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "nvidia",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/nvidia.yaml"
            }
        },
        {
            rule: settings.fhjyg,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "asus",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/asus.yaml"
            }
        },
        {
            rule: settings.sjtat,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "hp",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/hp.yaml"
            }
        },
        {
            rule: settings.shrnl,
            type: 'DIRECT',
            dns: `${settings.owphv}#DIRECT`,
            ruleProvider: {
                format: "yaml",
                geosite: "lenovo",
                geositeURL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/lenovo.yaml"
            }
        },
    ];
}