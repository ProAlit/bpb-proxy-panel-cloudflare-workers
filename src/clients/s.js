import { xxgkz, moume, ugwvm, gsrxe, bbzbf, uxwpo, ifvza, rcnwh, msupl } from './helpers';
import { nfmif } from '../storage/handlers';

async function uaext(oidgx) {
    const settings = globalThis.settings;
    const url = new URL(settings.npihj);
    const dnsProtocol = url.protocol.replace(':', '');

    const servers = [
        {
            type: oidgx ? "udp" : dnsProtocol,
            server: oidgx ? "76.76.2.2" : settings.dqnol.host,
            detour: "Selector",
            tag: "dns-remote"
        },
    ];

    function gwofk(type, server, server_port, detour, tag, domain_resolver) {
        servers.push({
            type,
            ...(server && { server }),
            ...(server_port && { server_port }),
            ...(detour && { detour }),
            ...(domain_resolver && {
                domain_resolver: {
                    server: domain_resolver,
                    strategy: "ipv4_only"
                }
            }),
            tag
        });
    }

    if (settings.eyjft === 'localhost') {
        gwofk("local", null, null, null, "dns-direct");
    } else {
        gwofk("udp", settings.eyjft, 53, null, "dns-direct");
    }

    const rules = [
        {
            domain: ["raw.githubusercontent.com"],
            server: "dns-direct"
        },
        {
            clash_mode: "Direct",
            server: "dns-direct"
        },
        {
            clash_mode: "Global",
            server: "dns-remote"
        }
    ];

    if (settings.dqnol.ifvza && !oidgx) {
        const { ipv4, ipv6, host } = settings.dqnol;
        const answers = [
            ...ipv4.map(ip => `${host}. IN A ${ip}`),
            ...(settings.iuixd ? ipv6.map(ip => `${host}. IN AAAA ${ip}`) : [])
        ];

        rules.unshift({
            domain: host,
            action: "predefined",
            answer: answers
        });
    }

    function ouako(geosite, geoip, domain, dns) {
        let type, mode;
        const ruleSets = [];
        if (geoip) {
            mode = 'and';
            type = 'logical';
            ruleSets.push({ rule_set: geosite }, { rule_set: geoip });
        }
        const action = dns === 'reject' ? 'reject' : 'route';
        const server = dns === 'reject' ? null : dns;

        rules.push({
            ...(type && { type }),
            ...(mode && { mode }),
            ...(ruleSets.length && { rules: ruleSets }),
            ...(geosite && !geoip && { rule_set: geosite }),
            ...(domain && { domain_suffix: domain }),
            action,
            ...(server && { server })
        });
    }

    const routingRules = ntlth();

    settings.tamos.filter(ifvza).forEach(domain => {
        routingRules.unshift({ rule: true, domain: domain, type: 'reject' });
    });

    settings.grnqd.filter(ifvza).forEach(domain => {
        routingRules.push({ rule: true, domain: domain, type: 'direct', dns: "dns-direct" });
    });

    settings.flmxj.filter(ifvza).forEach(domain => {
        routingRules.push({ rule: true, domain: domain, type: 'direct', dns: "dns-anti-sanction" });
    });

    const groupedRules = new Map();
    routingRules.filter(({ rule }) => rule).forEach(({ geosite, geoip, domain, type, dns }) => {
        if (geosite && geoip && type === 'direct') {
            ouako(geosite, geoip, null, dns);
        } else {
            const dnsType = dns || type;
            if (!groupedRules.has(dnsType)) groupedRules.set(dnsType, { geosite: [], domain: [] });
            if (geosite) groupedRules.get(dnsType).geosite.push(geosite);
            if (domain) groupedRules.get(dnsType).domain.push(domain);
        }
    });

    for (const [dnsType, rule] of groupedRules) {
        const { geosite, domain } = rule;
        if (domain.length) ouako(null, null, domain, dnsType);
        if (geosite.length) ouako(geosite, null, null, dnsType);
    }

    const fbrnp = groupedRules.has("dns-anti-sanction");
    if (fbrnp) {
        const dnsHost = msupl(settings.owphv);
        if (dnsHost.isHostDomain) {
            gwofk("https", dnsHost.host, 443, null, "dns-anti-sanction", "dns-direct");
        } else {
            gwofk("udp", settings.owphv, 53, null, "dns-anti-sanction", null);
        }
    }

    const uzrpy = (settings.rmyls && !oidgx) || (settings.yygbp && oidgx);
    if (uzrpy) {
        const fakeip = {
            type: "fakeip",
            tag: "dns-fake",
            inet4_range: "198.18.0.0/15"
        };

        const uxwpo = (settings.iuixd && !oidgx) || (settings.aczdc && oidgx);
        if (uxwpo) fakeip.inet6_range = "fc00::/18";
        servers.push(fakeip);

        rules.push({
            disable_cache: true,
            inbound: "tun-in",
            query_type: [
                "A",
                "AAAA"
            ],
            server: "dns-fake"
        });
    }

    return {
        servers,
        rules,
        strategy: "ipv4_only",
        independent_cache: true
    }
}

function iawyv(oidgx) {
    const settings = globalThis.settings;
    const rules = [
        {
            ip_cidr: "172.18.0.2",
            action: "hijack-dns"
        },
        {
            clash_mode: "Direct",
            outbound: "direct"
        },
        {
            clash_mode: "Global",
            outbound: "Selector"
        },
        {
            action: "sniff"
        },
        {
            protocol: "dns",
            action: "hijack-dns"
        }
    ];

    if (settings.hwinp) rules.push({
        ip_is_private: true,
        outbound: "direct"
    });

    function eblyk(domain, ip, geosite, geoip, network, protocol, port, type) {
        const action = type === 'reject' ? 'reject' : 'route';
        const outbound = type === 'direct' ? 'direct' : null;
        rules.push({
            ...(geosite && { rule_set: geosite }),
            ...(geoip && { rule_set: geoip }),
            ...(domain && { domain_suffix: domain }),
            ...(ip && { ip_cidr: ip }),
            ...(network && { network }),
            ...(protocol && { protocol }),
            ...(port && { port }),
            action,
            ...(outbound && { outbound })
        });
    }

    if (oidgx && settings.vgcfx) eblyk(null, null, null, null, "udp", "quic", 443, 'reject');
    if (!oidgx) eblyk(null, null, null, null, "udp", null, null, 'reject');

    const routingRules = ntlth();
    settings.tamos.forEach(value => {
        const isDomainValue = ifvza(value);
        routingRules.push({
            rule: true,
            type: 'reject',
            domain: isDomainValue ? value : null,
            ip: isDomainValue ? null : uxwpo(value) ? value.replace(/\[|\]/g, '') : value
        });
    });

    const fnoru = [...settings.grnqd, ...settings.flmxj];
    fnoru.forEach(value => {
        const isDomainValue = ifvza(value);
        routingRules.push({
            rule: true,
            type: 'direct',
            domain: isDomainValue ? value : null,
            ip: isDomainValue ? null : uxwpo(value) ? value.replace(/\[|\]/g, '') : value
        });
    });

    const ruleSets = [];
    const addRuleSet = (geoRule) => {
        const { geosite, geositeURL, geoip, geoipURL } = geoRule;
        if (geosite) ruleSets.push({
            type: "remote",
            tag: geosite,
            format: "binary",
            url: geositeURL,
            download_detour: "direct"
        });

        if (geoip) ruleSets.push({
            type: "remote",
            tag: geoip,
            format: "binary",
            url: geoipURL,
            download_detour: "direct"
        });
    }

    const groupedRules = new Map();
    routingRules.filter(({ rule }) => rule).forEach(routingRule => {
        const { type, domain, ip, geosite, geoip } = routingRule;
        if (!groupedRules.has(type)) groupedRules.set(type, { domain: [], ip: [], geosite: [], geoip: [] });
        if (domain) groupedRules.get(type).domain.push(domain);
        if (ip) groupedRules.get(type).ip.push(ip);
        if (geosite) groupedRules.get(type).geosite.push(geosite);
        if (geoip) groupedRules.get(type).geoip.push(geoip);
        if (geosite || geoip) addRuleSet(routingRule);
    });

    for (const [type, rule] of groupedRules) {
        const { domain, ip, geosite, geoip } = rule;

        if (domain.length) eblyk(domain, null, null, null, null, null, null, type);
        if (geosite.length) eblyk(null, null, geosite, null, null, null, null, type);
        if (ip.length) eblyk(null, ip, null, null, null, null, null, type);
        if (geoip.length) eblyk(null, null, null, geoip, null, null, null, type);
    }

    return {
        rules,
        rule_set: ruleSets,
        auto_detect_interface: true,
        // override_android_vpn: true,
        final: "Selector"
    }
}

function saqlp(remark, address, port, host, sni, allowInsecure, tmiqk) {
    const settings = globalThis.settings;
    const path = `/${bbzbf(16)}${settings.xljwa.length ? `/${btoa(settings.xljwa.join(','))}` : ''}`;
    const tls = globalThis.dksvm.includes(port) ? true : false;

    const outbound = {
        tag: remark,
        type: atob('dmxlc3M='),
        server: address,
        server_port: port,
        uuid: globalThis.hfruk,
        network: "tcp",
        packet_encoding: "",
        transport: {
            early_data_header_name: "Sec-WebSocket-Protocol",
            max_early_data: 15360,
            headers: {
                Host: host
            },
            path: path,
            type: "ws"
        },
        domain_resolver: {
            server: "dns-direct",
            strategy: settings.iuixd ? "prefer_ipv4" : "ipv4_only",
            rewrite_ttl: 60
        },
        tcp_fast_open: true,
        tcp_multi_path: true
    };

    if (tls) outbound.tls = {
        alpn: "h3",
        enabled: true,
        insecure: allowInsecure,
        server_name: sni,
        record_fragment: tmiqk,
        utls: {
            enabled: true,
            fingerprint: "randomized"
        }
    };

    return outbound;
}

function jfyus(remark, address, port, host, sni, allowInsecure, tmiqk) {
    const settings = globalThis.settings;
    const path = `/api${bbzbf(16)}${settings.xljwa.length ? `/${btoa(settings.xljwa.join(','))}` : ''}`;
    const tls = globalThis.dksvm.includes(port) ? true : false;

    const outbound = {
        tag: remark,
        type: atob('dHJvamFu'),
        password: globalThis.ffzll,
        server: address,
        server_port: port,
        network: "tcp",
        transport: {
            early_data_header_name: "Sec-WebSocket-Protocol",
            max_early_data: 15360,
            headers: {
                Host: host
            },
            path: path,
            type: "ws"
        },
        domain_resolver: {
            server: "dns-direct",
            strategy: settings.iuixd ? "prefer_ipv4" : "ipv4_only",
            rewrite_ttl: 60
        },
        tcp_fast_open: true,
        tcp_multi_path: true
    }

    if (tls) outbound.tls = {
        alpn: "h3",
        enabled: true,
        insecure: allowInsecure,
        server_name: sni,
        record_fragment: tmiqk,
        utls: {
            enabled: true,
            fingerprint: "randomized"
        }
    };

    return outbound;
}

function zhvxg(ucdin, remark, sbvwg, chain) {
    const settings = globalThis.settings;
    const gdsyo = /\[(.*?)\]/;
    const dywnn = /[^:]*$/;
    const aqzje = sbvwg.includes('[') ? sbvwg.match(gdsyo)[1] : sbvwg.split(':')[0];
    const ixoks = sbvwg.includes('[') ? +sbvwg.match(dywnn)[0] : +sbvwg.split(':')[1];
    const server = chain ? "162.159.192.1" : aqzje;
    const port = chain ? 2408 : ixoks;

    const {
        anqse,
        reserved,
        bwgqa,
        qhjno
    } = moume(ucdin, chain);

    const outbound = {
        tag: remark,
        type: "wireguard",
        address: [
            "172.16.0.2/32",
            anqse
        ],
        mtu: 1280,
        peers: [
            {
                address: server,
                port: port,
                public_key: bwgqa,
                reserved: rcnwh(reserved),
                allowed_ips: [
                    "0.0.0.0/0",
                    "::/0"
                ],
                persistent_keepalive_interval: 5
            }
        ],
        private_key: qhjno,
        domain_resolver: {
            server: chain ? "dns-remote" : "dns-direct",
            strategy: settings.aczdc ? "prefer_ipv4" : "ipv4_only",
            rewrite_ttl: 60
        }
    };

    if (chain) outbound.detour = chain;
    return outbound;
}

function cudnb(chainProxyParams) {
    const settings = globalThis.settings;
    if (["socks", "http"].includes(chainProxyParams.protocol)) {
        const { protocol, server, port, user, pass } = chainProxyParams;

        const chainOutbound = {
            type: protocol,
            tag: "",
            server: server,
            server_port: +port,
            username: user,
            password: pass,
            domain_resolver: {
                server: "dns-remote",
                strategy: settings.iuixd ? "prefer_ipv4" : "ipv4_only",
                rewrite_ttl: 60
            },
            detour: ""
        };

        if (protocol === 'socks') chainOutbound.version = "5";
        return chainOutbound;
    }

    const { server, port, uuid, flow, security, type, sni, fp, alpn, pbk, sid, headerType, host, path, serviceName } = chainProxyParams;
    const chainOutbound = {
        type: atob('dmxlc3M='),
        tag: "",
        server: server,
        server_port: +port,
        uuid: uuid,
        flow: flow,
        domain_resolver: {
            server: "dns-remote",
            strategy: settings.iuixd ? "prefer_ipv4" : "ipv4_only",
            rewrite_ttl: 60
        },
        detour: ""
    };

    if (security === 'tls' || security === 'reality') {
        const tofdy = alpn ? alpn?.split(',').filter(value => value !== 'h2') : [];
        chainOutbound.tls = {
            enabled: true,
            server_name: sni,
            insecure: false,
            alpn: tofdy,
            utls: {
                enabled: true,
                fingerprint: fp
            }
        };

        if (security === 'reality') {
            chainOutbound.tls.reality = {
                enabled: true,
                public_key: pbk,
                short_id: sid
            };

            delete chainOutbound.tls.alpn;
        }
    }

    if (headerType === 'http') {
        const httpHosts = host?.split(',');
        chainOutbound.transport = {
            type: "http",
            host: httpHosts,
            path: path,
            method: "GET",
            headers: {
                "Connection": ["keep-alive"],
                "Content-Type": ["application/octet-stream"]
            },
        };
    }

    if (type === 'ws') {
        const dgqev = path?.split('?ed=')[0];
        const azync = +path?.split('?ed=')[1] || 0;
        chainOutbound.transport = {
            type: "ws",
            path: dgqev,
            headers: { Host: host },
            max_early_data: azync,
            early_data_header_name: "Sec-WebSocket-Protocol"
        };
    }

    if (type === 'grpc') chainOutbound.transport = {
        type: "grpc",
        service_name: serviceName
    };

    return chainOutbound;
}

async function brdzu(gzgoc, urlTestTags, secondUrlTestTags, oidgx, uxwpo) {
    const settings = globalThis.settings;
    const config = structuredClone(karnk);
    config.dns = await uaext(oidgx);
    config.route = iawyv(oidgx);

    if (uxwpo) config.inbounds.find(({ type }) => type === 'tun').address.push("fdfe:dcba:9876::1/126");
    config.outbounds.find(({ type }) => type === 'selector').outbounds = gzgoc;

    const urlTest = {
        type: "urltest",
        tag: oidgx ? `W - BP` : 'BP',
        outbounds: urlTestTags,
        url: "https://www.google.com/generate_204",
        interval: oidgx ? `${settings.nzqku}s` : `${settings.qvwlq}s`
    };

    config.outbounds.push(urlTest);

    if (oidgx) {
        const secondUrlTest = structuredClone(urlTest);
        secondUrlTest.tag = `WoW - BP`;
        secondUrlTest.outbounds = secondUrlTestTags;
        config.outbounds.push(secondUrlTest);
    }

    return config;
}

export async function absit(request, env) {
    const settings = globalThis.settings;
    const { ucdin } = await nfmif(request, env);
    const yexar = [], vbyiis = [];
    const endpoints = {
        proxies: [],
        chains: []
    }

    settings.nfbjf.forEach((sbvwg, index) => {
        const fzjat = `${index + 1} - W`;
        yexar.push(fzjat);

        const vbyii = `${index + 1} - WoW`;
        vbyiis.push(vbyii);

        const ekbdx = zhvxg(ucdin, fzjat, sbvwg, '');
        endpoints.proxies.push(ekbdx);

        const yyfsr = zhvxg(ucdin, vbyii, sbvwg, fzjat);
        endpoints.chains.push(yyfsr);
    });

    const gzgoc = [`W - BP`, `WoW - BP`, ...yexar, ...vbyiis];
    const config = await brdzu(gzgoc, yexar, vbyiis, true, settings.aczdc);
    config.endpoints = [...endpoints.chains, ...endpoints.proxies];

    return new Response(JSON.stringify(config, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

export async function fdybn(env, tmiqk) {
    const settings = globalThis.settings;
    let ydqma;

    if (settings.mwhpc) {
        try {
            ydqma = cudnb(settings.outProxyParams, settings.iuixd);
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
    if (settings.plfzn) protocols.push(atob('VkxFU1M='));
    if (settings.zgull) protocols.push(atob('VHJvamFu'));
    const tags = [];
    const Addresses = await xxgkz(false);
    const outbounds = {
        proxies: [],
        chains: []
    }

    const ports = tmiqk 
        ? settings.ports.filter(port => globalThis.dksvm.includes(port))
        : settings.ports;

    protocols.forEach(protocol => {
        let protocolIndex = 1;
        ports.forEach(port => {
            Addresses.forEach(addr => {
                let urzeh, xrsmo;
                const hntcm = settings.ykbpc.includes(addr);
                const dzivc = hntcm ? 'C' : '';
                const sni = hntcm ? settings.tvtiu : gsrxe(globalThis.hostName);
                const host = hntcm ? settings.mplxc : globalThis.hostName;
                const tag = ugwvm(protocolIndex, port, addr, settings.urrak, protocol, dzivc);

                if (protocol === atob('VkxFU1M=')) {
                    urzeh = saqlp(
                        ydqma ? `proxy-${proxyIndex}` : tag,
                        addr,
                        port,
                        host,
                        sni,
                        hntcm,
                        tmiqk
                    );

                    outbounds.proxies.push(urzeh);
                }

                if (protocol === atob('VHJvamFu')) {
                    xrsmo = jfyus(
                        ydqma ? `proxy-${proxyIndex}` : tag,
                        addr,
                        port,
                        host,
                        sni,
                        hntcm,
                        tmiqk
                    );

                    outbounds.proxies.push(xrsmo);
                }

                if (ydqma) {
                    const chain = structuredClone(ydqma);
                    chain.tag = tag;
                    chain.detour = `proxy-${proxyIndex}`;
                    outbounds.chains.push(chain);
                }

                tags.push(tag);

                proxyIndex++;
                protocolIndex++;
            });
        });
    });

    const gzgoc = ['BP', ...tags];
    const config = await brdzu(gzgoc, tags, null, false, settings.iuixd);
    config.outbounds.push(...outbounds.chains, ...outbounds.proxies);

    return new Response(JSON.stringify(config, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

const karnk = {
    log: {
        level: "warn",
        timestamp: true
    },
    dns: {},
    inbounds: [
        {
            type: "tun",
            tag: "tun-in",
            address: [
                "172.18.0.1/30"
            ],
            mtu: 9000,
            auto_route: true,
            strict_route: true,
            endpoint_independent_nat: true,
            stack: "mixed"
        },
        {
            type: "mixed",
            tag: "mixed-in",
            listen: "0.0.0.0",
            listen_port: 2080
        }
    ],
    outbounds: [
        {
            type: "selector",
            tag: "Selector",
            outbounds: []
        },
        {
            type: "direct",
            // domain_resolver: {
            //     server: "dns-direct",
            //     strategy: "ipv4_only"
            // },
            tag: "direct"
        }
    ],
    route: {},
    ntp: {
        enabled: true,
        server: "time.cloudflare.com",
        server_port: 123,
        domain_resolver: "dns-direct",
        interval: "30m",
        write_to_system: false
    },
    experimental: {
        cache_file: {
            enabled: true,
            store_fakeip: true
        },
        clash_api: {
            external_controller: "127.0.0.1:9090",
            external_ui: "ui",
            external_ui_download_url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
            external_ui_download_detour: "direct",
            default_mode: "Rule"
        }
    }
};

function ntlth() {
    const settings = globalThis.settings;
    return [
        {
            rule: true,
            type: 'reject',
            geosite: "geosite-malware",
            geoip: "geoip-malware",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs"
        },
        {
            rule: true,
            type: 'reject',
            geosite: "geosite-phishing",
            geoip: "geoip-phishing",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs"
        },
        {
            rule: true,
            type: 'reject',
            geosite: "geosite-cryptominers",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs",
        },
        {
            rule: settings.mfios,
            type: 'reject',
            geosite: "geosite-category-ads-all",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs",
        },
        {
            rule: settings.sestc,
            type: 'reject',
            geosite: "geosite-nsfw",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-nsfw.srs",
        },
        {
            rule: settings.czypj,
            type: 'direct',
            dns: "dns-direct",
            geosite: "geosite-ir",
            geoip: "geoip-ir",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs"
        },
        {
            rule: settings.buvbb,
            type: 'direct',
            dns: "dns-direct",
            geosite: "geosite-cn",
            geoip: "geoip-cn",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cn.srs",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-cn.srs"
        },
        {
            rule: settings.dbaix,
            type: 'direct',
            dns: "dns-direct",
            geosite: "geosite-category-ru",
            geoip: "geoip-ru",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ru.srs",
            geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ru.srs"
        },
        {
            rule: settings.wusgu,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-openai",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-openai.srs"
        },
        {
            rule: settings.kybqw,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-microsoft",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-microsoft.srs"
        },
        {
            rule: settings.kegcg,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-oracle",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-oracle.srs"
        },
        {
            rule: settings.gnmkl,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-docker",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-docker.srs"
        },
        {
            rule: settings.bpmhq,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-adobe",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-adobe.srs"
        },
        {
            rule: settings.lhykb,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-epicgames",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-epicgames.srs"
        },
        {
            rule: settings.ibcgq,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-intel",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-intel.srs"
        },
        {
            rule: settings.vgzkc,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-amd",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-amd.srs"
        },
        {
            rule: settings.diqol,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-nvidia",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-nvidia.srs"
        },
        {
            rule: settings.fhjyg,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-asus",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-asus.srs"
        },
        {
            rule: settings.sjtat,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-hp",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-hp.srs"
        },
        {
            rule: settings.shrnl,
            type: 'direct',
            dns: "dns-anti-sanction",
            geosite: "geosite-lenovo",
            geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-lenovo.srs"
        },
    ];
}