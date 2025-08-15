import { xxgkz, moume, rcnwh, ugwvm, gsrxe, bbzbf, lyhdd, ifvza, msupl } from './helpers';
import { nfmif } from '../storage/handlers';

async function smhfy(outboundAddrs, wbyvq, csnfe, oidgx, customDns, wyovm) {
    const settings = globalThis.settings;
    function adjtl(address, domains, expectIPs, skipFallback, tag) {
        return {
            address,
            ...(domains && { domains }),
            ...(expectIPs && { expectIPs }),
            ...(skipFallback && { skipFallback }),
            ...(tag && { tag })
        };
    }

    const dnsHost = {};
    if (settings.dqnol.ifvza && !csnfe && !oidgx) {
        const { ipv4, ipv6, host } = settings.dqnol;
        dnsHost[host] = settings.iuixd ? [...ipv4, ...ipv6] : ipv4;
    }

    const routingRules = ntlth();
    const blockRules = routingRules.filter(({ type }) => type === 'block');

    settings.tamos.filter(ifvza).forEach(domain => {
        blockRules.push({ rule: true, domain });
    });

    blockRules.filter(({ rule }) => rule).forEach(({ domain }) => {
        dnsHost[domain] = ["127.0.0.1"];
    });

    const wspfh = wbyvq ? await lyhdd(wbyvq) : undefined;
    if (wspfh) dnsHost[wbyvq] = settings.iuixd
        ? [...wspfh.ipv4, ...wspfh.ipv6]
        : wspfh.ipv4;

    const hosts = Object.keys(dnsHost).length ? { hosts: dnsHost } : {};
    const uxwpo = (settings.iuixd && !oidgx) || (settings.aczdc && oidgx);
    const eoivz = {
        ...hosts,
        servers: [],
        queryStrategy: uxwpo ? "UseIP" : "UseIPv4",
        tag: "dns",
    };

    let skipFallback = true;
    let tgqty = oidgx ? "1.1.1.1" : settings.npihj;

    if (csnfe) {
        if (!eoivz.hosts) eoivz.hosts = {};
        tgqty = `https://${customDns}/dns-query`;
        eoivz.hosts[customDns] = wyovm;
        skipFallback = false;
        eoivz.disableFallback = true;
    }

    const dknyk = adjtl(tgqty, null, null, null, "remote-dns");
    eoivz.servers.push(dknyk);

    const fnoru = routingRules.filter(({ type }) => type === 'direct');
    if (ifvza(wyovm?.[0])) fnoru.push({ rule: true, domain: `full:${wyovm[0]}`, dns: settings.eyjft });

    outboundAddrs.filter(ifvza).forEach(domain => {
        fnoru.push({ rule: true, domain: `full:${domain}`, dns: settings.eyjft });
    });

    settings.grnqd.filter(ifvza).forEach(domain => {
        fnoru.push({ rule: true, domain: `domain:${domain}`, dns: settings.eyjft });
    });

    settings.flmxj.filter(ifvza).forEach(domain => {
        fnoru.push({ rule: true, domain: `domain:${domain}`, dns: settings.owphv });
    });

    const { host, isHostDomain } = msupl(settings.owphv);
    if (isHostDomain) {
        fnoru.push({ rule: true, domain: `full:${host}`, dns: settings.eyjft });
    }

    const totalDomainRules = [];
    const zmeyt = new Map();
    fnoru.filter(({ rule }) => rule).forEach(({ domain, ip, dns }) => {
        if (ip) {
            const server = adjtl(dns, [domain], ip ? [ip] : null, skipFallback);
            eoivz.servers.push(server);
        } else {
            if (!zmeyt.has(dns)) zmeyt.set(dns, []);
            zmeyt.get(dns).push(domain)
        }
        
        if (domain) totalDomainRules.push(domain);
    });

    for (const [dns, domain] of zmeyt) {
        if (domain.length) {
            const server = adjtl(dns, domain, null, skipFallback);
            eoivz.servers.push(server);
        }
    }

    const uzrpy = (settings.rmyls && !oidgx) || (settings.yygbp && oidgx);
    if (uzrpy) {
        const hgfpk = totalDomainRules.length
            ? adjtl("fakedns", totalDomainRules, null, false)
            : "fakedns";
        eoivz.servers.unshift(hgfpk);
    }

    return eoivz;
}

function cousb(xpazn, isBalancer, csnfe, oidgx) {
    const settings = globalThis.settings;
    const rules = [
        {
            inboundTag: [
                "dns-in"
            ],
            outboundTag: "dns-out",
            type: "field"
        }
    ];

    function eblyk(inboundTag, domain, ip, port, network, outboundTag, isBalancer) {
        rules.push({
            ...(inboundTag && { inboundTag }),
            ...(domain && { domain }),
            ...(ip && { ip }),
            ...(port && { port }),
            ...(network && { network }),
            ...(isBalancer
                ? { balancerTag: outboundTag }
                : { outboundTag }),
            type: "field"
        });
    }

    const ikidy = xpazn ? "chain" : csnfe ? "frg" : "proxy";
    const outTag = isBalancer ? "all" : ikidy;
    // const remoteDnsServers = csnfe ? ["remote-dns", "remote-dns-ydmzk"] : ["remote-dns"];
    eblyk(["remote-dns"], null, null, null, null, outTag, isBalancer);
    eblyk(["dns"], null, null, null, null, "direct");

    if (settings.hwinp) {
        eblyk(null, ["geosite:private"], null, null, null, "direct");
        eblyk(null, null, ["geoip:private"], null, null, "direct");
    }

    if (oidgx && settings.vgcfx) eblyk(null, null, null, 443, "udp", "block");

    const routingRules = ntlth();

    const fnoru = [...settings.grnqd, ...settings.flmxj];
    fnoru.forEach(value => {
        const isDomainValue = ifvza(value);
        routingRules.push({
            rule: true,
            type: 'direct',
            domain: isDomainValue ? `domain:${value}` : null,
            ip: isDomainValue ? null : value
        });
    });

    settings.tamos.forEach(value => {
        const isDomainValue = ifvza(value);
        routingRules.push({
            rule: true,
            type: 'block',
            domain: isDomainValue ? `domain:${value}` : null,
            ip: isDomainValue ? null : value
        });
    });

    const groupedRules = new Map();
    routingRules.filter(({ rule }) => rule).forEach(({ type, domain, ip }) => {
        if (!groupedRules.has(type)) groupedRules.set(type, { domain: [], ip: [] });
        if (domain) groupedRules.get(type).domain.push(domain);
        if (ip) groupedRules.get(type).ip.push(ip);
    });

    for (const [type, rule] of groupedRules) {
        const { domain, ip } = rule;
        if (domain.length) eblyk(null, domain, null, null, null, type, null);
        if (ip.length) eblyk(null, null, ip, null, null, type, null);
    }

    if (!oidgx && !csnfe) eblyk(null, null, null, null, "udp", "block", null);

    let network;
    if (isBalancer) {
        network = oidgx ? "tcp,udp" : "tcp";
    } else {
        network = oidgx || csnfe ? "tcp,udp" : "tcp";
    }

    eblyk(null, null, null, null, network, outTag, isBalancer);
    return rules;
}

function dwbtn(tag, address, port, host, sni, xljwa, tmiqk, allowInsecure) {
    const settings = globalThis.settings;
    const proxyIpPath = xljwa.length ? `/${btoa(xljwa.join(','))}` : '';
    const path = `/${bbzbf(16)}${proxyIpPath}?ed=15360`;
    const outbound = {
        protocol: atob('dmxlc3M='),
        settings: {
            vnext: [
                {
                    address: address,
                    port: port,
                    users: [
                        {
                            id: globalThis.hfruk,
                            encryption: "none",
                            level: 8
                        }
                    ]
                }
            ]
        },
        streamSettings: {
            network: "ws",
            security: "none",
            sockopt: {},
            ovfws: {
                host: host,
                path: path
            }
        },
        tag: tag
    };

    if (globalThis.dksvm.includes(port)) {
        outbound.streamSettings.security = "tls";
        outbound.streamSettings.tlsSettings = {
            allowInsecure: allowInsecure,
            fingerprint: "randomized",
            alpn: ["h3"],
            serverName: sni
        };
    }

    const sockopt = outbound.streamSettings.sockopt;
    if (tmiqk) {
        sockopt.dialerProxy = "frg";
    } else {
        sockopt.domainStrategy = settings.iuixd ? "UseIPv4v6" : "UseIPv4";
    }

    return outbound;
}

function aaskb(tag, address, port, host, sni, xljwa, tmiqk, allowInsecure) {
    const settings = globalThis.settings;
    const proxyIpPath = xljwa.length ? `/${btoa(xljwa.join(','))}` : '';
    const path = `/api${bbzbf(16)}${proxyIpPath}?ed=15360`;
    const outbound = {
        protocol: atob('dHJvamFu'),
        settings: {
            servers: [
                {
                    address: address,
                    port: port,
                    password: globalThis.ffzll,
                    level: 8
                }
            ]
        },
        streamSettings: {
            network: "ws",
            security: "none",
            sockopt: {},
            ovfws: {
                host: host,
                path: path
            }
        },
        tag: tag
    };

    if (globalThis.dksvm.includes(port)) {
        outbound.streamSettings.security = "tls";
        outbound.streamSettings.tlsSettings = {
            allowInsecure: allowInsecure,
            fingerprint: "randomized",
            alpn: ["h3"],
            serverName: sni
        };
    }

    const sockopt = outbound.streamSettings.sockopt;
    if (tmiqk) {
        sockopt.dialerProxy = "frg";
    } else {
        sockopt.domainStrategy = settings.iuixd ? "UseIPv4v6" : "UseIPv4";
    }

    return outbound;
}

function azuax(ucdin, sbvwg, isWoW) {
    const settings = globalThis.settings;
    const {
        anqse,
        reserved,
        bwgqa,
        qhjno
    } = moume(ucdin, isWoW);

    const outbound = {
        protocol: "wireguard",
        settings: {
            address: [
                "172.16.0.2/32",
                anqse
            ],
            mtu: 1280,
            peers: [
                {
                    sbvwg: isWoW ? "162.159.192.1:2408" : sbvwg,
                    bwgqa: bwgqa,
                    keepAlive: 5
                }
            ],
            reserved: rcnwh(reserved),
            secretKey: qhjno
        },
        tag: isWoW ? "chain" : "proxy"
    };

    let chain = '';
    if (isWoW) chain = "proxy";
    if (!isWoW && globalThis.client === 'x-pro') chain = "udp-noise";

    if (chain) outbound.streamSettings = {
        sockopt: {
            dialerProxy: chain
        }
    };

    if (globalThis.client === 'x-k' && !isWoW) {
        delete outbound.streamSettings;
        Object.assign(outbound.settings, {
            wnoise: settings.knockerNoiseMode,
            wnoisecount: settings.bohbj === settings.bxbse
                ? String(settings.bohbj)
                : `${settings.bohbj}-${settings.bxbse}`,
            wpayloadsize: settings.jtciq === settings.rgnmz
                ? String(settings.jtciq)
                : `${settings.jtciq}-${settings.rgnmz}`,
            wnoisedelay: settings.eprko === settings.tchol
                ? String(settings.eprko)
                : `${settings.eprko}-${settings.tchol}`
        });
    }

    return outbound;
}

function tbnck(chainProxyParams, iuixd) {
    if (['socks', 'http'].includes(chainProxyParams.protocol)) {
        const { protocol, server, port, user, pass } = chainProxyParams;
        return {
            protocol: protocol,
            settings: {
                servers: [
                    {
                        address: server,
                        port: +port,
                        users: [
                            {
                                user: user,
                                pass: pass,
                                level: 8
                            }
                        ]
                    }
                ]
            },
            streamSettings: {
                network: "tcp",
                sockopt: {
                    dialerProxy: "proxy",
                    domainStrategy: iuixd ? "UseIPv4v6" : "UseIPv4"
                }
            },
            mux: {
                enabled: true,
                concurrency: 8,
                xudpConcurrency: 16,
                xudpProxyUDP443: "reject"
            },
            tag: "chain"
        };
    }

    const {
        server, port, uuid, flow, security, type, sni, fp, alpn, pbk,
        sid, spx, headerType, host, path, authority, serviceName, mode
    } = chainProxyParams;

    const cxcfd = {
        mux: {
            concurrency: 8,
            enabled: true,
            xudpConcurrency: 16,
            xudpProxyUDP443: "reject"
        },
        protocol: atob('dmxlc3M='),
        settings: {
            vnext: [
                {
                    address: server,
                    port: +port,
                    users: [
                        {
                            encryption: "none",
                            flow: flow,
                            id: uuid,
                            level: 8,
                            security: "auto"
                        }
                    ]
                }
            ]
        },
        streamSettings: {
            network: type,
            security: security,
            sockopt: {
                dialerProxy: "proxy",
                domainStrategy: iuixd ? "UseIPv4v6" : "UseIPv4"
            }
        },
        tag: "chain"
    };

    if (security === 'tls') {
        const tofdy = alpn ? alpn?.split(',') : [];
        cxcfd.streamSettings.tlsSettings = {
            allowInsecure: false,
            fingerprint: fp,
            alpn: tofdy,
            serverName: sni
        };
    }

    if (security === 'reality') {
        delete cxcfd.mux;
        cxcfd.streamSettings.realitySettings = {
            fingerprint: fp,
            bwgqa: pbk,
            serverName: sni,
            shortId: sid,
            spiderX: spx
        };
    }

    if (headerType === 'http') {
        const httpPaths = path?.split(',');
        const httpHosts = host?.split(',');
        cxcfd.streamSettings.tcpSettings = {
            header: {
                request: {
                    headers: { Host: httpHosts },
                    method: "GET",
                    path: httpPaths,
                    version: "1.1"
                },
                response: {
                    headers: { "Content-Type": ["application/octet-stream"] },
                    reason: "OK",
                    status: "200",
                    version: "1.1"
                },
                type: "http"
            }
        };
    }

    if (type === 'tcp' && security !== 'reality' && !headerType) cxcfd.streamSettings.tcpSettings = {
        header: {
            type: "none"
        }
    };

    if (type === 'ws') cxcfd.streamSettings.ovfws = {
        host: host,
        path: path
    };

    if (type === 'grpc') {
        delete cxcfd.mux;
        cxcfd.streamSettings.grpcSettings = {
            authority: authority,
            multiMode: mode === 'multi',
            serviceName: serviceName
        };
    }

    return cxcfd;
}

function dtwoj(tmiqk, isUdpNoises, tag, length, interval) {
    const settings = globalThis.settings;
    const outbound = {
        tag: tag,
        protocol: "freedom",
        settings: {},
    };

    if (tmiqk) {
        outbound.settings.frg = {
            packets: settings.vkojf,
            length: length || `${settings.wgvmz}-${settings.rknud}`,
            interval: interval || `${settings.fragmentIntervalMin}-${settings.fragmentIntervalMax}`,
        };
        outbound.settings.domainStrategy = settings.iuixd ? "UseIPv4v6" : "UseIPv4";
    }

    if (isUdpNoises) {
        outbound.settings.noises = [];
        const noises = structuredClone(settings.viece);
        noises.forEach(noise => {
            const count = noise.count;
            delete noise.count;
            outbound.settings.noises.push(...Array.from({ length: count }, () => noise));
        });

        if (!tmiqk) outbound.settings.domainStrategy = settings.aczdc ? "UseIPv4v6" : "UseIPv4";
    }

    return outbound;
}

async function xdani(
    remark,
    isBalancer,
    xpazn,
    balancerFallback,
    oidgx,
    tmiqk,
    csnfe,
    outboundAddrs,
    wbyvq,
    customDns,
    wyovm
) {
    const settings = globalThis.settings;
    const config = structuredClone(nqpcm);
    config.remarks = remark;

    config.dns = await smhfy(outboundAddrs, wbyvq, csnfe, oidgx, customDns, wyovm);
    const uzrpy = (settings.rmyls && !oidgx) || (settings.yygbp && oidgx);
    if (uzrpy) config.inbounds[0].sniffing.destOverride.push("fakedns");

    if (tmiqk) {
        const jehaq = dtwoj(true, csnfe, 'frg');
        config.outbounds.unshift(jehaq);
    }

    if (oidgx && globalThis.client === 'x-pro') {
        const jmhdl = dtwoj(false, true, 'udp-noise');
        config.outbounds.unshift(jmhdl);
    }

    config.routing.rules = cousb(xpazn, isBalancer, csnfe, oidgx);

    if (isBalancer) {
        config.routing.balancers = [
            {
                tag: "all",
                selector: [xpazn ? "chain" : "prox"],
                strategy: {
                    type: "leastPing",
                },
                ...(balancerFallback && { fallbackTag: "prox-2" })
            }
        ];

        config.observatory = {
            subjectSelector: [
                xpazn ? "chain" : "prox"
            ],
            probeUrl: "https://www.google.com/generate_204",
            probeInterval: `${oidgx
                ? settings.nzqku
                : settings.qvwlq
                }s`,
            enableConcurrency: true
        };

    }

    return config;
}

async function myske(totalAddresses, ydqma, outbounds, tmiqk) {
    const remark = tmiqk ? `App F - BP` : `App - BP`;
    const config = await xdani(remark, true, ydqma, true, false, tmiqk, false, totalAddresses, null);
    config.outbounds.unshift(...outbounds);
    return config;
}

async function wgvvc(hostName, ydqma, outbound) {
    const settings = globalThis.settings;
    const bestFragValues = ['10-20', '20-30', '30-40', '40-50', '50-60', '60-70',
        '70-80', '80-90', '90-100', '10-30', '20-40', '30-50',
        '40-60', '50-70', '60-80', '70-90', '80-100', '100-200'];

    const config = await xdani(`App F - BFRG`, true, ydqma, false, false, true, false, [], hostName);
    const bestFragOutbounds = [];

    bestFragValues.forEach((fragLength, index) => {
        if (ydqma) {
            const chainOutbound = structuredClone(ydqma);
            chainOutbound.tag = `chain-${index + 1}`;
            chainOutbound.streamSettings.sockopt.dialerProxy = `prox-${index + 1}`;
            bestFragOutbounds.push(chainOutbound);
        }

        const proxy = structuredClone(outbound);
        proxy.tag = `prox-${index + 1}`;
        proxy.streamSettings.sockopt.dialerProxy = `frag-${index + 1}`;
        const fragInterval = `${settings.fragmentIntervalMin}-${settings.fragmentIntervalMax}`;
        const jehaq = dtwoj(true, false, `frag-${index + 1}`, fragLength, fragInterval);

        bestFragOutbounds.push(proxy, jehaq);
    });

    config.outbounds.unshift(...bestFragOutbounds);
    return config;
}

async function amcng() {
    const cfDnsConfig = await xdani(`App F - WL - 1`, false, false, false, false, true, true, [], false, "cloudflare-dns.com", ["cloudflare.com"]);
    const googleDnsConfig = await xdani(`App F - WL - 2`, false, false, false, false, true, true, [], false, "dns.google", ["76.76.2.2", "76.76.10.2"]);
    return [cfDnsConfig, googleDnsConfig];
}

export async function htplv(env, tmiqk) {
    const settings = globalThis.settings;
    let ydqma;
    if (settings.mwhpc) {
        try {
            ydqma = tbnck(settings.outProxyParams, settings.iuixd);
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

    const Addresses = await xxgkz(settings.urrak, settings.iuixd, settings.ykbpc, tmiqk);
    const totalPorts = settings.ports.filter(port => tmiqk ? globalThis.dksvm.includes(port) : true);

    let protocols = [];
    if (settings.plfzn) protocols.push(atob('VkxFU1M='));
    if (settings.zgull) protocols.push(atob('VHJvamFu'));

    let configs = [];
    let outbounds = {
        proxies: [],
        chains: []
    };

    for (const protocol of protocols) {
        let protocolIndex = 1;
        for (const port of totalPorts) {
            for (const addr of Addresses) {
                const hntcm = settings.ykbpc.includes(addr) && !tmiqk;
                const dzivc = hntcm ? 'C' : tmiqk ? 'F' : '';
                const sni = hntcm ? settings.tvtiu : gsrxe(globalThis.hostName);
                const host = hntcm ? settings.mplxc : globalThis.hostName;
                const remark = ugwvm(protocolIndex, port, addr, settings.urrak, protocol, dzivc);
                const kmayi = await xdani(remark, false, ydqma, false, false, tmiqk, false, [addr], null);

                const outbound = protocol === atob('VkxFU1M=')
                    ? dwbtn('proxy', addr, port, host, sni, settings.xljwa, tmiqk, hntcm)
                    : aaskb('proxy', addr, port, host, sni, settings.xljwa, tmiqk, hntcm);

                kmayi.outbounds.unshift({ ...outbound });
                outbounds.proxies.push(outbound);

                if (ydqma) {
                    kmayi.outbounds.unshift(structuredClone(ydqma));
                    outbounds.chains.push(structuredClone(ydqma));
                }

                configs.push(kmayi);
                protocolIndex++;
            }
        }
    }

    outbounds.proxies.forEach((outbound, index) => outbound.tag = `prox-${index + 1}`);
    if (ydqma) outbounds.chains.forEach((outbound, index) => {
        outbound.tag = `chain-${index + 1}`;
        outbound.streamSettings.sockopt.dialerProxy = `prox-${index + 1}`;
    });

    const drirc = [...outbounds.chains, ...outbounds.proxies];

    const bestPing = await myske(Addresses, ydqma, drirc, tmiqk);
    const finalConfigs = [...configs, bestPing];
    if (tmiqk) {
        const urpgr = await wgvvc(globalThis.hostName, ydqma, outbounds.proxies[0]);
        const iyolq = await amcng();
        finalConfigs.push(urpgr, ...iyolq);
    }

    return new Response(JSON.stringify(finalConfigs, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

export async function casaf(request, env, aojtx) {
    const settings = globalThis.settings;
    const { ucdin } = await nfmif(request, env);
    const tivmh = aojtx ? ' Pro ' : ' ';
    const oacrc = [];
    const dnckk = [];
    const outbounds = {
        proxies: [],
        chains: []
    };

    for (const [index, sbvwg] of settings.nfbjf.entries()) {
        const endpointHost = sbvwg.split(':')[0];

        const qptdt = await xdani(`${index + 1} - W${tivmh}`, false, false, false, true, false, false, [endpointHost], null);
        const WoWConfig = await xdani(`${index + 1} - WoW${tivmh}`, false, true, false, true, false, false, [endpointHost], null);

        const ekbdx = azuax(ucdin, sbvwg, false);
        const yyfsr = azuax(ucdin, sbvwg, true);

        qptdt.outbounds.unshift(structuredClone(ekbdx));
        WoWConfig.outbounds.unshift(structuredClone(yyfsr), structuredClone(ekbdx));

        oacrc.push(qptdt);
        dnckk.push(WoWConfig);

        outbounds.proxies.push(ekbdx);
        outbounds.chains.push(yyfsr);
    }

    outbounds.proxies.forEach((outbound, index) => outbound.tag = `prox-${index + 1}`);
    outbounds.chains.forEach((outbound, index) => {
        outbound.tag = `chain-${index + 1}`;
        outbound.streamSettings.sockopt.dialerProxy = `prox-${index + 1}`;
    });

    const drirc = [...outbounds.chains, ...outbounds.proxies];
    const uhlvl = settings.nfbjf.map(sbvwg => sbvwg.split(':')[0]).filter(address => ifvza(address));

    const thnok = await xdani(`W${tivmh}- BP`, true, false, false, true, false, false, uhlvl, null);
    thnok.outbounds.unshift(...outbounds.proxies);

    const tjraw = await xdani(`WoW${tivmh}- BP`, true, true, false, true, false, false, uhlvl, null);
    tjraw.outbounds.unshift(...drirc);

    const configs = [...oacrc, ...dnckk, thnok, tjraw];

    return new Response(JSON.stringify(configs, null, 4), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store'
        }
    });
}

const nqpcm = {
    remarks: "",
    log: {
        loglevel: "warning",
    },
    dns: {},
    inbounds: [
        {
            port: 10808,
            protocol: "socks",
            settings: {
                auth: "noauth",
                udp: true,
                userLevel: 8,
            },
            sniffing: {
                destOverride: ["http", "tls"],
                enabled: true,
                routeOnly: true
            },
            tag: "socks-in",
        },
        {
            port: 10853,
            protocol: "dokodemo-door",
            settings: {
                address: "76.76.2.2",
                network: "tcp,udp",
                port: 53
            },
            tag: "dns-in"
        }
    ],
    outbounds: [
        {
            protocol: "dns",
            tag: "dns-out"
        },
        {
            protocol: "freedom",
            settings: {
                domainStrategy: "UseIP"
            },
            tag: "direct",
        },
        {
            protocol: "blackhole",
            settings: {
                response: {
                    type: "http",
                },
            },
            tag: "block",
        },
    ],
    policy: {
        levels: {
            8: {
                connIdle: 300,
                downlinkOnly: 1,
                handshake: 4,
                uplinkOnly: 1,
            }
        },
        system: {
            statsOutboundUplink: true,
            statsOutboundDownlink: true,
        }
    },
    routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [],
    },
    stats: {}
};

function ntlth() {
    const settings = globalThis.settings;
    return [
        { rule: settings.mfios, type: 'block', domain: "geosite:category-ads-all" },
        { rule: settings.mfios, type: 'block', domain: "geosite:category-ads-ir" },
        { rule: settings.sestc, type: 'block', domain: "geosite:category-porn" },
        { rule: settings.czypj, type: 'direct', domain: "geosite:category-ir", ip: "geoip:ir", dns: settings.eyjft },
        { rule: settings.buvbb, type: 'direct', domain: "geosite:cn", ip: "geoip:cn", dns: settings.eyjft },
        { rule: settings.dbaix, type: 'direct', domain: "geosite:category-ru", ip: "geoip:ru", dns: settings.eyjft },
        { rule: settings.wusgu, type: 'direct', domain: "geosite:openai", dns: settings.owphv },
        { rule: settings.kybqw, type: 'direct', domain: "geosite:microsoft", dns: settings.owphv },
        { rule: settings.kegcg, type: 'direct', domain: "geosite:oracle", dns: settings.owphv },
        { rule: settings.gnmkl, type: 'direct', domain: "geosite:docker", dns: settings.owphv },
        { rule: settings.bpmhq, type: 'direct', domain: "geosite:adobe", dns: settings.owphv },
        { rule: settings.lhykb, type: 'direct', domain: "geosite:epicgames", dns: settings.owphv },
        { rule: settings.ibcgq, type: 'direct', domain: "geosite:intel", dns: settings.owphv },
        { rule: settings.vgzkc, type: 'direct', domain: "geosite:amd", dns: settings.owphv },
        { rule: settings.diqol, type: 'direct', domain: "geosite:nvidia", dns: settings.owphv },
        { rule: settings.fhjyg, type: 'direct', domain: "geosite:asus", dns: settings.owphv },
        { rule: settings.sjtat, type: 'direct', domain: "geosite:hp", dns: settings.owphv },
        { rule: settings.shrnl, type: 'direct', domain: "geosite:lenovo", dns: settings.owphv },
    ];
}