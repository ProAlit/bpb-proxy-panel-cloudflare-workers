import { getDomain, resolveDNS } from '../clients/helpers';
import { fetchWarpConfigs } from '../types/w';

export async function getDataset(request, env) {
    let proxySettings, warpConfigs;

    try {
        proxySettings = await env.S.get("proxySettings", { type: 'json' });
        warpConfigs = await env.S.get('warpConfigs', { type: 'json' });
    } catch (error) {
        console.log(error);
        throw new Error(`An error occurred while getting S - ${error}`);
    }

    if (!proxySettings) {
        proxySettings = await updateDataset(request, env);
        const configs = await fetchWarpConfigs(env);
        warpConfigs = configs;
    }

    if (globalThis.panelVersion !== proxySettings.panelVersion) proxySettings = await updateDataset(request, env);
    return { proxySettings, warpConfigs }
}

export async function updateDataset(request, env) {
    let newSettings = request.method === 'POST' ? await request.json() : null;
    const isReset = newSettings?.resetSettings;
    let currentSettings;
    if (!isReset) {
        try {
            currentSettings = await env.S.get("proxySettings", { type: 'json' });
        } catch (error) {
            console.log(error);
            throw new Error(`An error occurred while getting current S settings - ${error}`);
        }
    }
    
    const populateField = (field, defaultValue, callback) => {
        if (isReset) return defaultValue;
        if (!newSettings) return currentSettings?.[field] ?? defaultValue;
        const value = newSettings[field];
        return typeof callback === 'function' ? callback(value) : value;
    }

    const remoteDNS = populateField('remoteDNS', 'https://8.8.8.8/dns-query');
    const initDoh = async () => {
        const { host, isHostDomain } = getDomain(remoteDNS);
        const dohHost = {
            host,
            isDomain: isHostDomain
        }

        if (isHostDomain) {
            const { ipv4, ipv6 } = await resolveDNS(host);
            dohHost.ipv4 = ipv4;
            dohHost.ipv6 = ipv6;
        }

        return dohHost;
    }

    const settings = {
        remoteDNS,
        dohHost: await initDoh(), 
        localDNS: populateField('localDNS', '76.76.2.2'),
        antiSanctionDNS: populateField('antiSanctionDNS', '78.157.42.100'),
        VLTRFakeDNS: populateField('VLTRFakeDNS', false),
        proxyIPs: populateField('proxyIPs', []),
        outProxy: populateField('outProxy', ''),
        outProxyParams: populateField('outProxy', {}, field => extractChainProxyParams(field)),
        cleanIPs: populateField('cleanIPs', []),
        VLTRenableIPv6: populateField('VLTRenableIPv6', true),
        customCdnAddrs: populateField('customCdnAddrs', []),
        customCdnHost: populateField('customCdnHost', ''),
        customCdnSni: populateField('customCdnSni', ''),
        bestVLTRInterval: populateField('bestVLTRInterval', 30),
        VLConfigs: populateField('VLConfigs', true),
        TRConfigs: populateField('TRConfigs', true),
        ports: populateField('ports', [443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 2052, 2082, 2086, 2095, 8880]),
        fragmentLengthMin: populateField('fragmentLengthMin', 100),
        fragmentLengthMax: populateField('fragmentLengthMax', 200),
        fragmentIntervalMin: populateField('fragmentIntervalMin', 1),
        fragmentIntervalMax: populateField('fragmentIntervalMax', 1),
        fragmentPackets: populateField('fragmentPackets', 'tlshello'),
        bypassLAN: populateField('bypassLAN', true),
        bypassIran: populateField('bypassIran', true),
        bypassChina: populateField('bypassChina', false),
        bypassRussia: populateField('bypassRussia', false),
        bypassOpenAi: populateField('bypassOpenAi', true),
        bypassMicrosoft: populateField('bypassMicrosoft', true),
        bypassOracle: populateField('bypassOracle', true),
        bypassDocker: populateField('bypassDocker', true),
        bypassAdobe: populateField('bypassAdobe', true),
        bypassEpicGames: populateField('bypassEpicGames', true),
        bypassIntel: populateField('bypassIntel', true),
        bypassAmd: populateField('bypassAmd', true),
        bypassNvidia: populateField('bypassNvidia', true),
        bypassAsus: populateField('bypassAsus', true),
        bypassHp: populateField('bypassHp', true),
        bypassLenovo: populateField('bypassLenovo', true),
        blockAds: populateField('blockAds', true),
        blockPorn: populateField('blockPorn', false),
        blockUDP443: populateField('blockUDP443', false),
        customBypassRules: populateField('customBypassRules', []),
        customBlockRules: populateField('customBlockRules', []),
        customBypassSanctionRules: populateField('customBypassSanctionRules', []),
        warpEndpoints: populateField('warpEndpoints', ['engage.cloudflareclient.com:2408']),
        warpFakeDNS: populateField('warpFakeDNS', true),
        warpEnableIPv6: populateField('warpEnableIPv6', true),
        bestWarpInterval: populateField('bestWarpInterval', 30),
        xrayUdpNoises: populateField('xrayUdpNoises', [
            {
                type: 'rand',
                packet: '50-100',
                delay: '1-1',
                count: 5
            }
        ]),
        hiddifyNoiseMode: populateField('hiddifyNoiseMode', 'm4'),
        knockerNoiseMode: populateField('knockerNoiseMode', 'quic'),
        noiseCountMin: populateField('noiseCountMin', 10),
        noiseCountMax: populateField('noiseCountMax', 15),
        noiseSizeMin: populateField('noiseSizeMin', 5),
        noiseSizeMax: populateField('noiseSizeMax', 10),
        noiseDelayMin: populateField('noiseDelayMin', 1),
        noiseDelayMax: populateField('noiseDelayMax', 1),
        amneziaNoiseCount: populateField('amneziaNoiseCount', 5),
        amneziaNoiseSizeMin: populateField('amneziaNoiseSizeMin', 50),
        amneziaNoiseSizeMax: populateField('amneziaNoiseSizeMax', 100),
        panelVersion: globalThis.panelVersion
    };

    try {
        await env.S.put("proxySettings", JSON.stringify(settings));
    } catch (error) {
        console.log(error);
        throw new Error(`An error occurred while updating S - ${error}`);
    }

    return settings;
}

function extractChainProxyParams(chainProxy) {
    let configParams = {};
    if (!chainProxy) return {};
    const url = new URL(chainProxy);
    const protocol = url.protocol.slice(0, -1);
    if (protocol === atob('dmxlc3M=')) {
        const params = new URLSearchParams(url.search);
        configParams = {
            protocol: protocol,
            uuid: url.username,
            server: url.hostname,
            port: url.port
        };

        params.forEach((value, key) => {
            configParams[key] = value;
        });
    } else {
        configParams = {
            protocol: protocol,
            user: url.username,
            pass: url.password,
            server: url.host,
            port: url.port
        };
    }

    return configParams;
}