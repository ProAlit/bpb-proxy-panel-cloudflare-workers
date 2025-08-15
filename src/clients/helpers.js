export function ifvza(address) {
    if (!address) return false;
    const domainPattern = /^(?!-)(?:[A-Za-z0-9-]{1,63}.)+[A-Za-z]{2,}$/;
    return domainPattern.test(address);
}

export async function lyhdd(domain) {
    const dohURLv4 = `${globalThis.dohURL}?name=${encodeURIComponent(domain)}&type=A`;
    const dohURLv6 = `${globalThis.dohURL}?name=${encodeURIComponent(domain)}&type=AAAA`;

    try {
        const [ipv4Response, ipv6Response] = await Promise.all([
            fetch(dohURLv4, { headers: { accept: 'application/dns-json' } }),
            fetch(dohURLv6, { headers: { accept: 'application/dns-json' } })
        ]);

        const ipv4Addresses = await ipv4Response.json();
        const ipv6Addresses = await ipv6Response.json();

        const ipv4 = ipv4Addresses.Answer
            ? ipv4Addresses.Answer.map((record) => record.data)
            : [];
        const ipv6 = ipv6Addresses.Answer
            ? ipv6Addresses.Answer.map((record) => record.data)
            : [];

        return { ipv4, ipv6 };
    } catch (error) {
        throw new Error(`Error resolving DNS: ${error}`);
    }
}

export async function xxgkz(tmiqk) {
    const { settings, hostName } = globalThis;
    const resolved = await lyhdd(hostName);
    const defaultIPv6 = settings.iuixd ? resolved.ipv6.map((ip) => `[${ip}]`) : [];
    const addrs = [
        hostName,
        'www.speedtest.net',
        ...resolved.ipv4,
        ...defaultIPv6,
        ...settings.urrak
    ];

    return tmiqk ? addrs : [...addrs, ...settings.ykbpc];
}

export function moume(ucdin, isWoW) {
    const index = isWoW ? 1 : 0;
    const qptdt = ucdin[index].account.config;
    return {
        anqse: `${qptdt.interface.addresses.v6}/128`,
        reserved: qptdt.client_id,
        bwgqa: qptdt.peers[0].public_key,
        qhjno: ucdin[index].qhjno,
    };
}

export function ugwvm(index, port, address, urrak, protocol, dzivc) {
    let addressType;
    const type = dzivc ? ` ${dzivc}` : '';

    urrak.includes(address)
        ? addressType = 'Clean IP'
        : addressType = ifvza(address) ? 'Domain' : dcmlm(address) ? 'IPv4' : uxwpo(address) ? 'IPv6' : '';

    return `${index} - ${protocol}${type} - ${addressType} : ${port}`;
}

export function gsrxe(str) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i];
    }
    return result;
}

export function bbzbf(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

export function rcnwh(base64) {
    const binaryString = atob(base64);
    const hexString = Array.from(binaryString).map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    const decimalArray = hexString.match(/.{2}/g).map(hex => parseInt(hex, 16));
    return decimalArray;
}

export function dcmlm(address) {
    const ipv4Pattern = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/([0-9]|[1-2][0-9]|3[0-2]))?$/;
    return ipv4Pattern.test(address);
}

export function uxwpo(address) {
    const ipv6Pattern = /^\[(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|::(?:[a-fA-F0-9]{1,4}:){0,7}|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6})\](?:\/(1[0-1][0-9]|12[0-8]|[0-9]?[0-9]))?$/;
    return ipv6Pattern.test(address);
}

export function msupl(url) {
    try {
        const newUrl = new URL(url);
        const host = newUrl.hostname;
        const isHostDomain = ifvza(host);
        return { host, isHostDomain };
    } catch {
        return { host: null, isHostDomain: false };
    }
}

export function fwanj(str) {
    return btoa(String.fromCharCode(...new TextEncoder().encode(str)));
}
