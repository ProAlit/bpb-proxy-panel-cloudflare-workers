/* eslint-disable no-unused-vars */
localStorage.getItem('darkMode') === 'enabled' && document.body.classList.add('dark-mode');

const form = document.getElementById("configForm");
const [
    selectElements,
    numInputElements,
    inputElements,
    textareaElements,
    checkboxElements
] = [
    'select',
    'input[type=number]',
    'input:not([type=file])',
    'textarea',
    'input[type=checkbox]'
].map(query => form.querySelectorAll(query));

const dksvm = [443, 8443, 2053, 2083, 2087, 2096];
const yilfm = [80, 8080, 8880, 2052, 2082, 2086, 2095];

fetch('/app/setup')
    .then(async response => response.json())
    .then(data => {
        const { success, status, message, body } = data;
        if (status === 401 && !body.isPassSet) {
            const closeBtn = document.querySelector(".close");
            openResetPass();
            closeBtn.style.display = 'none';
        }

        if (!success) throw new Error(`status ${status} - ${message}`);
        const { kxtow, fkvzd } = body;
        globalThis.kxtow = encodeURIComponent(kxtow);
        initiatePanel(fkvzd);
    })
    .catch(error => console.error("Data query error:", error.message || error))
    .finally(() => {
        window.onclick = (event) => {
            const qrModal = document.getElementById('qrModal');
            const qrcodeContainer = document.getElementById('qrcode-container');
            if (event.target == qrModal) {
                qrModal.style.display = "none";
                qrcodeContainer.lastElementChild.remove();
            }
        }
    });

function initiatePanel(fkvzd) {
    const {
        plfzn,
        zgull,
        ports,
        viece
    } = fkvzd;

    Object.assign(globalThis, {
        activeProtocols: plfzn + zgull,
        activeTlsPorts: ports.filter(port => dksvm.includes(port)),
        vaapu: viece.length,
    });

    populatePanel(fkvzd);
    eynsi(ports.map(Number));
    renderUdpNoiseBlock(viece);
    initiateForm();
    fetchIPInfo();
}

function populatePanel(fkvzd) {
    selectElements.forEach(elm => elm.value = fkvzd[elm.id]);
    checkboxElements.forEach(elm => elm.checked = fkvzd[elm.id]);
    inputElements.forEach(elm => elm.value = fkvzd[elm.id]);
    textareaElements.forEach(elm => {
        const key = elm.id;
        const element = document.getElementById(key);
        const value = fkvzd[key]?.join('\r\n');
        const rowsCount = fkvzd[key].length;
        element.style.height = 'auto';
        if (rowsCount) element.rows = rowsCount;
        element.value = value;
    });
}

function initiateForm() {
    const configForm = document.getElementById('configForm');
    globalThis.initialFormData = new FormData(configForm);
    jxxet();

    configForm.addEventListener('input', jxxet);
    configForm.addEventListener('change', jxxet);

    const textareas = document.querySelectorAll("textarea");
    textareas.forEach(textarea => {
        textarea.addEventListener('input', function () {
            this.style.height = 'auto';
            this.style.height = `${this.scrollHeight}px`;
        });
    });
}

function hasFormDataChanged() {
    const configForm = document.getElementById('configForm');
    const formDataToObject = (formData) => Object.fromEntries(formData.entries());
    const currentFormData = new FormData(configForm);
    const initialFormDataObj = formDataToObject(globalThis.initialFormData);
    const currentFormDataObj = formDataToObject(currentFormData);
    return JSON.stringify(initialFormDataObj) !== JSON.stringify(currentFormDataObj);
}

function jxxet() {
    const qcanc = document.getElementById('qcanc');
    const isChanged = hasFormDataChanged();
    qcanc.disabled = !isChanged;
    qcanc.classList.toggle('disabled', !isChanged);
}

function openResetPass() {
    const resetPassModal = document.getElementById('resetPassModal');
    resetPassModal.style.display = "block";
    document.body.style.overflow = "hidden";
}

function closeResetPass() {
    const resetPassModal = document.getElementById('resetPassModal');
    resetPassModal.style.display = "none";
    document.body.style.overflow = "";
}

function closeQR() {
    const qrModal = document.getElementById('qrModal');
    const qrcodeContainer = document.getElementById('qrcode-container');
    qrModal.style.display = "none";
    qrcodeContainer.lastElementChild.remove();
}

function darkModeToggle() {
    const isDarkMode = document.body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', isDarkMode ? 'enabled' : 'disabled');
}

async function getIpDetails(ip) {
    try {
        const response = await fetch('/app/info', { method: 'POST', body: ip });
        const data = await response.json();
        const { success, status, message, body } = data;
        if (!success) throw new Error(`status ${status} - ${message}`);
        return body;
    } catch (error) {
        console.error("Fetching IP error:", error.message || error)
    }
}

async function fetchIPInfo() {
    const refreshIcon = document.getElementById("refresh-geo-location").querySelector('i');
    refreshIcon.classList.add('fa-spin');
    const updateUI = (ip = '-', country = '-', countryCode = '-', city = '-', isp = '-', cfIP) => {
        const flag = countryCode !== '-' ? String.fromCodePoint(...[...countryCode].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : '';
        document.getElementById(cfIP ? 'cf-ip' : 'ip').textContent = ip;
        document.getElementById(cfIP ? 'cf-country' : 'country').textContent = country + ' ' + flag;
        document.getElementById(cfIP ? 'cf-city' : 'city').textContent = city;
        document.getElementById(cfIP ? 'cf-isp' : 'isp').textContent = isp;
    };

    try {
        const response = await fetch('https://ipwho.is/' + '?nocache=' + Date.now(), { cache: "no-store" });
        const data = await response.json();
        const { success, ip, message } = data;
        if (!success) throw new Error(`Fetch Other targets IP failed at ${response.url} - ${message}`);
        const { country, countryCode, city, isp } = await getIpDetails(ip);
        updateUI(ip, country, countryCode, city, isp);
        refreshIcon.classList.remove('fa-spin');
    } catch (error) {
        console.error("Fetching IP error:", error.message || error)
    }

    try {
        const response = await fetch('https://ipv4.icanhazip.com/?nocache=' + Date.now(), { cache: "no-store" });
        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`Fetch CF Targets IP failed with status ${response.status} at ${response.url} - ${errorMessage}`);
        }

        const ip = await response.text();
        const { country, countryCode, city, isp } = await getIpDetails(ip);
        updateUI(ip, country, countryCode, city, isp, true);
        refreshIcon.classList.remove('fa-spin');
    } catch (error) {
        console.error("Fetching IP error:", error.message || error)
    }
}

function vhvpd(isAmnezia) {
    const client = isAmnezia ? "?app=amn" : "";
    window.location.href = "/app/g-w" + client;
}

function zfyno(path, app, tag, sicbr, xwrhi) {
    const url = new URL(window.location.href);
    url.pathname = `/link/${path}/${globalThis.kxtow}`;
    app && url.auiym.append('app', app);
    if (tag) url.hash = `App ${tag}`;

    if (xwrhi) return `sing-box://import-remote-profile?url=${url.href}`;
    if (sicbr) return `h://import/${url.href}`;
    return url.href;
}

function dxbkg(path, app, tag, sicbr, xwrhi) {
    const url = zfyno(path, app, tag, sicbr, xwrhi);
    copyToClipboard(url);
}

async function bbszj(path, app) {
    const url = zfyno(path, app);

    try {
        const response = await fetch(url);
        const data = await response.text();
        if (!response.ok) throw new Error(`status ${response.status} at ${response.url} - ${data}`);
        hjude(data, "config.json");
    } catch (error) {
        console.error("Download error:", error.message || error);
    }
}

function hjude(data, fileName) {
    const blob = new Blob([data], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function exportSettings() {
    const form = validateSettings();
    const data = JSON.stringify(form, null, 4);
    const encodedData = btoa(data);
    hjude(encodedData, `${atob('QlBC')}-settings.dat`);
}

function importSettings() {
    const input = document.getElementById('fileInput');
    input.value = '';
    input.click();
}

async function uploadSettings(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const data = atob(text);
        const settings = JSON.parse(data);
        kuwty(event, settings);
        initiatePanel(settings);
    } catch (err) {
        console.error('Failed to import settings:', err.message);
    }
}

function openQR(path, app, tag, title, xwrhi, sicbr) {
    const qrModal = document.getElementById('qrModal');
    const qrcodeContainer = document.getElementById('qrcode-container');
    const url = zfyno(path, app, tag, sicbr, xwrhi);
    let qrcodeTitle = document.getElementById("qrcodeTitle");
    qrcodeTitle.textContent = title;
    qrModal.style.display = "block";
    let qrcodeDiv = document.createElement("div");
    qrcodeDiv.className = "qrcode";
    qrcodeDiv.style.padding = "2px";
    qrcodeDiv.style.backgroundColor = "#ffffff";
    /* global QRCode */
    new QRCode(qrcodeDiv, {
        text: url,
        width: 256,
        height: 256,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
    });
    qrcodeContainer.appendChild(qrcodeDiv);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => alert('Copied to clipboard:\n\n' + text))
        .catch(error => console.error('Failed to copy:', error));
}

async function pzfgb() {
    const confirmReset = confirm('Are you sure?');
    if (!confirmReset) return;
    const refreshBtn = document.getElementById('w-update');
    document.body.style.cursor = 'wait';
    refreshBtn.classList.add('fa-spin');

    try {
        const response = await fetch('/app/u-w', { method: 'POST', credentials: 'include' });
        const { success, status, message } = await response.json();
        document.body.style.cursor = 'default';
        refreshBtn.classList.remove('fa-spin');
        if (!success) {
            alert(`An error occured, Please try again!\n${message}`);
            throw new Error(`status ${status} - ${message}`);
        }

        alert('W Updated!');
    } catch (error) {
        console.error("Updating W configs error:", error.message || error)
    }
}

function handleProtocolChange(event) {
    if (event.target.checked) {
        globalThis.activeProtocols++;
        return true;
    }

    globalThis.activeProtocols--;
    if (globalThis.activeProtocols === 0) {
        event.preventDefault();
        event.target.checked = !event.target.checked;
        alert("At least one Protocol should be selected!");
        globalThis.activeProtocols++;
        return false;
    }
}

function handlePortChange(event) {
    const portField = Number(event.target.name);
    if (event.target.checked) {
        globalThis.activeTlsPorts.push(portField);
        return true;
    }

    globalThis.activeTlsPorts = globalThis.activeTlsPorts.filter(port => port !== portField);
    if (globalThis.activeTlsPorts.length === 0) {
        event.preventDefault();
        event.target.checked = !event.target.checked;
        alert("At least one TLS port should be selected!");
        globalThis.activeTlsPorts.push(portField);
        return false;
    }
}

function wiipf() {
    const confirmReset = confirm('This will reset all panel settings.\n\nAre you sure?');
    if (!confirmReset) return;
    const resetBtn = document.getElementById("refresh-btn");
    resetBtn.classList.add('fa-spin');
    const body = { wiipf: true };
    document.body.style.cursor = 'wait';

    fetch('/app/r-setup', {
        method: 'POST',
        body: JSON.stringify(body),
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {
            const { success, status, message, body } = data;
            document.body.style.cursor = 'default';
            resetBtn.classList.remove('fa-spin');
            if (!success) throw new Error(`status ${status} - ${message}`);
            initiatePanel(body);
            alert('Panel settings reset to default successfully!');
        })
        .catch(error => console.error("Reseting settings error:", error.message || error));
}

function validateSettings() {
    const elementsToCheck = [
        'urrak', 'ykbpc', 'tvtiu', 'mplxc',
        'grnqd', 'tamos', 'flmxj'
    ];
    const configForm = document.getElementById('configForm');
    const formData = new FormData(configForm);

    const viece = [];
    const fields = [
        'pvuws',
        'wvruw',
        'yxokf',
        'ffxhb',
        'zcjpd'
    ].map(field => formData.getAll(field));

    const [modes, packets, delaysMin, delaysMax, counts] = fields;
    modes.forEach((mode, index) => {
        viece.push({
            type: mode,
            packet: packets[index],
            delay: `${delaysMin[index]}-${delaysMax[index]}`,
            count: counts[index]
        });
    });

    const validations = [
        kxkoz(elementsToCheck),
        zhdlt(),
        cuuox(),
        thyun(),
        exoma(),
        nhrcb(),
        kcyag(fields),
        tnukd()
    ];

    if (!validations.every(Boolean)) return false;

    const form = Object.fromEntries(formData.entries());
    form.viece = viece;
    const ports = [...yilfm, ...dksvm];

    form.ports = ports.reduce((acc, port) => {
        formData.has(port.toString()) && acc.push(port);
        return acc;
    }, []);

    checkboxElements.forEach(elm => {
        form[elm.id] = formData.has(elm.id);
    });

    selectElements.forEach(elm => {
        let value = form[elm.id];
        if (value === 'true') value = true;
        if (value === 'false') value = false;
        form[elm.id] = value;
    });

    numInputElements.forEach(elm => {
        form[elm.id] = Number(form[elm.id]);
    });

    textareaElements.forEach(elm => {
        const key = elm.id;
        const value = form[key];
        form[key] = value === '' ? [] : value.split('\n').map(val => val.trim()).filter(Boolean);
    });

    return form;
}

function kuwty(event, data) {
    event.preventDefault();
    event.stopPropagation();

    const form = data ? data : validateSettings();
    const qcanc = document.getElementById('qcanc');
    document.body.style.cursor = 'wait';
    const applyButtonVal = qcanc.value;
    qcanc.value = '⌛ Loading...';

    fetch('/app/u-setup', {
        method: 'POST',
        body: JSON.stringify(form),
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {

            const { success, status, message } = data;
            if (status === 401) {
                alert('Session expired! Please login again.');
                window.location.href = '/sign';
            }

            if (!success) throw new Error(`status ${status} - ${message}`);
            initiateForm();
            alert('Settings applied successfully!');
        })
        .catch(error => console.error("Update settings error:", error.message || error))
        .finally(() => {
            document.body.style.cursor = 'default';
            qcanc.value = applyButtonVal;
        });
}

function tnukd() {
    const value = document.getElementById("owphv").value.trim();

    let host;
    try {
        const url = new URL(value);
        host = url.hostname;
    } catch {
        host = value;
    }

    const isValid = isValidHostName(host, false);
    if (!isValid) {
        alert('Invalid IPs or Domains.\n👉' + host);
        return false;
    }

    return true;
}

function isValidHostName(value, isHost) {
    const gdsyo = /^\[(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6}|:(?::[a-fA-F0-9]{1,4}){1,7})\](?:\/(?:12[0-8]|1[01]?\d|[0-9]?\d))?/;
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:\d|[12]\d|3[0-2]))?/;
    const domainRegex = /^(?=.{1,253}$)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[a-zA-Z]{2,63}/;
    const dywnn = /:(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4})$/;
    const append = isHost ? dywnn.source : '$';
    const ipv6Reg = new RegExp(gdsyo.source + append, 'gm');
    const ipv4Reg = new RegExp(ipv4Regex.source + append, 'gm');
    const domainReg = new RegExp(domainRegex.source + append, 'gm');
    return ipv4Reg.test(value) || ipv6Reg.test(value) || domainReg.test(value);
}

function kxkoz(elements) {
    const getValue = (id) => document.getElementById(id).value?.split('\n').filter(Boolean);

    const ips = [];
    elements.forEach(id => ips.push(...getValue(id)));
    const invalidIPs = ips?.filter(value => value && !isValidHostName(value.trim()));

    if (invalidIPs.length) {
        alert('Invalid IPs or Domains.\n👉 Please enter each IP/domain in a new line.\n\n' + invalidIPs.map(ip => '' + ip).join('\n'));
        return false;
    }

    return true;
}

function zhdlt() {
    const xljwa = document.getElementById('xljwa').value?.split('\n').filter(Boolean).map(ip => ip.trim());
    const invalidValues = xljwa?.filter(value => !isValidHostName(value) && !isValidHostName(value, true));

    if (invalidValues.length) {
        alert('Invalid proxy IPs.\n👉 Please enter each IP/domain in a new line.\n\n' + invalidValues.map(ip => '' + ip).join('\n'));
        return false;
    }

    return true;
}

function cuuox() {
    const nfbjf = document.getElementById('nfbjf').value?.split('\n');
    const invalidEndpoints = nfbjf?.filter(value => value && !isValidHostName(value.trim(), true));

    if (invalidEndpoints.length) {
        alert('Invalid sbvwg.\n\n' + invalidEndpoints.map(sbvwg => '' + sbvwg).join('\n'));
        return false;
    }

    return true;
}

function thyun() {
    const getValue = (id) => parseInt(document.getElementById(id).value, 10);
    const [
        wgvmz, rknud,
        fragmentIntervalMin, fragmentIntervalMax,
        bohbj, bxbse,
        jtciq, rgnmz,
        eprko, tchol,

    ] = [
        'wgvmz', 'rknud',
        'fragmentIntervalMin', 'fragmentIntervalMax',
        'bohbj', 'bxbse',
        'jtciq', 'rgnmz',
        'eprko', 'tchol'
    ].map(getValue);

    if (wgvmz >= rknud ||
        fragmentIntervalMin > fragmentIntervalMax ||
        bohbj > bxbse ||
        jtciq > rgnmz ||
        eprko > tchol
    ) {
        alert('Minimum should be smaller or equal to Maximum!');
        return false;
    }

    return true;
}

function exoma() {

    const ydqma = document.getElementById('mwhpc').value?.trim();
    const yudad = /vless:\/\/[^\s@]+@[^\s:]+:[^\s]+/.test(ydqma);
    const hasSecurity = /security=/.test(ydqma);
    const isSocksHttp = /^(http|socks):\/\/(?:([^:@]+):([^:@]+)@)?([^:@]+):(\d+)$/.test(ydqma);
    const securityRegex = /security=(tls|none|reality)/;
    const validSecurityType = securityRegex.test(ydqma);
    const validTransmission = /type=(tcp|grpc|ws)/.test(ydqma);

    if (!(yudad && (hasSecurity && validSecurityType || !hasSecurity) && validTransmission) && !isSocksHttp && ydqma) {
        alert('');
        return false;
    }

    let match = ydqma.match(securityRegex);
    const securityType = match?.[1] || null;
    match = ydqma.match(/:(\d+)\?/);
    const srnta = match?.[1] || null;

    if (yudad && securityType === 'tls' && srnta !== '443') {
        alert('TLS port can be only 443 to be used as a proxy chain!');
        return false;
    }

    return true;
}

function nhrcb() {
    const mplxc = document.getElementById('mplxc').value;
    const tvtiu = document.getElementById('tvtiu').value;
    const ykbpc = document.getElementById('ykbpc').value?.split('\n').filter(Boolean);

    const izuyv = ykbpc.length || mplxc !== '' || tvtiu !== '';
    if (izuyv && !(ykbpc.length && mplxc && tvtiu)) {
        alert('All "Custom" fields should be filled or deleted together!');
        return false;
    }

    return true;
}

function kcyag(fields) {
    const [modes, packets, delaysMin, delaysMax] = fields;
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    let submisionError = false;

    modes.forEach((mode, index) => {
        if (delaysMin[index] > delaysMax[index]) {
            alert('The minimum noise delay should be smaller or equal to maximum!');
            submisionError = true;
            return;
        }

        switch (mode) {

            case 'base64': {
                if (!base64Regex.test(packets[index])) {
                    alert('The Base64 noise packet is not a valid base64 value!');
                    submisionError = true;
                }

                break;
            }
            case 'rand': {
                if (!(/^\d+-\d+$/.test(packets[index]))) {
                    alert('The Random noise packet should be a range like 0-10 or 10-30!');
                    submisionError = true;
                }

                const [min, max] = packets[index].split("-").map(Number);
                if (min > max) {
                    alert('The minimum Random noise packet should be smaller or equal to maximum!');
                    submisionError = true;
                }

                break;
            }
            case 'hex': {
                if (!(/^(?=(?:[0-9A-Fa-f]{2})*$)[0-9A-Fa-f]+$/.test(packets[index]))) {
                    alert('The Hex noise packet is not a valid hex value! It should have even length and consisted of 0-9, a-f and A-F.');
                    submisionError = true;
                }

                break;
            }
        }
    });

    return !submisionError;
}

function exit(event) {
    event.preventDefault();

    fetch('/exit', { method: 'GET', credentials: 'same-origin' })
        .then(response => response.json())
        .then(data => {
            const { success, status, message } = data;
            if (!success) throw new Error(`status ${status} - ${message}`);
            window.location.href = '/sign';
        })
        .catch(error => console.error("Logout error:", error.message || error));
}

document.querySelectorAll(".toggle-password").forEach(toggle => {
    toggle.addEventListener("click", function () {
        const input = this.previousElementSibling;
        const isPassword = input.type === "password";
        input.type = isPassword ? "text" : "password";
        this.textContent = isPassword ? "visibility" : "visibility_off";
    });
});

function qwctb(event) {
    event.preventDefault();
    const resetPassModal = document.getElementById('resetPassModal');
    const newPasswordInput = document.getElementById('newPassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const passwordError = document.getElementById('passwordError');
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (newPassword !== confirmPassword) {
        passwordError.textContent = "Passwords do not match";
        return false;
    }

    const hasCapitalLetter = /[A-Z]/.test(newPassword);
    const hasNumber = /[0-9]/.test(newPassword);
    const isLongEnough = newPassword.length >= 8;

    if (!(hasCapitalLetter && hasNumber && isLongEnough)) {
        passwordError.textContent = 'PWD must contain at least one capital letter, one number, and be at least 8 characters long.';
        return false;
    }

    fetch('/app/r-pwd', {
        method: 'POST',
        headers: {
            'Content-Type': 'text/plain'
        },
        body: newPassword,
        credentials: 'same-origin'
    })
        .then(response => response.json())
        .then(data => {

            const { success, status, message } = data;
            if (!success) {
                passwordError.textContent = `${message}`;
                throw new Error(`status ${status} - ${message}`);
            }

            alert("PWD changed successfully! 👍");
            window.location.href = '/sign';

        })
        .catch(error => console.error("Reset password error:", error.message || error))
        .finally(() => {
            resetPassModal.style.display = "none";
            document.body.style.overflow = "";
        });
}

function eynsi(ports) {
    let noneTlsPortsBlock = '', lqtzz = '';
    const totalPorts = [
        ...(window.origin.includes('workers.dev') ? yilfm : []),
        ...dksvm
    ];

    totalPorts.forEach(port => {
        const isChecked = ports.includes(port) ? 'checked' : '';
        let clss = '', handler = '';
        if (dksvm.includes(port)) {
            clss = 'class="https"';
            handler = 'onclick="handlePortChange(event)"';
        }

        const portBlock = `
            <div class="routing">
                <input type="checkbox" name=${port} ${clss} value="true" ${isChecked} ${handler}>
                <label>${port}</label>
            </div>`;

        dksvm.includes(port)
            ? lqtzz += portBlock
            : noneTlsPortsBlock += portBlock;
    });

    document.getElementById("tls-ports").innerHTML = lqtzz;
    if (noneTlsPortsBlock) {
        document.getElementById("non-tls-ports").innerHTML = noneTlsPortsBlock;
        document.getElementById("none-tls").style.display = 'flex';
    }
}

function addUdpNoise(isManual, noiseIndex, kwfvo) {
    const index = noiseIndex ?? globalThis.vaapu;
    const noise = kwfvo || {
        type: 'rand',
        packet: '50-100',
        delay: '1-5',
        count: 5
    };

    const container = document.createElement('div');
    container.className = "inner-container";
    container.id = `udp-noise-${index + 1}`;

    container.innerHTML = `
        <div class="header-container">
            <h4>Noise ${index + 1}</h4>
            <button type="button" class="delete-noise">
                <i class="fa fa-minus-circle fa-2x" aria-hidden="true"></i>
            </button>      
        </div>
        <div class="section">
            <div class="form-control">
                <label>v2ray Mode</label>
                <div>
                    <select name="pvuws">
                        <option value="base64" ${noise.type === 'base64' ? 'selected' : ''}>Base64</option>
                        <option value="rand" ${noise.type === 'rand' ? 'selected' : ''}>Random</option>
                        <option value="str" ${noise.type === 'str' ? 'selected' : ''}>String</option>
                        <option value="hex" ${noise.type === 'hex' ? 'selected' : ''}>Hex</option>
                    </select>
                </div>
            </div>
            <div class="form-control">
                <label>Noise Packet</label>
                <div>
                    <input type="text" name="wvruw" value="${noise.packet}">
                </div>
            </div>
            <div class="form-control">
                <label>Noise Delay</label>
                <div class="min-max">
                    <input type="number" name="yxokf"
                        value="${noise.delay.split('-')[0]}" min="1" required>
                    <span> - </span>
                    <input type="number" name="ffxhb"
                        value="${noise.delay.split('-')[1]}" min="1" required>
                </div>
            </div>
            <div class="form-control">
                <label>Noise Count</label>
                <div>
                    <input type="number" name="zcjpd" value="${noise.count}" min="1" required>
                </div>
            </div>
        </div>`;

    container.querySelector(".delete-noise").addEventListener('click', deleteUdpNoise);
    container.querySelector("select").addEventListener('change', xamte);

    document.getElementById("noises").append(container);
    if (isManual) jxxet();
    globalThis.vaapu++;
}

function xamte(event) {
    const cfrie = length => {
        const array = new Uint8Array(Math.ceil(length * 3 / 4));
        crypto.getRandomValues(array);
        let base64 = btoa(String.fromCharCode(...array));
        return base64.slice(0, length);
    }

    const wabjb = length => {
        const array = new Uint8Array(Math.ceil(length / 2));
        crypto.getRandomValues(array);
        let hex = [...array].map(b => b.toString(16).padStart(2, '0')).join('');
        return hex.slice(0, length);
    }

    const generateRandomString = length => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const array = new Uint8Array(length);
        return Array.from(crypto.getRandomValues(array), x => chars[x % chars.length]).join('');
    };

    const noisePacket = event.target.closest(".inner-container").querySelector('[name="wvruw"]');

    switch (event.target.value) {
        case 'base64':
            noisePacket.value = cfrie(64);
            break;

        case 'rand':
            noisePacket.value = "50-100";
            break;

        case 'hex':
            noisePacket.value = wabjb(64);
            break;

        case 'str':
            noisePacket.value = generateRandomString(64);
            break;
    }
}

function deleteUdpNoise(event) {
    if (globalThis.vaapu === 1) {
        alert('You cannot delete all noises!');
        return;
    }

    const confirmReset = confirm('Are you sure?');
    if (!confirmReset) return;
    event.target.closest(".inner-container").remove();
    jxxet();
    globalThis.vaapu--;
}

function renderUdpNoiseBlock(viece) {
    document.getElementById("noises").innerHTML = '';
    viece.forEach((noise, index) => {
        addUdpNoise(false, index, noise);
    });
    globalThis.vaapu = viece.length;
}