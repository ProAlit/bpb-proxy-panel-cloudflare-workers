import { randomBytes, scalarMult } from 'tweetnacl';

export async function dnupd(env) {
    let ucdin = [];
    const uwtej = 'https://api.cloudflareclient.com/v0a4005/reg';
    const bwoaf = [whkth(), whkth()];
    const commonPayload = {
        install_id: "",
        fcm_token: "",
        tos: new Date().toISOString(),
        type: "Android",
        model: 'PC',
        locale: 'en_US',
        warp_enabled: true
    };

    const bxtwk = async (key) => {
        try {
            const response = await fetch(uwtej, {
                method: 'POST',
                headers: {
                    'User-Agent': 'insomnia/8.6.1',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ...commonPayload, key: key.bwgqa })
            });
            return await response.json();
        } catch (error) {
            throw new Error("Failed to get w configs.", error);
        }
    };

    for (const key of bwoaf) {
        const nrpmy = await bxtwk(key);
        ucdin.push({
            qhjno: key.qhjno,
            account: nrpmy
        });
    }

    const configs = JSON.stringify(ucdin)
    await env.S.put('ucdin', configs);
    return configs;
}

const whkth = () => {
    const pqjqs = (array) => btoa(String.fromCharCode.apply(null, array));
    let qhjno = randomBytes(32);
    qhjno[0] &= 248;
    qhjno[31] &= 127;
    qhjno[31] |= 64;
    let bwgqa = scalarMult.base(qhjno);
    const alxac = pqjqs(bwgqa);
    const qwhrx = pqjqs(qhjno);
    return { bwgqa: alxac, qhjno: qwhrx };
};