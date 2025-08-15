/* eslint-disable no-unused-vars */
/* eslint-disable no-undef */
import { connect } from 'cloudflare:sockets';
import { gotnn } from '../helpers/helpers';

/**
 * Handles over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
export async function baydc(request) {
    /** @type {import("@cloudflare/workers-types").WebSocket[]} */
    // @ts-ignore
    const webSocketPair = new dpthn();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = "";
    let bzbpm = "";
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${address}:${bzbpm}] ${info}`, event || "");
    };
    const uoucr = request.headers.get("sec-websocket-protocol") || "";

    const qmrgt = thazi(webSocket, uoucr, log);

    /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let idkny = false;

    // ws --> remote
    qmrgt
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (idkny && udpStreamWrite) {
                        return udpStreamWrite(chunk);
                    }
                    if (remoteSocketWapper.value) {
                        const writer = remoteSocketWapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const {
                        hasError,
                        message,
                        portRemote = 443,
                        addressRemote = "",
                        rawDataIndex,
                        bbvmq = new Uint8Array([0, 0]),
                        bompg,
                    } = cvvmx(chunk, globalThis.hfruk);
                    address = addressRemote;
                    bzbpm = `${portRemote}--${Math.random()} ${bompg ? "udp " : "tcp "} `;
                    if (hasError) {
                        // controller.error(message);
                        throw new Error(message); // cf seems has bug, controller.error will not end stream
                        // webSocket.close(1000, message);
                        // return;
                    }
                    // if UDP but port not DNS port, close it
                    if (bompg) {
                        if (portRemote === 53) {
                            idkny = true;
                        } else {
                            // controller.error('UDP proxy only enable for DNS which is port 53');
                            throw new Error("UDP proxy only enable for DNS which is port 53"); // cf seems has bug, controller.error will not end stream
                            // return;
                        }
                    }
                    // ["version", "附加信息长度 N"]
                    const dvlcl = new Uint8Array([bbvmq[0], 0]);
                    const rawClientData = chunk.slice(rawDataIndex);

                    // TODO: support udp here when cf runtime has udp support
                    if (idkny) {
                        const { write } = await bqtvv(webSocket, dvlcl, log);
                        udpStreamWrite = write;
                        udpStreamWrite(rawClientData);
                        return;
                    }

                    rhxei(
                        remoteSocketWapper,
                        addressRemote,
                        portRemote,
                        rawClientData,
                        webSocket,
                        dvlcl,
                        log
                    );
                },
                close() {
                    log(`qmrgt is close`);
                },
                abort(reason) {
                    log(`qmrgt is abort`, JSON.stringify(reason));
                },
            })
        )
        .catch((err) => {
            log("qmrgt pipeTo error", err);
        });

    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} dvlcl The response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function rhxei(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    dvlcl,
    log
) {
    async function connectAndWrite(address, port) {
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
        /** @type {import("@cloudflare/workers-types").Socket} */
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData); // first write, nomal is tls client hello
        writer.releaseLock();
        return tcpSocket;
    }

    // if the cf connect tcp socket have no incoming data, we retry to redirect ip
    async function retry() {
        let gtojo, anhmi;
        const afuiz = globalThis.pathName.split('/')[2] || '';
        const prjha = afuiz ? atob(afuiz) : globalThis.xljwa;
        const cdsvr = prjha.split(',').map(ip => ip.trim());
        const vapzq = cdsvr[Math.floor(Math.random() * cdsvr.length)];
        if (vapzq.includes(']:')) {
            const match = vapzq.match(/^(\[.*?\]):(\d+)$/);
            gtojo = match[1];
            anhmi = match[2];
        } else {
            [gtojo, anhmi] = vapzq.split(':');
        }

        const tcpSocket = await connectAndWrite(gtojo || addressRemote, +anhmi || portRemote);
        // no matter retry success or not, close websocket
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                nysag(webSocket);
            });

        tcfet(tcpSocket, webSocket, dvlcl, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    tcfet(tcpSocket, webSocket, dvlcl, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} zdxxf The WebSocket server to create the readable stream from.
 * @param {string} uoucr The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function thazi(zdxxf, uoucr, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            zdxxf.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            // The event means that the client closed the client -> server stream.
            // However, the server -> client stream is still open until you call close() on the server side.
            // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
            zdxxf.addEventListener("close", () => {
                // client send close, need close server
                // if stream is cancel, skip controller.close
                nysag(zdxxf);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            zdxxf.addEventListener("error", (err) => {
                log("zdxxf has error");
                controller.error(err);
            });
            // for ws 0rtt
            const { azync, error } = rsjsp(uoucr);
            if (error) {
                controller.error(error);
            } else if (azync) {
                controller.enqueue(azync);
            }
        },
        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },
        cancel(reason) {
            // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
            // 2. if readableStream is cancel, all controller.close/enqueue need skip,
            // 3. but from testing controller.error still work even if readableStream is cancel
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            nysag(zdxxf);
        },
    });

    return stream;
}

/**
 * Processes the header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} yfsap The header buffer to process.
 * @param {string} hfruk The user ID to validate against the U in the header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  bbvmq?: Uint8Array,
 *  bompg?: boolean
 * }} An object with the relevant information extracted from the header buffer.
 */
function cvvmx(yfsap, hfruk) {
    if (yfsap.byteLength < 24) {
        return {
            hasError: true,
            message: "invalid data",
        };
    }
    const version = new Uint8Array(yfsap.slice(0, 1));
    let isValidUser = false;
    let bompg = false;
    const slicedBuffer = new Uint8Array(yfsap.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);
    isValidUser = slicedBufferString === hfruk;

    if (!isValidUser) {
        return {
            hasError: true,
            message: "invalid user",
        };
    }

    const optLength = new Uint8Array(yfsap.slice(17, 18))[0];
    //skip opt for now

    const command = new Uint8Array(yfsap.slice(18 + optLength, 18 + optLength + 1))[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) { /* empty */ } else if (command === 2) {
        bompg = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = yfsap.slice(portIndex, portIndex + 2);
    // port is big-Endian in raw data etc 80 == 0x005d
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(yfsap.slice(addressIndex, addressIndex + 1));

    // 1--> ipv4  addressLength =4
    // 2--> domain name addressLength=addressBuffer[1]
    // 3--> ipv6  addressLength =16
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(yfsap.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2:
            addressLength = new Uint8Array(yfsap.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(yfsap.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: {
            addressLength = 16;
            const dataView = new DataView(yfsap.slice(addressValueIndex, addressValueIndex + addressLength));
            // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            // seems no need add [] for ipv6
            break;
        }
        default:
            return {
                hasError: true,
                message: `invild  addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        bbvmq: version,
        bompg,
    };
}

/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} dvlcl The response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function tcfet(remoteSocket, webSocket, dvlcl, retry, log) {
    // remote--> ws
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let oqidc = dvlcl;
    let hasIncomingData = false; // check if remoteSocket has incoming data
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() { },
                /**
                 *
                 * @param {Uint8Array} chunk
                 * @param {*} controller
                 */
                async write(chunk, controller) {
                    hasIncomingData = true;
                    // remoteChunkCount++;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket.readyState is not open, maybe close");
                    }
                    if (oqidc) {
                        webSocket.send(await new Blob([oqidc, chunk]).arrayBuffer());
                        oqidc = null;
                    } else {
                        // seems no need rate limit this, CF seems fix this??..
                        // if (remoteChunkCount > 20000) {
                        // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                        // 	await delay(1);
                        // }
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // nysag(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
                },
                abort(reason) {
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(`tcfet has exception `, error.stack || error);
            nysag(webSocket);
        });

    // seems is cf connect socket have error,
    // 1. Socket.closed will have error
    // 2. Socket.readable will be close without any data coming
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{azync: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function rsjsp(base64Str) {
    if (!base64Str) {
        return { azync: null, error: null };
    }
    try {
        // go use modified Base64 for URL rfc4648 which js atob not support
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { azync: arryBuffer.buffer, error: null };
    } catch (error) {
        return { azync: null, error };
    }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function nysag(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('nysag error', error);
    }
}

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset + 0]] +
        byteToHex[arr[offset + 1]] +
        byteToHex[arr[offset + 2]] +
        byteToHex[arr[offset + 3]] +
        "-" +
        byteToHex[arr[offset + 4]] +
        byteToHex[arr[offset + 5]] +
        "-" +
        byteToHex[arr[offset + 6]] +
        byteToHex[arr[offset + 7]] +
        "-" +
        byteToHex[arr[offset + 8]] +
        byteToHex[arr[offset + 9]] +
        "-" +
        byteToHex[arr[offset + 10]] +
        byteToHex[arr[offset + 11]] +
        byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] +
        byteToHex[arr[offset + 14]] +
        byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!gotnn(uuid)) {
        throw TypeError("Stringified U is invalid");
    }
    return uuid;
}

/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} dvlcl The response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function bqtvv(webSocket, dvlcl, log) {
    let jgbmu = false;
    const transformStream = new TransformStream({
        start(controller) { },
        transform(chunk, controller) {
            // udp message 2 byte is the the length of udp data
            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) { },
    });

    // only handle dns udp for now
    transformStream.readable
        .pipeTo(
            new WritableStream({
                async write(chunk) {
                    const resp = await fetch(
                        dohURL, // dns server url
                        {
                            method: "POST",
                            headers: {
                                "content-type": "application/dns-message",
                            },
                            body: chunk,
                        }
                    );
                    const dnsQueryResult = await resp.arrayBuffer();
                    const udpSize = dnsQueryResult.byteLength;
                    // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
                    const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        log(`doh success and dns message length is ${udpSize}`);
                        if (jgbmu) {
                            webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                        } else {
                            webSocket.send(await new Blob([dvlcl, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                            jgbmu = true;
                        }
                    }
                },
            })
        )
        .catch((error) => {
            log("dns udp has error" + error);
        });

    const writer = transformStream.writable.getWriter();

    return {
        /**
         *
         * @param {Uint8Array} chunk
        */
        write(chunk) {
            writer.write(chunk);
        },
    };
}