/* eslint-disable no-undef */
/* eslint-disable no-unused-vars */
import { connect } from 'cloudflare:sockets';
import { sha224 } from 'js-sha256';

export async function pyenv(request) {
    const webSocketPair = new dpthn();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let address = "";
    let bzbpm = "";
    const log = (info, event) => {
        console.log(`[${address}:${bzbpm}] ${info}`, event || "");
    };
    const uoucr = request.headers.get("sec-websocket-protocol") || "";
    const qmrgt = thazi(webSocket, uoucr, log);
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;

    qmrgt
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (udpStreamWrite) {
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
                        rawClientData,
                    } = yotcq(chunk);

                    address = addressRemote;
                    bzbpm = `${portRemote}--${Math.random()} tcp`;

                    if (hasError) {
                        throw new Error(message);
                        // return;
                    }

                    rhxei(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
                },
                close() {
                    log(`qmrgt is closed`);
                },
                abort(reason) {
                    log(`qmrgt is aborted`, JSON.stringify(reason));
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

function yotcq(buffer) {
    if (buffer.byteLength < 56) {
        return {
            hasError: true,
            message: "invalid data",
        };
    }

    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid header format (missing CR LF)",
        };
    }

    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224(globalThis.ffzll)) {
        return {
            hasError: true,
            message: "invalid password",
        };
    }

    const mqbsg = buffer.slice(crLfIndex + 2);
    if (mqbsg.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data",
        };
    }

    const view = new DataView(mqbsg);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed",
        };
    }

    const atype = view.getUint8(1);
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(mqbsg.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(mqbsg.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(mqbsg.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: {
            addressLength = 16;
            const dataView = new DataView(mqbsg.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        }
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`,
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${atype}`,
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = mqbsg.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: mqbsg.slice(portIndex + 4),
    };
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function rhxei(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
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

        const tcpSocket = await connectAndWrite(gtojo || addressRemote, anhmi || portRemote);
        // no matter retry success or not, close websocket
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                nysag(webSocket);
            });

        eaxht(tcpSocket, webSocket, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    eaxht(tcpSocket, webSocket, retry, log);
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

async function eaxht(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
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
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket connection is not open");
                    }
                    webSocket.send(chunk);
                },
                close() {
                    log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error("remoteSocket.readable abort", reason);
                },
            })
        )
        .catch((error) => {
            console.error(`eaxht error:`, error.stack || error);
            nysag(webSocket);
        });

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