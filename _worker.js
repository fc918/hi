import { connect } from "cloudflare:sockets";

// Variables
let serviceName = "";
let APP_DOMAIN = "";

let prxIP = "";
let cachedPrxList = [];

// Constant
const horse = "dHJvamFu";
const flash = "dm1lc3M=";
const v2 = "djJyYXk=";
const neko = "Y2xhc2g=";

// 10个内置的Cloudflare优选域名
const CUSTOM_DOMAINS = [
    "www.visa.com",
    "www.msn.com",
    "www.icbc.com.cn",
    "www.reuters.com",
    "www.aol.com",
    "cdn.anycast.eu.org",
    "cdn-all.xn--b6gac.eu.org",
    "edgetunnel.anycast.eu.org",
    "www.speedtest.net",
    "www.hugedomains.com"
];

const PORTS = [443, 2053, 2083, 2087, 2096]; // 5个TLS端口
const PROTOCOLS = [atob(horse)]; // 仅保留trojan协议
const SUB_PAGE_URL = "https://foolvpn.me/nautica";
const KV_PRX_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";
const PRX_BANK_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
host: "udp-relay.hobihaus.space",
port: 7300,
};
const PRX_HEALTH_CHECK_API = "https://id1.foolvpn.me/api/v1/check";
const CONVERTER_URL = "https://api.foolvpn.me/convert";
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
"Access-Control-Allow-Origin": "*",
"Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
"Access-Control-Max-Age": "86400",
};

async function getKVPrxList(kvPrxUrl = KV_PRX_URL) {
if (!kvPrxUrl) {
throw new Error("No URL Provided!");
}

const kvPrx = await fetch(kvPrxUrl);
if (kvPrx.status == 200) {
return await kvPrx.json();
} else {
return {};
}
}

async function getPrxList(prxBankUrl = PRX_BANK_URL) {
if (!prxBankUrl) {
throw new Error("No URL Provided!");
}

const prxBank = await fetch(prxBankUrl);
if (prxBank.status == 200) {
const text = (await prxBank.text()) || "";
const prxString = text.split("\n").filter(Boolean);
cachedPrxList = prxString
  .map((entry) => {
    const [prxIP, prxPort, country, org] = entry.split(",");
    return {
      prxIP: prxIP || "Unknown",
      prxPort: prxPort || "Unknown",
      country: country || "Unknown",
      org: org || "Unknown Org",
    };
  })
  .filter(Boolean);

}

return cachedPrxList;
}

async function reverseWeb(request, target, targetPath) {
const targetUrl = new URL(request.url);
const targetChunk = target.split(":");

targetUrl.hostname = targetChunk[0];
targetUrl.port = targetChunk[1]?.toString() || "443";
targetUrl.pathname = targetPath || targetUrl.pathname;

const modifiedRequest = new Request(targetUrl, request);

modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

const response = await fetch(modifiedRequest);

const newResponse = new Response(response.body, response);
for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
newResponse.headers.set(key, value);
}
newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

return newResponse;
}

export default {
async fetch(request, env, ctx) {
try {
const url = new URL(request.url);
APP_DOMAIN = url.hostname;
serviceName = APP_DOMAIN.split(".")[0];
const upgradeHeader = request.headers.get("Upgrade");

  if (upgradeHeader === "websocket") {
    const prxMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

    if (url.pathname.length == 3 || url.pathname.match(",")) {
      const prxKeys = url.pathname.replace("/", "").toUpperCase().split(",");
      const prxKey = prxKeys[Math.floor(Math.random() * prxKeys.length)];
      const kvPrx = await getKVPrxList();

      prxIP = kvPrx[prxKey][Math.floor(Math.random() * kvPrx[prxKey].length)];

      return await websocketHandler(request);
    } else if (prxMatch) {
      prxIP = prxMatch[1];
      return await websocketHandler(request);
    }
  }

  if (url.pathname.startsWith("/sub")) {
    return Response.redirect(SUB_PAGE_URL + `?host=${APP_DOMAIN}`, 301);
  } else if (url.pathname.startsWith("/check")) {
    const target = url.searchParams.get("target").split(":");
    const result = await checkPrxHealth(target[0], target[1] || "443");

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: {
        ...CORS_HEADER_OPTIONS,
        "Content-Type": "application/json",
      },
    });
  } else if (url.pathname.startsWith("/api/v1")) {
    const apiPath = url.pathname.replace("/api/v1", "");

    if (apiPath.startsWith("/wfc888")) {
      const filterCC = url.searchParams.get("cc")?.split(",") || [];
      const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
      const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
      const filterLimit = parseInt(url.searchParams.get("limit")) || 9999;
      const filterFormat = url.searchParams.get("format") || "raw";
      
      const prxBankUrl = url.searchParams.get("prx-list") || env.PRX_BANK_URL;
      const prxList = await getPrxList(prxBankUrl)
        .then((prxs) => {
          if (filterCC.length) {
            return prxs.filter((prx) => filterCC.includes(prx.country));
          }
          return prxs;
        })
        .then((prxs) => {
          shuffleArray(prxs);
          return prxs;
        });

      const uuid = crypto.randomUUID();
      const result = [];
      for (const prx of prxList) {
        // 从内置域名列表中随机选择一个域名
        const randomDomain = CUSTOM_DOMAINS[Math.floor(Math.random() * CUSTOM_DOMAINS.length)];

        const uri = new URL(`${atob(horse)}://${randomDomain}`);
        uri.searchParams.set("encryption", "none");
        uri.searchParams.set("type", "ws");
        uri.searchParams.set("host", randomDomain);

        for (const port of filterPort) {
          for (const protocol of filterVPN) {
            if (result.length >= filterLimit) break;

            uri.protocol = protocol;
            uri.port = port.toString();
            uri.username = uuid;
            uri.searchParams.set("security", "tls");
            uri.searchParams.set("sni", randomDomain);
            uri.searchParams.set("path", `/${prx.prxIP}-${prx.prxPort}`);

            uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} WS TLS [${serviceName}]`;
            result.push(uri.toString());
          }
        }
      }

      let finalResult = "";
      switch (filterFormat) {
        case "raw":
          finalResult = result.join("\n");
          break;
        case atob(v2):
          finalResult = btoa(result.join("\n"));
          break;
        case atob(neko):
        case "sfa":
        case "bfr":
          const res = await fetch(CONVERTER_URL, {
            method: "POST",
            body: JSON.stringify({
              url: result.join(","),
              format: filterFormat,
              template: "cf",
            }),
          });
          if (res.status == 200) {
            finalResult = await res.text();
          } else {
            return new Response(res.statusText, {
              status: res.status,
              headers: { ...CORS_HEADER_OPTIONS },
            });
          }
          break;
      }

      return new Response(finalResult, {
        status: 200,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    } else if (apiPath.startsWith("/myip")) {
      return new Response(
        JSON.stringify({
          ip:
            request.headers.get("cf-connecting-ipv6") ||
            request.headers.get("cf-connecting-ip") ||
            request.headers.get("x-real-ip"),
          colo: request.headers.get("cf-ray")?.split("-")[1],
          ...request.cf,
        }),
        {
          headers: { ...CORS_HEADER_OPTIONS },
        }
      );
    }
  }

  const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
  return await reverseWeb(request, targetReversePrx);
} catch (err) {
  return new Response(`An error occurred: ${err.toString()}`, {
    status: 500,
    headers: { ...CORS_HEADER_OPTIONS },
  });
}
},
};

async function websocketHandler(request) {
const webSocketPair = new WebSocketPair();
const [client, webSocket] = Object.values(webSocketPair);

webSocket.accept();

let addressLog = "";
let portLog = "";
const log = (info, event) => {
console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
};
const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

let remoteSocketWrapper = {
value: null,
};
let isDNS = false;

readableWebSocketStream
.pipeTo(
new WritableStream({
async write(chunk, controller) {
if (isDNS) {
return handleUDPOutbound(
DNS_SERVER_ADDRESS,
DNS_SERVER_PORT,
chunk,
webSocket,
null,
log,
RELAY_SERVER_UDP
);
}
if (remoteSocketWrapper.value) {
const writer = remoteSocketWrapper.value.writable.getWriter();
await writer.write(chunk);
writer.releaseLock();
return;
}
const protocol = await protocolSniffer(chunk);
      let protocolHeader;

      if (protocol === atob(horse)) {
        protocolHeader = readHorseHeader(chunk);
      } else if (protocol === atob(flash)) {
        protocolHeader = readFlashHeader(chunk);
      } else {
        throw new Error("Unknown Protocol!");
      }

      addressLog = protocolHeader.addressRemote;
      portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

      if (protocolHeader.hasError) {
        throw new Error(protocolHeader.message);
      }

      if (protocolHeader.isUDP) {
        if (protocolHeader.portRemote === 53) {
          isDNS = true;
          return handleUDPOutbound(
            DNS_SERVER_ADDRESS,
            DNS_SERVER_PORT,
            chunk,
            webSocket,
            protocolHeader.version,
            log,
            RELAY_SERVER_UDP
          );
        }

        return handleUDPOutbound(
          protocolHeader.addressRemote,
          protocolHeader.portRemote,
          chunk,
          webSocket,
          protocolHeader.version,
          log,
          RELAY_SERVER_UDP
        );
      }

      handleTCPOutBound(
        remoteSocketWrapper,
        protocolHeader.addressRemote,
        protocolHeader.portRemote,
        protocolHeader.rawClientData,
        webSocket,
        protocolHeader.version,
        log
      );
    },
    close() {
      log(`readableWebSocketStream is close`);
    },
    abort(reason) {
      log(`readableWebSocketStream is abort`, JSON.stringify(reason));
    },
  })
)
.catch((err) => {
  log("readableWebSocketStream pipeTo error", err);
});

return new Response(null, {
status: 101,
webSocket: client,
});
}

async function protocolSniffer(buffer) {
if (buffer.byteLength >= 62) {
const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
return atob(horse);
}
}
}
}

return atob(flash); // Fallback
}

async function handleTCPOutBound(
remoteSocket,
addressRemote,
portRemote,
rawClientData,
webSocket,
responseHeader,
log
) {
async function connectAndWrite(address, port) {
const tcpSocket = connect({
hostname: address,
port: port,
});
remoteSocket.value = tcpSocket;
log(`connected to ${address}:${port}`);
const writer = tcpSocket.writable.getWriter();
await writer.write(rawClientData);
writer.releaseLock();
return tcpSocket;
}

async function retry() {
const tcpSocket = await connectAndWrite(
prxIP.split(/[:=-]/)[0] || addressRemote,
prxIP.split(/[:=-]/)[1] || portRemote
);
tcpSocket.closed
.catch((error) => {
console.log("retry tcpSocket closed error", error);
})
.finally(() => {
safeCloseWebSocket(webSocket);
});
remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
}

const tcpSocket = await connectAndWrite(addressRemote, portRemote);

remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
try {
let protocolHeader = responseHeader;
const tcpSocket = connect({
  hostname: relay.host,
  port: relay.port,
});

const header = `udp:${targetAddress}:${targetPort}`;
const headerBuffer = new TextEncoder().encode(header);
const separator = new Uint8Array([0x7c]);
const relayMessage = new Uint8Array(headerBuffer.length + separator.length + dataChunk.byteLength);
relayMessage.set(headerBuffer, 0);
relayMessage.set(separator, headerBuffer.length);
relayMessage.set(new Uint8Array(dataChunk), headerBuffer.length + separator.length);

const writer = tcpSocket.writable.getWriter();
await writer.write(relayMessage);
writer.releaseLock();

await tcpSocket.readable.pipeTo(
  new WritableStream({
    async write(chunk) {
      if (webSocket.readyState === WS_READY_STATE_OPEN) {
        if (protocolHeader) {
          webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
          protocolHeader = null;
        } else {
          webSocket.send(chunk);
        }
      }
    },
    close() {
      log(`UDP connection to ${targetAddress} closed`);
    },
    abort(reason) {
      console.error(`UDP connection aborted due to ${reason}`);
    },
  })
);

} catch (e) {
console.error(`Error while handling UDP outbound: ${e.message}`);
}
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
let readableStreamCancel = false;
const stream = new ReadableStream({
start(controller) {
webSocketServer.addEventListener("message", (event) => {
if (readableStreamCancel) {
return;
}
const message = event.data;
controller.enqueue(message);
});
webSocketServer.addEventListener("close", () => {
safeCloseWebSocket(webSocketServer);
if (readableStreamCancel) {
return;
}
controller.close();
});
webSocketServer.addEventListener("error", (err) => {
log("webSocketServer has error");
controller.error(err);
});
const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
if (error) {
controller.error(error);
} else if (earlyData) {
controller.enqueue(earlyData);
}
},
pull(controller) {},
cancel(reason) {
  if (readableStreamCancel) {
    return;
  }
  log(`ReadableStream was canceled, due to ${reason}`);
  readableStreamCancel = true;
  safeCloseWebSocket(webSocketServer);
},

});

return stream;
}

function readFlashHeader(buffer) {
const version = new Uint8Array(buffer.slice(0, 1));
let isUDP = false;

const optLength = new Uint8Array(buffer.slice(17, 18))[0];

const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
if (cmd === 1) {
} else if (cmd === 2) {
isUDP = true;
} else {
return {
hasError: true,
message: `command ${cmd} is not supported`,
};
}
const portIndex = 18 + optLength + 1;
const portBuffer = buffer.slice(portIndex, portIndex + 2);
const portRemote = new DataView(portBuffer).getUint16(0);

let addressIndex = portIndex + 2;
const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));

const addressType = addressBuffer[0];
let addressLength = 0;
let addressValueIndex = addressIndex + 1;
let addressValue = "";
switch (addressType) {
case 1:
addressLength = 4;
addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
break;
case 2:
addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
addressValueIndex += 1;
addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
break;
case 3:
addressLength = 16;
const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
const ipv6 = [];
for (let i = 0; i < 8; i++) {
ipv6.push(dataView.getUint16(i * 2).toString(16));
}
addressValue = ipv6.join(":");
break;
default:
return {
hasError: true,
message: `invalid addressType is ${addressType}`,
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
addressType: addressType,
portRemote: portRemote,
rawDataIndex: addressValueIndex + addressLength,
rawClientData: buffer.slice(addressValueIndex + addressLength),
version: new Uint8Array([version[0], 0]),
isUDP: isUDP,
};
}

function readHorseHeader(buffer) {
const dataBuffer = buffer.slice(58);
if (dataBuffer.byteLength < 6) {
return {
hasError: true,
message: "invalid request data",
};
}

let isUDP = false;
const view = new DataView(dataBuffer);
const cmd = view.getUint8(0);
if (cmd == 3) {
isUDP = true;
} else if (cmd != 1) {
throw new Error("Unsupported command type!");
}

let addressType = view.getUint8(1);
let addressLength = 0;
let addressValueIndex = 2;
let addressValue = "";
switch (addressType) {
case 1:
addressLength = 4;
addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
break;
case 3:
addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
addressValueIndex += 1;
addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
break;
case 4:
addressLength = 16;
const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
const ipv6 = [];
for (let i = 0; i < 8; i++) {
ipv6.push(dataView.getUint16(i * 2).toString(16));
}
addressValue = ipv6.join(":");
break;
default:
return {
hasError: true,
message: `invalid addressType is ${addressType}`,
};
}

if (!addressValue) {
return {
hasError: true,
message: `address is empty, addressType is ${addressType}`,
};
}

const portIndex = addressValueIndex + addressLength;
const portBuffer = dataBuffer.slice(portIndex, portIndex + 2);
const portRemote = new DataView(portBuffer).getUint16(0);
return {
hasError: false,
addressRemote: addressValue,
addressType: addressType,
portRemote: portRemote,
rawDataIndex: portIndex + 4,
rawClientData: dataBuffer.slice(portIndex + 4),
version: null,
isUDP: isUDP,
};
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
let header = responseHeader;
let hasIncomingData = false;
await remoteSocket.readable
.pipeTo(
new WritableStream({
start() {},
async write(chunk, controller) {
hasIncomingData = true;
if (webSocket.readyState !== WS_READY_STATE_OPEN) {
controller.error("webSocket.readyState is not open, maybe close");
}
if (header) {
webSocket.send(await new Blob([header, chunk]).arrayBuffer());
header = null;
} else {
webSocket.send(chunk);
}
},
close() {
log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
},
abort(reason) {
console.error(`remoteConnection!.readable abort`, reason);
},
})
)
.catch((error) => {
console.error(`remoteSocketToWS has exception `, error.stack || error);
safeCloseWebSocket(webSocket);
});
if (hasIncomingData === false && retry) {
log(`retry`);
retry();
}
}

function safeCloseWebSocket(socket) {
try {
if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
socket.close();
}
} catch (error) {
console.error("safeCloseWebSocket error", error);
}
}

async function checkPrxHealth(prxIP, prxPort) {
const req = await fetch(`${PRX_HEALTH_CHECK_API}?ip=${prxIP}:${prxPort}`);
return await req.json();
}

// Helpers
function base64ToArrayBuffer(base64Str) {
if (!base64Str) {
return { error: null };
}
try {
base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
const decode = atob(base64Str);
const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
return { earlyData: arryBuffer.buffer, error: null };
} catch (error) {
return { error };
}
}

function arrayBufferToHex(buffer) {
return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
let currentIndex = array.length;

while (currentIndex != 0) {
let randomIndex = Math.floor(Math.random() * currentIndex);
currentIndex--;
[array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
}
}

function getFlagEmoji(isoCode) {
const codePoints = isoCode
.toUpperCase()
.split("")
.map((char) => 127397 + char.charCodeAt(0));
return String.fromCodePoint(...codePoints);
}
