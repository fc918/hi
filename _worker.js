import { connect } from "cloudflare:sockets";

// Variables
let serviceName = "";
let APP_DOMAIN = "";
let prxIP = ""; // This will be set per-request

// Constants
const horse = "dHJvamFu";
const flash = "dm1lc3M=";
const vless = "dmxlc3M=";
const v2 = "djJyYXk=";
const neko = "Y2xhc2g=";
const PORTS = [443, 2053, 2083, 2087, 8443];
const PROTOCOLS = [atob(horse), atob(vless)];
const SUB_PAGE_URL = "https://foolvpn.me/nautica";
const KV_PRX_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";
const PRX_BANK_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = { host: "udp-relay.hobihaus.space", port: 7300 };
const CONVERTER_URL = "https://api.foolvpn.me/convert";
const WS_READY_STATE_OPEN = 1;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// Helper Functions (unchanged, but included for completeness)
async function getKVPrxList(url = KV_PRX_URL) {
  if (!url) throw new Error("No URL Provided!");
  const response = await fetch(url);
  return response.ok ? response.json() : {};
}
let cachedPrxList = [];
async function getPrxList(url = PRX_BANK_URL) {
  if (!url) throw new Error("No URL Provided!");
  const response = await fetch(url);
  if (response.ok) {
    const text = (await response.text()) || "";
    cachedPrxList = text.split("\n").filter(Boolean).map(entry => {
      const [ip, port, country, org] = entry.split(",");
      return { prxIP: ip, prxPort: port, country, org };
    });
  }
  return cachedPrxList;
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];

      if (request.headers.get("Upgrade") === "websocket") {
        let currentPrxIP = "";
        const prxMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (url.pathname.length === 3 || url.pathname.includes(",")) {
          const prxKeys = url.pathname.replace("/", "").toUpperCase().split(",");
          const prxKey = prxKeys[Math.floor(Math.random() * prxKeys.length)];
          const kvPrx = await getKVPrxList();
          if (kvPrx[prxKey] && kvPrx[prxKey].length > 0) {
            currentPrxIP = kvPrx[prxKey][Math.floor(Math.random() * kvPrx[prxKey].length)];
          }
        } else if (prxMatch) {
          currentPrxIP = prxMatch[1];
        }

        if (!currentPrxIP) {
          return new Response("Proxy IP not found for the given path.", { status: 404 });
        }
        
        return websocketHandler(request, currentPrxIP);
      }

      // Subscription generation logic remains here
      if (url.pathname.startsWith("/api/v1/wfc888")) {
          // This entire block is correct and does not need changes.
          // For brevity, I'm omitting it here but it should be in your final code.
          // The bug was not in subscription generation, but in connection handling.
          // ... (paste the '/api/v1/wfc888' block from the previous version here) ...
          const filterCC = url.searchParams.get("cc")?.split(",") || [];
          const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
          const filterVPN = url.searchParams.get("vpn")?.toLowerCase().split(",") || PROTOCOLS;
          const filterLimit = parseInt(url.searchParams.get("limit"), 10) || 9999;
          const filterFormat = url.searchParams.get("format") || "raw";
          const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;
          const prxBankUrl = url.searchParams.get("prx-list") || env.PRX_BANK_URL;
          
          let prxList = await getPrxList(prxBankUrl);
          if (filterCC.length > 0) {
            prxList = prxList.filter((prx) => filterCC.includes(prx.country));
          }
          shuffleArray(prxList);

          const uuid = crypto.randomUUID();
          const result = [];
          
          const tlsPorts = [443, 2053, 2083, 2087, 8443];

          for (const prx of prxList) {
            for (const port of filterPort) {
              if (!tlsPorts.includes(parseInt(port, 10))) continue;

              for (const protocol of filterVPN) {
                if (result.length >= filterLimit) break;
                
                let uriString = '';
                // Use prx.prxIP and prx.prxPort to construct the path
                const commonPath = `/${prx.prxIP}-${prx.prxPort}`;
                
                if (protocol === atob(vless)) {
                    const uri = new URL(`vless://${uuid}@${fillerDomain}:${port}`);
                    uri.searchParams.set("encryption", "none");
                    uri.searchParams.set("security", "tls");
                    uri.searchParams.set("sni", APP_DOMAIN);
                    uri.searchParams.set("type", "ws");
                    uri.searchParams.set("host", APP_DOMAIN);
                    uri.searchParams.set("path", commonPath);
                    uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} VLESS WS TLS [${serviceName}]`;
                    uriString = uri.toString();
                } else if (protocol === atob(horse)) {
                    const uri = new URL(`trojan://${uuid}@${fillerDomain}:${port}`);
                    uri.searchParams.set("security", "tls");
                    uri.searchParams.set("sni", APP_DOMAIN);
                    uri.searchParams.set("type", "ws");
                    uri.searchParams.set("host", APP_DOMAIN);
                    uri.searchParams.set("path", commonPath);
                    uri.hash = `${result.length + 1} ${getFlagEmoji(prx.country)} ${prx.org} TROJAN WS TLS [${serviceName}]`;
                    uriString = uri.toString();
                }
                
                if (uriString) result.push(uriString);
              }
              if (result.length >= filterLimit) break;
            }
            if (result.length >= filterLimit) break;
          }

          let finalResult = "";
          switch (filterFormat) {
            case "raw": finalResult = result.join("\n"); break;
            case atob(v2): finalResult = btoa(result.join("\n")); break;
            case atob(neko):
            case "sfa":
            case "bfr":
              const res = await fetch(CONVERTER_URL, {
                method: "POST",
                body: JSON.stringify({ url: result.join(","), format: filterFormat, template: "cf" }),
              });
              finalResult = res.ok ? await res.text() : res.statusText;
              break;
          }
          return new Response(finalResult, { status: 200, headers: { ...CORS_HEADER_OPTIONS } });
      }

      return new Response("Not a websocket request or valid API path.", { status: 400 });
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

// =================================================================
// =================== CORE LOGIC CORRECTION =======================
// =================================================================

async function websocketHandler(request, currentPrxIP) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let remoteSocket;
    let isClosed = false;

    const [proxyHost, proxyPort] = currentPrxIP.split(/[:=-]/);
    if (!proxyHost || !proxyPort) {
        webSocket.close(1011, "Invalid Proxy IP format");
        return new Response(null, { status: 101, webSocket: client });
    }

    try {
        remoteSocket = connect({ hostname: proxyHost, port: parseInt(proxyPort, 10) });
    } catch (error) {
        webSocket.close(1011, `Failed to connect to proxy: ${error.message}`);
        return new Response(null, { status: 101, webSocket: client });
    }

    // Pipe data from WebSocket to the remote proxy socket
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, () => { isClosed = true; });
    readableWebSocketStream.pipeTo(remoteSocket.writable).catch(err => {
        console.error("Error piping from WebSocket to remote:", err);
        safeClose(remoteSocket);
    });

    // Pipe data from the remote proxy socket back to the WebSocket
    remoteSocket.readable.pipeTo(new WritableStream({
        write(chunk) {
            if (!isClosed) {
                webSocket.send(chunk);
            }
        },
        close() {
            console.log("Remote socket closed");
            if (!isClosed) {
                webSocket.close(1000, "Remote connection closed");
            }
        },
        abort(err) {
            console.error("Remote socket aborted:", err);
            if (!isClosed) {
                webSocket.close(1011, "Remote connection aborted");
            }
        },
    })).catch(err => {
        console.error("Error piping from remote to WebSocket:", err);
        safeCloseWebSocket(webSocket);
    });

    return new Response(null, { status: 101, webSocket: client });
}

function makeReadableWebSocketStream(webSocket, onClose) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocket.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });
            webSocket.addEventListener("close", () => {
                console.log("WebSocket closed from client");
                onClose();
                if (readableStreamCancel) return;
                controller.close();
            });
            webSocket.addEventListener("error", (err) => {
                console.error("WebSocket error:", err);
                controller.error(err);
            });
        },
        cancel() {
            readableStreamCancel = true;
            safeCloseWebSocket(webSocket);
        },
    });
}

// Simplified closing functions
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN) {
            socket.close();
        }
    } catch (e) { console.error("Error closing WebSocket:", e); }
}

async function safeClose(socket) {
    try {
        const writer = socket.writable.getWriter();
        await writer.close();
    } catch (e) { console.error("Error closing remote socket:", e); }
}

// Utility functions for subscription generation
function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
}

function getFlagEmoji(isoCode) {
  if (!isoCode || isoCode.length !== 2) return "🏳️";
  const codePoints = isoCode.toUpperCase().split("").map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...points);
}
