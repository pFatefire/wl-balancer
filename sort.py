import argparse
import glob
import json
import os
import re
import sys
import urllib.request
from urllib.parse import unquote, urlparse

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) vl2balancer/2.0"
SERVERS_PER_BALANCER = 25
BALANCER_NAME = "🚧 | Белые списки {index} | {count}"
SUBSCRIPTION_FILE = "subscription.json"
DEFAULT_SOURCE = "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"
LINK_RE = re.compile(r"vless://[^\s<>\"'`]+")
RESERVED = ["geosite:category-ir", "geosite:category-ru", "geosite:cn"]
RESERVED_IP = ["geoip:private", "geoip:ir", "geoip:ru", "geoip:cn", "geoip:vn"]


def read_source(src):
    if src.startswith("http"):
        request = urllib.request.Request(src, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="ignore")
    if os.path.isdir(src):
        paths = [p for p in glob.glob(os.path.join(src, "*")) if os.path.isfile(p)]
    elif os.path.isfile(src):
        paths = [src]
    else:
        raise FileNotFoundError("no such file or directory: " + src)
    chunks = []
    for path in paths:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            chunks.append(handle.read())
    return "\n".join(chunks)


def collect_links(sources):
    links = []
    for src in sources:
        try:
            links.extend(LINK_RE.findall(read_source(src)))
        except OSError as error:
            print(f"Cannot read {src}: {error}", file=sys.stderr)
    return links


def parse_query(text):
    query = {}
    for part in text.split("&"):
        if part:
            key, _, value = part.partition("=")
            query[unquote(key)] = unquote(value)
    return query


def parse_link(link):
    parsed = urlparse(link.strip())
    if parsed.scheme != "vless" or not parsed.username or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if not port:
        return None
    return {"id": unquote(parsed.username), "host": parsed.hostname,
            "port": port, "query": parse_query(parsed.query)}


def stream_settings(query):
    network = (query.get("type") or "tcp").lower()
    security = (query.get("security") or "none").lower()
    stream = {"network": network, "security": security}

    if security == "tls":
        tls = {"serverName": query.get("sni"), "fingerprint": query.get("fp")}
        tls = {k: v for k, v in tls.items() if v}
        if query.get("alpn"):
            tls["alpn"] = [a for a in query["alpn"].split(",") if a]
        if query.get("allowInsecure") in ("1", "true", "True"):
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls

    if security == "reality":
        reality = {"serverName": query.get("sni"), "fingerprint": query.get("fp"),
                   "publicKey": query.get("pbk"), "shortId": query.get("sid"),
                   "spiderX": query.get("spx"), "mldsa65Verify": query.get("pqv")}
        stream["realitySettings"] = {k: v for k, v in reality.items() if v}

    if network == "xhttp":
        settings = {k: query[k] for k in ("host", "path", "mode") if query.get(k)}
        settings.setdefault("mode", "auto")
        settings.setdefault("path", "/")
        if query.get("extra") not in (None, "", "null"):
            try:
                settings["extra"] = json.loads(query["extra"])
            except json.JSONDecodeError:
                pass
        stream["xhttpSettings"] = settings
    elif network == "ws":
        stream["wsSettings"] = {k: query[k] for k in ("host", "path") if query.get(k)}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": query.get("serviceName", "")}
    elif network in ("tcp", "raw"):
        if query.get("headerType") == "http":
            request = {"path": [query.get("path", "/")]}
            if query.get("host"):
                request["headers"] = {"Host": [query["host"]]}
            stream["tcpSettings"] = {"header": {"type": "http", "request": request}}
    elif network in ("h2", "http"):
        http = {}
        if query.get("host"):
            http["host"] = [query["host"]]
        if query.get("path"):
            http["path"] = query["path"]
        stream["httpSettings"] = http

    return stream


def make_outbound(config, tag, fmt):
    query = config["query"]
    encryption = query.get("encryption") or "none"
    if fmt == "xray":
        user = {"id": config["id"], "encryption": encryption, "level": 8}
        if query.get("flow"):
            user["flow"] = query["flow"]
        settings = {"vnext": [{"address": config["host"], "port": config["port"],
                               "users": [user]}]}
    else:
        settings = {"address": config["host"], "port": config["port"],
                    "id": config["id"], "encryption": encryption, "level": 8}
        if query.get("flow"):
            settings["flow"] = query["flow"]
    return {"protocol": "vless", "settings": settings,
            "streamSettings": stream_settings(query), "tag": tag}


def make_config(configs, index, total, fmt, port_base):
    prefix = f"bal-{index}-"
    outbounds = [make_outbound(c, f"{prefix}{n}", fmt)
                 for n, c in enumerate(configs, start=1)]
    outbounds.append({"protocol": "freedom", "settings": {}, "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "settings": {}, "tag": "block"})

    return {
        "remarks": BALANCER_NAME.format(key=configs[0]["host"], index=index,
                                        count=len(configs), total=total),
        "log": {"loglevel": "warning"},
        "dns": {"tag": "dns_out", "queryStrategy": "UseIP",
                "servers": [{"address": "8.8.8.8", "skipFallback": False}]},
        "inbounds": [
            {"tag": "mixed", "listen": "127.0.0.1", "port": port_base,
             "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
             "sniffing": {"enabled": True,
                          "destOverride": ["http", "tls", "quic", "fakedns"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": port_base + 1,
             "protocol": "http", "settings": {"userLevel": 8}},
        ],
        "outbounds": outbounds,
        "burstObservatory": {
            "subjectSelector": [prefix],
            "pingConfig": {"connectivity": "", "httpMethod": "HEAD",
                           "destination": "https://www.google.com/generate_204",
                           "interval": "5s", "sampling": 2, "timeout": "5s"},
        },
        "policy": {
            "levels": {"8": {"handshake": 4, "connIdle": 300,
                             "uplinkOnly": 1, "downlinkOnly": 1}},
            "system": {"statsOutboundUplink": True,
                       "statsOutboundDownlink": True},
        },
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [{"tag": f"balancer-{index}", "selector": [prefix],
                           "strategy": {"type": "leastPing"},
                           "fallbackTag": f"{prefix}1"}],
            "rules": [
                {"type": "field", "outboundTag": "direct", "domain": RESERVED},
                {"type": "field", "outboundTag": "direct", "ip": RESERVED_IP},
                {"type": "field", "balancerTag": f"balancer-{index}",
                 "network": "tcp,udp"},
            ],
        },
        "stats": {},
    }


def dedupe(configs):
    seen, unique = set(), []
    for config in configs:
        signature = (config["id"], config["host"], config["port"],
                     json.dumps(config["query"], sort_keys=True))
        if signature not in seen:
            seen.add(signature)
            unique.append(config)
    return unique


def split_chunks(items, size):
    size = max(1, size)
    return [items[start:start + size] for start in range(0, len(items), size)]


def build_configs(chunks, args):
    configs = []
    for index, chunk in enumerate(chunks, start=1):
        if len(chunk) < args.min_outbounds:
            print(f"  skip balancer {index}: only {len(chunk)} server(s)",
                  file=sys.stderr)
            continue
        port_base = args.port_base + index * 100 if args.unique_ports \
            else args.port_base
        config = make_config(chunk, index, len(chunks), args.format, port_base)
        print(f"  [{index}] {len(chunk)} servers", file=sys.stderr)
        configs.append(config)
    return configs


def write_subscription(configs, output_dir):
    path = os.path.join(output_dir, SUBSCRIPTION_FILE)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(configs, handle, ensure_ascii=False, indent=2)
    return path


def main():
    parser = argparse.ArgumentParser(
        description="Split vless:// links into Xray balancer configs")
    parser.add_argument("paths", nargs="*",
                        help="URLs, files or directories with vless:// links")
    parser.add_argument("--out", default="out",
                        help="output directory (default: out next to the script)")
    parser.add_argument("--format", default="flat", choices=["flat", "xray"])
    parser.add_argument("--port-base", type=int, default=10808)
    parser.add_argument("--unique-ports", action="store_true",
                        help="Use a separate inbound port for every config")
    parser.add_argument("--min-outbounds", type=int, default=1,
                        help="Skip balancers with fewer outbounds")
    args = parser.parse_args()

    sources = list(args.paths) or [DEFAULT_SOURCE]
    if not args.paths:
        print(f"No arguments given, using default source: {DEFAULT_SOURCE}",
              file=sys.stderr)
    output_dir = args.out

    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(here, output_dir)
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as error:
        print(f"Cannot create {output_dir}: {error}", file=sys.stderr)
        return 1

    links = collect_links(sources)
    if not links:
        print("No vless:// links found.", file=sys.stderr)
        return 0
    print(f"Found {len(links)} vless:// links", file=sys.stderr)

    configs, skipped = [], 0
    for link in links:
        config = parse_link(link)
        if config is None:
            skipped += 1
        else:
            configs.append(config)
    if skipped:
        print(f"Skipped invalid links: {skipped}", file=sys.stderr)

    unique = dedupe(configs)
    if not unique:
        print("No usable servers found.", file=sys.stderr)
        return 0

    chunks = split_chunks(unique, SERVERS_PER_BALANCER)
    print(f"Unique servers: {len(unique)}, balancers: {len(chunks)}",
          file=sys.stderr)

    configs = build_configs(chunks, args)
    for old in glob.glob(os.path.join(output_dir, "balancer-*.json")):
        os.remove(old)
    path = write_subscription(configs, output_dir)
    print(f"Done. Wrote {len(configs)} balancers to {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
