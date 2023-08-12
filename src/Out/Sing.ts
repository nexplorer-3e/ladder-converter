import { Base64, toBase64 } from 'js-base64'
import { ConvertError } from '../Error'
import { ProxyServer } from '../ProxyServer'

function FormatProxyForSing(ProxyList: ProxyServer[]): any[] {
    const proxies: any[] = []
    for (let rawProxy of ProxyList) {
        const config: any = {}
        if (rawProxy.Type === 'vmess') {
            let proxy = rawProxy
            config.tag = proxy.Name
            config.type = 'vmess'
            config.server = proxy.ServerAddress
            config.server_port = +proxy.ServerPort
            config.security = proxy.Cipher
            config.uuid = proxy.ClientID
            config.alter_id = proxy.ClientAlterID
            if (proxy.Transport !== 'tcp') {
                config.transport = {}
                config.transport.type = proxy.Transport
            }
            if (proxy.TransportSecurity === 'tls') {
                config.tls = {}
                config.tls.enabled = true
                if (proxy.ServerName) {
                    config.tls.server_name = proxy.ServerName
                }
            }
            if (proxy.Transport === 'ws' && proxy.WebSocketPath) {
                config.transport.path = proxy.WebSocketPath
            }
            if (proxy.Transport === 'ws' && proxy.WebSocketHost) {
                config.transport.headers = { Host: proxy.WebSocketHost }
            }
        } else if (rawProxy.Type === 'ss') {
            let proxy = rawProxy
            config.tag = proxy.Name
            config.type = 'shadowsocks'
            config.server = proxy.ServerAddress
            config.server_port = +proxy.ServerPort
            config.method = proxy.Cipher
            config.password = proxy.Password
            // if (proxy.SupportUDP) {
            //     config.network = "udp"
            // }
        } else if (rawProxy.Type === 'ssr') { // not supported
            let proxy = rawProxy
            config.method = proxy.Cipher
            config.tag = proxy.Name
            config.obfs = proxy.Obfs
            if (proxy.ObfsParams) {
                config['obfs-param'] = proxy.ObfsParams
            }
            config.password = proxy.Password
            config.server_port = proxy.ServerPort
            config.protocol = proxy.Protocol
            if (proxy.ProtocolParams) {
                config['protocol-param'] = proxy.ProtocolParams
            }
            config.server = proxy.ServerAddress
            config.type = 'shadowsocksr'
            if (proxy.SupportUDP) {
                config.network = "udp"
            }
        } else if (rawProxy.Type === 'trojan') {
            let proxy = rawProxy
            config.tag = proxy.Name
            config.password = proxy.Password
            config.server_port = +proxy.ServerPort
            config.server = proxy.ServerAddress
            config.type = 'trojan'
            if (proxy.SupportUDP) {
                config.network = 'udp'
            }
            if (proxy.ServerName) {
                config.tls = {}
                config.tls.server_name = proxy.ServerName
            }
            if (proxy.AllowInsecure) {
                if (config.tls === undefined) config.tls = {}
                config.tls.insecure = proxy.AllowInsecure
            }
        } else {
            throw new ConvertError(`unknown type: ${(rawProxy as any)?.Type}`).WithTarget('clash').WithData(rawProxy)
        }
        proxies.push(config)
    }
    return proxies
}

export default function FormatProfileForSFA(ProxyList: ProxyServer[], overrideRoute: string|undefined): string {
    let template: any = {
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "address": "tls://8.8.8.8"
                },
                {
                    "tag": "local",
                    "address": "223.5.5.5",
                    "detour": "direct"
                },
                {
                    "tag": "block",
                    "address": "rcode://success"
                }
            ],
            "rules": [
                {
                    "geosite": "category-ads-all",
                    "server": "block",
                    "disable_cache": true
                },
                {
                    "outbound": "any",
                    "server": "local"
                },
                {
                    "geosite": "cn",
                    "server": "local"
                }
            ],
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "strict_route": false,
                "sniff": true
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": [],
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            },
            {
                "type": "dns",
                "tag": "dns-out"
            }
        ],
        "route": {
            "geosite": {
                "download_url": "https://ghproxy.com/github.com/soffchen/sing-geosite/releases/latest/download/geosite.db"
            },
            "geoip": {
                "download_url": "https://ghproxy.com/github.com/soffchen/sing-geoip/releases/latest/download/geoip.db"  
            },
            "rules": [
                {
                    "protocol": "dns",
                    "outbound": "dns-out"
                },
                {
                    "geosite": "cn",
                    "geoip": [
                        "private",
                        "cn"
                    ],
                    "outbound": "direct"
                },
                {
                    "geosite": "category-ads-all",
                    "outbound": "block"
                }
            ],
            "auto_detect_interface": true
        }
    }
    const outbounds = FormatProxyForSing(ProxyList)
    for (const outbound of outbounds) {
        template.outbounds.push(outbound);
        template.outbounds[0].outbounds.push(outbound.tag);
    }
    if (overrideRoute) {
        const route = JSON.parse(Base64.decode(overrideRoute));
        template.route = route;
    }
    return JSON.stringify(template)
}