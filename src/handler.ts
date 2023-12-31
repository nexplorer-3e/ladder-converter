import GetProxyListFromBase64 from './In/Base64'
import GetProxyListFromClash from './In/Clash'
import FormatProxyToBase64 from './Out/Base64'
import FormatProfileForSFA from './Out/Sing'
import FormatProxyForClash from './Out/Clash'
import FormatProxyForSurge from './Out/Surge'
import Guide from './guide.html'
import { ResolveDNSForProxy } from './Processer/dns'
import { ProxyServer } from './ProxyServer'

export async function handleRequest(request: Request): Promise<Response> {
    const query = new URL(request.url).searchParams;
    const url = query.get('url');

    if (!url) {
        return new Response(Guide, {
            headers: new Headers({ 'Content-Type': 'text/html; charset=utf-8' })
        })
    }

    let data: string
    const headers = new Headers({ 'Content-Type': 'text/plain; charset=utf-8' })

    const ua = new Headers({ 'User-Agent': (query.get("from") ?? "clash") === "clash" ? "Clash" : "v2ray"});
    try {
        data = await fetch(url.startsWith("http") ? url : `https://${url}`, { redirect: 'follow', headers: ua}).then(response => response.text())
    } catch (e) {
        return new Response(e.stack || e, { status: 500 })
    }

    try {
        // import proxy from subscription
        let proxies: ProxyServer[]
        switch (query.get('from') ?? 'clash') {
            case 'yaml':
            case 'clash':
                proxies = GetProxyListFromClash(data)
                break
            case 'base64':
                proxies = GetProxyListFromBase64(data)
                break
            default:
                return new Response(`${query.get('from')} is not supported`, { status: 500 })
        }

        // filter proxy list
        if (query.has('filter')) {
            proxies = proxies.filter(({ Name }) => Name.match(new RegExp(query.getAll('filter').join('|'))))
        }
        if (query.has('exempt')) {
            proxies = proxies.filter(({ Name }) => !Name.match(new RegExp(query.getAll('exempt').join('|'))))
        }
        proxies.sort((a, b) => a.Name.localeCompare(b.Name))

        if (query.has('resolve')) {
            headers.set('X-DNS-Resolver', 'enabled')
            await Promise.all(proxies.map(ResolveDNSForProxy))
        }

        // output
        switch (query.get('to') ?? 'clash') {
            case 'base64':
                return new Response(FormatProxyToBase64(proxies), { headers })
            case 'sfa':
                headers.set("Content-Type", "application/json");
                return new Response(FormatProfileForSFA(proxies, query.get('sfacfg')), { headers })
            case 'clash':
                return new Response(FormatProxyForClash(proxies), { headers })
            case 'surge':
                return new Response(FormatProxyForSurge(proxies), { headers })
            default:
                return new Response(`${query.get('to')} is not supported`, { status: 500 })
        }
    } catch (e) {
        return new Response(e.stack || e, { status: 500 })
    }
}
