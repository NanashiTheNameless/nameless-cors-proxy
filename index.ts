import { proxyConfig } from './config'

const ALLOWED_METHODS = 'GET,HEAD,POST,OPTIONS'
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])
const ALLOWED_METHOD_SET = new Set(['GET', 'HEAD', 'POST', 'OPTIONS'])
const ALLOWED_FETCH_METADATA_SITES = new Set(['same-origin', 'same-site'])
const ALLOWED_FETCH_METADATA_MODES = new Set(['cors', 'same-origin'])
const ALLOWED_FETCH_METADATA_DEST = 'empty'
const DEFAULT_WARNING_LINE = 'You should not be here.'
const RARE_WARNING_LINE =
  'This place is not a place of honor... No highly esteemed deed is commemorated here... Nothing valued is here...'
const RARE_WARNING_PROBABILITY = 0.1
const NO_STORE_CACHE_CONTROL = 'no-store'
const FETCH_METADATA_VARY_VALUE =
  'Origin, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest'
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="22" fill="#000"/>
</svg>`
const PROXY_USAGE_URL = createProxyUsageUrl()
const ALLOWED_ORIGIN_DESCRIPTION = createAllowedOriginDescription()
const STRIPPED_UPSTREAM_HEADERS = new Set([
  'accept-encoding',
  'authorization',
  'cdn-loop',
  'connection',
  'content-length',
  'cookie',
  'cookie2',
  'expect',
  'forwarded',
  'host',
  'keep-alive',
  'origin',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'referer',
  'te',
  'trailer',
  'transfer-encoding',
  'true-client-ip',
  'upgrade',
  'via',
  'x-real-ip'
])
const STRIPPED_UPSTREAM_HEADER_PREFIXES = ['cf-', 'sec-', 'x-forwarded-']

// Headers from the upstream response that must never reach the client. Set-Cookie
// would let an arbitrary target set cookies scoped to the proxy's parent domain,
// and Clear-Site-Data would let it wipe state for the proxy origin.
const STRIPPED_DOWNSTREAM_HEADERS = new Set([
  'clear-site-data',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'public-key-pins',
  'set-cookie',
  'set-cookie2',
  'strict-transport-security',
  'te',
  'timing-allow-origin',
  'trailer',
  'transfer-encoding',
  'upgrade'
])
const STRIPPED_DOWNSTREAM_HEADER_PREFIXES = ['access-control-']

const MAX_UPSTREAM_REDIRECTS = 5
const MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
const PROXY_HOSTNAME = new URL(proxyConfig.publicUrl).hostname.toLowerCase()
const BLOCKED_TARGET_HOSTNAMES = new Set(['localhost', ''])
const BLOCKED_TARGET_HOSTNAME_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.home.arpa'
]

type TargetUrlState =
  | { kind: 'absent' }
  | { kind: 'missing' }
  | { kind: 'invalid' }
  | { kind: 'unsupported', targetUrl: URL }
  | { kind: 'blocked', targetUrl: URL }
  | { kind: 'valid', targetUrl: URL }

function matchesHostnamePattern (hostname: string, pattern: string): boolean {
  const normalizedPattern = pattern.toLowerCase()

  if (normalizedPattern.startsWith('*.')) {
    const baseHostname = normalizedPattern.slice(2)
    const suffix = `.${baseHostname}`

    return hostname === baseHostname || hostname.endsWith(suffix)
  }

  return hostname === normalizedPattern
}

function isAllowedHostname (hostname: string): boolean {
  const normalizedHostname = hostname.toLowerCase()

  return proxyConfig.allowedOriginHostPatterns.some((pattern) =>
    matchesHostnamePattern(normalizedHostname, pattern)
  )
}

function parseUrl (value: string): URL | null {
  try {
    return new URL(value)
  } catch {
    return null
  }
}

function isAllowedSiteUrl (url: URL): boolean {
  return ALLOWED_PROTOCOLS.has(url.protocol) && isAllowedHostname(url.hostname)
}

function isAllowedTargetUrl (url: URL): boolean {
  return ALLOWED_PROTOCOLS.has(url.protocol)
}

// The URL parser normalizes every legacy IPv4 form (decimal, octal, hex, short
// dotted) to dotted-quad, so matching the normalized hostname is sufficient.
function parseIpv4Literal (hostname: string): number[] | null {
  const parts = hostname.split('.')

  if (parts.length !== 4) {
    return null
  }

  const octets: number[] = []

  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null
    }

    const octet = Number(part)

    if (octet > 255) {
      return null
    }

    octets.push(octet)
  }

  return octets
}

function isBlockedIpv4 (octets: number[]): boolean {
  const [a, b] = octets

  return (
    a === 0 || // 0.0.0.0/8 "this network"
    a === 10 || // RFC 1918
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // RFC 6598 CGNAT
    (a === 169 && b === 254) || // link-local, incl. cloud metadata
    (a === 172 && b >= 16 && b <= 31) || // RFC 1918
    (a === 192 && b === 0) || // IETF protocol assignments / TEST-NET-1
    (a === 192 && b === 88) || // 6to4 relay anycast
    (a === 192 && b === 168) || // RFC 1918
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    (a === 198 && b === 51) || // TEST-NET-2
    (a === 203 && b === 0) || // TEST-NET-3
    a >= 224 // multicast and reserved
  )
}

function isBlockedIpv6 (hostname: string): boolean {
  if (!hostname.startsWith('[') || !hostname.endsWith(']')) {
    return false
  }

  const address = hostname.slice(1, -1).toLowerCase()

  if (address === '::1' || address === '::') {
    return true
  }

  // IPv4-mapped / IPv4-compatible addresses tunnel the IPv4 ranges above.
  const embeddedIpv4 = address.split(':').pop() ?? ''
  const embeddedOctets = parseIpv4Literal(embeddedIpv4)

  if ((embeddedOctets != null) && isBlockedIpv4(embeddedOctets)) {
    return true
  }

  return (
    address.startsWith('fc') || // unique local
    address.startsWith('fd') || // unique local
    address.startsWith('fe8') || // link-local
    address.startsWith('fe9') ||
    address.startsWith('fea') ||
    address.startsWith('feb') ||
    address.startsWith('ff') // multicast
  )
}

function isBlockedTargetHostname (hostname: string): boolean {
  const normalizedHostname = hostname.toLowerCase().replace(/\.$/, '')

  if (normalizedHostname === PROXY_HOSTNAME) {
    return true // prevents recursive self-proxying
  }

  if (BLOCKED_TARGET_HOSTNAMES.has(normalizedHostname)) {
    return true
  }

  if (
    BLOCKED_TARGET_HOSTNAME_SUFFIXES.some((suffix) =>
      normalizedHostname.endsWith(suffix)
    )
  ) {
    return true
  }

  if (isBlockedIpv6(normalizedHostname)) {
    return true
  }

  const octets = parseIpv4Literal(normalizedHostname)

  return (octets != null) && isBlockedIpv4(octets)
}

function isBlockedTargetUrl (url: URL): boolean {
  return isBlockedTargetHostname(url.hostname)
}

function createProxyUsageUrl (): string {
  const usageUrl = new URL(proxyConfig.publicUrl)
  usageUrl.hash = ''
  usageUrl.search = ''
  usageUrl.searchParams.set('url', '<URL_ENCODED_TARGET_URL>')

  return usageUrl.toString()
}

function createAllowedOriginDescription (): string {
  const patterns = proxyConfig.allowedOriginHostPatterns.join(', ')

  if (proxyConfig.allowedOriginHostPatterns.length === 1) {
    return `Only ${patterns} may use this proxy.`
  }

  return `Only these host patterns may use this proxy:\n${patterns}`
}

function getAllowedOrigin (request: Request): URL | null {
  const origin = request.headers.get('Origin')

  if (!origin) {
    return null
  }

  const parsedOrigin = parseUrl(origin)

  return (parsedOrigin != null) && isAllowedSiteUrl(parsedOrigin) ? parsedOrigin : null
}

function createCorsHeaders (origin: string) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': ALLOWED_METHODS,
    'Access-Control-Max-Age': '86400',
    'Access-Control-Expose-Headers': '*',
    'Cross-Origin-Resource-Policy': 'same-site',
    Vary: FETCH_METADATA_VARY_VALUE
  }
}

function isAllowedMethod (method: string): boolean {
  return ALLOWED_METHOD_SET.has(method)
}

function createMethodNotAllowedResponse (
  headers: Record<string, string> = {}
) {
  return new Response(null, {
    status: 405,
    statusText: 'Method Not Allowed',
    headers: {
      'cache-control': NO_STORE_CACHE_CONTROL,
      Allow: ALLOWED_METHODS,
      ...headers
    }
  })
}

function textResponse (
  body: string | null,
  status: number,
  headers: Record<string, string> = {}
) {
  return new Response(body, {
    status,
    headers: {
      'cache-control': NO_STORE_CACHE_CONTROL,
      'content-type': 'text/plain;charset=UTF-8',
      ...headers
    }
  })
}

function htmlResponse (
  body: string,
  status: number,
  headers: Record<string, string> = {}
) {
  return new Response(body, {
    status,
    headers: {
      'cache-control': NO_STORE_CACHE_CONTROL,
      'content-type': 'text/html;charset=UTF-8',
      ...headers
    }
  })
}

function svgResponse (
  body: string | null,
  headers: Record<string, string> = {}
) {
  return new Response(body, {
    status: 200,
    headers: {
      'cache-control': 'public, max-age=86400',
      'content-type': 'image/svg+xml;charset=UTF-8',
      ...headers
    }
  })
}

function getTargetUrlState (requestUrl: URL): TargetUrlState {
  if (!requestUrl.searchParams.has('url')) {
    return { kind: 'absent' }
  }

  const rawTargetUrl = requestUrl.searchParams.get('url') ?? ''

  if (!rawTargetUrl) {
    return { kind: 'missing' }
  }

  const targetUrl = parseUrl(rawTargetUrl)

  if (targetUrl == null) {
    return { kind: 'invalid' }
  }

  if (!isAllowedTargetUrl(targetUrl)) {
    return { kind: 'unsupported', targetUrl }
  }

  if (isBlockedTargetUrl(targetUrl)) {
    return { kind: 'blocked', targetUrl }
  }

  return { kind: 'valid', targetUrl }
}

function escapeHtml (value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function getWarningLine (): string {
  return Math.random() < RARE_WARNING_PROBABILITY
    ? RARE_WARNING_LINE
    : DEFAULT_WARNING_LINE
}

function getErrorPrefixLines (): string[] {
  return [
    ...ALLOWED_ORIGIN_DESCRIPTION.split('\n'),
    '',
    getWarningLine(),
    ''
  ]
}

function getErrorLines (...lines: string[]): string[] {
  return [...getErrorPrefixLines(), ...lines]
}

function getErrorMessage (...lines: string[]): string {
  return getErrorLines(...lines).join('\n')
}

function getMissingUrlMessage (): string {
  return getErrorMessage(
    'Missing url query parameter.',
    'Add ?url=<URL_ENCODED_TARGET_URL>.'
  )
}

function getInvalidUrlMessage (): string {
  return getErrorMessage(
    'Invalid url query parameter.',
    'The url query parameter must be a URL-encoded absolute http or https URL.'
  )
}

function getUnsupportedUrlMessage (): string {
  return getErrorMessage('Target URL must use http or https.')
}

function getBlockedUrlMessage (): string {
  return getErrorMessage(
    'Target host is not reachable through this proxy.',
    'Private, loopback, link-local and reserved hosts are blocked.'
  )
}

function getUnauthorizedMessage (targetUrl: URL): string {
  return getErrorMessage(
    'Please go directly to your destination:',
    targetUrl.toString()
  )
}

function getUnauthorizedLines (targetUrl: URL): string[] {
  const safeTargetUrl = escapeHtml(targetUrl.toString())

  return getErrorLines(
    'Please go directly to your destination:',
    `<a href="${safeTargetUrl}">${safeTargetUrl}</a>`
  )
}

function shouldRenderHtml (request: Request): boolean {
  const accept = request.headers.get('Accept') ?? ''
  const fetchDestination = request.headers.get('Sec-Fetch-Dest') ?? ''

  return (
    request.method === 'GET' &&
    (accept.includes('text/html') ||
      fetchDestination === 'document' ||
      fetchDestination === 'iframe')
  )
}

function hasBrowserFetchMetadata (request: Request): boolean {
  const fetchSite = request.headers.get('Sec-Fetch-Site')
  const fetchMode = request.headers.get('Sec-Fetch-Mode')
  const fetchDest = request.headers.get('Sec-Fetch-Dest')

  return (
    fetchSite !== null &&
    fetchMode !== null &&
    fetchDest !== null &&
    ALLOWED_FETCH_METADATA_SITES.has(fetchSite) &&
    ALLOWED_FETCH_METADATA_MODES.has(fetchMode) &&
    fetchDest === ALLOWED_FETCH_METADATA_DEST
  )
}

function getBrowserMetadataRequiredMessage (): string {
  return getErrorMessage(
    'Browser fetch metadata required.',
    'This proxy only accepts browser fetch() requests from allowed site origins.'
  )
}

function shouldForwardUpstreamHeader (headerName: string): boolean {
  const normalizedHeaderName = headerName.toLowerCase()

  return (
    !STRIPPED_UPSTREAM_HEADERS.has(normalizedHeaderName) &&
    !STRIPPED_UPSTREAM_HEADER_PREFIXES.some((prefix) =>
      normalizedHeaderName.startsWith(prefix)
    )
  )
}

function createUpstreamHeaders (request: Request): Headers {
  const upstreamHeaders = new Headers()

  for (const [name, value] of request.headers) {
    if (shouldForwardUpstreamHeader(name)) {
      upstreamHeaders.set(name, value)
    }
  }

  // No Origin is sent upstream. Forging one that matches the target would defeat
  // Origin-based CSRF checks on every host reachable through this proxy.
  return upstreamHeaders
}

function shouldForwardDownstreamHeader (headerName: string): boolean {
  const normalizedHeaderName = headerName.toLowerCase()

  return (
    !STRIPPED_DOWNSTREAM_HEADERS.has(normalizedHeaderName) &&
    !STRIPPED_DOWNSTREAM_HEADER_PREFIXES.some((prefix) =>
      normalizedHeaderName.startsWith(prefix)
    )
  )
}

function createDownstreamHeaders (upstreamResponse: Response, origin: string): Headers {
  const headers = new Headers()

  for (const [name, value] of upstreamResponse.headers) {
    if (shouldForwardDownstreamHeader(name)) {
      headers.append(name, value)
    }
  }

  headers.set('Access-Control-Allow-Origin', origin)
  headers.set('Access-Control-Expose-Headers', '*')
  headers.set('Cross-Origin-Resource-Policy', 'same-site')
  headers.set('X-Content-Type-Options', 'nosniff')
  // The edge cache keys on URL and ignores Vary, so a cacheable upstream response
  // could be replayed to a different origin with the wrong Allow-Origin header.
  headers.set('Cache-Control', NO_STORE_CACHE_CONTROL)
  headers.set('Vary', FETCH_METADATA_VARY_VALUE)

  return headers
}

function renderStatusPage (lines: string[]): string {
  const lineMarkup = lines.map((line) => `<div class="line">${line}</div>`).join('')

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Access Denied</title>
    <link rel="icon" href="/favicon.ico" sizes="any" type="image/svg+xml">
    <!--
      This page uses the bundled 0xProto font.
      0xProto is Copyright (c) 2026, 0xType Project Authors and is licensed under the SIL Open Font License, Version 1.1.
      See https://github.com/NanashiTheNameless/nameless-cors-proxy/blob/master/0xProto/LICENSE
    -->
    <style>
      @font-face {
        font-family: "0xProto";
        src: url("/0xProto-Regular.otf") format("opentype");
        font-style: normal;
        font-weight: 400;
        font-display: swap;
      }

      :root {
        color-scheme: dark;
        --bg: #000000;
        --text: #ffffff;
        --page-padding-x: clamp(24px, 4vw, 64px);
        --page-padding-y: clamp(24px, 4vw, 64px);
        --line-size: 16px;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        min-height: 100vh;
        background: var(--bg);
        color: var(--text);
        font-family: "0xProto", monospace;
        overflow: hidden;
      }

      main {
        width: 100%;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: var(--page-padding-y) var(--page-padding-x);
      }

      .status {
        width: max-content;
        max-width: none;
        display: grid;
        gap: 0.14em;
        justify-items: center;
        text-align: center;
      }

      .line {
        margin: 0;
        font-size: var(--line-size);
        line-height: 0.95;
        white-space: nowrap;
        color: var(--text);
      }

      .line:empty::before {
        content: "\\00a0";
      }

      a {
        color: var(--text);
        text-decoration-thickness: 0.08em;
        text-underline-offset: 0.16em;
      }

      code {
        font-family: inherit;
      }
    </style>
  </head>
  <body>
    <main>
      <div class="status" id="status">
        ${lineMarkup}
      </div>
    </main>
    <script>
      (() => {
        const root = document.documentElement;
        const main = document.querySelector("main");
        const lines = Array.from(document.querySelectorAll(".line"));
        const canvas = document.createElement("canvas");
        const context = canvas.getContext("2d");

        const fitLines = () => {
          if (!context || !main || lines.length === 0) {
            return;
          }

          const styles = getComputedStyle(main);
          const availableWidth =
            main.clientWidth -
            parseFloat(styles.paddingLeft) -
            parseFloat(styles.paddingRight);
          const availableHeight =
            main.clientHeight -
            parseFloat(styles.paddingTop) -
            parseFloat(styles.paddingBottom);

          const baseSize = 100;
          context.font = baseSize + 'px "0xProto"';

          const maxLineWidth = Math.max(
            ...lines.map((line) => context.measureText(line.textContent ?? "").width),
          );

          const lineCount = lines.length;
          const lineHeightFactor = 0.95;
          const gapFactor = 0.14;
          const widthSize = availableWidth / (maxLineWidth / baseSize);
          const heightSize =
            availableHeight /
            (lineCount * lineHeightFactor + (lineCount - 1) * gapFactor);
          const nextSize = Math.max(
            12,
            Math.floor(Math.min(widthSize, heightSize) * 0.98),
          );

          root.style.setProperty("--line-size", nextSize + "px");
        };

        let frame = 0;
        const scheduleFit = () => {
          cancelAnimationFrame(frame);
          frame = requestAnimationFrame(fitLines);
        };

        window.addEventListener("resize", scheduleFit);
        window.addEventListener("load", scheduleFit);
        document.fonts?.ready.then(scheduleFit);
        scheduleFit();
      })();
    </script>
  </body>
</html>`
}

function getDocumentErrorResponse (targetUrlState: TargetUrlState): Response {
  switch (targetUrlState.kind) {
    case 'absent':
    case 'missing':
      return htmlResponse(
        renderStatusPage(getErrorLines(
          'Missing url query parameter.',
          'Add ?url=&lt;URL_ENCODED_TARGET_URL&gt; to this proxy URL.'
        )),
        400
      )
    case 'invalid':
      return htmlResponse(
        renderStatusPage(getErrorLines(
          'Invalid url query parameter.',
          'The url query parameter must be a URL-encoded absolute http or https URL.'
        )),
        400
      )
    case 'unsupported':
      return htmlResponse(
        renderStatusPage(getErrorLines(
          'Target URL must use http or https.',
          `The provided URL uses an unsupported protocol: <code>${escapeHtml(targetUrlState.targetUrl.protocol)}</code>.`
        )),
        403
      )
    case 'blocked':
      return htmlResponse(
        renderStatusPage(getErrorLines(
          'Target host is not reachable through this proxy.',
          'Private, loopback, link-local and reserved hosts are blocked.'
        )),
        403
      )
    case 'valid':
      return htmlResponse(
        renderStatusPage(getUnauthorizedLines(targetUrlState.targetUrl)),
        403
      )
  }
}

function getTextErrorResponse (targetUrlState: TargetUrlState): Response {
  switch (targetUrlState.kind) {
    case 'absent':
    case 'missing':
      return textResponse(getMissingUrlMessage(), 400)
    case 'invalid':
      return textResponse(getInvalidUrlMessage(), 400)
    case 'unsupported':
      return textResponse(getUnsupportedUrlMessage(), 403)
    case 'blocked':
      return textResponse(getBlockedUrlMessage(), 403)
    case 'valid':
      return textResponse(getUnauthorizedMessage(targetUrlState.targetUrl), 403)
  }
}

function publicErrorResponse (request: Request, targetUrlState: TargetUrlState): Response {
  if (shouldRenderHtml(request)) {
    return getDocumentErrorResponse(targetUrlState)
  }

  return getTextErrorResponse(targetUrlState)
}

export default {
  async fetch (request: Request) {
    const url = new URL(request.url)

    if (url.pathname === '/favicon.ico') {
      if (request.method === 'GET') {
        return svgResponse(FAVICON_SVG)
      }

      if (request.method === 'HEAD') {
        return svgResponse(null)
      }

      return createMethodNotAllowedResponse()
    }

    const targetUrlState = getTargetUrlState(url)
    const allowedOrigin = getAllowedOrigin(request)

    if (allowedOrigin == null) {
      return publicErrorResponse(request, targetUrlState)
    }

    const origin = allowedOrigin.origin
    const corsHeaders = createCorsHeaders(origin)

    switch (targetUrlState.kind) {
      case 'missing':
        return textResponse(getMissingUrlMessage(), 400, corsHeaders)
      case 'invalid':
        return textResponse(getInvalidUrlMessage(), 400, corsHeaders)
      case 'unsupported':
        return textResponse(getUnsupportedUrlMessage(), 403, corsHeaders)
      case 'blocked':
        return textResponse(getBlockedUrlMessage(), 403, corsHeaders)
      case 'absent':
        break
      case 'valid':
        break
    }

    function infoResponse (json: string) {
      return new Response(json, {
        status: 200,
        headers: {
          'cache-control': NO_STORE_CACHE_CONTROL,
          'content-type': 'application/json;charset=UTF-8',
          ...corsHeaders
        }
      })
    }

    async function handleOptions (request: Request) {
      if (
        request.headers.get('Origin') !== null &&
        request.headers.get('Access-Control-Request-Method') !== null
      ) {
        return new Response(null, {
          headers: {
            'cache-control': NO_STORE_CACHE_CONTROL,
            ...corsHeaders,
            'Access-Control-Allow-Headers':
              request.headers.get('Access-Control-Request-Headers') ?? '*'
          }
        })
      }

      return new Response(null, {
        headers: {
          'cache-control': NO_STORE_CACHE_CONTROL,
          Allow: ALLOWED_METHODS
        }
      })
    }

    if (request.method === 'OPTIONS') {
      return await handleOptions(request)
    }

    if (!isAllowedMethod(request.method)) {
      return createMethodNotAllowedResponse(corsHeaders)
    }

    if (targetUrlState.kind === 'valid' && !hasBrowserFetchMetadata(request)) {
      return textResponse(getBrowserMetadataRequiredMessage(), 403, corsHeaders)
    }

    async function handleRequest (request: Request, targetUrl: URL) {
      const upstreamHeaders = createUpstreamHeaders(request)
      const hasBody = request.method !== 'GET' && request.method !== 'HEAD'

      let body: ArrayBuffer | null = null

      if (hasBody) {
        const declaredLength = Number(request.headers.get('Content-Length') ?? '')

        if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
          return textResponse(
            getErrorMessage('Request body too large.'),
            413,
            corsHeaders
          )
        }

        // Buffered rather than streamed so the body can be replayed across a
        // 307/308 redirect, and so an unbounded upload cannot be relayed.
        body = await request.arrayBuffer()

        if (body.byteLength > MAX_REQUEST_BODY_BYTES) {
          return textResponse(
            getErrorMessage('Request body too large.'),
            413,
            corsHeaders
          )
        }
      }

      let currentUrl = targetUrl
      let currentMethod = request.method
      let currentBody = body

      for (let hop = 0; hop <= MAX_UPSTREAM_REDIRECTS; hop++) {
        const upstreamResponse = await fetch(currentUrl.toString(), {
          method: currentMethod,
          headers: upstreamHeaders,
          body: currentBody,
          redirect: 'manual'
        })

        const location = upstreamResponse.headers.get('Location')

        if (!REDIRECT_STATUSES.has(upstreamResponse.status) || location === null) {
          return new Response(upstreamResponse.body, {
            status: upstreamResponse.status,
            statusText: upstreamResponse.statusText,
            headers: createDownstreamHeaders(upstreamResponse, origin)
          })
        }

        let nextUrl: URL

        try {
          nextUrl = new URL(location, currentUrl)
        } catch {
          return textResponse(
            getErrorMessage('Upstream returned an invalid redirect.'),
            502,
            corsHeaders
          )
        }

        // Every hop is revalidated; otherwise a permitted target could redirect
        // the proxy into a private or reserved host.
        if (!isAllowedTargetUrl(nextUrl) || isBlockedTargetUrl(nextUrl)) {
          return textResponse(getBlockedUrlMessage(), 403, corsHeaders)
        }

        if (upstreamResponse.status === 303 ||
          ((upstreamResponse.status === 301 || upstreamResponse.status === 302) &&
            currentMethod === 'POST')) {
          currentMethod = 'GET'
          currentBody = null
          upstreamHeaders.delete('content-type')
        }

        currentUrl = nextUrl
      }

      return textResponse(
        getErrorMessage('Too many redirects from the target URL.'),
        502,
        corsHeaders
      )
    }

    if (targetUrlState.kind === 'valid') {
      const { targetUrl } = targetUrlState

      return await handleRequest(request, targetUrl)
    }

    const requesterInfo = JSON.stringify({
      warning: getWarningLine(),
      usage: PROXY_USAGE_URL,
      origin
    })

    return infoResponse(requesterInfo)
  }
}
