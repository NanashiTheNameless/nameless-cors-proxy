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
  'connection',
  'content-length',
  'cookie',
  'cookie2',
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
  'upgrade',
  'via',
  'x-real-ip'
])
const STRIPPED_UPSTREAM_HEADER_PREFIXES = ['cf-', 'sec-', 'x-forwarded-']

type TargetUrlState =
  | { kind: 'absent' }
  | { kind: 'missing' }
  | { kind: 'invalid' }
  | { kind: 'unsupported', targetUrl: URL }
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

function createUpstreamHeaders (request: Request, targetUrl: URL): Headers {
  const upstreamHeaders = new Headers()

  for (const [name, value] of request.headers) {
    if (shouldForwardUpstreamHeader(name)) {
      upstreamHeaders.set(name, value)
    }
  }

  upstreamHeaders.set('Origin', targetUrl.origin)

  return upstreamHeaders
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
      const upstreamHeaders = createUpstreamHeaders(request, targetUrl)

      const upstreamInit: RequestInit = {
        method: request.method,
        headers: upstreamHeaders,
        redirect: 'follow'
      }

      if (request.method !== 'GET' && request.method !== 'HEAD') {
        upstreamInit.body = request.body
      }

      const upstreamResponse = await fetch(targetUrl.toString(), upstreamInit)
      const response = new Response(upstreamResponse.body, upstreamResponse)

      response.headers.set('Access-Control-Allow-Origin', origin)
      response.headers.set('Access-Control-Expose-Headers', '*')
      response.headers.append('Vary', 'Origin')
      response.headers.append('Vary', 'Sec-Fetch-Site')
      response.headers.append('Vary', 'Sec-Fetch-Mode')
      response.headers.append('Vary', 'Sec-Fetch-Dest')

      return response
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
