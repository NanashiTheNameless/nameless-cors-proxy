// Minimal relay for nameless-cors-proxy. Outbound fetches from Workers running
// on the namelessnanashi.dev zone fail with 525 for some Cloudflare-fronted hosts
// (github.com, api.github.com), while the same fetch from a workers.dev request
// succeeds. The main proxy retries those hops through here.
//
// The main proxy does all validation (origin, target, redirects, headers); this
// Worker only performs the single fetch and returns the raw upstream response.

const SECRET_HEADER = 'x-relay-secret'
const TARGET_HEADER = 'x-relay-target'
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])

interface Env {
  RELAY_SECRET?: string
}

async function digest (value: string): Promise<ArrayBuffer> {
  return await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
}

// Hashing first gives both inputs the same length, as timingSafeEqual requires.
async function isValidSecret (provided: string | null, expected: string | undefined): Promise<boolean> {
  if (!expected || provided === null) {
    return false
  }

  const [providedHash, expectedHash] = await Promise.all([digest(provided), digest(expected)])

  return crypto.subtle.timingSafeEqual(providedHash, expectedHash)
}

function parseTargetUrl (value: string | null): URL | null {
  if (value === null) {
    return null
  }

  try {
    const url = new URL(value)

    return ALLOWED_PROTOCOLS.has(url.protocol) ? url : null
  } catch {
    return null
  }
}

export default {
  async fetch (request: Request, env: Env) {
    if (!(await isValidSecret(request.headers.get(SECRET_HEADER), env.RELAY_SECRET))) {
      return new Response(null, { status: 404 })
    }

    const targetUrl = parseTargetUrl(request.headers.get(TARGET_HEADER))

    if (targetUrl === null) {
      return new Response(null, { status: 400 })
    }

    const upstreamHeaders = new Headers(request.headers)
    upstreamHeaders.delete(SECRET_HEADER)
    upstreamHeaders.delete(TARGET_HEADER)

    const hasBody = request.method !== 'GET' && request.method !== 'HEAD'

    return await fetch(targetUrl.toString(), {
      method: request.method,
      headers: upstreamHeaders,
      body: hasBody ? await request.arrayBuffer() : null,
      redirect: 'manual'
    })
  }
}
