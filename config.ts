interface ProxyConfig {
  publicUrl: string
  allowedOriginHostPatterns: readonly string[]
  // Upstream hops answered with one of these statuses are retried through relayUrl.
  relayUrl: string
  relayRetryStatuses: readonly number[]
}

export const proxyConfig: ProxyConfig = {
  publicUrl: 'https://cors.namelessnanashi.dev/',
  relayUrl: 'https://nameless-cors-relay.nanashi-s-account.workers.dev/',
  relayRetryStatuses: [525],
  allowedOriginHostPatterns: [
    '*.namelessnanashi.dev'
  ]
}
