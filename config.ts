type ProxyConfig = {
  publicUrl: string;
  allowedOriginHostPatterns: readonly string[];
};

export const proxyConfig: ProxyConfig = {
  publicUrl: "https://cors.namelessnanashi.dev/",
  allowedOriginHostPatterns: [
    "*.namelessnanashi.dev",
  ],
};
