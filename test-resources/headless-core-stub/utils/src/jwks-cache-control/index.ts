import { JSONWebKeySet } from "jose";

let cachedJWKS: JSONWebKeySet | null = null;
let cachedJWKSExpiry: number | null = null;

export const isJWKSCacheValid = () => Boolean(cachedJWKS && cachedJWKSExpiry && cachedJWKSExpiry >= Date.now());

export const parseCacheControlMaxAge = (cacheControlHeaderValue?: string): number => {
    const match = cacheControlHeaderValue?.match(/max-age=(\d+)/);
    const maxAgeSeconds = match ? parseInt(match[1], 10) : -1;
    return Date.now() + maxAgeSeconds * 1000;
};

export const fetchAndCacheJWKS = async (jwksUrl: URL, logger: { info: (msg: string) => void }) => {
    const jwksResponse = await fetch(jwksUrl);
    if (!jwksResponse.ok) {
        throw new Error(
            `Error received from the JWKS endpoint, status received: ${jwksResponse.status} ${jwksResponse.statusText}`,
        );
    }

    cachedJWKS = (await jwksResponse.json()) as JSONWebKeySet;
    cachedJWKSExpiry = parseCacheControlMaxAge(jwksResponse?.headers?.get("Cache-Control") as string);
    logger.info(`JWKS cache has been updated to  ${cachedJWKSExpiry}`);
};

export const clearJWKSCache = () => {
    cachedJWKS = null;
    cachedJWKSExpiry = null;
};

export const getCachedJWKS = () => cachedJWKS;
