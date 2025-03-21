import { JWK } from "jose";

export class TestKeys {
    static privateSigningJwk = {
        kty: "EC",
        d: "_0A_bq8i4sKtrlRMJrYWO5OoZnT1PeJjTAFN1pj-nIg", //pragma: allowlist secret
        use: "sig",
        crv: "P-256",
        kid: "qs1Pk2hlU7yi1ZS8KahLWiPbkS4sg2rN2_SZNCwjR0c", //pragma: allowlist secret
        x: "bmq8WpXGO6zpasLAd_ESqKlFXp99kgfydj0apnQ3Wyw", //pragma: allowlist secret
        y: "xaS8yXipEFCk_KJxp3V5wz2cFeWVnwTp4zGL9Qc4CAY", //pragma: allowlist secret
        alg: "ES256",
    } as JWK;
}
