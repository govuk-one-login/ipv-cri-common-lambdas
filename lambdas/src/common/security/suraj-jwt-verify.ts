import {CompactEncrypt, importJWK, JWTPayload, jwtVerify, SignJWT} from "jose";

const key = {
    /* Pass decrypted value from /stubs/core/cri/env/CORE_STUB_SIGNING_PRIVATE_KEY_JWK_BASE64 */
};


export class SurajJwtVerify {

    public async verify(
        encodedJwt: Buffer
    ): Promise<JWTPayload | null> {
        try {
            const signingAlgorithm = "ES256";
            const publicKey = await importJWK(key, signingAlgorithm);
            const {  protectedHeader, payload } = await jwtVerify(encodedJwt, publicKey);
            return payload;
        } catch (error) {
            console.log("JWT verification failed", error as Error);
            return null;
        }
    }

    public async signJwt(): Promise<any> {
        const payload = {
            "sub": "urn:fdc:gov.uk:2022:6d40fbef-ed87-4369-bc5a-76e001f29217",
            "shared_claims": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://vocab.london.cloudapps.digital/contexts/identity-v1.jsonld"
                ],
                "name": [
                    {
                        "nameParts": [
                            {
                                "type": "GivenName",
                                "value": "Jim"
                            },
                            {
                                "type": "FamilyName",
                                "value": "Ferguson"
                            }
                        ]
                    }
                ],
                "birthDate": [
                    {
                        "value": "1948-04-24"
                    }
                ],
                "address": [
                    {
                        "buildingNumber": "",
                        "buildingName": "",
                        "streetName": "",
                        "addressLocality": "",
                        "postalCode": "",
                        "validFrom": "2021-01-01"
                    }
                ]
            },
            "iss": "https://cri.core.build.stubs.account.gov.uk",
            "persistent_session_id": "3d76cb61-f747-44b8-a60d-b47b030e5342",
            "response_type": "code",
            "client_id": "ipv-core-stub-aws-build",
            "govuk_signin_journey_id": "9dc88eab-7673-48e7-858e-660685f8edb4",
            "aud": "https://review-hc.staging.account.gov.uk",
            "nbf": 1697463677,
            "scope": "openid",
            "redirect_uri": "https://cri.core.build.stubs.account.gov.uk/callback",
            "state": "9lXmNhOfbNWeN2iAaMpnb8bLcMZg3ZGAhG0aNk2XluM",
            "exp": 1697467277,
            "iat": 1697463677
        };

        const publicKey = await importJWK(key, "ES256");

        return await new SignJWT({ payload }) // details to  encode in the token
            .setProtectedHeader({ alg: 'ES256', kid: "ipv-core-stub-2-from-mkjwk.org" }) // algorithm
            .setIssuedAt(1697463677)
            .setIssuer("https://cri.core.build.stubs.account.gov.uk")
            .setAudience("https://review-hc.staging.account.gov.uk")
            .setExpirationTime(1697475554)
            .sign(publicKey);
    }

    public async toJWE(jwt: string): Promise<any> {
        const publicKey = await importJWK(key, "ES256");
        return  await new CompactEncrypt(Uint8Array.from(Buffer.from(jwt)))
            .setProtectedHeader({
                cty:"JWT",
                enc:"A256GCM",
                alg:"RSA-OAEP-256"
            })
            .encrypt(publicKey);
    }
}