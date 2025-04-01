import { JWTPayload } from "jose";
import { JWTClaimsSet } from "../../lambdas/start/src/types/jwt-claims-set";

export class TestData {
    static privateSigningKey = {
        kty: "EC",
        d: "_0A_bq8i4sKtrlRMJrYWO5OoZnT1PeJjTAFN1pj-nIg",
        use: "sig",
        crv: "P-256",
        kid: "qs1Pk2hlU7yi1ZS8KahLWiPbkS4sg2rN2_SZNCwjR0c",
        x: "bmq8WpXGO6zpasLAd_ESqKlFXp99kgfydj0apnQ3Wyw",
        y: "xaS8yXipEFCk_KJxp3V5wz2cFeWVnwTp4zGL9Qc4CAY",
        alg: "ES256",
    };

    static jwt =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdC5jb20iLCJjbGllbnRfaWQiOiJpcHYtY29yZS1zdHViLWF3cy1oZWFkbGVzcyIsImV4cCI6MTc0MjM4NTI0NCwiZ292dWtfc2lnbmluX2pvdXJuZXlfaWQiOiJkNmUwMGE5Yi1kNjZhLTQ1NzItYjMzMS0zMThlZGYzMDdlY2EiLCJpYXQiOjE3NDIzODQ5NDUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LmNvbSIsIm5iZiI6MTc0MjM4NDk0NSwibm9uY2UiOiIiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2xvY2FsaG9zdC5jb20vY2FsbGJhY2siLCJyZXNwb25zZV90eXBlIjoiY29kZSIsInNjb3BlIjoiIiwic2hhcmVkX2NsYWltcyI6eyJhZGRyZXNzIjpbeyJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJ2YWxpZEZyb20iOiIyMDIxLTAxLTAxIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NS0wNy0wOCJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XX0sInN0YXRlIjoiYjcyYjBhYzYtNDAzOC00NGUxLTkwNGMtZjFlMDc4MzJmMjY2Iiwic3ViIjoidXJuOmZkYzpnb3YudWs6YTlmYjhlMzgtMDQ1OC00ZGMwLThiZWMtMjY2MjcwOWNiMjQwIn0.xIOMcA0sCSe3N2NVpasT1uTkL936trpvvply5wDC6kKwtNkLYIh9LjuheNBABCMumdbOVVjaaxDAvk3Ej87LyA";

    static jwtWithoutSig =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdC5jb20iLCJjbGllbnRfaWQiOiJpcHYtY29yZS1zdHViLWF3cy1oZWFkbGVzcyIsImV4cCI6MTc0MjM4NTI0NCwiZ292dWtfc2lnbmluX2pvdXJuZXlfaWQiOiJkNmUwMGE5Yi1kNjZhLTQ1NzItYjMzMS0zMThlZGYzMDdlY2EiLCJpYXQiOjE3NDIzODQ5NDUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LmNvbSIsIm5iZiI6MTc0MjM4NDk0NSwicmVkaXJlY3RfdXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3QuY29tL2NhbGxiYWNrIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzaGFyZWRfY2xhaW1zIjp7ImFkZHJlc3MiOlt7ImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJidWlsZGluZ051bWJlciI6IjgiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInZhbGlkRnJvbSI6IjIwMjEtMDEtMDEifV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTY1LTA3LTA4In1dLCJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IktFTk5FVEgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJERUNFUlFVRUlSQSJ9XX1dfSwic3RhdGUiOiJiNzJiMGFjNi00MDM4LTQ0ZTEtOTA0Yy1mMWUwNzgzMmYyNjYiLCJzdWIiOiJ1cm46ZmRjOmdvdi51azphOWZiOGUzOC0wNDU4LTRkYzAtOGJlYy0yNjYyNzA5Y2IyNDAifQ.";
    static jwtClaimsSet: JWTClaimsSet = {
        aud: "https://localhost.com",
        client_id: "ipv-core-stub-aws-headless",
        exp: 1742385244,
        govuk_signin_journey_id: "d6e00a9b-d66a-4572-b331-318edf307eca",
        iat: 1742384945,
        iss: "https://localhost.com",
        nbf: 1742384945,
        redirect_uri: "https://localhost.com/callback",
        response_type: "code",
        shared_claims: {
            address: [
                {
                    addressLocality: "BATH",
                    buildingNumber: "8",
                    postalCode: "BA2 5AA",
                    streetName: "HADLEY ROAD",
                    validFrom: "2021-01-01",
                },
            ],
            birthDate: [
                {
                    value: "1965-07-08",
                },
            ],
            name: [
                {
                    nameParts: [
                        {
                            type: "GivenName",
                            value: "KENNETH",
                        },
                        {
                            type: "FamilyName",
                            value: "DECERQUEIRA",
                        },
                    ],
                },
            ],
        },
        state: "b72b0ac6-4038-44e1-904c-f1e07832f266",
        sub: "urn:fdc:gov.uk:a9fb8e38-0458-4dc0-8bec-2662709cb240",
    };

    static jwtPayload: JWTPayload = TestData.jwtClaimsSet as JWTPayload;
}
