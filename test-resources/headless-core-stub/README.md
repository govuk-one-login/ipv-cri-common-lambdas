# Headless Core Stub

## /start

This endpoint will generate an encrypted JWT that can be used to start a session in a CRI. You can pass in a JSON body to override the values of the JWT Claims Set, or if you pass in an empty JSON object it will generate with default values. 

A full example of top level field overrides can be seen below. For shared_claims and evidence_requested there are more nested fields you can provide. 

It is recommended to not provide overwrites for most fields. For example, time based fields - These should only be overridden if you want to test how a CRI handles expired JWTs etc.

```
{
    "iss": "https://localhost.gov.uk",
    "sub": "urn:fdc:gov.uk:abcdevg",
    "aud": "https://review-a.dev.account.gov.uk",
    "iat": 1,
    "exp": 2,
    "nbf": 1,
    "response_type": "code",
    "client_id": "ipv-core-stub-aws-headless",
    "redirect_uri": "https://localhost.gov.uk/callback",
    "state": "abc",
    "govuk_signin_journey_id": "abc",
    "shared_claims": {
        "address": [
            {
                "addressLocality": "LONDON",
                "buildingNumber": "10",
                "postalCode": "SW1A 2AA",
                "streetName": "DOWNING STREET",
                "validFrom": "2020-01-01"
            }
        ],
        "birthDate": [
            {
                "value": "1990-01-01"
            }
        ],
        "name": [
            {
                "nameParts": [
                    {
                        "type": "GivenName",
                        "value": "JOE"
                    },
                    {
                        "type": "FamilyName",
                        "value": "BLOGGS"
                    }
                ]
            }
        ]
    },
    "evidence_requested": {
        "scoringPolicy": "gpg45",
        "strengthScore": 2,
        "verificationScore": 2
    },
    "context": "cri_context"
}
```

If shared_claims is not overridden, the default will be;

```
{
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
    birthDate: [
        {
            value: "1965-07-08",
        },
    ],
    address: [
        {
            buildingNumber: "8",
            streetName: "HADLEY ROAD",
            addressLocality: "BATH",
            postalCode: "BA2 5AA",
            validFrom: "2021-01-01",
        },
    ],
};
```
### Configuration

This stack will need to be deployed into an account with a 'core-infrastructure' stack, as it requires the `core-infrastructure-CriDecryptionKey1Id`

It requires a (test) JWK private key as stored in an SSM param at `/test-resources/ipv-core-stub-aws-headless/privateSigningKey`

If you are planning to use default values for `aud`, `iss`, `redirect_uri`, all of these will need SSM parameters at;   
`/${COMMON_LAMBDAS_STACK_NAME}/clients/ipv-core-stub-aws-headless/jwtAuthentication/audience`  
`/${COMMON_LAMBDAS_STACK_NAME}/clients/ipv-core-stub-aws-headless/jwtAuthentication/issuer`   
`/${COMMON_LAMBDAS_STACK_NAME}/clients/ipv-core-stub-aws-headless/jwtAuthentication/redirectUri`   