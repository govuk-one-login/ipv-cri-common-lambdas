# Headless Core Stub

## /start
```
{
    "aud": "https://review-a.dev.account.gov.uk"
}
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
    }
}
```