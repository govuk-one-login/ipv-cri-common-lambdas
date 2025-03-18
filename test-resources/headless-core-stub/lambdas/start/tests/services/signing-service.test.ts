import { clearCaches } from "@aws-lambda-powertools/parameters";
import { GetPublicKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { mockClient } from "aws-sdk-client-mock";
import { generateKeyPairSync } from "crypto";
import { HeadlessCoreStubError } from "../../src/errors/headless-core-stub-error";
import {
    encryptSignedJwt,
    getPrivateSigningKey,
    getPublicEncryptionKey,
    signJwt,
} from "../../src/services/signing-service";
import { TestData } from "../test-data";

describe("crypto-service", () => {
    describe("getPrivateSigningKey", () => {
        const mockSSMClient = mockClient(SSMClient);

        afterEach(() => {
            mockSSMClient.reset();
            clearCaches();
        });

        it("retrieves private signing key", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test-resources/ipv-core-stub-aws-headless/privateSigningKey",
                })
                .resolvesOnce({ Parameter: { Value: JSON.stringify(TestData.privateSigningKey) } });

            const result = await getPrivateSigningKey();

            expect(result).toEqual(TestData.privateSigningKey);
        });

        it("throws error with 500 if ssm param cannot be retrieved", async () => {
            await expect(getPrivateSigningKey()).rejects.toThrow(
                new HeadlessCoreStubError(
                    "Error retrieving /test-resources/ipv-core-stub-aws-headless/privateSigningKey",
                    500,
                ),
            );
        });

        it("throws error with 500 if ssm param is not valid", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test-resources/ipv-core-stub-aws-headless/privateSigningKey",
                })
                .resolvesOnce({ Parameter: { Value: "Not JSON" } });

            await expect(getPrivateSigningKey()).rejects.toThrow(
                new HeadlessCoreStubError(
                    "Error retrieving /test-resources/ipv-core-stub-aws-headless/privateSigningKey",
                    500,
                ),
            );
        });
    });

    describe("getPrivateSigningKey", () => {
        it("retrieves private signing key", async () => {
            const result = await signJwt(TestData.jwtPayload, TestData.privateSigningKey);
            expect(result).toMatch(/eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*/g);
            const jwtWithoutSig =
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdC5jb20iLCJjbGllbnRfaWQiOiJpcHYtY29yZS1zdHViLWF3cy1oZWFkbGVzcyIsImV4cCI6MTc0MjM4NTI0NCwiZ292dWtfc2lnbmluX2pvdXJuZXlfaWQiOiJkNmUwMGE5Yi1kNjZhLTQ1NzItYjMzMS0zMThlZGYzMDdlY2EiLCJpYXQiOjE3NDIzODQ5NDUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LmNvbSIsIm5iZiI6MTc0MjM4NDk0NSwibm9uY2UiOiIiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2xvY2FsaG9zdC5jb20vY2FsbGJhY2siLCJyZXNwb25zZV90eXBlIjoiY29kZSIsInNjb3BlIjoiIiwic2hhcmVkX2NsYWltcyI6eyJhZGRyZXNzIjpbeyJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJ2YWxpZEZyb20iOiIyMDIxLTAxLTAxIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NS0wNy0wOCJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XX0sInN0YXRlIjoiYjcyYjBhYzYtNDAzOC00NGUxLTkwNGMtZjFlMDc4MzJmMjY2Iiwic3ViIjoidXJuOmZkYzpnb3YudWs6YTlmYjhlMzgtMDQ1OC00ZGMwLThiZWMtMjY2MjcwOWNiMjQwIn0.";
            const expJwtWithoutSigRegex = new RegExp(`^${jwtWithoutSig}?`);
            expect(result).toMatch(expJwtWithoutSigRegex);
        });
    });

    describe("getPublicEncryptionKey", () => {
        const mockKMSClient = mockClient(KMSClient);

        afterEach(() => {
            mockKMSClient.reset();
            clearCaches();
        });

        it("throws error with 500 if decryption key env variable not set", async () => {
            await expect(getPublicEncryptionKey()).rejects.toThrow(
                new HeadlessCoreStubError("Decryption key ID not present", 500),
            );
        });

        it("throws error with 500 if kms key not retrieved", async () => {
            process.env.DECRYPTION_KEY_ID = "abc123";
            await expect(getPublicEncryptionKey()).rejects.toThrow(
                new HeadlessCoreStubError("Unable to retrieve public encryption key", 500),
            );
        });

        it("retrieves public encryption key", async () => {
            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: "spki",
                    format: "der",
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "der",
                },
            });
            const keyBuffer = Buffer.from(publicKey);

            process.env.DECRYPTION_KEY_ID = "abc123";

            const mockKMSClient = mockClient(KMSClient);
            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const result = await getPublicEncryptionKey();
            expect(result.type).toEqual("public");
        });
    });

    describe("encryptSignedJwt", () => {
        it("creates encrypted signed jwt", async () => {
            const { publicKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: "spki",
                    format: "der",
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "der",
                },
            });
            const keyBuffer = Buffer.from(publicKey);

            process.env.DECRYPTION_KEY_ID = "abc123";

            const mockKMSClient = mockClient(KMSClient);
            mockKMSClient.on(GetPublicKeyCommand, { KeyId: "abc123" }).resolvesOnce({ PublicKey: keyBuffer });

            const result = await getPublicEncryptionKey();

            const resulta = await encryptSignedJwt(TestData.jwt, result);
            expect(resulta).toMatch(
                /^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/g,
            );
        });
    });
});
