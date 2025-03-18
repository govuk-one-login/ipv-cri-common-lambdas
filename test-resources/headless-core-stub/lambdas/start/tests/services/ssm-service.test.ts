import { clearCaches } from "@aws-lambda-powertools/parameters";
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { mockClient } from "aws-sdk-client-mock";
import { HeadlessCoreStubError } from "../../src/errors/headless-core-stub-error";
import { getJsonSSMParameter, getSSMParameter } from "../../src/services/ssm-service";

describe("ssm-service", () => {
    const mockSSMClient = mockClient(SSMClient);

    afterEach(() => {
        mockSSMClient.reset();
        clearCaches();
    });
    describe("getSSMParameter", () => {
        it("returns ssm param value", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test/ssm/param/name",
                })
                .resolvesOnce({ Parameter: { Value: "Param Value" } });

            const result = await getSSMParameter("/test/ssm/param/name");
            expect(result).toEqual("Param Value");
        });

        it("throws error if not found", async () => {
            await expect(getSSMParameter("/i/do/not/exist")).rejects.toThrow(
                new HeadlessCoreStubError("Error retrieving /i/do/not/exist", 500),
            );
        });

        it("throws error if not undefined", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test/ssm/param/name",
                })
                .resolvesOnce({ Parameter: { Value: undefined } });
            await expect(getSSMParameter("/i/am/undefined")).rejects.toThrow(
                new HeadlessCoreStubError("Error retrieving /i/am/undefined", 500),
            );
        });

        it("caches ssm param", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test/ssm/param/name",
                })
                .resolvesOnce({ Parameter: { Value: "Param value" } });

            await getSSMParameter("/test/ssm/param/name");

            await getSSMParameter("/test/ssm/param/name");

            clearCaches();

            await expect(getSSMParameter("/test/ssm/param/name")).rejects.toThrow(
                new HeadlessCoreStubError("Error retrieving /test/ssm/param/name", 500),
            );
        });
    });

    describe("getJsonSSMParameter", () => {
        it("returns ssm param value", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test/ssm/param/name",
                })
                .resolvesOnce({ Parameter: { Value: JSON.stringify({ value: "Param value" }) } });

            const result = await getJsonSSMParameter("/test/ssm/param/name");
            expect(result).toEqual({ value: "Param value" });
        });

        it("throws error if not found", async () => {
            await expect(getJsonSSMParameter("/i/do/not/exist")).rejects.toThrow(
                new HeadlessCoreStubError("Error retrieving /i/do/not/exist", 500),
            );
        });

        it("throws error if not undefined", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test/ssm/param/name",
                })
                .resolvesOnce({ Parameter: { Value: undefined } });
            await expect(getJsonSSMParameter("/i/am/undefined")).rejects.toThrow(
                new HeadlessCoreStubError("Error retrieving /i/am/undefined", 500),
            );
        });

        it("throws error if not valid json", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test/ssm/param/name",
                })
                .resolvesOnce({ Parameter: { Value: "Not Json" } });

            await expect(getJsonSSMParameter("/i/am/not/json")).rejects.toThrow(
                new HeadlessCoreStubError("Error retrieving /i/am/not/json", 500),
            );
        });

        it("caches ssm param", async () => {
            mockSSMClient
                .on(GetParameterCommand, {
                    Name: "/test/ssm/param/name",
                })
                .resolvesOnce({ Parameter: { Value: JSON.stringify({ value: "Param value" }) } });

            await getJsonSSMParameter("/test/ssm/param/name");

            await getJsonSSMParameter("/test/ssm/param/name");

            clearCaches();

            await expect(getJsonSSMParameter("/test/ssm/param/name")).rejects.toThrow(
                new HeadlessCoreStubError("Error retrieving /test/ssm/param/name", 500),
            );
        });
    });
});
