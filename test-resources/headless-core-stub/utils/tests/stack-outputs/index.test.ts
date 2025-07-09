import { CloudFormationClient, DescribeStacksCommandOutput } from "@aws-sdk/client-cloudformation";
import { stackOutputs } from "../../src/stack-outputs";

jest.mock("@aws-sdk/client-cloudformation");
const mockSend = jest.fn();

describe("stackOutputs", () => {
    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(CloudFormationClient.prototype, "send").mockImplementation(mockSend);
    });

    it("returns stack outputs as key-value pairs", async () => {
        const mockResponse: DescribeStacksCommandOutput = {
            Stacks: [
                {
                    Outputs: [
                        { OutputKey: "ApiUrl", OutputValue: "https://api.example.com" },
                        { OutputKey: "BucketName", OutputValue: "my-bucket" },
                    ],
                },
            ],
        } as DescribeStacksCommandOutput;

        mockSend.mockResolvedValueOnce(mockResponse);

        const result = await stackOutputs("test-stack");

        expect(result).toEqual({
            ApiUrl: "https://api.example.com",
            BucketName: "my-bucket",
        });
    });

    it("returns empty object when no outputs exist", async () => {
        const mockResponse: DescribeStacksCommandOutput = {
            Stacks: [{ Outputs: [] }],
        } as unknown as DescribeStacksCommandOutput;

        mockSend.mockResolvedValueOnce(mockResponse);

        const result = await stackOutputs("test-stack");

        expect(result).toEqual({});
    });

    it("returns empty object when stack has no outputs property", async () => {
        const mockResponse: DescribeStacksCommandOutput = {
            Stacks: [{}],
        } as unknown as DescribeStacksCommandOutput;

        mockSend.mockResolvedValueOnce(mockResponse);

        const result = await stackOutputs("test-stack");

        expect(result).toEqual({});
    });

    it("throws error when stack name is not provided", async () => {
        await expect(stackOutputs()).rejects.toThrow("Stack name not provided.");
    });

    it("throws error when stack name is empty string", async () => {
        await expect(stackOutputs("")).rejects.toThrow("Stack name not provided.");
    });

    it("calls send method when stack name is provided", async () => {
        const mockResponse: DescribeStacksCommandOutput = {
            Stacks: [{ Outputs: [] }],
        } as unknown as DescribeStacksCommandOutput;

        mockSend.mockResolvedValueOnce(mockResponse);

        await stackOutputs("my-test-stack");

        expect(mockSend).toHaveBeenCalledTimes(1);
    });
});
