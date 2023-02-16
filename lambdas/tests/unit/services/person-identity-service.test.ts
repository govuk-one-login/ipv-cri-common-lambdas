import { DynamoDBDocument, PutCommand } from "@aws-sdk/lib-dynamodb";
import { CommonConfigKey } from "../../../src/types/config-keys";
import { ConfigService } from "../../../src/common/config/config-service";
import { PersonIdentity } from "../../../src/types/person-identity";
import { PersonIdentityService } from "../../../src/services/person-identity-service";

jest.mock("@aws-sdk/lib-dynamodb", () => {
    const mockPut = jest.fn();
    mockPut.mockImplementation(() => {
        return {
            input: {
                Item: {
                    sessionId: "test-session-id",
                },
            },
        };
    });
    return {
        __esModule: true,
        ...jest.requireActual("@aws-sdk/lib-dynamodb"),
        PutCommand: mockPut,
        DynamoDBDocument: {
            prototype: {
                send: jest.fn(),
            },
        },
    };
}); //  this is so we only mock out the PutCommand

describe("PersonIdentityService", () => {
    let personIdentityService: PersonIdentityService;
    const mockPutCommand = jest.mocked(PutCommand);
    const mockDynamoDb = jest.mocked(DynamoDBDocument);
    const mockConfigService = jest.mocked(ConfigService);

    jest.spyOn(mockConfigService.prototype, "getConfigEntry").mockImplementation((key: CommonConfigKey) => {
        if (key === CommonConfigKey.PERSON_IDENTITY_TABLE_NAME) {
            return "PersonIdentityTable";
        } else {
            return "1675382400";
        }
    });

    const sessionId = "test-session-id";

    const mockPerson: PersonIdentity = {
        name: [
            {
                nameParts: [
                    {
                        type: "firstName",
                        value: "Jane",
                    },
                    {
                        type: "lastName",
                        value: "Doe",
                    },
                ],
            },
        ],
        birthDate: [
            {
                value: "2023-01-01",
            },
        ],
        address: [
            {
                uprn: 0,
                organisationName: "N/A",
                departmentName: "N/A",
                subBuildingName: "N/A",
                buildingNumber: "1",
                buildingName: "N/A",
                dependentStreetName: "N/A",
                streetName: "Test Street",
                doubleDependentAddressLocality: "N/A",
                dependentAddressLocality: "N/A",
                addressLocality: "N/A",
                postalCode: "AA1 1AA",
                addressCountry: "UK",
                validFrom: "2022-01",
                validUntil: "2023-01",
            },
        ],
    };

    beforeEach(() => {
        jest.clearAllMocks();

        personIdentityService = new PersonIdentityService(mockDynamoDb.prototype, mockConfigService.prototype);
    });

    it("should call the config service to obtain configuration", async () => {
        await personIdentityService.savePersonIdentity(mockPerson, sessionId);

        expect(mockConfigService.prototype.getConfigEntry).toHaveBeenCalledTimes(2);
        expect(mockConfigService.prototype.getConfigEntry).toHaveBeenCalledWith(CommonConfigKey.SESSION_TTL);
        expect(mockConfigService.prototype.getConfigEntry).toHaveBeenCalledWith(
            CommonConfigKey.PERSON_IDENTITY_TABLE_NAME,
        );
    });

    it("should correctly format personal identity information", async () => {
        await personIdentityService.savePersonIdentity(mockPerson, sessionId);

        expect(mockPutCommand).toHaveBeenCalledWith({
            TableName: "PersonIdentityTable",
            Item: {
                sessionId: "test-session-id",
                addresses: mockPerson.address,
                birthDates: mockPerson.birthDate,
                expiryDate: 1675382400,
                names: mockPerson.name,
            },
        });
    });

    it("should avoid formatting blank identities", async () => {
        const newMockPerson: PersonIdentity = {
            name: [],
            birthDate: [],
            address: [],
        };
        await personIdentityService.savePersonIdentity(newMockPerson, sessionId);

        expect(mockPutCommand).toHaveBeenCalledWith({
            TableName: "PersonIdentityTable",
            Item: {
                sessionId: "test-session-id",
                addresses: [],
                birthDates: [],
                expiryDate: 1675382400,
                names: [],
            },
        });
    });

    it("should save the person identity to dynamo db", async () => {
        await personIdentityService.savePersonIdentity(mockPerson, sessionId);

        expect(mockPutCommand).toHaveBeenCalledTimes(1);
        expect(mockDynamoDb.prototype.send).toHaveBeenCalledTimes(1);
    });

    it("should return the session ID", async () => {
        const response = await personIdentityService.savePersonIdentity(mockPerson, sessionId);

        expect(response).toEqual("test-session-id");
    });
});
