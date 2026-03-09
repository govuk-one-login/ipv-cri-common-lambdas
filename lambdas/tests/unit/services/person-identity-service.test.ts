import { DynamoDBDocument, PutCommand } from "@aws-sdk/lib-dynamodb";
import { CommonConfigKey } from "../../../src/types/config-keys";
import { ConfigService } from "../../../src/common/config/config-service";
import { PersonIdentity } from "../../../src/types/person-identity";
import { PersonIdentityService } from "../../../src/services/person-identity-service";
import { PersonIdentityDrivingPermit } from "../../../src/types/person-identity-item";

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
        } else if (key === CommonConfigKey.SESSION_TTL) {
            return 7200;
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
        socialSecurityRecord: [
            {
                personalNumber: "AA000003D",
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
        const expectedExpiry: number = Math.floor((Date.now() + 7200 * 1000) / 1000);
        await personIdentityService.savePersonIdentity(mockPerson, sessionId);

        expect(mockPutCommand).toHaveBeenCalledWith({
            TableName: "PersonIdentityTable",
            Item: {
                sessionId: "test-session-id",
                addresses: mockPerson.address,
                birthDates: mockPerson.birthDate,
                expiryDate: expectedExpiry,
                names: mockPerson.name,
                socialSecurityRecord: mockPerson.socialSecurityRecord,
            },
        });
    });

    it("should correctly format personal identity information with driving permit", async () => {
        // Needs a copy as this is unique shared claims configuration
        const mockPersonDeepCopy: PersonIdentity = JSON.parse(JSON.stringify(mockPerson));

        mockPersonDeepCopy.address = [];
        mockPersonDeepCopy.drivingPermit = [
            {
                personalNumber: "55667788",
                expiryDate: "2042-10-01",
                issueNumber: undefined,
                issuedBy: "DVA",
                issueDate: "2018-04-19",
                fullAddress: "70 OLD BAKERS COURT BELFAST NW3 5RG",
            },
        ] as PersonIdentityDrivingPermit[];

        const expectedExpiry: number = Math.floor((Date.now() + 7200 * 1000) / 1000);
        await personIdentityService.savePersonIdentity(mockPersonDeepCopy, sessionId);

        expect(mockPutCommand).toHaveBeenCalledWith({
            TableName: "PersonIdentityTable",
            Item: {
                sessionId: "test-session-id",
                addresses: [{ postalCode: "NW3 5RG" }],
                birthDates: mockPerson.birthDate,
                expiryDate: expectedExpiry,
                names: mockPerson.name,
                socialSecurityRecord: mockPerson.socialSecurityRecord,
                drivingPermits: mockPersonDeepCopy.drivingPermit,
            },
        });
    });

    // Test ported from the Java Person Identity Mapper Tests - Tests postcode extraction from full address
    describe("PersonIdentityService - Driving Permit Mapping", () => {
        beforeEach(() => {
            jest.clearAllMocks();
        });

        const testCases: [string, string | undefined, string | undefined][] = [
            ["DVA", undefined, undefined], // No full address
            // Just postcodes
            ["DVA", "BT11AB", "BT11AB"], // Edge case full address is just a 6 char postcode
            ["DVA", "BT1 1AB", "BT1 1AB"], // Edge case full address is just a 6 char postcode mid-space
            ["DVA", ",BT11AB", "BT11AB"], // Edge case OCR failure, 6 char postcode with comma
            ["DVA", ",BT1 1AB", "BT1 1AB"], // Edge case as above but with space
            ["DVA", ",BT121AB", "BT121AB"], // Edge case OCR failure, 7 char postcode with comma
            ["DVA", ",BT12 1AB", "BT12 1AB"], // Edge case as above but with space
            ["DVA", "BT11 1AB", "BT11 1AB"], // 8 Exactly
            ["DVA", ",BT11 1AB", "BT11 1AB"], // 8 Exactly, with leading comma
            // Full Address
            ["DVA", "Building, Road, Town, County, BT11AB", "BT11AB"], // 6Char postcode/ address-commas
            ["DVA", "Building Road Town County BT11AB", "Y BT11AB"], // 6Char postcode/ address-spaces
            ["DVA", "Building, Road, Town, County, BT1 1AB", "BT1 1AB"], // 7Char postcode/ address-commas
            ["DVA", "Building Road Town County BT1 1AB", "BT1 1AB"], // 7Char postcode address-spaces
            ["DVA", "Building, Road, Town, County, BT121AB", "BT121AB"], // 7Char postcode address-commas
            ["DVA", "Building Road Town County BT12 1AB", "BT12 1AB"], // 7Char postcode/ address-spaces
            ["DVA", "Building, Road, Town, County, BT12 1AB", "BT12 1AB"], // 8Char postcode/ Address commas
            ["DVA", "Building Road Town County BT12 1AB", "BT12 1AB"], // 8Char postcode, address-spaces
            // DVA No postcode Tests
            ["DVA", "Building, Road, Town, County", "COUNTY"], // No postcode / Address commas
            ["DVA", "Building Road Town County", "N COUNTY"], // No postcode/ Address spaces
            // DVLA
            ["DVLA", undefined, undefined], // No full address
            // Just postcodes
            ["DVLA", "AB11AB", "AB11AB"], // Edgecase full address is just a 6 char postcode
            ["DVLA", "AB1 1AB", "AB1 1AB"], // Edgecase full address is just a 6 char postcode mid space
            ["DVLA", ",AB11AB", "AB11AB"], // Edgecase OCR failure, 6 char postcode with comma
            ["DVLA", ",AB1 1AB", "AB1 1AB"], // Edgecase as above but with space
            ["DVLA", ",AB121AB", "AB121AB"], // Edgecase OCR failure, 7 char postcode with comma
            ["DVLA", ",AB12 1AB", "AB12 1AB"], // Edgecase as above but with space
            ["DVLA", "AB11 1AB", "AB11 1AB"], // 8 Exactly
            ["DVLA", ",AB11 1AB", "AB11 1AB"], // 8 Exactly, with leading comma
            // DVLA Full Address
            ["DVLA", "Building, Road, Town, County, AB11AB", "AB11AB"], // 6Char postcode/ address-commas
            ["DVLA", "Building Road Town County AB11AB", "Y AB11AB"], // 6Char postcode/ address-spaces
            ["DVLA", "Building, Road, Town, County, AB1 1AB", "AB1 1AB"], // 7Char postcode/ address-commas
            ["DVLA", "Building Road Town County AB1 1AB", "AB1 1AB"], // 7Char postcode address-spaces
            ["DVLA", "Building, Road, Town, County, AB121AB", "AB121AB"], // 7Char postcode address-commas
            ["DVLA", "Building Road Town County AB12 1AB", "AB12 1AB"], // 7Char postcode/ address-spaces
            ["DVLA", "Building, Road, Town, County, AB12 1AB", "AB12 1AB"], // 8Char postcode/ address-commas
            ["DVLA", "Building Road Town County AB12 1AB", "AB12 1AB"], // 8Char postcode, address-spaces
            // DVLA No postcode Tests
            ["DVLA", "Building, Road, Town, County,", "COUNTY,"], // No postcode / Address-commas
            ["DVLA", "Building Road Town County", "N COUNTY"], // No postcode/ Address-spaces
        ];

        test.each(testCases)(
            "should map driving permit with issuer=%s, fullAddress=%s to postcode=%s",
            async (issuer, fullAddress, expectedPostcode) => {
                const sharedClaims: PersonIdentity = {
                    name: [
                        {
                            nameParts: [
                                { type: "GivenName", value: "Jon" },
                                { type: "FamilyName", value: "Smith" },
                            ],
                        },
                    ],
                    birthDate: [{ value: "1984-06-27" }],
                    address: [],
                    drivingPermit: [
                        {
                            personalNumber: "personalNumber",
                            expiryDate: "2029-10-21",
                            issueDate: "2011-10-21",
                            issueNumber: "issueNumber",
                            issuedBy: issuer,
                            fullAddress: fullAddress!,
                        },
                    ],
                };

                await personIdentityService.savePersonIdentity(sharedClaims, "test-session-id");

                const putCall = mockPutCommand.mock.calls[mockPutCommand.mock.calls.length - 1][0];
                const item = putCall.Item!;

                expect(item.names[0].nameParts[0].value).toBe("Jon");
                expect(item.names[0].nameParts[0].type).toBe("GivenName");
                expect(item.names[0].nameParts[1].value).toBe("Smith");
                expect(item.names[0].nameParts[1].type).toBe("FamilyName");
                expect(item.birthDates[0].value).toBe("1984-06-27");

                if (item.addresses.length > 0) {
                    const address = item.addresses[0];
                    expect(address.addressLocality).toBeUndefined();
                    expect(address.buildingName).toBeUndefined();
                    expect(address.buildingNumber).toBeUndefined();
                    expect(address.streetName).toBeUndefined();
                    expect(address.postalCode).toBe(expectedPostcode);
                    expect(address.addressRegion).toBeUndefined();
                    expect(address.validFrom).toBeUndefined();
                    expect(address.validUntil).toBeUndefined();
                } else {
                    expect(fullAddress).toBeUndefined();
                }

                expect(item.drivingPermits[0].personalNumber).toBe("personalNumber");
                expect(item.drivingPermits[0].expiryDate).toBe("2029-10-21");
                expect(item.drivingPermits[0].issueDate).toBe("2011-10-21");
                expect(item.drivingPermits[0].issueNumber).toBe("issueNumber");
                expect(item.drivingPermits[0].issuedBy).toBe(issuer);
                expect(item.drivingPermits[0].fullAddress).toBe(fullAddress);
            },
        );
    });

    it("should avoid formatting blank identities", async () => {
        const expectedExpiry: number = Math.floor((Date.now() + 7200 * 1000) / 1000);
        const newMockPerson: PersonIdentity = {
            socialSecurityRecord: [],
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
                expiryDate: expectedExpiry,
                names: [],
                socialSecurityRecord: [],
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
