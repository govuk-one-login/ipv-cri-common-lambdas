import { DynamoDBDocument, PutCommand } from "@aws-sdk/lib-dynamodb";
import { ConfigService } from "../common/config/config-service";
import { CommonConfigKey } from "../common/config/config-keys";
import { Address, BirthDate, Name, PersonIdentity } from "../common/services/models/person-identity";
import {
    PersonIdentityAddress,
    PersonIdentityDateOfBirth,
    PersonIdentityItem,
    PersonIdentityName,
} from "./models/person-identity-item";

export class PersonIdentityService {
    constructor(private dynamoDbClient: DynamoDBDocument, private config: Array<string|number>) {}

    public async savePersonIdentity(sharedClaims: PersonIdentity, sessionId: string): Promise<string> {
        const [ tableName, sessionExpirationEpoch] = this.config;
        const personIdentityItem = this.createPersonIdentityItem(sharedClaims, sessionId, sessionExpirationEpoch as number);
        const putSessionCommand = new PutCommand({
            TableName: tableName as string,
            Item: personIdentityItem,
        });
        await this.dynamoDbClient.send(putSessionCommand);
        return putSessionCommand.input.Item!.sessionId;
    }
    private createPersonIdentityItem(
        sharedClaims: PersonIdentity,
        sessionId: string,
        sessionExpirationEpoch: number,
    ): PersonIdentityItem {
        return {
            sessionId: sessionId,
            addresses: this.mapAddresses(sharedClaims.address),
            birthDates: this.mapBirthDates(sharedClaims.birthDate),
            expiryDate: sessionExpirationEpoch,
            names: this.mapNames(sharedClaims.name),
        };
    }
    private mapAddresses(addresses: Address[]): PersonIdentityAddress[] {
        if (addresses && addresses.length) {
            return addresses.map((address) => {
                return {
                    uprn: address.uprn,
                    organisationName: address.organisationName,
                    departmentName: address.departmentName,
                    subBuildingName: address.subBuildingName,
                    buildingNumber: address.buildingNumber,
                    buildingName: address.buildingName,
                    dependentStreetName: address.dependentStreetName,
                    streetName: address.streetName,
                    addressCountry: address.addressCountry,
                    postalCode: address.postalCode,
                    addressLocality: address.addressLocality,
                    dependentAddressLocality: address.dependentAddressLocality,
                    doubleDependentAddressLocality: address.doubleDependentAddressLocality,
                    validFrom: address.validFrom,
                    validUntil: address.validUntil,
                };
            });
        }
        return [];
    }
    private mapBirthDates(birthDates: BirthDate[]): PersonIdentityDateOfBirth[] {
        if (birthDates && birthDates.length) {
            return birthDates.map((bd) => {
                return { value: bd.value };
            });
        }
        return [];
    }
    private mapNames(names: Name[]): PersonIdentityName[] {
        if (names && names.length) {
            return names.map((name) => {
                let personIdentityName: PersonIdentityName = { nameParts: [] };
                if (name.nameParts && name.nameParts.length) {
                    personIdentityName.nameParts = name.nameParts.map((namePart) => {
                        return { type: namePart.type, value: namePart.value };
                    });
                }
                return personIdentityName;
            });
        }
        return [];
    }
}
