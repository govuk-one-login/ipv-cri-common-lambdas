import { DynamoDBDocument, PutCommand } from "@aws-sdk/lib-dynamodb";
import { ConfigService } from "../common/config/config-service";
import { CommonConfigKey } from "../types/config-keys";
import { Address, BirthDate, Name, PersonIdentity, SocialSecurityRecord } from "../types/person-identity";
import {
    PersonIdentityAddress,
    PersonIdentityDateOfBirth,
    PersonIdentityItem,
    PersonIdentityName,
    PersonIdentitySocialSecurityRecord,
} from "../types/person-identity-item";

export class PersonIdentityService {
    constructor(
        private dynamoDbClient: DynamoDBDocument,
        private configService: ConfigService,
    ) {}

    public async savePersonIdentity(sharedClaims: PersonIdentity, sessionId: string): Promise<string> {
        const sessionExpirationEpoch = this.configService.getSessionExpirationEpoch();
        const personIdentityItem = this.createPersonIdentityItem(sharedClaims, sessionId, sessionExpirationEpoch);

        const putSessionCommand = new PutCommand({
            TableName: this.configService.getConfigEntry(CommonConfigKey.PERSON_IDENTITY_TABLE_NAME),
            Item: personIdentityItem,
        });
        await this.dynamoDbClient.send(putSessionCommand);
        return putSessionCommand?.input?.Item?.sessionId;
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
            socialSecurityRecord: this.mapNino(sharedClaims.socialSecurityRecord),
        };
    }
    private mapAddresses(addresses: Address[]): PersonIdentityAddress[] {
        return addresses?.map((address) => ({
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
        }));
    }
    private mapBirthDates(birthDates: BirthDate[]): PersonIdentityDateOfBirth[] {
        return birthDates?.map((bd) => ({ value: bd.value }));
    }
    private mapNames(names: Name[]): PersonIdentityName[] {
        return names?.map((name) => ({
            nameParts: name?.nameParts?.map((namePart) => ({
                type: namePart.type,
                value: namePart.value,
            })),
        }));
    }
    private mapNino(socialSecurityRecord?: SocialSecurityRecord[]): PersonIdentitySocialSecurityRecord[] | undefined {
        return socialSecurityRecord?.map((record) => ({ personalNumber: record?.personalNumber }));
    }
}
