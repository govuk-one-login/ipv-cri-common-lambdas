import { DynamoDBDocument, PutCommand } from "@aws-sdk/lib-dynamodb";
import { ConfigService } from "../common/config/config-service";
import { CommonConfigKey } from "../types/config-keys";
import {
    Address,
    BirthDate,
    DrivingPermit,
    Name,
    PersonIdentity,
    SocialSecurityRecord,
} from "../types/person-identity";
import {
    PersonIdentityAddress,
    PersonIdentityDateOfBirth,
    PersonIdentityDrivingPermit,
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
        const drivingPermitAddresses = this.extractAddressPostalCodeFromDrivingPermitFullAddress(
            sharedClaims.drivingPermit,
        );

        return {
            sessionId: sessionId,
            addresses:
                drivingPermitAddresses.length > 0 ? drivingPermitAddresses : this.mapAddresses(sharedClaims.address),
            birthDates: this.mapBirthDates(sharedClaims.birthDate),
            expiryDate: sessionExpirationEpoch,
            names: this.mapNames(sharedClaims.name),
            socialSecurityRecord: this.mapNino(sharedClaims.socialSecurityRecord),
            drivingPermits: this.mapDrivingPermit(sharedClaims.drivingPermit),
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
    private mapDrivingPermit(drivingPermit?: DrivingPermit[]): PersonIdentityDrivingPermit[] | undefined {
        return drivingPermit?.map((record) => ({
            personalNumber: record?.personalNumber,
            expiryDate: record?.expiryDate,
            issueNumber: record?.issueNumber,
            issuedBy: record?.issuedBy,
            issueDate: record?.issueDate,
            fullAddress: record?.fullAddress,
        }));
    }

    private extractAddressPostalCodeFromDrivingPermitFullAddress(
        drivingPermit?: DrivingPermit[],
    ): PersonIdentityAddress[] {
        if (!drivingPermit) return [];

        return drivingPermit
            .filter((permit) => permit.fullAddress)
            .map(
                (permit) =>
                    ({
                        postalCode: this.extractPostalCode(permit),
                    }) as PersonIdentityAddress,
            )
            .filter((addr) => addr.postalCode);
    }

    private extractPostalCode(dp: DrivingPermit): string | undefined {
        const fullAddress = dp.fullAddress.toUpperCase();

        if (fullAddress.length <= 6) {
            return fullAddress;
        }

        const suffix = fullAddress.length >= 8 ? fullAddress.slice(-8) : fullAddress;
        const trimmed = suffix.startsWith(",") ? suffix.slice(1) : suffix;
        return trimmed.trim();
    }
}
