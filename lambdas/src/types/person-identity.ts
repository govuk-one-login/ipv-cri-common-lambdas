export interface SocialSecurityRecord {
    personalNumber: string;
}

export interface NamePart {
    type: string;
    value: string;
}

export interface Name {
    nameParts: NamePart[];
}

export interface BirthDate {
    value: string;
}

export interface Address {
    uprn: number;
    organisationName: string;
    departmentName: string;
    subBuildingName: string;
    buildingNumber: string;
    buildingName: string;
    dependentStreetName: string;
    streetName: string;
    doubleDependentAddressLocality: string;
    dependentAddressLocality: string;
    addressLocality: string;
    postalCode: string;
    addressCountry: string;
    validFrom: string;
    validUntil: string;
}

export interface PersonIdentity {
    socialSecurityRecord?: SocialSecurityRecord[];
    name: Name[];
    birthDate: BirthDate[];
    address: Address[];
}

export interface TxMAPersonIdentity {
    name?: Name[];
    birthDate?: BirthDate[];
    address?: Address[];
    device_information?: {
        encoded: string;
    };
}
