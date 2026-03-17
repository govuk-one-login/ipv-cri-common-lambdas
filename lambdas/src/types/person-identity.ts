export interface PersonIdentity {
    name: Name[];
    birthDate: BirthDate[];
    address: Address[];
    socialSecurityRecord?: SocialSecurityRecord[];
    drivingPermit?: DrivingPermit[];
}

export interface Name {
    nameParts: NamePart[];
}

export interface NamePart {
    type: string;
    value: string;
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

export interface SocialSecurityRecord {
    personalNumber: string;
}

export interface DrivingPermit {
    personalNumber: string;
    expiryDate: string;
    issueNumber: string | undefined;
    issuedBy: string;
    issueDate: string;
    fullAddress: string;
}

export interface TxMAPersonIdentity {
    name?: Name[];
    birthDate?: BirthDate[];
    address?: Address[];
    device_information?: {
        encoded: string;
    };
}
