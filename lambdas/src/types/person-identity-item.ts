export interface PersonIdentityItem {
    sessionId: string;
    names: PersonIdentityName[];
    birthDates: PersonIdentityDateOfBirth[];
    addresses: PersonIdentityAddress[];
    socialSecurityRecord?: PersonIdentitySocialSecurityRecord[];
    drivingPermits?: PersonIdentityDrivingPermit[]; // NOTE drivingPermit(s)
    expiryDate: number;
}

export interface PersonIdentityName {
    nameParts: PersonIdentityNamePart[];
}

export interface PersonIdentityNamePart {
    type: string;
    value: string;
}

export interface PersonIdentityDateOfBirth {
    value: string;
}

export interface PersonIdentityAddress {
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

export interface PersonIdentitySocialSecurityRecord {
    personalNumber: string;
}

export interface PersonIdentityDrivingPermit {
    personalNumber: string;
    expiryDate: string;
    issueNumber: string | undefined;
    issuedBy: string;
    issueDate: string;
    fullAddress: string;
}
