export type ValidationResult = {
    isValid: boolean;
    errorMsg: string | null;
    validatedObject?: any;
};
