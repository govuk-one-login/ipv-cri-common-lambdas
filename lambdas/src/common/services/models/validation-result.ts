export interface ValidationResult {
    isValid: boolean;
    errorMsg: string | null;
    validatedObject?: any;
}
