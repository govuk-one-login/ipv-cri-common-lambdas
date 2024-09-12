export class MockSSMProvider {
    private parameters: { [key: string]: string };

    constructor(initialParameters: { [key: string]: string } = {}) {
        this.parameters = initialParameters;
    }

    async getParametersByName<T extends string>(paramsObject: { [key in T]: object }): Promise<
        Record<T, string | undefined>
    > {
        const result: Partial<Record<T, string | undefined>> = {};
        const errors: string[] = [];

        for (const paramName in paramsObject) {
            if (this.parameters[paramName]) {
                result[paramName as T] = this.parameters[paramName];
            } else {
                errors.push(paramName);
                result[paramName as T] = undefined;
            }
        }

        return result as Record<T, string | undefined>;
    }
}
