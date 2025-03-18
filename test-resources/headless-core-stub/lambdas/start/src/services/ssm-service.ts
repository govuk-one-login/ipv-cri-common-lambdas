import { Logger } from "@aws-lambda-powertools/logger";
import { getParameter } from "@aws-lambda-powertools/parameters/ssm";
import { HeadlessCoreStubError } from "../errors/headless-core-stub-error";

const logger = new Logger();

export const getSSMParameter = async (name: string) => {
    try {
        const value = await getParameter(name, {
            maxAge: 1800,
        });
        if (value) {
            return value;
        }
    } catch (e) {
        logger.debug(`Error retrieving ${name}: ` + (e as Error).stack);
    }
    throw new HeadlessCoreStubError(`Error retrieving ${name}`, 500);
};

export const getJsonSSMParameter = async (name: string) => {
    try {
        const value = await getParameter(name, { maxAge: 1800, transform: "json" });
        if (value) {
            return value;
        }
    } catch (e) {
        logger.error(`Error retrieving ${name}: ` + (e as Error).stack);
    }
    throw new HeadlessCoreStubError(`Error retrieving ${name}`, 500);
};
