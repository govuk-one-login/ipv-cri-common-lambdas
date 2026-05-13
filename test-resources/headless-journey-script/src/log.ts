/* eslint-disable no-console */
import { input } from "./cli-args.ts";

export function error(...args: Parameters<typeof console.log>) {
    console.error(...args);
}

export function logIfVerbose(...args: Parameters<typeof console.log>) {
    if (input.verbose) console.log(...args);
}

export async function logFinalEnvironment(environment: { sessionId?: string; vcPayload?: Record<string, unknown> }) {
    // wait 100ms to allow test runners to complete
    await new Promise((resolve) => setTimeout(resolve, 100));

    console.log();
    console.log("Session ID:", environment.sessionId);
    console.log();
    console.log("VC JWT payload:", environment.vcPayload);
    console.log();

    // log the full VC (loses syntax highlighting but should log the full object depth)
    logIfVerbose(`Full VC JWT payload:`);
    logIfVerbose(JSON.stringify(environment.vcPayload, undefined, 2));
}
