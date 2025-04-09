import { Buffer } from "buffer";

export const base64Encode = (stringToEncode: string) => Buffer.from(stringToEncode, "binary").toString("base64");

export const base64Decode = (base64String: string) => Buffer.from(base64String, "base64").toString("binary");
