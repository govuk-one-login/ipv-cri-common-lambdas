import {Logger} from "@aws-lambda-powertools/logger";
import {SurajJwtVerify} from "../src/common/security/suraj-jwt-verify";

const jwt = "eyJraWQiOiJpcHYtY29yZS1zdHViLTItZnJvbS1ta2p3ay5vcmciLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46ZmRjOmdvdi51azoyMDIyOjZkNDBmYmVmLWVkODctNDM2OS1iYzVhLTc2ZTAwMWYyOTIxNyIsInNoYXJlZF9jbGFpbXMiOnsiQGNvbnRleHQiOlsiaHR0cHM6XC9cL3d3dy53My5vcmdcLzIwMThcL2NyZWRlbnRpYWxzXC92MSIsImh0dHBzOlwvXC92b2NhYi5sb25kb24uY2xvdWRhcHBzLmRpZ2l0YWxcL2NvbnRleHRzXC9pZGVudGl0eS12MS5qc29ubGQiXSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJKaW0ifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJGZXJndXNvbiJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk0OC0wNC0yNCJ9XSwiYWRkcmVzcyI6W3siYnVpbGRpbmdOdW1iZXIiOiIiLCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiIiwiYWRkcmVzc0xvY2FsaXR5IjoiIiwicG9zdGFsQ29kZSI6IiIsInZhbGlkRnJvbSI6IjIwMjEtMDEtMDEifV19LCJpc3MiOiJodHRwczpcL1wvY3JpLmNvcmUuYnVpbGQuc3R1YnMuYWNjb3VudC5nb3YudWsiLCJwZXJzaXN0ZW50X3Nlc3Npb25faWQiOiIzZDc2Y2I2MS1mNzQ3LTQ0YjgtYTYwZC1iNDdiMDMwZTUzNDIiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6Imlwdi1jb3JlLXN0dWItYXdzLWJ1aWxkIiwiZ292dWtfc2lnbmluX2pvdXJuZXlfaWQiOiI5ZGM4OGVhYi03NjczLTQ4ZTctODU4ZS02NjA2ODVmOGVkYjQiLCJhdWQiOiJodHRwczpcL1wvcmV2aWV3LWhjLnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJuYmYiOjE2OTc0NjM2NzcsInNjb3BlIjoib3BlbmlkIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6XC9cL2NyaS5jb3JlLmJ1aWxkLnN0dWJzLmFjY291bnQuZ292LnVrXC9jYWxsYmFjayIsInN0YXRlIjoiOWxYbU5oT2ZiTldlTjJpQWFNcG5iOGJMY01aZzNaR0FoRzBhTmsyWGx1TSIsImV4cCI6MTY5NzQ2NzI3NywiaWF0IjoxNjk3NDYzNjc3fQ.I7dSywkY2nm9btpjXdXzHXj0UNgd2XpLdKAYv-xByWMnwoXwhN28HIgnsLj0IWjPAvhJiSMIfj4Hl1DGJ0ePhw";

describe("suraj-jwt-verifier", () => {

    xit("should decode JWT", async () => {
        const verifier = new SurajJwtVerify();
        const result = await verifier.verify(Buffer.from(jwt));
        expect(result).toBeNull();
    });

    it("should sign JWT", async () => {
        const verifier = new SurajJwtVerify();
        const result = await verifier.signJwt();
        expect(result).toBeNull();
    });

    it("should create JWE", async () => {
        const verifier = new SurajJwtVerify();
        const result = await verifier.signJwt();
        const jwe = await verifier.toJWE(result.toString());
        expect(jwe).toBeNull();
    });
});
