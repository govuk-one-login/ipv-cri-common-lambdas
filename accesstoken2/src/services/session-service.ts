import { DynamoDBDocument, GetCommand, UpdateCommand, QueryCommandInput } from "@aws-sdk/lib-dynamodb";
import {SessionItem} from "../types/session-item";
// import { v4 as uuidv4 } from "uuid";
import {ConfigService} from "./config-service";

export class SessionService {
    constructor(private dynamoDbClient: DynamoDBDocument, private configService: ConfigService) {}

    public async getSession(sessionId: string | undefined): Promise<SessionItem> {
        const tableName = await this.configService.getSessionTableName();
        const getSessionCommand = new GetCommand({
            TableName: tableName,
            Key: {
                sessionId: sessionId,
            },
        });
        const result = await this.dynamoDbClient.send(getSessionCommand);
        if (!result.Item) {
            throw new Error(`Could not find session item with id: ${sessionId}`)
        }
        return result.Item as SessionItem;
    }

    public async createAuthorizationCode(sessionItem: SessionItem) {
        const tableName = await this.configService.getSessionTableName();
        sessionItem.authorizationCode = 'uuidv4()';
        sessionItem.authorizationCodeExpiryDate = this.configService.getAuthorizationCodeExpirationEpoch();

        const updateSessionCommand = new UpdateCommand({
            TableName: tableName,
            Key: { sessionId: sessionItem.sessionId },
            UpdateExpression: "SET authorizationCode=:authCode, authorizationCodeExpiryDate=:authCodeExpiry",
            ExpressionAttributeValues: {
                ":authCode": sessionItem.authorizationCode,
                ":authCodeExpiry": sessionItem.authorizationCodeExpiryDate
            }
        });
        await this.dynamoDbClient.send(updateSessionCommand);
    }

    public async getSessionByAuthorizationCode(code: string | undefined): Promise<SessionItem> {

        const tableName = await this.configService.getSessionTableName();
 
        const params : QueryCommandInput = {
            TableName: tableName,
            IndexName: 'authorizationCode-index',
            KeyConditionExpression: "authorizationCode = :authorizationCode",
            ExpressionAttributeValues: {
              ':authorizationCode': code
            }
          };

        const sessionItem  = await  this.dynamoDbClient.query(params);

        if (!sessionItem.Items){
            throw new Error(`Could not find session Item`); 
        }

        if(sessionItem.Items.length != 1){
            throw new Error(`Could not find session Item`); 
        }

        return sessionItem.Items[0] as SessionItem;
       
    }

}