import { Request, Response } from 'express';
import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import { JwtPayload } from 'jsonwebtoken';
interface ICognito {
    id: string;
    client_id: string;
    user_pool: string;
}
interface IUser {
    sub: string;
    token_use: string;
    scope?: string;
    username?: string;
    email?: string;
}
interface IAuthenticatedRequest extends Request {
    user?: IUser;
}
export declare class CognitoAuth {
    static dynamo: DocumentClient;
    static poolsDictionary: {
        [key: string]: ICognito;
    };
    static cognitoAuth: (req: Request, res: Response, next: any) => Promise<void>;
    static getDataClient: (id_client: string) => Promise<void>;
    static init: (id_client: string) => Promise<{
        [key: string]: string;
    }>;
    static verifyMiddleWare: (pem: {
        [key: string]: string;
    }, req: IAuthenticatedRequest, res: Response, next: any) => void;
    static verify: (pems: {
        [key: string]: string;
    }, auth: string, id_client: string) => Promise<JwtPayload | string>;
}
export {};
//# sourceMappingURL=cognitoAuth.d.ts.map