import { Request, Response } from 'express';
export declare class CognitoAuth {
    private static dynamo;
    private static poolsDictionary;
    static process: (req: Request, res: Response, next: any) => Promise<void>;
    private static getDataClient;
    private static init;
    private static verifyMiddleWare;
    private static verify;
}
//# sourceMappingURL=cognitoAuth.d.ts.map