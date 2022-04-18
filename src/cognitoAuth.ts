
import { Request, Response } from 'express';
import { DynamoDB } from "aws-sdk";
import fs from 'fs'
import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import request from 'request'
import jwkToPem from 'jwk-to-pem'
import jwt, { JwtPayload } from 'jsonwebtoken'

const MAX_TOKEN_AGE = 60 * 60 * 1 // 3600 seconds

const TOKEN_USE_ACCESS = 'access'
const TOKEN_USE_ID = 'id'
const HEADER_CLIENT = 'client_nexux'
const HEADER_AUTHORIZATION = 'Authorization'
const ALLOWED_TOKEN_USES = [TOKEN_USE_ACCESS, TOKEN_USE_ID]
const TABLE_CLIENT = process.env.TABLE_CLIENT
const REGION = process.env.REGION

class AuthError extends Error { }

interface ICognito {
    id: string,
    client_id: string,
    user_pool: string
}

interface IUser {
    sub: string,
    token_use: string,
    scope?: string,
    username?: string,
    email?: string
}

interface IAuthenticatedRequest extends Request {
    user?: IUser
}

export class CognitoAuth {

    private static dynamo: DocumentClient = new DynamoDB.DocumentClient({ apiVersion: '2012-08-10', region: REGION })
    private static poolsDictionary: { [key: string]: ICognito } = {}

    public static process = async (req: Request, res: Response, next: any) => {
        try {
            //obtener el valor del header client_nexux
            let id_client = req.get(HEADER_CLIENT) || 'soapros'

            const pemsDownloadProm: { [key: string]: string } = await CognitoAuth.init(id_client)
            //verificación usando el archivo JWKS
            CognitoAuth.verifyMiddleWare(pemsDownloadProm, req, res, next)
        } catch (err) {
            console.error(err)
        }
    }

    private static getDataClient = async (id_client: string) => {

        let params: DynamoDB.DocumentClient.GetItemInput = {
            TableName: TABLE_CLIENT!,
            Key: {
                id: id_client
            },
            ProjectionExpression: "id, aws_cognito_clientapp_id, aws_cognito_userpool_id"
        }

        let cognito: ICognito = {
            id: "0",
            client_id: "0",
            user_pool: "0"
        }

        try {
            //validar si ya existe en el dictionario
            if (CognitoAuth.poolsDictionary[id_client]) {
                let result = await CognitoAuth.dynamo.get(params).promise()
                cognito.id = result.Item?.id
                cognito.client_id = result.Item?.aws_cognito_clientapp_id
                cognito.user_pool = result.Item?.aws_cognito_userpool_id
                CognitoAuth.poolsDictionary[id_client] = cognito
            }

        } catch (e) {
            if (e instanceof Error) {
                throw new Error(e.message)
            }

        }
    }

    private static init = (id_client: string) => {
        return new Promise<{ [key: string]: string }>((resolve, reject) => {
            let existSign = fs.existsSync(`/usr/${id_client}.pem`)

            if (!existSign) {
                //cargar la data del tabla cliente
                CognitoAuth.getDataClient(id_client)
                    .then((result) => {
                        //ruta de donde bajar la firma publica
                        let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`
                        const options = {
                            url: `${ISSUER}/.well-known/jwks.json`,
                            json: true
                        }

                        //descargar la firma publica JWKS
                        request.get(options, (err, resp, body) => {
                            if (err) {
                                return reject(new Error("No se pudo descargar el JWKS"))
                            }
                            if (!body || !body.keys) {
                                return reject(new Error("Formato de JWSK no es el adecuado"))
                            }
                            const pems: { [key: string]: string } = {}
                            for (let key of body.keys) {
                                pems[key.kid] = jwkToPem(key)
                            }
                            fs.writeFileSync(`/usr/${id_client}.pem`, JSON.stringify(pems))
                            resolve(pems)
                        })
                    })

            } else { //leer la firma publica
                let sign = JSON.parse(fs.readFileSync(`/usr/${id_client}.pem`, "utf-8"))
                resolve(sign)
            }
        })
    }

    private static verifyMiddleWare = (pem: { [key: string]: string }, req: IAuthenticatedRequest, res: Response, next: any) => {

        CognitoAuth.verify(pem, req.get(HEADER_AUTHORIZATION)!, req.get(HEADER_CLIENT)!)
            .then((decoded) => {

                if (typeof decoded !== "string") {
                    //Asignar al Request información del usuario autenticado
                    req.user = {
                        sub: decoded.sub!,
                        token_use: decoded.token_use
                    }

                    if (decoded.token_use === TOKEN_USE_ACCESS) {
                        // access token specific fields
                        req.user!.scope = decoded.scope.split(' ')
                        req.user!.username = decoded.username
                    }

                    if (decoded.token_use === TOKEN_USE_ID) {
                        // id token specific fields
                        req.user!.email = decoded.email
                        req.user!.username = decoded['cognito:username']
                    }

                }
                console.log(`request: ${JSON.stringify(req.user)}`)
                next()

            }).catch((err) => {
                const status = (err instanceof AuthError ? 401 : 500)
                res.status(status).send(err.message || err)
            })
    }

    private static verify = (pems: { [key: string]: string }, auth: string, id_client: string): Promise<JwtPayload | string> => {

        let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`

        return new Promise((resolve, reject) => {

            //verificar el formato del auth en el header
            if (!auth || auth.length < 10) {
                return reject(new AuthError("Invalido o ausente Authorization header. Esperado formato \'Bearer <your_JWT_token>\'. "))
            }

            const authPrefix = auth.substring(0, 7).toLowerCase()
            if (authPrefix !== 'bearer ') {
                return reject(new AuthError('Authorization header esperdo en el formato \'Bearer <your_JWT_token>\'.'))
            }

            //Obtener el token
            const token = auth.substring(7)

            // Decodificar el token JWT para ver si hace match con la llave
            const decodedNotVerified = jwt.decode(token, { complete: true })

            //Verificar que exista el token decodificado
            if (!decodedNotVerified) {
                return reject(new AuthError('Authorization header contiene un token inválido'))
            }

            //Validar que la KID coincida con JWSK (Que el token haya sido firmado con la llave publica del USER_POOL)
            if (!decodedNotVerified.header.kid || !pems[decodedNotVerified.header.kid]) {
                return reject(new AuthError("Authorization header contiene un token inválido"))
            }

            //Decodificar la firma con la Llave publica
            jwt.verify(token, pems[decodedNotVerified.header.kid], { issuer: ISSUER, maxAge: MAX_TOKEN_AGE }, (err, decodeAndVerified) => {

                if (err) {
                    if (err instanceof jwt.TokenExpiredError) {
                        return reject(new AuthError("Authorization header contiene un JWT que ha expirado en: " + err.expiredAt.toISOString()))
                    } else {
                        return reject(new AuthError("Authorization header contiene un JWT inválido"))
                    }
                }

                //La firma coincide y sabemos que el token proviene de una instancia de Cognito
                //verificar el Claims

                if (typeof decodeAndVerified !== "string") {
                    //validar que token_use = 'access'
                    if (ALLOWED_TOKEN_USES.indexOf(decodeAndVerified!.token_use) === -1) {
                        return reject(new AuthError('Authorization header contiene un token inválido.'))
                    }
                    //validar que client_id corresponda con el CLIENT_ID del USER_POOL
                    const clientId = (decodeAndVerified!.aud || decodeAndVerified!.client_id)
                    if (clientId !== CognitoAuth.poolsDictionary[id_client].client_id) {
                        return reject(new AuthError('Authorization header contiene un token inválido.')) // don't return detailed info to the caller
                    }
                }

                return resolve(decodeAndVerified!)
            })

        })
    }
}


//export default cognitoAuth