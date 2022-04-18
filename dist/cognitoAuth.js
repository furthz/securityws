"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.CognitoAuth = void 0;
const aws_sdk_1 = require("aws-sdk");
const fs_1 = __importDefault(require("fs"));
const request_1 = __importDefault(require("request"));
const jwk_to_pem_1 = __importDefault(require("jwk-to-pem"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const MAX_TOKEN_AGE = 60 * 60 * 1; // 3600 seconds
const TOKEN_USE_ACCESS = 'access';
const TOKEN_USE_ID = 'id';
const HEADER_CLIENT = 'client_nexux';
const HEADER_AUTHORIZATION = 'Authorization';
const ALLOWED_TOKEN_USES = [TOKEN_USE_ACCESS, TOKEN_USE_ID];
const TABLE_CLIENT = process.env.TABLE_CLIENT;
const REGION = process.env.REGION;
class AuthError extends Error {
}
class CognitoAuth {
}
exports.CognitoAuth = CognitoAuth;
_a = CognitoAuth;
CognitoAuth.dynamo = new aws_sdk_1.DynamoDB.DocumentClient({ apiVersion: '2012-08-10', region: REGION });
CognitoAuth.poolsDictionary = {};
CognitoAuth.process = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        //obtener el valor del header client_nexux
        let id_client = req.get(HEADER_CLIENT) || 'soapros';
        const pemsDownloadProm = yield CognitoAuth.init(id_client);
        //verificación usando el archivo JWKS
        CognitoAuth.verifyMiddleWare(pemsDownloadProm, req, res, next);
    }
    catch (err) {
        console.error(err);
    }
});
CognitoAuth.getDataClient = (id_client) => __awaiter(void 0, void 0, void 0, function* () {
    var _b, _c, _d;
    let params = {
        TableName: TABLE_CLIENT,
        Key: {
            id: id_client
        },
        ProjectionExpression: "id, aws_cognito_clientapp_id, aws_cognito_userpool_id"
    };
    let cognito = {
        id: "0",
        client_id: "0",
        user_pool: "0"
    };
    try {
        //validar si ya existe en el dictionario
        if (CognitoAuth.poolsDictionary[id_client]) {
            let result = yield CognitoAuth.dynamo.get(params).promise();
            cognito.id = (_b = result.Item) === null || _b === void 0 ? void 0 : _b.id;
            cognito.client_id = (_c = result.Item) === null || _c === void 0 ? void 0 : _c.aws_cognito_clientapp_id;
            cognito.user_pool = (_d = result.Item) === null || _d === void 0 ? void 0 : _d.aws_cognito_userpool_id;
            CognitoAuth.poolsDictionary[id_client] = cognito;
        }
    }
    catch (e) {
        if (e instanceof Error) {
            throw new Error(e.message);
        }
    }
});
CognitoAuth.init = (id_client) => {
    return new Promise((resolve, reject) => {
        let existSign = fs_1.default.existsSync(`/usr/${id_client}.pem`);
        if (!existSign) {
            //cargar la data del tabla cliente
            CognitoAuth.getDataClient(id_client)
                .then((result) => {
                //ruta de donde bajar la firma publica
                let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`;
                const options = {
                    url: `${ISSUER}/.well-known/jwks.json`,
                    json: true
                };
                //descargar la firma publica JWKS
                request_1.default.get(options, (err, resp, body) => {
                    if (err) {
                        return reject(new Error("No se pudo descargar el JWKS"));
                    }
                    if (!body || !body.keys) {
                        return reject(new Error("Formato de JWSK no es el adecuado"));
                    }
                    const pems = {};
                    for (let key of body.keys) {
                        pems[key.kid] = (0, jwk_to_pem_1.default)(key);
                    }
                    fs_1.default.writeFileSync(`/usr/${id_client}.pem`, JSON.stringify(pems));
                    resolve(pems);
                });
            });
        }
        else { //leer la firma publica
            let sign = JSON.parse(fs_1.default.readFileSync(`/usr/${id_client}.pem`, "utf-8"));
            resolve(sign);
        }
    });
};
CognitoAuth.verifyMiddleWare = (pem, req, res, next) => {
    CognitoAuth.verify(pem, req.get(HEADER_AUTHORIZATION), req.get(HEADER_CLIENT))
        .then((decoded) => {
        if (typeof decoded !== "string") {
            //Asignar al Request información del usuario autenticado
            req.user = {
                sub: decoded.sub,
                token_use: decoded.token_use
            };
            if (decoded.token_use === TOKEN_USE_ACCESS) {
                // access token specific fields
                req.user.scope = decoded.scope.split(' ');
                req.user.username = decoded.username;
            }
            if (decoded.token_use === TOKEN_USE_ID) {
                // id token specific fields
                req.user.email = decoded.email;
                req.user.username = decoded['cognito:username'];
            }
        }
        console.log(`request: ${JSON.stringify(req.user)}`);
        next();
    }).catch((err) => {
        const status = (err instanceof AuthError ? 401 : 500);
        res.status(status).send(err.message || err);
    });
};
CognitoAuth.verify = (pems, auth, id_client) => {
    let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`;
    return new Promise((resolve, reject) => {
        //verificar el formato del auth en el header
        if (!auth || auth.length < 10) {
            return reject(new AuthError("Invalido o ausente Authorization header. Esperado formato \'Bearer <your_JWT_token>\'. "));
        }
        const authPrefix = auth.substring(0, 7).toLowerCase();
        if (authPrefix !== 'bearer ') {
            return reject(new AuthError('Authorization header esperdo en el formato \'Bearer <your_JWT_token>\'.'));
        }
        //Obtener el token
        const token = auth.substring(7);
        // Decodificar el token JWT para ver si hace match con la llave
        const decodedNotVerified = jsonwebtoken_1.default.decode(token, { complete: true });
        //Verificar que exista el token decodificado
        if (!decodedNotVerified) {
            return reject(new AuthError('Authorization header contiene un token inválido'));
        }
        //Validar que la KID coincida con JWSK (Que el token haya sido firmado con la llave publica del USER_POOL)
        if (!decodedNotVerified.header.kid || !pems[decodedNotVerified.header.kid]) {
            return reject(new AuthError("Authorization header contiene un token inválido"));
        }
        //Decodificar la firma con la Llave publica
        jsonwebtoken_1.default.verify(token, pems[decodedNotVerified.header.kid], { issuer: ISSUER, maxAge: MAX_TOKEN_AGE }, (err, decodeAndVerified) => {
            if (err) {
                if (err instanceof jsonwebtoken_1.default.TokenExpiredError) {
                    return reject(new AuthError("Authorization header contiene un JWT que ha expirado en: " + err.expiredAt.toISOString()));
                }
                else {
                    return reject(new AuthError("Authorization header contiene un JWT inválido"));
                }
            }
            //La firma coincide y sabemos que el token proviene de una instancia de Cognito
            //verificar el Claims
            if (typeof decodeAndVerified !== "string") {
                //validar que token_use = 'access'
                if (ALLOWED_TOKEN_USES.indexOf(decodeAndVerified.token_use) === -1) {
                    return reject(new AuthError('Authorization header contiene un token inválido.'));
                }
                //validar que client_id corresponda con el CLIENT_ID del USER_POOL
                const clientId = (decodeAndVerified.aud || decodeAndVerified.client_id);
                if (clientId !== CognitoAuth.poolsDictionary[id_client].client_id) {
                    return reject(new AuthError('Authorization header contiene un token inválido.')); // don't return detailed info to the caller
                }
            }
            return resolve(decodeAndVerified);
        });
    });
};
//export default cognitoAuth
