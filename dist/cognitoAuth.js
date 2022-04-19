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
const nexuxlog_1 = require("nexuxlog");
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
/**
 * Método principal para realizar la validación de los headers: Authorization y client_nexux
 * @param req Request
 * @param res Response
 * @param next Siguiente función a procesar de pasar la validación
 */
CognitoAuth.process = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        nexuxlog_1.Logger.message(nexuxlog_1.Level.info, { action: "validacion", id: req.id }, "req.id.toString()", "validacion del header");
        //obtener el valor del header client_nexux
        let id_client = req.get(HEADER_CLIENT) || 'soapros';
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, req.body, "req.id.toString()", "ingreso a la validacion");
        const pemsDownloadProm = yield CognitoAuth.init(id_client, "req.id.toString()");
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, pemsDownloadProm, "req.id.toString()", "Llave publica");
        //verificación usando el archivo JWKS
        CognitoAuth.verifyMiddleWare(pemsDownloadProm, req, res, next);
    }
    catch (err) {
        if (err instanceof Error) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, "req.id.toString()", err.message);
        }
    }
});
/**
 * Método para buscar en la tabla Cliente, la información del Pool y ClientId de Cognito para un determinado cliente
 * @param id_client Id del cliente
 * @param transacion_id Id de la transacción
 */
CognitoAuth.getDataClient = (id_client, transacion_id) => __awaiter(void 0, void 0, void 0, function* () {
    var _b, _c, _d;
    let params = {
        TableName: TABLE_CLIENT,
        Key: {
            id: id_client
        },
        ProjectionExpression: "id, aws_cognito_clientapp_id, aws_cognito_userpool_id"
    };
    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, params, transacion_id, "parametros de busqueda en la tabla cliente");
    let cognito = {
        id: "0",
        client_id: "0",
        user_pool: "0"
    };
    try {
        //validar si ya existe en el dictionario
        if (!CognitoAuth.poolsDictionary[id_client]) {
            let result = yield CognitoAuth.dynamo.get(params).promise();
            if (Object.keys(result).length == 0) {
                throw new Error(`El cliente: ${id_client} no existe`);
            }
            cognito.id = (_b = result.Item) === null || _b === void 0 ? void 0 : _b.id;
            cognito.client_id = (_c = result.Item) === null || _c === void 0 ? void 0 : _c.aws_cognito_clientapp_id;
            cognito.user_pool = (_d = result.Item) === null || _d === void 0 ? void 0 : _d.aws_cognito_userpool_id;
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, result, transacion_id, "resultado en la tabla cliente");
            CognitoAuth.poolsDictionary[id_client] = cognito;
        }
    }
    catch (e) {
        if (e instanceof Error) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, e, transacion_id, "Error en la busqueda de la BD");
            throw new Error(e.message);
        }
    }
});
/**
 * Método que inicializa la descarga de la Firma pública para el cliente solicitado
 * @param id_client Id del cliente
 * @param transacion_id Id de la transaccion
 * @returns
 */
CognitoAuth.init = (id_client, transacion_id) => {
    return new Promise((resolve, reject) => {
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { id_client }, transacion_id, "Descarga de la firma publica");
        let existSign = fs_1.default.existsSync(`/usr/${id_client}.pem`);
        if (!existSign) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { id_client }, transacion_id, "Primera descarga de la firma publica");
            //cargar la data del tabla cliente
            CognitoAuth.getDataClient(id_client, transacion_id)
                .then((result) => {
                nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { result }, transacion_id, "se obtuvo la información del id_client");
                //ruta de donde bajar la firma publica
                let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`;
                const options = {
                    url: `${ISSUER}/.well-known/jwks.json`,
                    json: true
                };
                nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { options }, transacion_id, "Link de descarga");
                //descargar la firma publica JWKS
                request_1.default.get(options, (err, resp, body) => {
                    if (err) {
                        nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, transacion_id, err);
                        return reject(new Error("No se pudo descargar el JWKS"));
                    }
                    if (!body || !body.keys) {
                        nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, transacion_id, "Formato de JWSK");
                        return reject(new Error("Formato de JWSK no es el adecuado"));
                    }
                    const pems = {};
                    for (let key of body.keys) {
                        pems[key.kid] = (0, jwk_to_pem_1.default)(key);
                    }
                    fs_1.default.writeFileSync(`/usr/${id_client}.pem`, JSON.stringify(pems));
                    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { file: `/usr/${id_client}.pem` }, transacion_id, "Firma publica guardada");
                    resolve(pems);
                });
            }).catch((error) => {
                if (error instanceof Error) {
                    nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, transacion_id, "GetCliente");
                    reject(new Error(error.message));
                }
            });
        }
        else { //leer la firma publica
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { file: `/usr/${id_client}.pem` }, transacion_id, "Firma publica leída");
            let sign = JSON.parse(fs_1.default.readFileSync(`/usr/${id_client}.pem`, "utf-8"));
            resolve(sign);
        }
    });
};
/**
 * Validar el token y añadir la información del usuario en el request si la validación es exitosa
 * @param pem Llave publica
 * @param req Request
 * @param res Response
 * @param next Siguiente Función a procesar
 */
CognitoAuth.verifyMiddleWare = (pem, req, res, next) => {
    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { Auth: req.get(HEADER_AUTHORIZATION), client: req.get(HEADER_CLIENT) }, "req.id.toString()", "Función verifyMiddleWare");
    CognitoAuth.verify(pem, req.get(HEADER_AUTHORIZATION), req.get(HEADER_CLIENT), "req.id.toString()")
        .then((decoded) => {
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { Auth: req.get(HEADER_AUTHORIZATION), client: req.get(HEADER_CLIENT) }, "req.id.toString()", "Verificación del token");
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
            nexuxlog_1.Logger.message(nexuxlog_1.Level.info, { user: req.user }, "req.id.toString()", "Informacion del usuario");
        }
        next();
    }).catch((err) => {
        if (err instanceof Error) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, "req.id.toString()", err.message);
            const status = (err instanceof AuthError ? 401 : 500);
            res.status(status).send(err.message || err);
        }
    });
};
/**
 * Método para validar el token
 * @param pems Llave pública
 * @param auth Token de Authorization
 * @param id_client ID del cliente
 * @param transacion_id ID de la transacción
 * @returns
 */
CognitoAuth.verify = (pems, auth, id_client, transacion_id) => {
    let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`;
    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { ISSUER }, transacion_id, "verificación del token");
    return new Promise((resolve, reject) => {
        //verificar el formato del auth en el header
        if (!auth || auth.length < 10) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "Formato no esperado, menor a 10 digitos");
            return reject(new AuthError("Invalido o ausente Authorization header. Esperado formato \'Bearer <your_JWT_token>\'. "));
        }
        const authPrefix = auth.substring(0, 7).toLowerCase();
        if (authPrefix !== 'bearer ') {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "El token no tiene el prefijo Bearer");
            return reject(new AuthError('Authorization header esperdo en el formato \'Bearer <your_JWT_token>\'.'));
        }
        //Obtener el token
        const token = auth.substring(7);
        // Decodificar el token JWT para ver si hace match con la llave
        const decodedNotVerified = jsonwebtoken_1.default.decode(token, { complete: true });
        //Verificar que exista el token decodificado
        if (!decodedNotVerified) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "Authorization header contiene un token invalido");
            return reject(new AuthError('Authorization header contiene un token inválido'));
        }
        //Validar que la KID coincida con JWSK (Que el token haya sido firmado con la llave publica del USER_POOL)
        if (!decodedNotVerified.header.kid || !pems[decodedNotVerified.header.kid]) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "el KID no coincide");
            return reject(new AuthError("Authorization header contiene un token inválido"));
        }
        //Decodificar la firma con la Llave publica
        jsonwebtoken_1.default.verify(token, pems[decodedNotVerified.header.kid], { issuer: ISSUER, maxAge: MAX_TOKEN_AGE }, (err, decodeAndVerified) => {
            if (err) {
                if (err instanceof jsonwebtoken_1.default.TokenExpiredError) {
                    nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "Authorzation header expirado");
                    return reject(new AuthError("Authorization header contiene un JWT que ha expirado en: " + err.expiredAt.toISOString()));
                }
                else {
                    nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "JWT inválido");
                    return reject(new AuthError("Authorization header contiene un JWT inválido"));
                }
            }
            //La firma coincide y sabemos que el token proviene de una instancia de Cognito
            //verificar el Claims
            if (typeof decodeAndVerified !== "string") {
                //validar que token_use = 'access'
                if (ALLOWED_TOKEN_USES.indexOf(decodeAndVerified.token_use) === -1) {
                    nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "Authorization contiene token inválido no ACCESS");
                    return reject(new AuthError('Authorization header contiene un token inválido.'));
                }
                //validar que client_id corresponda con el CLIENT_ID del USER_POOL
                const clientId = (decodeAndVerified.aud || decodeAndVerified.client_id);
                if (clientId !== CognitoAuth.poolsDictionary[id_client].client_id) {
                    nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "Authozation contine token inválido CLIENT_ID no coincide");
                    return reject(new AuthError('Authorization header contiene un token inválido.')); // don't return detailed info to the caller
                }
            }
            return resolve(decodeAndVerified);
        });
    });
};
//export default cognitoAuth
