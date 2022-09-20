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
const uuid_1 = require("uuid");
const jwk_to_pem_1 = __importDefault(require("jwk-to-pem"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const nexuxlog_1 = require("nexuxlog");
const MAX_TOKEN_AGE = 60 * 60 * 1; // 3600 seconds
const TOKEN_USE_ACCESS = 'access';
const TOKEN_USE_ID = 'id';
const HEADER_CLIENT = 'client_nexux';
const HEADER_AUTHORIZATION = 'Authorization';
const ALLOWED_TOKEN_USES = [TOKEN_USE_ACCESS, TOKEN_USE_ID];
if (process.env.STAGE === 'test') {
    process.env.STAGE = 'qa';
}
let stage = process.env.STAGE || '';
process.env.STAGE = (stage.toLowerCase() === 'test' ? 'qa' : stage).toLowerCase();
const GLOBAL_STAGE = process.env.STAGE;
const TABLE_CLIENT = process.env.TABLE_CLIENT || 'capacniam-cliente-' + GLOBAL_STAGE;
const REGION = process.env.REGION;
class AuthError extends Error {
}
function getClientesTemporal() {
    const map = new Map();
    if (GLOBAL_STAGE === 'dev' || GLOBAL_STAGE === 'qa' || GLOBAL_STAGE === 'prd') {
        map.set('tdp', {
            id: 'tdp',
            aws_cognito_clientapp_id: '4kpq25sb27tutk54v0j7if0jpf',
            aws_cognito_userpool_id: 'us-east-1_5LjA8Pbem'
        });
        map.set('bn_ripley', {
            id: 'bn_ripley',
            aws_cognito_clientapp_id: '434gcllmokbpmj9qkhl37geh8v',
            aws_cognito_userpool_id: 'us-east-1_KpauCTxDx'
        });
    }
    return map;
}
/**
 * Clase para realizar la validación de seguridad de acceso a partir de un JWT
 */
class CognitoAuth {
}
exports.CognitoAuth = CognitoAuth;
_a = CognitoAuth;
CognitoAuth.dynamo = new aws_sdk_1.DynamoDB.DocumentClient({ apiVersion: '2012-08-10', region: REGION });
CognitoAuth.poolsDictionary = {};
// POR AHORA, VOY A ESCRIBIR LOS CLIENTES EN DURO, HASTA QUE EXISTA UN SERVICIO CAPAZ DE RESPONDER
// CON LA INFO DE CLIENTES DESDE WEAVER 3 O ALGO ASI
CognitoAuth.clientes = getClientesTemporal();
CognitoAuth.processHapi = (request, h) => __awaiter(void 0, void 0, void 0, function* () {
    const id = (0, uuid_1.v4)();
    let result = null;
    request.headers[HEADER_AUTHORIZATION] = request.headers[HEADER_AUTHORIZATION] || request.headers['authorization'];
    // const authorizationHeader = request.headers['Authorization'] || request.headers['authorization']
    try {
        if (!request.headers[HEADER_AUTHORIZATION]) {
            throw new AuthError("Es necesario el Header de 'Authorization'");
        }
        if (!request.headers[HEADER_CLIENT]) {
            throw new AuthError("Es necesario el Header de 'client_nexux'");
        }
        //obtener el valor del header client_nexux
        let id_client = request.headers[HEADER_CLIENT] || 'soapros';
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, request.raw, id, "ingreso a la validacion");
        const pemsDownloadProm = yield CognitoAuth.init(id_client, id);
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, pemsDownloadProm, id, "Llave publica");
        //verificación usando el archivo JWKS
        const app = request.app;
        app.id = id;
        request.app = app;
        yield CognitoAuth.hapiVerifyToken(pemsDownloadProm, request, h);
    }
    catch (err) {
        nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, id, err.message);
        result = { code: 500, message: err.message };
        if (err instanceof AuthError) {
            result.code = 401;
        }
    }
    return result;
});
/**
 * Método principal para realizar la validación de los headers: Authorization y client_nexux
 * @param req Request
 * @param res Response
 * @param next Siguiente función a procesar de pasar la validación
 */
CognitoAuth.process = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _b, _c, _d, _e, _f;
    try {
        nexuxlog_1.Logger.message(nexuxlog_1.Level.info, { action: "validacion", id: req.id }, (_b = req.id) === null || _b === void 0 ? void 0 : _b.toString(), "validacion del header");
        if (!req.get(HEADER_AUTHORIZATION) || !req.get(HEADER_CLIENT)) {
            throw new AuthError("Es necesario los Headers de Authorization y client_nexux");
        }
        //obtener el valor del header client_nexux
        let id_client = req.get(HEADER_CLIENT) || 'soapros';
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, req.body, (_c = req.id) === null || _c === void 0 ? void 0 : _c.toString(), "ingreso a la validacion");
        const pemsDownloadProm = yield CognitoAuth.init(id_client, (_d = req.id) === null || _d === void 0 ? void 0 : _d.toString());
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, pemsDownloadProm, (_e = req.id) === null || _e === void 0 ? void 0 : _e.toString(), "Llave publica");
        //verificación usando el archivo JWKS
        CognitoAuth.verifyMiddleWare(pemsDownloadProm, req, res, next);
    }
    catch (err) {
        if (err instanceof Error) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, (_f = req.id) === null || _f === void 0 ? void 0 : _f.toString(), err.message);
            const status = (err instanceof AuthError ? 401 : 500);
            res.status(status).json({ message: err.message || err });
        }
    }
});
/**
 * Método para buscar en la tabla Cliente, la información del Pool y ClientId de Cognito para un determinado cliente
 * @param id_client Id del cliente
 * @param transacion_id Id de la transacción
 */
CognitoAuth.getDataClient = (id_client, transacion_id) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        // let params: DynamoDB.DocumentClient.GetItemInput = {
        //   TableName: TABLE_CLIENT!,
        //   Key: {
        //     id: id_client
        //   },
        //   ProjectionExpression: "id, aws_cognito_clientapp_id, aws_cognito_userpool_id"
        // }
        // Logger.message(Level.debug, params, transacion_id, "parametros de busqueda en la tabla cliente")
        let cognito = {
            id: "0",
            client_id: "0",
            user_pool: "0"
        };
        //validar si ya existe en el dictionario
        if (!CognitoAuth.poolsDictionary[id_client]) {
            console.log('Buscando cliente en pool');
            const oCliente = CognitoAuth.clientes.get(id_client);
            if (!oCliente) {
                throw new AuthError(`El cliente: ${id_client} no existe`);
            }
            // let result = await CognitoAuth.dynamo.get(params).promise()
            // if (Object.keys(result).length == 0) {
            // }
            cognito.id = oCliente.id;
            cognito.client_id = oCliente.aws_cognito_clientapp_id;
            cognito.user_pool = oCliente.aws_cognito_userpool_id;
            CognitoAuth.poolsDictionary[id_client] = cognito;
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { oCliente, pool: CognitoAuth.poolsDictionary }, transacion_id, "resultado en la tabla cliente");
        }
        else {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, CognitoAuth.poolsDictionary, transacion_id, "Datos Cargados");
        }
    }
    catch (e) {
        if (e instanceof Error) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, e, transacion_id, "Error en la busqueda de la BD");
            throw new AuthError(e.message);
        }
    }
});
CognitoAuth.requestGetAsync = (options) => __awaiter(void 0, void 0, void 0, function* () {
    return new Promise(function (resolve, reject) {
        request_1.default.get(options, (err, resp, body) => {
            if (err) {
                return reject(err);
            }
            resolve({ response: resp, body: body });
        });
    });
});
/**
 * Método que inicializa la descarga de la Firma pública para el cliente solicitado
 * @param id_client Id del cliente
 * @param transacion_id Id de la transaccion
 * @returns
 */
CognitoAuth.init = (id_client, transacion_id) => __awaiter(void 0, void 0, void 0, function* () {
    // return new Promise<{ [key: string]: string }>((resolve, reject) => {
    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { id_client }, transacion_id, "Descarga de la firma publica");
    let existSign = fs_1.default.existsSync(`/usr/${id_client}.pem`);
    // Debe funcionar de la misma forma, intentando cargar en memoria los clientes en un key value
    let output = {};
    if (!existSign || !CognitoAuth.poolsDictionary[id_client]) {
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { id_client }, transacion_id, "Primera descarga de la firma publica");
        //cargar la data del tabla cliente
        try {
            const result = yield CognitoAuth.getDataClient(id_client, transacion_id);
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { result }, transacion_id, "se obtuvo la información del id_client");
            //ruta de donde bajar la firma publica
            let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`;
            const options = {
                url: `${ISSUER}/.well-known/jwks.json`,
                json: true
            };
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { options }, transacion_id, "Link de descarga");
            //descargar la firma publica JWKS
            try {
                const { body } = yield CognitoAuth.requestGetAsync(options); //, (err, resp, body) => {
                if (!body || !body.keys) {
                    nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, transacion_id, "Formato de JWSK");
                    throw new Error("Formato de JWSK no es el adecuado");
                }
                const pems = {};
                for (let key of body.keys) {
                    pems[key.kid] = (0, jwk_to_pem_1.default)(key);
                }
                yield fs_1.default.promises.writeFile(`/usr/${id_client}.pem`, JSON.stringify(pems));
                nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { file: `/usr/${id_client}.pem` }, transacion_id, "Firma publica guardada");
                // resolve(pems)
                output = pems;
            }
            catch (err) {
                nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, transacion_id, err);
                throw new Error("No se pudo descargar el JWKS");
            }
            // if (err) {
            //   Logger.message(Level.error, {}, transacion_id, err)
            //   return reject(new Error("No se pudo descargar el JWKS"))
            // }
            //})
        }
        catch (error) {
            if (error instanceof Error) {
                nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, transacion_id, "GetCliente");
                if (error instanceof AuthError) {
                    throw new AuthError(error.message);
                }
                else {
                    throw new Error(error.message);
                }
            }
        }
    }
    else { //leer la firma publica
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { file: `/usr/${id_client}.pem` }, transacion_id, "Firma publica leída");
        let sign = JSON.parse(yield fs_1.default.promises.readFile(`/usr/${id_client}.pem`, "utf-8"));
        output = sign;
        // resolve(sign)
    }
    // })
    return output;
});
CognitoAuth.hapiVerifyToken = (pem, request, h) => __awaiter(void 0, void 0, void 0, function* () {
    const headerAuth = request.headers[HEADER_AUTHORIZATION];
    const headerClient = request.headers[HEADER_CLIENT];
    const app = request.app;
    const id = app.id;
    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { Auth: headerAuth, client: headerClient }, id, "Función verifyMiddleWare");
    const decoded = yield CognitoAuth.verify(pem, headerAuth, headerClient, id);
    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { Auth: headerAuth, client: headerClient }, id, "Verificación del token");
    if (typeof decoded !== "string") {
        //Asignar al Request información del usuario autenticado
        const app = request.app;
        app.user = {
            sub: decoded.sub,
            token_use: decoded.token_use
        };
        if (decoded.token_use === TOKEN_USE_ACCESS) {
            // access token specific fields
            app.user.scope = decoded.scope.split(' ');
            app.user.username = decoded.username;
        }
        if (decoded.token_use === TOKEN_USE_ID) {
            // id token specific fields
            app.user.email = decoded.email;
            app.user.username = decoded['cognito:username'];
        }
        request.app = app;
        nexuxlog_1.Logger.message(nexuxlog_1.Level.info, { user: app.user }, id, "Informacion del usuario");
    }
});
/**
 * Validar el token y añadir la información del usuario en el request si la validación es exitosa
 * @param pem Llave publica
 * @param req Request
 * @param res Response
 * @param next Siguiente Función a procesar
 */
CognitoAuth.verifyMiddleWare = (pem, req, res, next) => {
    var _b, _c;
    nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { Auth: req.get(HEADER_AUTHORIZATION), client: req.get(HEADER_CLIENT) }, (_b = req.id) === null || _b === void 0 ? void 0 : _b.toString(), "Función verifyMiddleWare");
    CognitoAuth.verify(pem, req.get(HEADER_AUTHORIZATION), req.get(HEADER_CLIENT), (_c = req.id) === null || _c === void 0 ? void 0 : _c.toString())
        .then((decoded) => {
        var _b, _c;
        nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { Auth: req.get(HEADER_AUTHORIZATION), client: req.get(HEADER_CLIENT) }, (_b = req.id) === null || _b === void 0 ? void 0 : _b.toString(), "Verificación del token");
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
            nexuxlog_1.Logger.message(nexuxlog_1.Level.info, { user: req.user }, (_c = req.id) === null || _c === void 0 ? void 0 : _c.toString(), "Informacion del usuario");
        }
        next();
    }).catch((err) => {
        var _b;
        if (err instanceof Error) {
            nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, (_b = req.id) === null || _b === void 0 ? void 0 : _b.toString(), err.message);
            const status = (err instanceof AuthError ? 401 : 500);
            res.status(status).json({ message: err.message || err });
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
    return new Promise((resolve, reject) => {
        try {
            let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`;
            nexuxlog_1.Logger.message(nexuxlog_1.Level.debug, { ISSUER }, transacion_id, "verificación del token");
            //verificar el formato del auth en el header
            if (!auth || auth.length < 10) {
                nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "Formato no esperado, menor a 10 digitos");
                return reject(new AuthError("Inválido o ausente Authorization header. Esperado formato \'Bearer <your_JWT_token>\'. "));
            }
            const authPrefix = auth.substring(0, 7).toLowerCase();
            if (authPrefix !== 'bearer ') {
                nexuxlog_1.Logger.message(nexuxlog_1.Level.error, { id_client, auth }, transacion_id, "El token no tiene el prefijo Bearer");
                return reject(new AuthError('Authorization header esperado en el formato \'Bearer <your_JWT_token>\'.'));
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
        }
        catch (e) {
            if (e instanceof Error) {
                nexuxlog_1.Logger.message(nexuxlog_1.Level.error, {}, transacion_id, e.message);
                return reject(new Error(e.message));
            }
        }
    });
};
