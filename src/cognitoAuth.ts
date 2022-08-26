import * as Hapi from '@hapi/hapi'
import { Request, Response, Handler, NextFunction } from 'express';
import { DynamoDB } from "aws-sdk";
import fs from 'fs'
import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import request from 'request'
import { v4 } from 'uuid'
import jwkToPem from 'jwk-to-pem'
import jwt, { JwtPayload } from 'jsonwebtoken'
import { Level, Logger } from 'nexuxlog';


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

export type HapiCustomAuthError = {
  code: number
  message: string
}

/**
 * Clase para realizar la validación de seguridad de acceso a partir de un JWT
 */
export class CognitoAuth {

  private static dynamo: DocumentClient = new DynamoDB.DocumentClient({ apiVersion: '2012-08-10', region: REGION })
  private static poolsDictionary: { [key: string]: ICognito } = {}

  public static processHapi = async (request: Hapi.Request, h: Hapi.ResponseToolkit): Promise<HapiCustomAuthError | null> => {
    const id = v4()
    let result = null
    try {
      if (!request.headers[HEADER_AUTHORIZATION] || !request.headers[HEADER_CLIENT]) {
        throw new AuthError("Es necesario los Headers de Authorization y client_nexux")
      }
      //obtener el valor del header client_nexux
      let id_client = request.headers[HEADER_CLIENT] || 'soapros'
      Logger.message(Level.debug, request.raw, id, "ingreso a la validacion")

      const pemsDownloadProm: { [key: string]: string } = await CognitoAuth.init(id_client, id)
      Logger.message(Level.debug, pemsDownloadProm, id, "Llave publica")
      //verificación usando el archivo JWKS
      const app = request.app as any
      app.id = id
      request.app = app
      await CognitoAuth.hapiVerifyToken(pemsDownloadProm, request, h)
    } catch (err) {
      Logger.message(Level.error, {}, id, (err as any).message)
      result = { code: 500, message: (err as any).message }
      if (err instanceof AuthError) {
        result.code = 401
      }
    }
    return result
  }
  /**
   * Método principal para realizar la validación de los headers: Authorization y client_nexux
   * @param req Request
   * @param res Response
   * @param next Siguiente función a procesar de pasar la validación
   */
  public static process: Handler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      Logger.message(Level.info, { action: "validacion", id: req.id }, req.id?.toString(), "validacion del header")

      if (!req.get(HEADER_AUTHORIZATION) || !req.get(HEADER_CLIENT)) {
        throw new AuthError("Es necesario los Headers de Authorization y client_nexux")
      }
      //obtener el valor del header client_nexux
      let id_client = req.get(HEADER_CLIENT) || 'soapros'
      Logger.message(Level.debug, req.body, req.id?.toString(), "ingreso a la validacion")

      const pemsDownloadProm: { [key: string]: string } = await CognitoAuth.init(id_client, req.id?.toString())
      Logger.message(Level.debug, pemsDownloadProm, req.id?.toString(), "Llave publica")

      //verificación usando el archivo JWKS
      CognitoAuth.verifyMiddleWare(pemsDownloadProm, req, res, next)
    } catch (err) {
      if (err instanceof Error) {
        Logger.message(Level.error, {}, req.id?.toString(), err.message)
        const status = (err instanceof AuthError ? 401 : 500)
        res.status(status).json({ message: err.message || err })
      }
    }
  }

  /**
   * Método para buscar en la tabla Cliente, la información del Pool y ClientId de Cognito para un determinado cliente
   * @param id_client Id del cliente
   * @param transacion_id Id de la transacción
   */
  private static getDataClient = async (id_client: string, transacion_id: string) => {

    try {

      let params: DynamoDB.DocumentClient.GetItemInput = {
        TableName: TABLE_CLIENT!,
        Key: {
          id: id_client
        },
        ProjectionExpression: "id, aws_cognito_clientapp_id, aws_cognito_userpool_id"
      }
      Logger.message(Level.debug, params, transacion_id, "parametros de busqueda en la tabla cliente")

      let cognito: ICognito = {
        id: "0",
        client_id: "0",
        user_pool: "0"
      }

      //validar si ya existe en el dictionario
      if (!CognitoAuth.poolsDictionary[id_client]) {
        let result = await CognitoAuth.dynamo.get(params).promise()

        if (Object.keys(result).length == 0) {
          throw new AuthError(`El cliente: ${id_client} no existe`)
        }

        cognito.id = result.Item?.id
        cognito.client_id = result.Item?.aws_cognito_clientapp_id
        cognito.user_pool = result.Item?.aws_cognito_userpool_id

        CognitoAuth.poolsDictionary[id_client] = cognito
        Logger.message(Level.debug, { result, pool: CognitoAuth.poolsDictionary }, transacion_id, "resultado en la tabla cliente")

      } else {
        Logger.message(Level.debug, CognitoAuth.poolsDictionary, transacion_id, "Datos Cargados")
      }

    } catch (e) {
      if (e instanceof Error) {
        Logger.message(Level.error, e, transacion_id, "Error en la busqueda de la BD")
        throw new AuthError(e.message)
      }

    }
  }

  /**
   * Método que inicializa la descarga de la Firma pública para el cliente solicitado
   * @param id_client Id del cliente
   * @param transacion_id Id de la transaccion
   * @returns
   */
  private static init = (id_client: string, transacion_id: string) => {
    return new Promise<{ [key: string]: string }>((resolve, reject) => {
      Logger.message(Level.debug, { id_client }, transacion_id, "Descarga de la firma publica")
      let existSign = fs.existsSync(`/usr/${id_client}.pem`)

      if (!existSign || !CognitoAuth.poolsDictionary[id_client]) {
        Logger.message(Level.debug, { id_client }, transacion_id, "Primera descarga de la firma publica")

        //cargar la data del tabla cliente
        CognitoAuth.getDataClient(id_client, transacion_id)
          .then((result) => {
            Logger.message(Level.debug, { result }, transacion_id, "se obtuvo la información del id_client")

            //ruta de donde bajar la firma publica
            let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`
            const options = {
              url: `${ISSUER}/.well-known/jwks.json`,
              json: true
            }
            Logger.message(Level.debug, { options }, transacion_id, "Link de descarga")

            //descargar la firma publica JWKS
            request.get(options, (err, resp, body) => {
              if (err) {
                Logger.message(Level.error, {}, transacion_id, err)
                return reject(new Error("No se pudo descargar el JWKS"))
              }
              if (!body || !body.keys) {
                Logger.message(Level.error, {}, transacion_id, "Formato de JWSK")
                return reject(new Error("Formato de JWSK no es el adecuado"))
              }
              const pems: { [key: string]: string } = {}
              for (let key of body.keys) {
                pems[key.kid] = jwkToPem(key)
              }
              fs.writeFileSync(`/usr/${id_client}.pem`, JSON.stringify(pems))
              Logger.message(Level.debug, { file: `/usr/${id_client}.pem` }, transacion_id, "Firma publica guardada")
              resolve(pems)
            })
          }).catch((error) => {
            if (error instanceof Error) {
              Logger.message(Level.error, {}, transacion_id, "GetCliente")
              if (error instanceof AuthError) {
                return reject(new AuthError(error.message))
              } else {
                return reject(new Error(error.message))
              }
            }
          })

      } else { //leer la firma publica
        Logger.message(Level.debug, { file: `/usr/${id_client}.pem` }, transacion_id, "Firma publica leída")
        let sign = JSON.parse(fs.readFileSync(`/usr/${id_client}.pem`, "utf-8"))
        resolve(sign)
      }
    })
  }

  private static hapiVerifyToken = async (pem: { [key: string]: string }, request: Hapi.Request, h: Hapi.ResponseToolkit) => {
    const headerAuth = request.headers[HEADER_AUTHORIZATION]
    const headerClient = request.headers[HEADER_CLIENT]
    const app = request.app as any
    const id = app.id
    Logger.message(Level.debug, { Auth: headerAuth, client: headerClient }, id, "Función verifyMiddleWare")

    const decoded = await CognitoAuth.verify(pem, headerAuth, headerClient, id)
    Logger.message(Level.debug, { Auth: headerAuth, client: headerClient }, id, "Verificación del token")
    if (typeof decoded !== "string") {
      //Asignar al Request información del usuario autenticado
      const app = request.app as any
      app.user = {
        sub: decoded.sub!,
        token_use: decoded.token_use
      }

      if (decoded.token_use === TOKEN_USE_ACCESS) {
        // access token specific fields
        app.user.scope = decoded.scope.split(' ')
        app.user.username = decoded.username
      }

      if (decoded.token_use === TOKEN_USE_ID) {
        // id token specific fields
        app.user.email = decoded.email
        app.user.username = decoded['cognito:username']
      }
      request.app = app
      Logger.message(Level.info, { user: app.user }, id, "Informacion del usuario")
    }
  }
  /**
   * Validar el token y añadir la información del usuario en el request si la validación es exitosa
   * @param pem Llave publica
   * @param req Request
   * @param res Response
   * @param next Siguiente Función a procesar
   */
  private static verifyMiddleWare = (pem: { [key: string]: string }, req: IAuthenticatedRequest, res: Response, next: NextFunction) => {
    Logger.message(Level.debug, { Auth: req.get(HEADER_AUTHORIZATION)!, client: req.get(HEADER_CLIENT)! }, req.id?.toString(), "Función verifyMiddleWare")

    CognitoAuth.verify(pem, req.get(HEADER_AUTHORIZATION)!, req.get(HEADER_CLIENT)!, req.id?.toString())
      .then((decoded) => {
        Logger.message(Level.debug, { Auth: req.get(HEADER_AUTHORIZATION)!, client: req.get(HEADER_CLIENT)! }, req.id?.toString(), "Verificación del token")
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
          Logger.message(Level.info, { user: req.user! }, req.id?.toString(), "Informacion del usuario")
        }
        next()

      }).catch((err) => {
        if (err instanceof Error) {
          Logger.message(Level.error, {}, req.id?.toString(), err.message)
          const status = (err instanceof AuthError ? 401 : 500)
          res.status(status).json({ message: err.message || err })
        }

      })
  }

  /**
   * Método para validar el token
   * @param pems Llave pública
   * @param auth Token de Authorization
   * @param id_client ID del cliente
   * @param transacion_id ID de la transacción
   * @returns
   */
  private static verify = (pems: { [key: string]: string }, auth: string, id_client: string, transacion_id: string): Promise<JwtPayload | string> => {

    return new Promise((resolve, reject) => {

      try {

        let ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${CognitoAuth.poolsDictionary[id_client].user_pool}`
        Logger.message(Level.debug, { ISSUER }, transacion_id, "verificación del token")

        //verificar el formato del auth en el header
        if (!auth || auth.length < 10) {
          Logger.message(Level.error, { id_client, auth }, transacion_id, "Formato no esperado, menor a 10 digitos")
          return reject(new AuthError("Inválido o ausente Authorization header. Esperado formato \'Bearer <your_JWT_token>\'. "))
        }

        const authPrefix = auth.substring(0, 7).toLowerCase()
        if (authPrefix !== 'bearer ') {
          Logger.message(Level.error, { id_client, auth }, transacion_id, "El token no tiene el prefijo Bearer")
          return reject(new AuthError('Authorization header esperado en el formato \'Bearer <your_JWT_token>\'.'))
        }

        //Obtener el token
        const token = auth.substring(7)

        // Decodificar el token JWT para ver si hace match con la llave
        const decodedNotVerified = jwt.decode(token, { complete: true })

        //Verificar que exista el token decodificado
        if (!decodedNotVerified) {
          Logger.message(Level.error, { id_client, auth }, transacion_id, "Authorization header contiene un token invalido")
          return reject(new AuthError('Authorization header contiene un token inválido'))
        }

        //Validar que la KID coincida con JWSK (Que el token haya sido firmado con la llave publica del USER_POOL)
        if (!decodedNotVerified.header.kid || !pems[decodedNotVerified.header.kid]) {
          Logger.message(Level.error, { id_client, auth }, transacion_id, "el KID no coincide")
          return reject(new AuthError("Authorization header contiene un token inválido"))
        }

        //Decodificar la firma con la Llave publica
        jwt.verify(token, pems[decodedNotVerified.header.kid], { issuer: ISSUER, maxAge: MAX_TOKEN_AGE }, (err, decodeAndVerified) => {

          if (err) {
            if (err instanceof jwt.TokenExpiredError) {
              Logger.message(Level.error, { id_client, auth }, transacion_id, "Authorzation header expirado")
              return reject(new AuthError("Authorization header contiene un JWT que ha expirado en: " + err.expiredAt.toISOString()))
            } else {
              Logger.message(Level.error, { id_client, auth }, transacion_id, "JWT inválido")
              return reject(new AuthError("Authorization header contiene un JWT inválido"))
            }
          }

          //La firma coincide y sabemos que el token proviene de una instancia de Cognito
          //verificar el Claims

          if (typeof decodeAndVerified !== "string") {
            //validar que token_use = 'access'
            if (ALLOWED_TOKEN_USES.indexOf(decodeAndVerified!.token_use) === -1) {
              Logger.message(Level.error, { id_client, auth }, transacion_id, "Authorization contiene token inválido no ACCESS")
              return reject(new AuthError('Authorization header contiene un token inválido.'))
            }
            //validar que client_id corresponda con el CLIENT_ID del USER_POOL
            const clientId = (decodeAndVerified!.aud || decodeAndVerified!.client_id)
            if (clientId !== CognitoAuth.poolsDictionary[id_client].client_id) {
              Logger.message(Level.error, { id_client, auth }, transacion_id, "Authozation contine token inválido CLIENT_ID no coincide")
              return reject(new AuthError('Authorization header contiene un token inválido.')) // don't return detailed info to the caller
            }
          }

          return resolve(decodeAndVerified!)
        })

      } catch (e) {
        if (e instanceof Error) {
          Logger.message(Level.error, {}, transacion_id, e.message)
          return reject(new Error(e.message))
        }
      }



    })
  }
}
