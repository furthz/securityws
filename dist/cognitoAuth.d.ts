import { Handler } from 'express';
export declare class CognitoAuth {
    private static dynamo;
    private static poolsDictionary;
    /**
     * Método principal para realizar la validación de los headers: Authorization y client_nexux
     * @param req Request
     * @param res Response
     * @param next Siguiente función a procesar de pasar la validación
     */
    static process: Handler;
    /**
     * Método para buscar en la tabla Cliente, la información del Pool y ClientId de Cognito para un determinado cliente
     * @param id_client Id del cliente
     * @param transacion_id Id de la transacción
     */
    private static getDataClient;
    /**
     * Método que inicializa la descarga de la Firma pública para el cliente solicitado
     * @param id_client Id del cliente
     * @param transacion_id Id de la transaccion
     * @returns
     */
    private static init;
    /**
     * Validar el token y añadir la información del usuario en el request si la validación es exitosa
     * @param pem Llave publica
     * @param req Request
     * @param res Response
     * @param next Siguiente Función a procesar
     */
    private static verifyMiddleWare;
    /**
     * Método para validar el token
     * @param pems Llave pública
     * @param auth Token de Authorization
     * @param id_client ID del cliente
     * @param transacion_id ID de la transacción
     * @returns
     */
    private static verify;
}
//# sourceMappingURL=cognitoAuth.d.ts.map