# SecurityWS

## Description
Librería para incluir en todos los webservices de NexUx, para agregar seguridad usando JWT.
para lo cual se requiere que se añadan a los webservices, los siguientes headers:
- Authorization = Bearer <JWT>
- client_nexux = Id del cliente de NexUx, ejemplo: soapros

## Proceso de Validación
![Validacion](images/ValidacionToken.png)

### Pasos
1. Buscar en la tabla Cliente con el header client_nexux
2. Se obtiene los datos del UserPool y del ClientId del paso anterior
3. Se descarga la Firma pública del UserPool, JWKS
4. Se valida el Token (Authorization), con ela firma pública

## Dependencias
Se necesita que el Microservicio que va a exponer el webservice, incluya para el proceso de validación, las siguientes variables de entorno
- REGION = Region en aws donde se encuentra la tabla de clientes y el user pool de Cognito
- TABLE_CLIENT = Tabla cliente que contiene la información de configuración para dicho cliente

## Formas de uso
Se requiere instalar la librería usando el siguiente comando:
```
    npm install git+https://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:x-oauth-basic@github.com/furthz/securityws
```

para incorporar en el servicio web, la validación se requiere usar el siguiente código
```
//Incorporar el llamado del proceso da validación
import {CognitoAuth} from "nexuxsecurityws"

//Agregar a la ruta a controlar, el componente de validación: CognitoAuth.process
router.get('/health_check',CognitoAuth.process, inputController.health_check)
```