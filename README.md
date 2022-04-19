#SecurityWS

##Description
Librería para incluir en todos los webservices de NexUx, para agregar seguridad usando JWT.
para lo cual se requiere que se añadan a los webservices, los siguientes headers:
- Authorization = Bearer <JWT>
- client_nexux = Id del cliente de NexUx, ejemplo: soapros

##Dependencias
Se necesita que el Microservicio que va a exponer el webservice, incluya para el proceso de validación, las siguientes variables de entorno
- REGION = Region en aws donde se encuentra la tabla de clientes y el user pool de Cognito
- TABLE_CLIENT = Tabla cliente que contiene la información de configuración para dicho cliente