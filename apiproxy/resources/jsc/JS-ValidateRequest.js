var bodyRequest = JSON.parse(context.getVariable("request.content"));
var jwtMatch = context.getVariable("jwtMatch");
var isValidRequest = jwtMatch;
const ErrorCodes = {
    FORBIDDEN: '401.3',
    UNAUTHORIZED: '401.2'
    };
const errorsPayload = [];

const errorObj = {};

const keysIdcdc = ['idCDC', 'idCdc', 'id_cdc', 'idcdc'];
const keysEmail = ['email', 'correo'];

function isKeyValid(keys, request) {
    // Se devuelve el valor de inmediato si se encuentra la clave en el request
    return keys.find(key => key in request) ? request[keys.find(key => key in request)] : "";
}

if (jwtMatch) {
    const claimIdcdc = context.getVariable("jwt-claim-idcdc");
    const claimEmail = context.getVariable("jwt-claim-email");

    var idcdc = "";
    var email = "";

    // Comprobamos si alguna de las claves de idCDC está en el bodyRequest
    idcdc = isKeyValid(keysIdcdc, bodyRequest);
    if (idcdc) {
        isValidRequest = (idcdc === claimIdcdc);
    } else {
        // Si no se encontró idcdc, verificamos las claves de email
        email = isKeyValid(keysEmail, bodyRequest);
        if(email){
            isValidRequest = (email === claimEmail);    
        }
        
    }


    context.setVariable("isValidRequest", isValidRequest);
}


if(!jwtMatch){
    errorObj.code = ErrorCodes.UNAUTHORIZED;
    errorObj.message = 'Invalid JWT, please verify your information.';
}else if(!isValidRequest){
    errorObj.code = ErrorCodes.FORBIDDEN;
    errorObj.message = 'You do not have access to this information.';
}

errorsPayload.push(errorObj);
context.setVariable("errorMessage", JSON.stringify({ errors: errorsPayload.sort(function (a, b) { return a.code - b.code }) }));