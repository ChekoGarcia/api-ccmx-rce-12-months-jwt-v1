 const ErrorCodes = {
    INVALID_TYPE: '400.8',
    
};

const errorsPayload = [];

const errorObj = {};

errorObj.code = ErrorCodes.INVALID_TYPE;
errorObj.message = 'Tu peticion viola los requisitos de integridad.';

errorsPayload.push(errorObj);

context.setVariable("errorMessage", JSON.stringify({ errors: errorsPayload.sort(function (a, b) { return a.code - b.code }) }));
