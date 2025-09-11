const ErrorCodes = {
    INVALID_TYPE: '400.0',
    ENUM_MISMATCH: '400.1',
    STRING_LENGTH_SHORT: '400.2',
    STRING_LENGTH_LONG: '400.2',
    STRING_PATTERN: '400.2',
    OBJECT_REQUIRED: '400.3',
    DEFAULT: '400.4',
    UNPROCESSABLE_ENTITY: '400.2',
    METHOD_NOT_ALLOWED: '405'
};

const content = context.getVariable('OASValidation.OAS-RCE-12-MESES-Validation.fault.cause');


const errorsPayload = [];

if (content !== null) {
    var errorMessage = content.match(/failed with reason: "\[(.*?)]"/);
    
    if (errorMessage && errorMessage.length > 1) {
        errorMessage = errorMessage[1].replace(new RegExp('\"', 'g'), "'");
        
        const errors = errorMessage.split('ERROR - ');
        errors.shift();

        errors.forEach(error => {
            const errorObj = {};

             if (error.includes('Instance type') || error.includes('is not a valid') || error.includes('is invalid') || error.includes('Numeric instance is') || error.includes('Value for int32 leads to overflow')) {
                errorObj.code = ErrorCodes.INVALID_TYPE;
                errorObj.message = 'Tipo de dato no valido: ' + error.split('Path ')[1].split(']')[0];
            } else if (error.includes('not found in enum')) {
                errorObj.code = ErrorCodes.ENUM_MISMATCH;
            } else if (error.includes('is too short')) {
                errorObj.code = ErrorCodes.STRING_LENGTH_SHORT;
                errorObj.message = 'El campo: ' + error.split('Path ')[1].split(']')[0] + ' no cumple la longitud requerida';

            } else if (error.includes('is too long')) {
                errorObj.code = ErrorCodes.STRING_LENGTH_LONG;
            } else if (error.includes('ECMA 262 regex')) {
                errorObj.code = ErrorCodes.STRING_PATTERN;
                errorObj.message = 'El campo: ' + error.split('Path ')[1].split(']')[0] + ' no cumple el formato requerido';

            } else if (error.includes('has missing required properties') || error.includes('is required')) {
                errorObj.code = ErrorCodes.OBJECT_REQUIRED;
            } else if (error.includes('not allowed on path')) {
                errorObj.code = ErrorCodes.METHOD_NOT_ALLOWED;
                errorObj.message = 'Metodo no permitido.';
            } else {
                errorObj.code = ErrorCodes.DEFAULT;
                errorObj.message = 'PATH_ERROR: ' + context.getVariable('request.path');
            }

            errorObj.message = errorObj.message || error;
            errorsPayload.push(errorObj);
        });


        context.setVariable("errorMessage", JSON.stringify({ errors: errorsPayload.sort(function (a, b) { return a.code - b.code }) }));
    }
} else {
    // Manejar el caso en que no se encontraron errores OAS
    context.setVariable("errorMessage", JSON.stringify({ errors: [] }));
}


