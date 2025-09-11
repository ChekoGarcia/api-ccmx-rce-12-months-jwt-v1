       var getMessage = function(a){
    var arreglo = [];
    for(var i = 0;i<a.length;i++){
        if(a[i].code==302){
            a[i].message = a[i].message.replace("Missing required property:", "El campo");
            a[i].message = a[i].message+" no puede estar vacío.";
            arreglo.push({
                codigo:"400."+(i+1)+"",
                mensaje:a[i].message
            });
        }else if(a[i].code===0){
             arreglo.push({
                codigo:"400."+(i+1)+"",
                mensaje:a[i].message.replace("Invalid type", "Tipo inválido").replace("expected", "esperado")+", "+a[i].dataPath
            });
        }else if(a[i].code===202){
             arreglo.push({
                codigo:"400."+(i+1)+"",
                mensaje:"El campo "+a[i].dataPath+" contiene caracteres no permitidos "
            });
        }else if(a[i].code===1){
             arreglo.push({
                codigo:"400."+(i+1)+"",
                mensaje:"El campo "+a[i].dataPath+" no coincide con el catálogo "
            });
        }else if(a[i].code===200){
             arreglo.push({
                codigo:"400."+(i+1)+"",
                mensaje:a[i].message.replace("String is too short", "Longitud de cadena es muy corta")
                    .replace("chars", "caracteres")
                    .replace("minimum", "mínimo")
                    +", "+a[i].dataPath
            });
        }else{
            print(a[i].code);
            print(a[i].message);
             arreglo.push({
                codigo:"400."+(i+1)+"",
                mensaje:"No es posible procesar la información, "+a[i].dataPath
            });
            
        }
    }
    
    return JSON.stringify(arreglo);
}

function isNumeric(n) {
  return !isNaN(parseFloat(n)) && isFinite(n);
}

var arregloJSON=[];

var validKeys = function(objeto){
  try{
  var objectKeys = Object.keys(objeto);
    for(var i=0;i<objectKeys.length;i++){ 
      if(typeof objeto[objectKeys[i]]=='object'){      
        validKeys(objeto[objectKeys[i]]);
      }else{
        if(!Array.isArray(objeto[objectKeys[i]])){     
          if((objectKeys[i]==objeto[objectKeys[i]]?true:false)&&(!isNumeric(objectKeys[i]))){ 
            arregloJSON.push({
              codigo:404,
              mensaje:"No es posible colocar el mismo value '"+objeto[objectKeys[i]]+"' que el key '"+objectKeys[i]+"' del json."
            });
          }
        }
      }
    }
  }catch(err){

  }
 
};

try {
    context.setVariable('javascript.error', false);
    var bodyContent = context.getVariable('request.content');
     var arreglo = [];
       arreglo.push({
                codigo:400,
                mensaje:"Datos de consulta incorrectos "
            });
    context.setVariable('javascript.errorMessage',JSON.stringify(arreglo));
    var body = JSON.parse(bodyContent);
   
   tv4.addFormat({
        'date': function (data, schema) {
            if (typeof data === 'string' && /^\d{4}([\-/.])(0?[1-9]|1[0-2])\1(3[01]|[12][0-9]|0?[1-9])$/.test(data.toUpperCase())) {
                return null;
            }
            return "El formato de la fecha es incorrecto ";
        }
    });
    
    var result = tv4.validateMultiple(body, schema);
    if(!result.valid){
        if(result.missing.length>0 ) {
             result.errors[0].schema=schema;
            context.setVariable('javascript.errorMessage', getMessage(result.errors));
            throw "Definición de esquema no encontrada" + JSON.stringify(result.errors);
          
        }else if(result.errors.length>0){
            result.errors[0].schema=schema;
            context.setVariable('javascript.errorMessage', getMessage(result.errors));
            throw "Definición de esquema no encontrada" + JSON.stringify(result.errors);
     
        }
    }
    
    validKeys(body);
    if(arregloJSON.length>0){
        context.setVariable('javascript.errorMessage', JSON.stringify(arregloJSON));
        throw "Definición de esquema no encontrada" + JSON.stringify(arregloJSON);
    }
}
catch( err ) {
    print(err);
  context.setVariable('javascript.error', true);
}
