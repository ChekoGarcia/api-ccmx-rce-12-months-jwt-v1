 var newErrors=[];
var contentType = context.getVariable("response.header.content-type");

    function isEmpty(obj) {
        return Object.keys(obj).length === 0;
    }
    
    function typeNotFound() {
        var path = context.getVariable("proxy.pathsuffix");
        if(path.includes('folioConsulta')){
            return "No se encontró el folio consulta.";
        } else {
            return "No se encontraron resultados.";
        }        
    }    
    
     function typeUnauthorized() {
        return "Acceso no autorizado."; 
    };
try{
    
   
  

            var valid500 = true;
            print("------1");
            if(contentType.indexOf("text/html") > -1){
                print("------2");
                valid500 = false;
                
                newErrors.push({
                    codigo:"500.1",
                    mensaje: "Ocurrio un problema, inténtelo nuevamente más tarde."
                });
                context.setVariable("response.status.code", 500);
                context.setVariable("response.reason.phrase", "INTERNAL SERVER ERROR");    
               
            }else {
                var responseSF = context.getVariable("response.content");
                if(responseSF !== null && responseSF !== ""){
                    var objResponse = JSON.parse(responseSF);
                    if(response.status.code == 400){
                        //------1 ------3 ------3.1 ------3.2 ------3.3 ------3.4
                        var descErrors = objResponse.errores;
                        if(typeof descErrors === 'object' && descErrors.length > 0){
                                print("------3.5");
                                for(var i = 0; i < descErrors.length; i++) {
                                     newErrors.push({
                                        codigo:"400."+(i+1)+"",
                                        mensaje: "descErrors[i].mensaje"
                                    });
                                }
                           
                            context.setVariable("response.status.code", 400);
                            context.setVariable("response.reason.phrase", "BAD REQUEST");
                        }
                    }else if(response.status.code == 401 ){
                       context.setVariable("response.status.code", 401);
                            context.setVariable("response.reason.phrase", "UNAUTHORIZED");
                            newErrors.push({codigo:"401.2", mensaje: typeUnauthorized()});
                    }        
                }   
                
                if(response.status.code == 204 || responseSF.code == 404){
                    
                    print("------4");
                    
                    newErrors.push({
                        codigo:"404.1",
                        mensaje: typeNotFound()
                    });
                    context.setVariable("response.status.code", 404);
                    context.setVariable("response.reason.phrase", "NOT FOUND");
                }         
            }

            if(response.status.code == 204){
                print("------5");
                newErrors.push({
                    codigo:"404.1",
                    mensaje: typeNotFound()
                });
                context.setVariable("response.status.code", 404);
                context.setVariable("response.reason.phrase", "NOT FOUND");
            }else if( !valid500 && response.status.code == 500){
                print("------6");
                newErrors.push({
                    codigo:"500.1",
                    mensaje: "Ocurrio un problema, inténtelo nuevamente más tarde."
                });
                context.setVariable("response.status.code", 500);
                context.setVariable("response.reason.phrase", "INTERNAL SERVER ERROR");
            }
   
   
    }catch(e){
        print("***errors: GetResponseErrors***");
        print(e);
        print("***end******");
        print("------7");
        newErrors.push({
            codigo:"500.1",
            mensaje:"Ocurrió un problema, inténtelo nuevamente más tarde."
        });
        context.setVariable("response.status.code", 500);
        context.setVariable("response.reason.phrase", "INTERNAL SERVER ERROR");
    }

var errores =  {
      "errores": newErrors
} 
context.setVariable('response.content',JSON.stringify(errores));
//context.setVariable("response.errores",JSON.stringify(newErrors));