  try{
    var contentType = context.getVariable("response.header.content-type");
    
    
        context.setVariable('return.contentType.error',false);
        if(context.getVariable("response.status.code") == 404){
            var response = context.getVariable("response.content");
            if (response !== null && response !== undefined && response !=='') {
                var response = JSON.parse(response);
                var folioConsulta = response.folioConsulta;
                if (folioConsulta !== null && folioConsulta !== undefined && folioConsulta !=='') {
                    context.setVariable("info.folio",folioConsulta);
                }
            }
        }
            
    
    
}catch(e){
    print("***errors: ContentType ***");
    print(e);
    print("***end******");
}