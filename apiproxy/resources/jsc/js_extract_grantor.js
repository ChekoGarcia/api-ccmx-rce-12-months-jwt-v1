  try {
    
    if (context.flow=="PROXY_REQ_FLOW") {
         var dataStr = context.getVariable("jwt.Decode-JWT-1.claim.data");
         var datos = JSON.parse(dataStr);
        context.setVariable("info.otorgante", datos.otorganteCanal);

        context.setVariable("bitacora.cveProducto",context.getVariable("private.bf.cveProducto"));
    }
    
} catch(e){
    print("***errors: JS-ExtracOtorgante  ***");
    print(e);
    print("***end******");
}