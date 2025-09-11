var responseFS = context.getVariable("response.content");
var requestRCCPM = context.getVariable("request.content");
var dataStr = context.getVariable("jwt.Decode-JWT-1.claim.data");

var datos = JSON.parse(dataStr);
var objResponse = JSON.parse(responseFS);

var objRequest = JSON.parse(requestRCCPM);

function pad(n,e,r){return r=r||"0",(n+="").length>=e?n:new Array(e-n.length+1).join(r)+n} 

var username = datos?datos.numeroEmpleado:null;

var folioConsulta = (objResponse && objResponse.folioConsulta)?objResponse.folioConsulta:"0";
var folioMatch = (objRequest && objRequest.folioMatch)?objRequest.folioMatch:"0";

var claveOtorgante = context.getVariable('info.otorgante');
claveOtorgante = pad(claveOtorgante?claveOtorgante:'',6);

//Estos valores son seteados por core
var nperscve = "0";
var cveProducto = "0";
var cveRetorno = 0;

var indicadorFirma = context.getVariable("private.bf.indicadorFirma");
var sNombreServer = context.getVariable("private.bf.sNombreServer");

context.setVariable("bitacora.cveProducto",cveProducto);
context.setVariable("bitacora.cvePersona",nperscve);
context.setVariable("bitacora.cveRetorno", parseInt(cveRetorno).toFixed());

var start, end, delta;
start = context.getVariable('target.sent.start.timestamp');
end = context.getVariable('target.received.end.timestamp');
delta = Math.floor(end - start);
delta = parseInt(delta).toFixed();
    
if(context.proxyResponse){
    context.proxyResponse.headers['X-time-target-elapsed'] = delta;
}

context.setVariable("bitacora.tiempoBusqIlytics",delta);
start = context.getVariable('client.received.start.timestamp');
end = context.getVariable('system.timestamp');
delta = Math.floor(end - start);
delta = parseInt(delta).toFixed();
if(context.proxyResponse){
    context.proxyResponse.headers['X-time-total-elapsed'] = delta;
}
context.setVariable("bitacora.tiempoBusqueda",delta);
context.setVariable("bitacora.indicadorFirma",indicadorFirma);
context.setVariable("bitacora.sNombreServer",sNombreServer);

context.setVariable("bitacora.claveUsuario",username?username:"989");

context.setVariable("bitacora.numeroFirma",sNombreServer+"-"+folioConsulta);
context.setVariable("bitacora.claveOtorganteXML",claveOtorgante);
context.setVariable("bitacora.folioOtorgante",folioMatch);
context.setVariable("bitacora.folioConsulta",folioMatch);


//APIGEEE
var requestOrigin = context.getVariable("requestOrigin");
var headersOrigin = context.getVariable("headersOrigin");
var headerNames = context.getVariable('response.headers.names');
var headerCount = context.getVariable('response.headers.count');
headerNames = headerNames ? headerNames.toArray():[];
var resp_headers = {};
for (var i = 0; i < headerNames.length; i++) {
    resp_headers[headerNames[i]]= context.getVariable('response.header.'+headerNames[i].toLowerCase());    
}
var resp_payload = context.getVariable("response.content");
var headers = {
    "request":headersOrigin,
    "response":JSON.stringify(resp_headers)
}
var payload ={
    "request":requestOrigin,
    "response":context.getVariable("response.content")
}

context.setVariable("bitacora.payload",JSON.stringify(payload).replace(/\\"/g, '\"').replace(/\"/g, '\\"'));
context.setVariable("bitacora.headers",JSON.stringify(headers).replace(/\\"/g, '\"').replace(/\"/g, '\\"'));
context.setVariable("bitacora.statusCode",context.getVariable("message.status.code"));
    

