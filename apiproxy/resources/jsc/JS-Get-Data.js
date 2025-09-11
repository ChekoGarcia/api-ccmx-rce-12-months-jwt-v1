 var headerNames = context.getVariable('request.headers.names');
var headerCount = context.getVariable('request.headers.count');

headerNames = headerNames.toArray();

var req_headers = {};
for (var i = 0; i < headerNames.length; i++) {
    req_headers[headerNames[i]]= context.getVariable('request.header.'+ headerNames[i].toLowerCase());    
}
context.setVariable("headersOrigin",JSON.stringify(req_headers));
context.setVariable("requestOrigin",context.getVariable('request.content'));

context.setVariable("bitacora.verb",context.getVariable('request.verb'));
context.setVariable("bitacora.apiproxyName",context.getVariable('apiproxy.name'));
context.setVariable("bitacora.apiproxyRevision",context.getVariable('apiproxy.revision'));

