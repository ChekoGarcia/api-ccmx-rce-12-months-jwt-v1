 try{
 var data = context.getVariable("request.content");
data = JSON.parse(data);
var removeFalsy = function removeFalsy(obj) {
    if(typeof obj == 'object'){
           Object.keys(obj).forEach(function(key) {
                if (obj[key] && typeof obj[key] === 'object') removeFalsy(obj[key])
                else if (obj[key] === null || obj[key]===undefined || obj[key]==='') delete obj[key]
            });
    }
 
};
removeFalsy(data);
context.setVariable("request.content", JSON.stringify(data));
    
}catch(e){
    print("***errors: Null-request-param***");
    print(e);
    print("***end******");
}