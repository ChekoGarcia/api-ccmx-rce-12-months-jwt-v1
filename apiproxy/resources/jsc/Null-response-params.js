function filter(obj) {
  for(var key in obj){
    if (obj[key] === "" || obj[key] === null){
        delete obj[key];
    } else if (Object.prototype.toString.call(obj[key]) === '[object Object]') {
        if(Object.keys(obj[key]).length === 0){
            delete obj[key];
        }
        else{
            filter(obj[key]);
        }
    } else if (Array.isArray(obj[key])) {
        if(obj[key].length === 0){
            delete obj[key];
        }else{
            for(var _key in obj[key]){
                filter(obj[key][_key]);
            }
            obj[key] = obj[key].filter(value => Object.keys(value).length !== 0);
            if(obj[key].length === 0){
                delete obj[key];
            }
        }
    }  
}}

try{
    var data = context.getVariable("response.content");
    data = JSON.parse(data);
    filter(data);
    context.setVariable("response.content", JSON.stringify(data));
}catch(e){
    print(e);
}
