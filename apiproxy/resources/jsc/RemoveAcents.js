 var text = context.getVariable("request.content");
 if(text)
    text= text.normalize("NFD").replace(/[\u0300-\u036f]/g, "")
context.setVariable("request.content",text);