 var lastLoggedTime = context.getVariable("lastTimestamp");
var nowTime = context.getVariable("system.timestamp");

context.setVariable("lastTimestamp", nowTime);

if (lastLoggedTime !== null) {
  var deltaTime = nowTime - lastLoggedTime;
  context.setVariable("lastElapsed", deltaTime);
  context.setVariable("elapsed",deltaTime);
  context.setVariable("lastTimestamp",null);
}