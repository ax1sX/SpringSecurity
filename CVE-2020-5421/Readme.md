# Spring 安全漏洞 CVE-2020-5421复现 

## 漏洞概述
CVE-2020-5421 可通过jsessionid路径参数，绕过防御RFD攻击的保护。先前针对RFD的防护是为应对 CVE-2015-5211 添加的。  
**什么是RFD**  
>反射型文件下载漏洞(RFD)是一种攻击技术，通过从受信任的域虚拟下载文件，攻击者可以获得对受害者计算机的完全访问权限。  


## 影响版本
>Spring Framework 5.2.0 - 5.2.8  
Spring Framework 5.1.0 - 5.1.17  
>Spring Framework 5.0.0 - 5.0.18  
>Spring Framework 4.3.0 - 4.3.28

## 漏洞复现
`github地址：https://github.com/pandaMingx/CVE-2020-5421`
### 版本
基于SpringBoot-2.1.7.RELEASE,Spring-xxx-5.1.9.RELEASE进行测试。
```
   <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.7.RELEASE</version>
        <relativePath/>
    </parent>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>
```
### 复现代码
```
@Controller
@RequestMapping(value = "spring")
public class cve20205421 {

    // localhost:8080/spring/input?input=hello
    @RequestMapping("input")
    @ResponseBody
    public String input(String input){
        return input;
    }
}
```
**额外配置**
```
spring.mvc.pathmatch.use-suffix-pattern=true
spring.mvc.contentnegotiation.favor-path-extension=true
```

在url中添加**;jsessionid=**,如http://localhost:8080/spring/;jsessionid=/input.bat?input=calc，就会下载名为input.bat的可执行文件。

## 漏洞分析
CVE-2020-5421是针对CVE-2015-5211修复方式的绕过，定位到CVE-2015-5211的修复代码
org.springframework.web.servlet.mvc.method.annotation.AbstractMessageConverterMethodProcessor. addContentDispositionHeader
```
/**
	 * Check if the path has a file extension and whether the extension is
	 * either {@link #WHITELISTED_EXTENSIONS whitelisted} or explicitly
	 * {@link ContentNegotiationManager#getAllFileExtensions() registered}.
	 * If not, and the status is in the 2xx range, a 'Content-Disposition'
	 * header with a safe attachment file name ("f.txt") is added to prevent
	 * RFD exploits.
	 */
	private void addContentDispositionHeader(ServletServerHttpRequest request, ServletServerHttpResponse response) {
		HttpHeaders headers = response.getHeaders();
		if (headers.containsKey(HttpHeaders.CONTENT_DISPOSITION)) {
			return;
		}

		try {
			int status = response.getServletResponse().getStatus();
			if (status < 200 || status > 299) {
				return;
			}
		}
		catch (Throwable ex) {
			// ignore
		}

		HttpServletRequest servletRequest = request.getServletRequest();
		String requestUri = rawUrlPathHelper.getOriginatingRequestUri(servletRequest);

		int index = requestUri.lastIndexOf('/') + 1;
		String filename = requestUri.substring(index);
		String pathParams = "";

		index = filename.indexOf(';');
		if (index != -1) {
			pathParams = filename.substring(index);
			filename = filename.substring(0, index);
		}

		filename = decodingUrlPathHelper.decodeRequestString(servletRequest, filename);
		String ext = StringUtils.getFilenameExtension(filename);

		pathParams = decodingUrlPathHelper.decodeRequestString(servletRequest, pathParams);
		String extInPathParams = StringUtils.getFilenameExtension(pathParams);

		if (!safeExtension(servletRequest, ext) || !safeExtension(servletRequest, extInPathParams)) {
			headers.add(HttpHeaders.CONTENT_DISPOSITION, "inline;filename=f.txt");
		}
	}
```
跟进rawUrlPathHelper.getOriginatingRequestUri方法，一路跟进定位到org.springframework.web.util.UrlPathHelper.removeJsessionid方法中会将请求url中;jsessionid=字符串开始进行截断(或者下一个;前)。
```
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
由于这段删除;jsessionid=的代码，造成删除;jsessionid=之后CVE-2015-5211的后续防御代码即将获取不到请求的真实后缀文件名，从而绕过RDF防御代码。

## 修复建议
漏洞复现的过程中，在applcation.properties中添加了两个参数：spring.mvc.pathmatch.use-suffix-pattern=true，spring.mvc.contentnegotiation.favor-path-extension=true（SpringBoot中默认为false）
可见，CVE-2020-5421的利用条件是必须要开启后缀匹配模式和内容协商机制。如果SpringBoot项目中没有启用这两种模式则不存在漏洞利用条件，可不处理。  
如果存在漏洞利用条件，这里提供两个方案，其中方案二适用于升级Spring版本风险较大的项目。
### 方案一、升级Spring版本到安全版本：
>Spring Framework 5.2.9  
>Spring Framework 5.1.18  
>Spring Framework 5.0.19  
>Spring Framework 4.3.29

### 方案二、添加安全过滤器
方案二将校验含有**;jsessionid=**的ULR的后缀是否为安全后缀，如果不是则设置Content-Disposition=inline;filename=f.txt，强制将响应的内容下载到名为f.txt的文件中。（做法和spring的RDF防御机制一致）

```
public class SpringJsessionidRdfFilter implements Filter {

    private final Set<String> safeExtensions = new HashSet<>();
    /* Extensions associated with the built-in message converters */
    private static final Set<String> WHITELISTED_EXTENSIONS = new HashSet<>(Arrays.asList(
            "txt", "text", "yml", "properties", "csv",
            "json", "xml", "atom", "rss",
            "png", "jpe", "jpeg", "jpg", "gif", "wbmp", "bmp"));

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        String contentDisposition = response.getHeader(HttpHeaders.CONTENT_DISPOSITION);
        if (!"".equals(contentDisposition)&&null != contentDisposition) {
            return;
        }

        try {
            int status = response.getStatus();
            if (status < 200 || status > 299) {
                return;
            }
        }
        catch (Throwable ex) {
            // ignore
        }

        String requestUri = request.getRequestURI();

        System.out.println(requestUri);

        if(requestUri.contains(";jsessionid=")){
            int index = requestUri.lastIndexOf('/') + 1;
            String filename = requestUri.substring(index);
            String pathParams = "";

            index = filename.indexOf(';');
            if (index != -1) {
                pathParams = filename.substring(index);
                filename = filename.substring(0, index);
            }

            UrlPathHelper decodingUrlPathHelper = new UrlPathHelper();
            filename = decodingUrlPathHelper.decodeRequestString(request, filename);
            String ext = StringUtils.getFilenameExtension(filename);

            pathParams = decodingUrlPathHelper.decodeRequestString(request, pathParams);
            String extInPathParams = StringUtils.getFilenameExtension(pathParams);

            if (!safeExtension(request, ext) || !safeExtension(request, extInPathParams)) {
                response.addHeader(HttpHeaders.CONTENT_DISPOSITION, "inline;filename=f.txt");
            }
        }
        filterChain.doFilter(servletRequest,servletResponse);
    }

    private boolean safeExtension(HttpServletRequest request, @Nullable String extension) {
        if (!StringUtils.hasText(extension)) {
            return true;
        }
        extension = extension.toLowerCase(Locale.ENGLISH);
        this.safeExtensions.addAll(WHITELISTED_EXTENSIONS);
        if (this.safeExtensions.contains(extension)) {
            return true;
        }
        String pattern = (String) request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        if (pattern != null && pattern.endsWith("." + extension)) {
            return true;
        }
        if (extension.equals("html")) {
            String name = HandlerMapping.PRODUCIBLE_MEDIA_TYPES_ATTRIBUTE;
            Set<MediaType> mediaTypes = (Set<MediaType>) request.getAttribute(name);
            if (!CollectionUtils.isEmpty(mediaTypes) && mediaTypes.contains(MediaType.TEXT_HTML)) {
                return true;
            }
        }
        return false;
    }

}
```

## 参考文档
* https://www.xf1433.com/4595.html
* https://www.nsfocus.com.cn/html/2020/39_0921/976.html
* https://zhuanlan.zhihu.com/p/161166505
* https://github.com/spring-projects/spring-framework/commit/2281e421915627792a88acb64d0fea51ad138092








