package org.example.User;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class Client {
    public static void main(String[] args) {
//        ApplicationContext context=new ClassPathXmlApplicationContext("classpath:spring/spring-remote.xml");
//        IUserService userService=(IUserService) context.getBean("userService");
//        User user=userService.getUser();
//        System.out.println(user.getUsername());
//        System.out.println(user.getPassword());


        ApplicationContext context=new ClassPathXmlApplicationContext("classpath:invoker-client.xml");
        IUserService userService=(IUserService) context.getBean("userServiceProxy");
        User user=userService.getUser();
        System.out.println(user.getUsername());
        System.out.println(user.getPassword());
    }
}
