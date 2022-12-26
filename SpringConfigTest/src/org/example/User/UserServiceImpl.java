package org.example.User;

public class UserServiceImpl implements IUserService {

    public UserServiceImpl() {
        super();
    }

//    @Override
    public User getUser() {
        User user = new User();
        user.setUsername("admin");
        user.setPassword("123456");
        return user;
    }
}
