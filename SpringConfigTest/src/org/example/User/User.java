package org.example.User;

import org.example.Validate.CaseMode;
import org.example.Validate.CheckCase;
import org.hibernate.validator.constraints.NotBlank;

import java.io.Serializable;

public class User implements Serializable {
    @NotBlank(message = "用户名不能为空")
    @CheckCase(CaseMode.LOWER)
    private String username;

    @NotBlank(message = "密码不能为空")
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
