package com.example.springsecurity6demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity(prePostEnabled = true,  securedEnabled = true,  jsr250Enabled = true)
public class SpringSecurity6DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurity6DemoApplication.class, args);
    }

}
