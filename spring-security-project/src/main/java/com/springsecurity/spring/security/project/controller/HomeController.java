package com.springsecurity.spring.security.project.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home";  // Directs to home.html
    }

    @GetMapping("/home")
    public String homePage() {
        return "home";  // Directs to home.html after successful login
    }

    @GetMapping("/user")
    public String user() {
        return "user";  // Directs to user.html
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";  // Directs to admin.html
    }

    @GetMapping("/login")
    public String login() {
        return "login";  // Directs to login.html
    }
}
