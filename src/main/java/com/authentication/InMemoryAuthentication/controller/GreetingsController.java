package com.authentication.InMemoryAuthentication.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("hi")
    public String helloForAll() {
        return "Hi All";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("user")
    public String helloForUser() {
        return "Hi User";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("admin")
    public String helloForAdmin() {
        return "Hi Admin";
    }

}
