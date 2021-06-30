package com.springsecurity.demo.securityController;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/spring-security")
public class SpringSecurityController {
	
	@GetMapping("/hello")
	public String getHello() {
		return "Welcome to Spring Security!!!";
	}
	
	@GetMapping("/admin")
	public String admin() {
		return("<h1>Welcome To Admin!!!!</h1>");
	}
	
	@GetMapping("/user")
	public String user() {
		return("<h1>Welcome To User as well as Admin!!!!</h1>");
	}
	
	

}
