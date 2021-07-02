package com.springsecurity.demo.securityController;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.demo.jwt.util.JWTUtil;
import com.springsecurity.demo.models.AuthenticationRequest;
import com.springsecurity.demo.models.AuthenticationResponse;

@RestController
@RequestMapping("/spring-security")
public class SpringSecurityController {

	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	UserDetailsService userDeatailsService;
	
	@Autowired
	JWTUtil jwtUtil;

	@GetMapping("/hello")
	public String getHello() {
		return "Welcome to Spring Security!!!";
	}

	@GetMapping("/admin")
	public String admin() {
		return ("<h1>Welcome To Admin!!!!</h1>");
	}

	@GetMapping("/user")
	public String user() {
		return ("<h1>Welcome To User as well as Admin!!!!</h1>");
	}

	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword()));
		}
		catch (BadCredentialsException e) {
			throw new Exception("Incorrect Username and Password", e);
		}
		final UserDetails userDetails = userDeatailsService.loadUserByUsername(authenticationRequest.getUserName());
		final String jwt = jwtUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

}
