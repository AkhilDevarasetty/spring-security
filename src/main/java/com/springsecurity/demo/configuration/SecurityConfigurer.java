package com.springsecurity.demo.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter{

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		auth.inMemoryAuthentication()
		     .withUser("admin")
		     .password("Welcome@123")
		     .roles("ADMIN")
		     .and().withUser("admin1").password("admin1").roles("User");
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		    .antMatchers("/spring-security/admin").hasRole("ADMIN")
		    .antMatchers("/spring-security/user").hasAnyRole("User","ADMIN")
			.antMatchers("/spring-security/hello").permitAll()
		    .and().formLogin();
	}
}
