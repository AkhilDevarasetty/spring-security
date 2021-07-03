package com.springsecurity.demo.configuration;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.springsecurity.demo.filters.JwtRequestFilter;
import com.springsecurity.demo.service.MyUserDetailsService;

@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

	@Autowired
	DataSource dataSource;
	
	@Autowired
	JwtRequestFilter jwtRequestFilter;

	@Autowired
	MyUserDetailsService myUserDeatilsService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		/*
		 * auth.inMemoryAuthentication() .withUser("admin") .password("Welcome@123") /
		 * code for inMemory Authentication in spring secuirty / .roles("ADMIN")
		 * .and().withUser("admin1").password("admin1").roles("USER");
		 */

		/*
		 * auth.jdbcAuthentication().dataSource(dataSource).withDefaultSchema().
		 * withUser( User.withUsername("user").password("user").roles("USER")) /jdbc
		 * authentication with default schem / .withUser(
		 * User.withUsername("admin").password("admin").roles("ADMIN"));
		 */

		auth.userDetailsService(myUserDeatilsService);
	}

	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	@Bean
	public AuthenticationManager getAuthenticationManager() throws Exception {
		return super.authenticationManager();
	}

	
	  @Override protected void configure(HttpSecurity http) throws Exception {
		  
			/*
			 * http.authorizeRequests()
			 * .antMatchers("/spring-security/admin").hasRole("ADMIN")
			 * .antMatchers("/spring-security/user").hasAnyRole("USER","ADMIN")
			 * .antMatchers("/spring-security/hello").permitAll() .and().formLogin();
			 */
		  
		  http.csrf().disable().authorizeRequests().antMatchers("/spring-security/authenticate").permitAll()
		  .anyRequest().authenticated().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		  
		  http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
	   
	  }
	 
}
