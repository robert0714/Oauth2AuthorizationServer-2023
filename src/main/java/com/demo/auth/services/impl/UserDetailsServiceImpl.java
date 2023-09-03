package com.demo.auth.services.impl;

import java.util.Collections; 
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException; 

/***
 * refer: <br/>
 * https://github.com/robert0714/demo-springcloud-oauth-jwt/blob/master/authorization_server/src/main/java/com/example/demo/service/NtUserDetailService.java <br/>
 * https://github.com/robert0714/demo-springcloud-oauth-jwt/blob/master/authorization_server/src/main/java/com/example/demo/security/NtUserDetailsAuthenticationProvider.java <br/>
 * https://github.com/robert0714/demo-springcloud-oauth-jwt/blob/master/authorization_server/src/main/java/com/example/demo/config/ServerSecurityConfig.java <br/>
 * */
public class UserDetailsServiceImpl implements UserDetailsService {
	   
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { 
		var user1 = User.withUsername("user")
		.password("password")
		.authorities("read", "test")
		.build();
		return user1;
	}

}
