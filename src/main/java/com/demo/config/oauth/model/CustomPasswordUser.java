package com.demo.config.oauth.model;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public record CustomPasswordUser(String username, Collection<? extends GrantedAuthority> authorities) {

}
