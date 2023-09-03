package com.demo.config;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFilter 
//              extends OncePerRequestFilter 
implements Filter
              
              {
//	private static final List<String> ALLOWED_ALL = List.of("http://127.0.0.1:8082", "http://34.81.143.123","http://localhost:8082");
	private static final List<String> ALLOWED_ALL = List.of("*");
	
	 
 
       
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        response.setHeader("Access-Control-Allow-Origin", StringUtils.join(ALLOWED_ALL , ','));        
        response.setHeader("Access-Control-Allow-Methods",  "GET, POST, OPTIONS");         
        response.setHeader("Access-Control-Max-Age", "3600"); 
        response.setHeader("Access-Control-Allow-Headers",  "x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN, api_key");
        response.addHeader("Access-Control-Expose-Headers", "xsrf-token");
        if ("OPTIONS".equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else { 
            filterChain.doFilter(request, response);
        }
    }
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) resp;
        HttpServletRequest request = (HttpServletRequest) req;
        String origin = request.getHeader("referer");
        if(ALLOWED_ALL != null ){
        	 response.setHeader("Access-Control-Allow-Origin", StringUtils.join(ALLOWED_ALL , ','));   
        }
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");  
        response.setHeader("Access-Control-Max-Age", "3600"); 
        response.setHeader("Access-Control-Allow-Headers",  "x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN, api_key");
        response.addHeader("Access-Control-Expose-Headers", "xsrf-token");

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            chain.doFilter(req, resp);
        }
    }
}