package com.demo.config.oauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest; 
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.jupiter.api.Assertions.assertEquals;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Slf4j
public class CustomPassordAuthenticationProviderTest {
	@Autowired
	protected TestRestTemplate restTemplate;
	
	@BeforeEach
	protected void setUp() throws Exception {
		if (this.restTemplate == null) {
			 System.out.println("===============================================================");
		}
	}

	@Test
	public void testAuthenticate() {
		final String uri = "/oauth2/token"; 
		
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.add("PRIVATE-TOKEN", "xyz");

		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		
		map.add("grant_type","custom_password");		 
		map.add("username","III413");
		map.add("username","NCA001");
		map.add("username","91F147");
		 
		map.add("password","Ie=123456789");

		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers); 
 

		ResponseEntity<String> response = restTemplate.exchange(uri, HttpMethod.POST, entity, String.class);
		log.info(response.getBody());
//		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

}
