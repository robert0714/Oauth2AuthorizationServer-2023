package com.demo;
 
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean; 
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.ClassPathResource; 

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;
 
@EnableEncryptableProperties
@SpringBootApplication 
@EnableAutoConfiguration(exclude={DataSourceAutoConfiguration.class})
@Slf4j
public class AuthApplication  implements ApplicationListener<ApplicationReadyEvent>{
	 
	@Autowired
    ApplicationContext applicationContext;

    public void printBeans() {
        System.out.println(Arrays.asList(applicationContext.getBeanDefinitionNames()));
    }
	public static void main(String[] args) {
		
		SpringApplication.run(AuthApplication.class, args);
	}

	 
	/***
	 *  一定只能使用static ，以避免 此spring bean沒有複寫(overwriting)預設spring-bean
	 * **/
	@Bean
    public static PropertySourcesPlaceholderConfigurer placeholderConfigurer() {
        PropertySourcesPlaceholderConfigurer propsConfig 
          = new PropertySourcesPlaceholderConfigurer();
        propsConfig.setLocation(new ClassPathResource("git.properties"));
        
        //設定springExr找不到時，部會爆出錯誤訊息
        propsConfig.setIgnoreResourceNotFound(true);
        propsConfig.setIgnoreUnresolvablePlaceholders(true);
        return propsConfig;
    }
	
	@Value("${app.description: }") 
	private String description;

	@Value("${git.commit.message.short}")
	private String commitMessage;

	@Value("${git.branch}")
	private String branch;

	@Value("${git.commit.id}")
	private String commitId;

	@Value("${git.tags}")
	private String tags;

	@Value("${git.commit.user.name}")
	private String author;

	@Override
	public void onApplicationEvent(ApplicationReadyEvent event) {
		log.info("--------------------------------");
		log.info("Created version: {}",description);
		log.info("Commit branch: {}",branch);		
		log.info("Commit message: {}",commitMessage);
		log.info("Commit id: {}",commitId);		
		log.info("Author: {}",author);
		log.info("Tags: {}",tags);
		log.info("--------------------------------");
		printBeans();
	}
}
