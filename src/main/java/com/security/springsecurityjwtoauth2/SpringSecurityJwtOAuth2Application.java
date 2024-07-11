package com.security.springsecurityjwtoauth2;

import com.security.springsecurityjwtoauth2.config.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class SpringSecurityJwtOAuth2Application {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtOAuth2Application.class, args);
	}

}
