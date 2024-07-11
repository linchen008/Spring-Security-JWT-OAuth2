package com.security.springsecurityjwtoauth2.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 10/07/2024 15:02
 * @Description :
 */
@ConfigurationProperties(prefix = "jwt")
public record RSAKeyRecord(RSAPublicKey rsaPublicKey,
                           RSAPrivateKey rsaPrivateKey) {
}
