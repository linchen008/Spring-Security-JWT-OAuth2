package com.security.springsecurityjwtoauth2.config;


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.security.springsecurityjwtoauth2.jwtAuth.JwtAccessTokenFilter;
import com.security.springsecurityjwtoauth2.jwtAuth.JwtTokenUtils;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @author : Tommy
 * @version : 1.0
 * @createTime : 09/07/2024 16:32
 * @Description :
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity

@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final UserInfoManagerConfig userInfoManagerConfig;
    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;

    @Order(1)
    @Bean
    public SecurityFilterChain loginFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/login/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .userDetailsService(userInfoManagerConfig)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint((request, response, authException) ->
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // to secure the api
                .securityMatcher(new AntPathRequestMatcher("/api/**"))
                // to disable the csrf
                .csrf(AbstractHttpConfigurer::disable)
                // to authorize the request
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // to validate the jwt token
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                // to set the session management to stateless
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // to add the filter before UsernamePasswordAuthenticationFilter to validate the jwt token
                // and set the authentication object in the SecurityContext if the token is valid
                // and not expired and not tampered with the signature.
                .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
                // to handle the exception
                .exceptionHandling(ex -> {
                    log.error("[securityConfig: apiSecurityFilterChain] exception due to : {}", ex);
                    // to handle the exception if the token is not valid or expired or tampered with the signature or not present in the request.
                    ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                    // to handle the exception if the user is not authorized to access the resource.
                    ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Order(3)
    @Bean
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/h2-console/**"))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                // to display the h2 console in Iframe
                .headers(headers -> headers.frameOptions(Customizer.withDefaults()).disable())
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
                .withPublicKey(rsaKeyRecord.rsaPublicKey())
                .build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey
                .Builder(rsaKeyRecord.rsaPublicKey())
                .privateKey(rsaKeyRecord.rsaPrivateKey())
                .build();

        JWKSource<SecurityContext> jwkSource =
                new ImmutableJWKSet<>(new JWKSet(jwk));

        return new NimbusJwtEncoder(jwkSource);
    }
}
