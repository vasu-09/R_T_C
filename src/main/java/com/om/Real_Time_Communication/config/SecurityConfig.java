package com.om.Real_Time_Communication.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Basic security configuration that exposes the JWKS endpoint publicly while
 * securing all other endpoints as an OAuth2 resource server.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/.well-known/jwks.json","/ws").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)));
        return http.build();
    }

    /**
     * Defines the JwtDecoder using the issuer and JWK set URI from
     * {@link RtcJwtConfig}.
     */
    @Bean
    public JwtDecoder jwtDecoder(RtcJwtConfig cfg) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(cfg.getJwksUri()).build();
        OAuth2TokenValidator<Jwt> validator = JwtValidators.createDefaultWithIssuer(cfg.getIssuer());
        decoder.setJwtValidator(validator);
        return decoder;
    }
}