package com.techmarket.Gateway.config;

import com.techmarket.Gateway.security.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Value("${SECRET_KEY}")
    private String secretKey;

    @Bean
    public JwtAuthFilter jwtAuthFilter() {
        return new JwtAuthFilter(secretKey);
    }
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity httpSecurity){
        return httpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(
                                "/api/user/login",
                                "/api/user/register",
                                "/api/user/refresh",
                                "/fallback/**").permitAll()
                        .pathMatchers("/api/user/admin/**").hasRole("ADMIN")
                        .pathMatchers("/api/product/admin/**").hasRole("ADMIN")
                        .pathMatchers("/api/product/customer/**").hasRole("CUSTOMER")
                        .pathMatchers(HttpMethod.GET, "/api/product/**").permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtAuthFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}
