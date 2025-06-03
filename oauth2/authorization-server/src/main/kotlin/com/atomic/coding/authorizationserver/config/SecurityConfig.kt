package com.atomic.coding.authorizationserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .authorizeHttpRequests { auth ->
            auth
                .requestMatchers("/api/health").permitAll() // public
                .anyRequest().authenticated()              // secure everything else
        }
        .formLogin {} // enable default login form
        .build()
}
