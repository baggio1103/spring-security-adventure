package com.atomic.coding.authorizationserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.util.*

@Configuration
@EnableWebSecurity
class SecurityConfig {

// https://www.vmware.com/explore/us/springone?code=_Nn6DVvb4I1k3zBnKf-Uk2nD8bGY3qt7aVIsEdmf5YevT1UIGtypot4UbDoUQXevvC6MlJFW5OrBNf0SP--Kt46otWHxaTMYwxmq3WacOlR7Buc9LjPuTzqo1670EY1M

    @Bean
    @Order(1)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer()
        http.securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .with(authorizationServerConfigurer) { authorizationServer ->
                authorizationServer.oidc {}
            }
            .exceptionHandling { exceptionHandler ->
                exceptionHandler.authenticationEntryPoint(
                    LoginUrlAuthenticationEntryPoint("/login")
                )
            }
        return http.build()
    }

    @Bean
    @Order(2)
    fun appSecurityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .authorizeHttpRequests { authorization -> authorization.anyRequest().authenticated() }
        .formLogin(Customizer.withDefaults())
        .build()

    @Bean
    fun userDetailsService(): UserDetailsService = InMemoryUserDetailsManager(
        User.withUsername("user")
            .password("password")
            .authorities("read")
            .build()
    )

    @Bean
    fun passwordEncoder(): PasswordEncoder = NoOpPasswordEncoder.getInstance()

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registeredClient = RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientSecret("secret")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .redirectUri("https://springone.io/authorized")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings = AuthorizationServerSettings
        .builder()
        .build()

}
