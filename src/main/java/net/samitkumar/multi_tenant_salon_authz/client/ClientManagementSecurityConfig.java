package net.samitkumar.multi_tenant_salon_authz.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
class ClientManagementSecurityConfig {

    /** Its own stateless chain ahead of the login chain: no sessions, no CSRF, only the shared key gets in. */
    @Bean
    @Order(1)
    SecurityFilterChain clientManagementChain(HttpSecurity http,
            @Value("${spring.application.client-management.api-key:}") String apiKey,
            @Value("${spring.application.client-management.refuse-forwarded:true}") boolean refuseForwarded) throws Exception {
        return http
                .securityMatcher("/internal/clients", "/internal/clients/**")
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.anyRequest().permitAll())
                .addFilterBefore(new InternalApiKeyFilter(apiKey, refuseForwarded), AuthorizationFilter.class)
                .build();
    }
}
