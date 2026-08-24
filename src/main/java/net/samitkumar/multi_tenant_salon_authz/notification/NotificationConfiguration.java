package net.samitkumar.multi_tenant_salon_authz.notification;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;

@Configuration
public class NotificationConfiguration {

    @Bean
    RestClientHttpServiceGroupConfigurer mailjetGroupConfigurer(
            @Value("${spring.application.mailjet.api-key}") String apiKey,
            @Value("${spring.application.mailjet.api-secret}") String apiSecret) {
        return groups -> groups.filterByName("mailjet")
                .forEachClient((name, builder) ->
                        builder.defaultHeaders(h -> h.setBasicAuth(apiKey, apiSecret)));
    }
}
