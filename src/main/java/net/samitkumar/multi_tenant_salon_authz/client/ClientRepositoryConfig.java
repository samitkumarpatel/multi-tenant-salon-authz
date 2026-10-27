package net.samitkumar.multi_tenant_salon_authz.client;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration
class ClientRepositoryConfig {

    /**
     * Boot builds the repository for the clients in {@code application.yaml} and backs off if we declare our own,
     * which would drop the six app clients. Wrapping Boot's bean keeps them exactly as defined.
     */
    @Bean
    static BeanPostProcessor registeredClientRepositoryWrapper(ObjectProvider<JdbcTemplate> jdbc) {
        return new Wrapper(jdbc);
    }

    private static final class Wrapper implements BeanPostProcessor {
        private final ObjectProvider<JdbcTemplate> jdbc;
        private volatile JdbcRegisteredClientRepository dynamic;

        Wrapper(ObjectProvider<JdbcTemplate> jdbc) { this.jdbc = jdbc; }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (bean instanceof RegisteredClientRepository statics && !(bean instanceof CompositeRegisteredClientRepository)) {
                return new CompositeRegisteredClientRepository(statics, this::dynamic);
            }
            return bean;
        }

        // Created on first use: this post-processor runs before the DataSource is ready to hand out.
        private JdbcRegisteredClientRepository dynamic() {
            var repository = dynamic;
            if (repository == null) {
                synchronized (this) {
                    if (dynamic == null) dynamic = new JdbcRegisteredClientRepository(jdbc.getObject());
                    repository = dynamic;
                }
            }
            return repository;
        }
    }
}
