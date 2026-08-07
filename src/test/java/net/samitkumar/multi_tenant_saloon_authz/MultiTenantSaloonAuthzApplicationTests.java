package net.samitkumar.multi_tenant_saloon_authz;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class MultiTenantSaloonAuthzApplicationTests {

    @MockitoBean
    SaloonUserClient saloonUserClient;

    @Test
    void contextLoads() {
    }
}
