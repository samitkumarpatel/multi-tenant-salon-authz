package net.samitkumar.multi_tenant_saloon_authz;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class MultiTenantSaloonAuthzApplicationTests {

	@Test
	void contextLoads() {
	}

}
