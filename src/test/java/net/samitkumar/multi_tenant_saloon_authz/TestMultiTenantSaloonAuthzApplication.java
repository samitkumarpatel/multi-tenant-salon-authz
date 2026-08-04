package net.samitkumar.multi_tenant_saloon_authz;

import org.springframework.boot.SpringApplication;

public class TestMultiTenantSaloonAuthzApplication {

	public static void main(String[] args) {
		SpringApplication.from(MultiTenantSaloonAuthzApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
