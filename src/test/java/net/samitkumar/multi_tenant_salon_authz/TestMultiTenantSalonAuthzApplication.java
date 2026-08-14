package net.samitkumar.multi_tenant_salon_authz;

import org.springframework.boot.SpringApplication;

public class TestMultiTenantSalonAuthzApplication {

	public static void main(String[] args) {
		SpringApplication.from(MultiTenantSalonAuthzApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
