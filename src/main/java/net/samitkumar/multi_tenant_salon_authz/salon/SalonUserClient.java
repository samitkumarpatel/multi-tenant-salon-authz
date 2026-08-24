package net.samitkumar.multi_tenant_salon_authz.salon;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

import java.util.Optional;

@HttpExchange(url = "${spring.application.identity-service-url}")
public interface SalonUserClient {
    @GetExchange("/internal/user-identity")
    Optional<SalonUser> getUserIdentity(@RequestParam("email") String email);
}
