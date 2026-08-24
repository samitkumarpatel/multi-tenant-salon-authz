package net.samitkumar.multi_tenant_salon_authz.notification;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

import java.util.Map;

@HttpExchange("https://api.mailjet.com/v3.1")
public interface MailJetClient {
    @PostExchange("/send")
    Map<String, Object> send(@RequestBody MailjetRequest request);
}
