package net.samitkumar.multi_tenant_salon_authz.ott;

import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import java.security.Principal;
import java.util.*;

/** Presentation only: Spring Security still validates the authorization state and grants consent. */
@Controller
class ConsentController {
    private final RegisteredClientRepository clients;
    private final OAuth2AuthorizationConsentService consents;
    private final MessageSource messages;
    ConsentController(RegisteredClientRepository clients, OAuth2AuthorizationConsentService consents, MessageSource messages) {
        this.clients = clients; this.consents = consents; this.messages = messages;
    }
    record Scope(String value, String label) {}
    @GetMapping("/oauth2/consent")
    String consent(@RequestParam("client_id") String clientId, @RequestParam String scope, @RequestParam String state,
                   Principal principal, Locale locale, Model model) {
        var client = clients.findByClientId(clientId);
        var requested = new LinkedHashSet<>(Arrays.asList(scope.trim().split("\\s+")));
        if (client == null || state.isBlank() || !client.getScopes().containsAll(requested))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        var approved = consents.findById(client.getId(), principal.getName());
        var granted = approved == null ? Set.<String>of() : approved.getScopes();
        var pending = new ArrayList<Scope>(); var previous = new ArrayList<Scope>();
        for (String value : requested) {
            if (value.equals("openid")) continue;
            var item = new Scope(value, messages.getMessage("scope." + value, null, value, locale));
            (granted.contains(value) ? previous : pending).add(item);
        }
        model.addAttribute("accountName", principal.getName());
        model.addAttribute("clientId", clientId); model.addAttribute("state", state);
        model.addAttribute("clientName", client.getClientName() == null ? clientId : client.getClientName());
        model.addAttribute("pendingScopes", pending); model.addAttribute("previousScopes", previous);
        return "consent";
    }
}
