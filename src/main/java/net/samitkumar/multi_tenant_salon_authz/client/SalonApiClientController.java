package net.samitkumar.multi_tenant_salon_authz.client;

import net.samitkumar.multi_tenant_salon_authz.client.SalonApiClientService.ClientException;
import net.samitkumar.multi_tenant_salon_authz.client.SalonApiClientService.ClientView;
import net.samitkumar.multi_tenant_salon_authz.client.SalonApiClientService.CreatedClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Called only by the salon API (see {@link InternalApiKeyFilter}), which has already established that the caller owns
 * {@code salonId}. Authz still scopes every query by that id, so a client id of another salon is simply "not found".
 */
@RestController
@RequestMapping("/internal/clients")
class SalonApiClientController {
    private final SalonApiClientService clients;

    SalonApiClientController(SalonApiClientService clients) { this.clients = clients; }

    record CreateRequest(String salonId, String name, List<String> scopes, String createdBy) {}

    @GetMapping("/scopes")
    Set<String> scopes() { return SalonApiClientService.ALLOWED_SCOPES; }

    @GetMapping
    List<ClientView> list(@RequestParam String salonId) {
        return clients.list(salon(salonId));
    }

    @PostMapping
    ResponseEntity<CreatedClient> create(@RequestBody CreateRequest request) {
        return ResponseEntity.status(201).body(clients.create(salon(request.salonId()), request.name(), request.scopes(), request.createdBy()));
    }

    @PostMapping("/{clientId}/rotate")
    CreatedClient rotate(@PathVariable String clientId, @RequestParam String salonId) {
        return clients.rotate(salon(salonId), clientId);
    }

    @DeleteMapping("/{clientId}")
    ResponseEntity<Void> revoke(@PathVariable String clientId, @RequestParam String salonId, @RequestParam(required = false) String actor) {
        clients.revoke(salon(salonId), clientId, actor);
        return ResponseEntity.noContent().build();
    }

    // Handled here, not thrown as ResponseStatusException: an error dispatch would be sent through the login chain.
    @ExceptionHandler(ClientException.class)
    ResponseEntity<Map<String, String>> clientError(ClientException e) {
        return ResponseEntity.status(e.status).body(Map.of("error", e.getMessage()));
    }

    private static UUID salon(String salonId) {
        try {
            return UUID.fromString(salonId);
        } catch (RuntimeException e) {
            throw new ClientException(400, "salonId must be a UUID");
        }
    }
}
