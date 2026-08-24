package net.samitkumar.multi_tenant_salon_authz.notification;

import com.fasterxml.jackson.annotation.JsonProperty;

record MailjetEmail(
        @JsonProperty("Email") String email,
        @JsonProperty("Name") String name) {
}
