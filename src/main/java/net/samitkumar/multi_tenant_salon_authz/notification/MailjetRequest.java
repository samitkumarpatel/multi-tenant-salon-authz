package net.samitkumar.multi_tenant_salon_authz.notification;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

record MailjetRequest(@JsonProperty("Messages") List<MailjetMessage> messages) {}
