package net.samitkumar.multi_tenant_salon_authz.config;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.NOT_FOUND, reason = "User not found")
class UserNotfoundException extends RuntimeException {

    public UserNotfoundException() {
        super("User not found");
    }
}
