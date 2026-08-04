package net.samitkumar.multi_tenant_saloon_authz;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ThrowingCustomizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.registry.ImportHttpServices;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

import java.util.Collection;
import java.util.List;

@SpringBootApplication
@EnableWebSecurity
@ImportHttpServices(JsonPlaceHolderClient.class)
public class MultiTenantSaloonAuthzApplication {

	public static void main(String[] args) {
		SpringApplication.run(MultiTenantSaloonAuthzApplication.class, args);
	}

	@Bean
	RouterFunction<ServerResponse> routerFunction() {
		return RouterFunctions.route().GET("/", request -> ServerResponse.accepted().body("Hello, World!")).build();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) {
		http
			.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
			.formLogin(AbstractHttpConfigurer::disable)
			.oneTimeTokenLogin(ott -> ott
					.tokenGenerationSuccessHandler((request, response, oneTimeToken) -> {
						//Implement the email sending logic here
						IO.println("### OTT Token: " + oneTimeToken.getTokenValue());
						response.sendRedirect("/login/ott");
					})
			)
			.oauth2AuthorizationServer((authorizationServer) ->
				authorizationServer.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
			);

		return http.build();
	}

	@Bean
	UserDetailsService  userDetailsService(JsonPlaceHolderClient  jsonPlaceHolderClient) {
		return username -> jsonPlaceHolderClient.getUser(username).getFirst();
	}

}

record JsonPlaceholderUser(String id, String username, String email) implements UserDetails {
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of();
	}

	@Override
	public @Nullable String getPassword() {
		return "{noop}";
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return UserDetails.super.isAccountNonExpired();
	}

	@Override
	public boolean isAccountNonLocked() {
		return UserDetails.super.isAccountNonLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return UserDetails.super.isCredentialsNonExpired();
	}

	@Override
	public boolean isEnabled() {
		return UserDetails.super.isEnabled();
	}
}

@HttpExchange(url = "https://jsonplaceholder.typicode.com")
interface JsonPlaceHolderClient {
	@GetExchange("/users")
	List<JsonPlaceholderUser> getUser(@RequestParam("username") String username);
}

