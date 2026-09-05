package ca.gc.aafc.employee.api.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.cookie")
public record CookieProperties(boolean secure, String name) {}
