package ca.gc.aafc.employee.api.auth;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import ca.gc.aafc.employee.api.user.CustomUserDetailsService;
import io.jsonwebtoken.JwtException;

@Component
public class JwtFilter extends OncePerRequestFilter {
	
	private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;    
    private final String cookieName;
    
    public JwtFilter(JwtService jwtService, CustomUserDetailsService userDetailsService,
    		@Value("${app.cookie.name}") String cookieName) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.cookieName = cookieName;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
    	// Avoid 403 on /favicon.ico and errors in console
    	String uri = request.getRequestURI();
    	if (uri.startsWith("/favicon.ico") || uri.startsWith("/.well-known")) return;
    	
    	String jwt = null;
    	Cookie[] cookies = request.getCookies();
    	if (cookies != null) {
    	    for (Cookie cookie : cookies) {
    	        if (cookieName.equals(cookie.getName())) {
    	            jwt = cookie.getValue();
    	            break;
    	        }
    	    }
    	}
    	
        if (jwt == null || jwt.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }
    	
        try {
            String username = jwtService.extractUsername(jwt);
	        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
	            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
	            
	            if (jwtService.isTokenValid(jwt, userDetails)) {
	                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
	                		userDetails, null, userDetails.getAuthorities());
	                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
	                SecurityContextHolder.getContext().setAuthentication(auth);
	            }
	        }
        } catch (JwtException e) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT");
            // response.sendRedirect("/401"); // src/main/webapp/WEB-INF/views/401.jsp
            return;
        }
        
        filterChain.doFilter(request, response);
    }
}
