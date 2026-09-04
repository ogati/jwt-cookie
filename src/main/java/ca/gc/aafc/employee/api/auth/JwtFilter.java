package ca.gc.aafc.employee.api.auth;

import java.io.IOException;

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
    
    public JwtFilter(JwtService jwtService, CustomUserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
    	// Header-based authN: start
//        String header = request.getHeader("Authorization");
//        if (header == null || !header.startsWith("Bearer ")) { // if no token, the request is for login page
//            filterChain.doFilter(request, response);
//            return;
//        }
//        
//        String jwt = header.substring(7);
//        if (token.isBlank()) {
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT");
//            return;
//        }
    	// Header-based authN: end
    	
    	// Cookie-based authN: start
    	String jwt = null;
    	Cookie[] cookies = request.getCookies();
    	if (cookies != null) {
    	    for (Cookie cookie : cookies) {
    	        if ("JWT".equals(cookie.getName())) {
    	            jwt = cookie.getValue();
    	            break;
    	        }
    	    }
    	}
    	
        if (jwt == null || jwt.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }
        // Cookie-based authN: end
    	
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
