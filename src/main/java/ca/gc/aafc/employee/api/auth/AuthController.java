package ca.gc.aafc.employee.api.auth;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import jakarta.servlet.http.HttpServletResponse;

@Controller
public class AuthController {
	
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CookieProperties properties;
    
    public AuthController(AuthenticationManager authenticationManager, 
    		JwtService jwtService, CookieProperties properties) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.properties = properties;
    }
    
    @PostMapping("/login")
    public String login(@RequestBody AuthRequest request, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
        		new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtService.generateToken(userDetails);
        ResponseCookie cookie = ResponseCookie.from(properties.name(), jwt)
                .httpOnly(true)
                .secure(properties.secure())
                .path("/")
                .maxAge(Duration.ofHours(1))
                .sameSite("Strict")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        
        return "redirect:/employees"; // make a GET reqeust
    }
}
