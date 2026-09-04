package ca.gc.aafc.employee.api.auth;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.function.EntityResponse;

import ca.gc.aafc.employee.api.employee.EmployeeResponse;
import jakarta.servlet.http.HttpServletResponse;

@RestController
//@Controller
public class AuthController {
	
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    
    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }
    
    // header-based authN: start
//    @PostMapping("/login")
//    public AuthResponse login(@RequestBody AuthRequest request, HttpServletResponse response) {
//        // Authenticate username/password
//        Authentication authentication = authenticationManager.authenticate(
//        		new UsernamePasswordAuthenticationToken(request.username(), request.password()));
//        
//        // Get authenticated user
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//        
//        // Generate JWT
//        String token = jwtService.generateToken(userDetails);
//        
//        // Return JWT to client
//        return new AuthResponse(token);
//	}
    // header-based authN: end
    	
    // cookie-based authN: start
    @PostMapping("/login")
    public ResponseEntity<EmployeeResponse> login(@RequestBody AuthRequest request, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
        		new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        
        // Get authenticated user
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        
        // Generate JWT
        String jwt = jwtService.generateToken(userDetails);
        
        ResponseCookie cookie = ResponseCookie.from("JWT", jwt)
                .httpOnly(true)
                .secure(true)       // HTTPS in production
                .path("/")
                .maxAge(Duration.ofHours(1))
                .sameSite("Lax")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        
        return ResponseEntity.ok(new EmployeeResponse(1L, "Lei Liu", 80000L, "IT")); // "redirect:/employees";
    }
    // cookie-based authN: end
}
