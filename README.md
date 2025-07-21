# JWT Auth Lab: Secure a Dummy Controller with Spring Boot

Welcome to the **JWT Auth Lab**! This step-by-step assignment will teach you how to secure a Spring Boot application using **JWT (JSON Web Tokens)** and **Spring Security**. You don't need a database or a full application — just follow along using IntelliJ IDEA Community Edition.

This exercise is designed for **absolute beginners**. We explain everything from scratch with clear comments and guidance.

---

## ✨ What You Will Build

You will build a minimal Spring Boot application with the following:

* A hardcoded user (no database!)
* A `/login` endpoint that returns a JWT if login is successful
* A protected `/api/secure/hello` endpoint that requires a valid JWT to access
* An optional `/api/secure/admin` endpoint that requires the user to have an ADMIN role

---

## 🚀 Getting Started

### 📅 Step 1: Create the Spring Boot Project with Spring Initializr

1. Open **IntelliJ IDEA Community Edition**
2. Go to **File > New > Project...**
3. Choose **Spring Initializr**

   * Group: `com.example`
   * Artifact: `jwt-auth-lab`
   * Name: `jwt-auth-lab`
4. Click **Next**, then select the following dependencies:

   * **Spring Web**
   * **Spring Security**
   * **Spring Boot DevTools**
5. Click **Finish**. IntelliJ will generate your base project.

---

## ✏️ Step 2: Define the User Model

In `src/main/java/com/example/jwtauthlab/model/User.java`

```java
package com.example.jwtauthlab.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * A simple representation of a user with username, password, and roles.
 * This will be hardcoded instead of being stored in a database.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    /** Username of the user */
    private String username;

    /** Password in plain text (not recommended for real apps!) */
    private String password;

    /** Roles assigned to the user (e.g., USER, ADMIN) */
    private List<String> roles;
}
```

---

## ✨ Step 3: Create JWT Utility Class

In `src/main/java/com/example/jwtauthlab/security/JwtUtil.java`

```java
package com.example.jwtauthlab.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.function.Function;

/**
 * Utility class to generate and validate JWT tokens.
 * It uses a secret key to sign and parse tokens.
 */
@Component
public class JwtUtil {

    // Secret key used to sign the token (in a real app, move to config)
    private final String SECRET_KEY = "my_secret_key";

    /**
     * Extracts username from the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts roles from token (custom claim)
     */
    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("roles", List.class);
    }

    /**
     * Extract expiration date from token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Generic claim extractor
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generate token for a given user
     */
    public String generateToken(String username, List<String> roles) {
        return Jwts.builder()
                .claim("roles", roles) // Add roles to payload
                .setSubject(username)  // Set username
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    /**
     * Validates if the token is for the right user and not expired
     */
    public boolean validateToken(String token, String username) {
        return extractUsername(token).equals(username) && !isTokenExpired(token);
    }

    /**
     * Check if token is expired
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Parses the token and returns all claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }
}
```

---

## 🛡️ Step 4: Configure Spring Security

In `src/main/java/com/example/jwtauthlab/security/SecurityConfig.java`

```java
package com.example.jwtauthlab.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security Configuration class
 * Disables CSRF, enables JWT authentication, and allows /login access
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // disable CSRF for simplicity
            .authorizeHttpRequests()
            .requestMatchers(HttpMethod.POST, "/login").permitAll() // allow login
            .anyRequest().authenticated() // require auth for others
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // no sessions

        return http.build();
    }

    /**
     * Expose AuthenticationManager as a bean
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

---

## 📃 Step 5: Create Login Controller

In `src/main/java/com/example/jwtauthlab/controller/AuthController.java`

```java
package com.example.jwtauthlab.controller;

import com.example.jwtauthlab.model.User;
import com.example.jwtauthlab.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * AuthController handles login requests and returns JWT if credentials are valid.
 */
@RestController
public class AuthController {

    private final JwtUtil jwtUtil;

    // Hardcoded demo user
    private final User demoUser = new User("john", "password", List.of("USER"));

    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest) {
        // Check username/password (plain text match)
        if (loginRequest.getUsername().equals(demoUser.getUsername()) &&
            loginRequest.getPassword().equals(demoUser.getPassword())) {

            String token = jwtUtil.generateToken(demoUser.getUsername(), demoUser.getRoles());
            return ResponseEntity.ok("Bearer " + token);
        }

        return ResponseEntity.status(401).body("Invalid credentials");
    }
}
```

---

## 🛠️ Step 6: Create a Protected Controller

```java
package com.example.jwtauthlab.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Secure endpoints that require a valid JWT to access
 */
@RestController
@RequestMapping("/api/secure")
public class SecureController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello, authenticated user!";
    }
}
```

---

## 🌐 How to Test With Postman

1. **Login to Get JWT Token**

   * Method: POST
   * URL: `http://localhost:8080/login`
   * Body (JSON):

     ```json
     {
       "username": "john",
       "password": "password"
     }
     ```
   * Copy the returned token (starts with `Bearer ...`)

2. **Call Protected Endpoint**

   * Method: GET
   * URL: `http://localhost:8080/api/secure/hello`
   * Headers:

     * Key: `Authorization`
     * Value: `Bearer YOUR_TOKEN_HERE`

3. You should see the response:

   ```text
   Hello, authenticated user!
   ```

---

## 🚀 What’s Next?

* Add role-based access (e.g., restrict /admin endpoint to only ADMIN users)
* Replace hardcoded users with a user service and MongoDB
* Implement password hashing with BCrypt
* Add JWT filter to extract user from token and register as authenticated

---

Happy learning! 🤗
