# JWT Auth Lab: Secure a Dummy Controller (Beginner Friendly)

Welcome to the **JWT Auth Lab**! In this hands-on mini-assignment, you'll learn how to use **Spring Security** and **JWT (JSON Web Tokens)** to secure a simple REST API without the need for a database or full user management system.

> **Target audience**: Absolute beginners who already created a `User` model and want to explore authentication and authorization with JWT in Spring Boot.

---

## ✨ What You'll Build

A minimal Spring Boot application that:

* Has a hardcoded user
* Allows login with username and password
* Generates and returns a JWT token
* Allows access to a protected endpoint **only** if a valid token is provided
* Restricts access based on roles (e.g., only `ADMIN` can call certain routes)

---

## ⚖️ Technologies Used

* Java 17+
* Spring Boot
* Spring Security
* Maven
* JWT (via `io.jsonwebtoken.Jwts`)
* No database (hardcoded users)

---

## ✍️ Step-by-Step Instructions

### 1. Create a Spring Boot Project

Use your usual IntelliJ setup without Spring Initializr.

```
mkdir jwt-auth-lab
cd jwt-auth-lab
mvn archetype:generate -DgroupId=com.example -DartifactId=jwt-auth-lab -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false
```

Update the generated folder structure to a Spring Boot project with:

* `Main` class annotated with `@SpringBootApplication`
* Java 17 compiler

### 2. Add Dependencies in `pom.xml`

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.9.1</version>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

---

### 3. Create the `User` Model

```java
package com.example.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private String username;
    private String password;
    private List<String> roles;
}
```

### 4. Create a Dummy User Service

```java
package com.example.service;

import com.example.model.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DummyUserService {
    public User getUserByUsername(String username) {
        if (username.equals("user")) {
            return new User("user", "password", List.of("ROLE_USER"));
        } else if (username.equals("admin")) {
            return new User("admin", "adminpass", List.of("ROLE_ADMIN"));
        }
        return null;
    }
}
```

---

### 5. Create JWT Utility Class

```java
package com.example.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {
    private final String SECRET = "secret123";

    public String generateToken(String username, List<String> roles) {
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    public String validateTokenAndRetrieveSubject(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
```

---

### 6. Create the Login Controller

```java
package com.example.controller;

import com.example.model.User;
import com.example.service.DummyUserService;
import com.example.util.JwtUtil;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private DummyUserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest request) {
        User user = userService.getUserByUsername(request.getUsername());
        if (user == null || !user.getPassword().equals(request.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }
        return jwtUtil.generateToken(user.getUsername(), user.getRoles());
    }

    @Data
    static class AuthRequest {
        private String username;
        private String password;
    }
}
```

---

### 7. Create a Protected Endpoint

```java
package com.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/secure")
public class SecureController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello, you are authenticated!";
    }

    @GetMapping("/admin")
    public String admin() {
        return "Only admins can see this.";
    }
}
```

---

### 8. Configure Security and JWT Filter

You’ll need to:

* Create a filter that reads the `Authorization` header
* Validates the token
* Sets the authentication in `SecurityContextHolder`

For beginners, we’ll keep this part simple. You can follow the official [Spring Security + JWT](https://www.baeldung.com/spring-security-oauth-jwt) guide for deeper customization.

---

## 💳 Testing the App with Postman

1. POST to `/auth/login` with body:

```json
{
  "username": "user",
  "password": "password"
}
```

2. Copy the returned token.
3. GET `/api/secure/hello` with header:

```
Authorization: Bearer <token>
```

4. Try `/api/secure/admin` with a `user` token — it should be forbidden.
5. Repeat login with `admin` user.

---

## 🚀 Optional Challenge

* Add a filter for JWT validation
* Inject roles from the token
* Protect `/api/secure/admin` with `@PreAuthorize("hasRole('ADMIN')")`

---

## 📅 Submission

Push your solution to your GitHub and share the link.
Make sure your README includes:

* How to run the app
* Example requests
* Screenshots (optional)

---

## 📚 What You Learned

* What JWT is and how it works
* How to create and validate JWTs in Spring
* How to secure endpoints based on roles

---

Need help? Ask your instructor!

Happy coding! ✨
