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
 * This utility class handles everything related to JWT:
 * - Creating (signing) JWT tokens
 * - Extracting information (claims) from JWT tokens
 * - Validating JWT tokens
 * 
 * It uses the JJWT (io.jsonwebtoken) library to work with tokens.
 */
@Component // Marks this class as a Spring Bean so it can be injected where needed (e.g. in controllers)
public class JwtUtil {

    /**
     * Secret key used to sign the token.
     * 🔐 IMPORTANT: In real applications, do NOT hardcode the secret key.
     * Use an environment variable or configuration file.
     */
    private final String SECRET_KEY = "my_secret_key";

    /**
     * Extracts the username (i.e., the 'subject') from the JWT token.
     *
     * @param token the JWT token received from the client
     * @return the username stored in the token
     */
    public String extractUsername(String token) {
        // 'subject' is the standard field where we store the username
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts custom claim 'roles' from the JWT token.
     * 'roles' is a list we manually add to the token during creation.
     *
     * @param token the JWT token
     * @return list of roles (e.g., ["USER", "ADMIN"]) stored in the token
     */
    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token); // parse full payload from token
        return claims.get("roles", List.class); // get custom 'roles' field
    }

    /**
     * Extracts the expiration date from the token.
     * This helps check whether the token is still valid.
     *
     * @param token the JWT token
     * @return expiration date
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Generic method to extract any claim using a resolver function.
     * Helps to reduce code duplication for extracting various fields.
     *
     * @param token the JWT token
     * @param claimsResolver a lambda function specifying which claim to extract
     * @param <T> the type of claim to extract (e.g., String, Date, List)
     * @return the extracted claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); // get full token data
        return claimsResolver.apply(claims);           // apply custom extraction logic
    }

    /**
     * Generates a JWT token for a given username and list of roles.
     *
     * @param username the username to include in the token
     * @param roles list of roles (e.g., USER, ADMIN)
     * @return a signed JWT token string
     */
    public String generateToken(String username, List<String> roles) {
        return Jwts.builder() // start building the token
                .claim("roles", roles) // add custom claim 'roles' to payload
                .setSubject(username)  // standard claim 'sub' = username
                .setIssuedAt(new Date()) // token creation time = now
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // expires in 1 hour
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // sign using HMAC with SHA-256
                .compact(); // build the token into a compact string
    }

    /**
     * Validates a token by:
     * - Extracting the username and comparing it with expected username
     * - Ensuring the token is not expired
     *
     * @param token the JWT token
     * @param username the expected username
     * @return true if token is valid and belongs to the username
     */
    public boolean validateToken(String token, String username) {
        return extractUsername(token).equals(username) && !isTokenExpired(token);
    }

    /**
     * Checks if the token is expired.
     *
     * @param token the JWT token
     * @return true if the token is expired
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date()); // if expiration is before now, it’s expired
    }

    /**
     * Parses the token and extracts all claims (payload).
     * ⚠️ This method will throw an exception if the token is invalid or tampered with.
     *
     * @param token the JWT token
     * @return all the claims inside the token (including subject, expiration, roles, etc.)
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser() // JWT parser
                .setSigningKey(SECRET_KEY) // key used to verify token signature
                .parseClaimsJws(token)     // parse and verify token
                .getBody();                // extract the payload (claims)
    }
}
```

---

## ✅ Simulation Scenario

Let’s say:

* A user logs in with:

  * `username = "john"`
  * `password = "password"`
  * `roles = ["USER"]`

---

## 🟦 Step 1: User logs in via `/login`

```java
// Simulated in AuthController
User demoUser = new User("john", "password", List.of("USER"));

String token = jwtUtil.generateToken(demoUser.getUsername(), demoUser.getRoles());
```

### ▶ What happens inside `generateToken(...)`

```java
// Input:
username = "john"
roles = ["USER"]

// Inside JwtUtil.generateToken():
return Jwts.builder()
    .claim("roles", roles)              // adds roles as custom claim
    .setSubject(username)               // "sub": "john"
    .setIssuedAt(new Date())            // current time
    .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour expiry
    .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // signs with key
    .compact();
```

---

### ✅ Output:

A real-looking JWT (formatted with line breaks for clarity):

```
eyJhbGciOiJIUzI1NiJ9.         // Header: alg = HS256
eyJyb2xlcyI6WyJVU0VSIl0s      // Payload: roles=["USER"], sub="john", exp=...
ImpvaG4iLCJleHAiOjE3MDAwMDAwMDB9.
z3_3Dz82nO92NA5FXHjLD2t4a7g   // Signature (depends on secret key)
```

> The actual token would be one long string like:
> `eyJhbGciOiJIUzI1NiJ9.eyJyb2xlcyI6WyJVU0VSIl0sInN1YiI6ImpvaG4iLCJleHAiOjE3MDAwMDAwMDB9.z3_3Dz82nO92NA5FXHjLD2t4a7g`

---

## 🟨 Step 2: Client sends this JWT in a request header

**Request:**

```
GET /api/secure/hello
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

---

## 🟩 Step 3: Backend receives the token and validates it

In `SecurityFilter` (which we’ll add later), or any component using `JwtUtil`:

```java
String token = header.replace("Bearer ", "");

// Check if valid
if (jwtUtil.validateToken(token, "john")) {
    // Continue processing the request
    String username = jwtUtil.extractUsername(token); // "john"
    List<String> roles = jwtUtil.extractRoles(token); // ["USER"]
}
```

---

## 🔍 Inside the JWT on the backend:

```json
{
  "roles": ["USER"],
  "sub": "john",
  "iat": 1721550000000,
  "exp": 1721553600000
}
```

---

### ✅ What each method does at runtime:

| Method                         | Output/Explanation                         |
| ------------------------------ | ------------------------------------------ |
| `extractUsername(token)`       | `"john"` – from the `sub` (subject) claim  |
| `extractRoles(token)`          | `["USER"]` – from the custom `roles` claim |
| `extractExpiration(token)`     | `Date` object of expiration time           |
| `validateToken(token, "john")` | `true` if username matches and not expired |

---

## 📌 Data Flow

| Step | Action                                     | Example Value                               |
| ---- | ------------------------------------------ | ------------------------------------------- |
| 1    | User logs in                               | `john` / `password`                         |
| 2    | Server generates token                     | Contains: sub=`john`, roles=`["USER"]`      |
| 3    | Client sends token in Authorization header | `Bearer eyJhbGciOi...`                      |
| 4    | Server validates token                     | Username matches? Expired? Signature valid? |
| 5    | Extract roles for access control           | Use `["USER"]` for route authorization      |


---
### ✅ Summary:

| Section           | What it Does                                    | Why it Matters                                           |
| ----------------- | ----------------------------------------------- | -------------------------------------------------------- |
| `generateToken()` | Creates a signed JWT with username and roles    | So the client can authenticate itself on future requests |
| `extractClaim()`  | Reusable way to pull data from token            | Keeps code clean and avoids repetition                   |
| `validateToken()` | Checks if token is for the right user and valid | Prevents token reuse or forgery                          |
| `SECRET_KEY`      | Used to sign/verify the token                   | Critical for token integrity (must be kept safe)         |

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
 * This class defines Spring Security rules for your application.
 * 
 * Key goals:
 * - Allow anyone to access `/login` to get a JWT
 * - Require authentication for all other endpoints
 * - Disable session management (we’re using JWT instead of sessions)
 * - Disable CSRF (not needed for APIs)
 */
@Configuration // Marks this class as a source of Spring Beans (used by Spring Boot auto-configuration)
public class SecurityConfig {

    /**
     * Configures how HTTP security behaves in our app.
     * 
     * This method creates a SecurityFilterChain bean that Spring Security uses
     * to decide how to protect endpoints and manage authentication.
     * 
     * @param http the HttpSecurity object passed by Spring
     * @return configured SecurityFilterChain bean
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf().disable() 
            // ❌ CSRF (Cross-Site Request Forgery) protection is disabled
            // ✅ Why: It is mainly used in browser-based forms; not needed for token-based APIs

            .authorizeHttpRequests()
            .requestMatchers(HttpMethod.POST, "/login").permitAll() 
            // ✅ Allow anyone to POST to /login without authentication

            .anyRequest().authenticated() 
            // ✅ All other endpoints must be accessed by authenticated users

            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            // ✅ No HTTP sessions will be created — we rely on JWT to carry identity
            // 🔐 Each request must include the JWT to be authorized

        return http.build(); 
        // Finalize and return the security configuration
    }

    /**
     * Exposes the AuthenticationManager as a Spring Bean.
     * 
     * This is required if you want to perform manual authentication 
     * (not used in this basic version but needed for advanced JWT setup).
     * 
     * @param config The configuration automatically provided by Spring Boot
     * @return the AuthenticationManager used internally by Spring Security
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

```
---

### ✅ How It Works in Practice

| Behavior                | Outcome                                               |
| ----------------------- | ----------------------------------------------------- |
| POST `/login`           | ✅ Publicly accessible. Returns JWT if login is valid. |
| GET `/api/secure/hello` | 🔐 Requires valid JWT token in `Authorization` header |
| Sessions                | ❌ Not used. JWT is passed every request.              |
| CSRF Protection         | ❌ Disabled (safe for APIs with token-based auth)      |

---

### ✅ What Happens If JWT Is Missing?

Currently, if you try to access a protected endpoint (like `/api/secure/hello`) **without a JWT**, Spring Security will respond with:

```
403 Forbidden
```

Because no session exists and we didn’t yet plug in a custom `JwtAuthenticationFilter`.

---

### ✅ What You Can Add Later

* A custom `JwtAuthenticationFilter` to:

  * Read the JWT from the header
  * Validate it using `JwtUtil`
  * Set the Spring Security context with `UsernamePasswordAuthenticationToken`
* Role-based access (e.g., `.requestMatchers("/admin").hasRole("ADMIN")`)

---

## 🧠 Simulation Scenario: End-to-End Data Flow

---

### 👤 Actor: The User

* Username: `john`
* Password: `password`
* Roles: `["USER"]`

---

## 🟩 STEP 1: User Logs In

**Request:**

```http
POST /login
Content-Type: application/json

{
  "username": "john",
  "password": "password"
}
```

---

### 🔍 Backend Flow:

#### ✅ AuthController

```java
if (loginRequest.getUsername().equals(demoUser.getUsername()) &&
    loginRequest.getPassword().equals(demoUser.getPassword())) {

    String token = jwtUtil.generateToken(demoUser.getUsername(), demoUser.getRoles());
    return ResponseEntity.ok("Bearer " + token);
}
```

#### ✅ JwtUtil generates this token:

```java
jwtUtil.generateToken("john", List.of("USER"));
```

Which produces a JWT like:

```
eyJhbGciOiJIUzI1NiJ9.
eyJyb2xlcyI6WyJVU0VSIl0sInN1YiI6ImpvaG4iLCJpYXQiOjE3MjE1NTYwMDAsImV4cCI6MTcyMTU1OTYwMH0.
cPZ0DoyIQpBi9a6UuLhBr1cO2Cg8Ycq7R0CqE5SzKFo
```

---

### 🧾 Token Content (decoded):

**Header**:

```json
{
  "alg": "HS256"
}
```

**Payload**:

```json
{
  "roles": ["USER"],
  "sub": "john",
  "iat": 1721556000,
  "exp": 1721559600
}
```

**Signature**:

* Generated using the secret key: `"my_secret_key"`

---

### ✅ Response from Server:

```http
200 OK
Bearer eyJhbGciOiJIUzI1NiJ9...
```

---

## 🟧 STEP 2: Client Makes Authenticated Request

**Request:**

```http
GET /api/secure/hello
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

---

### 🔍 Backend Flow in SecurityConfig

#### ✅ `SecurityConfig` Settings:

```java
.requestMatchers(HttpMethod.POST, "/login").permitAll()
.anyRequest().authenticated()
.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
```

#### 🔒 Spring Security Tries to Authenticate

But — there's a catch:

> **We didn’t yet register a filter to read the JWT from the header.**
> So Spring Security **cannot extract and validate** the token.

---

### ❌ Result:

```http
403 Forbidden
```

Spring says:

> “You need to be authenticated to access this, but I don’t know how to handle your JWT.”

---

## ✅ Summary of Current Setup

| Step                   | What Happens                                                  |
| ---------------------- | ------------------------------------------------------------- |
| Login (`POST /login`)  | Allowed for everyone. JWT is created and sent to client.      |
| Secure Endpoint Access | Denied (403 Forbidden) unless we add a JWT filter.            |
| SecurityConfig         | Requires auth for all routes except `/login`. Stateless only. |
| Next Needed Step       | Plug in a filter to decode JWT and populate security context. |

---

### ✅ What to Learn from This Simulation

* Spring Security is enforcing access rules as expected.
* The token is valid and created properly.
* We need a **JWT Authentication Filter** to **read, validate, and authenticate** the JWT token from the request header — that’s the missing piece.

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
 * Controller responsible for handling login requests.
 * 
 * This class simulates login without a database — it compares
 * input credentials to a hardcoded user, and returns a JWT token
 * if the login is successful.
 */
@RestController // Marks this class as a REST controller that returns JSON responses
public class AuthController {

    private final JwtUtil jwtUtil;

    /**
     * Hardcoded user for demonstration purposes.
     * In real applications, this data would come from a database.
     */
    private final User demoUser = new User(
            "john",              // username
            "password",          // password (in plain text — not secure!)
            List.of("USER")      // roles assigned to this user
    );

    /**
     * Constructor-based dependency injection for JwtUtil
     */
    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    /**
     * Accepts login requests and returns a JWT token on success.
     * 
     * @param loginRequest JSON payload containing username and password
     * @return JWT token in plain text with \"Bearer \" prefix, or 401 error
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest) {
        // Compare the incoming username/password with the hardcoded user
        if (loginRequest.getUsername().equals(demoUser.getUsername()) &&
            loginRequest.getPassword().equals(demoUser.getPassword())) {

            // ✅ Credentials are valid → Generate JWT
            String token = jwtUtil.generateToken(
                    demoUser.getUsername(),
                    demoUser.getRoles()
            );

            // ✅ Return the token to the client with "Bearer " prefix
            return ResponseEntity.ok("Bearer " + token);
        }

        // ❌ If credentials are wrong, return HTTP 401 (unauthorized)
        return ResponseEntity.status(401).body("Invalid credentials");
    }
}
```

---

## 🧪 Simulation Example: Logging In via Postman

### ✅ Step-by-Step

1. Open **Postman**
2. Create a **POST** request to:

```
http://localhost:8080/login
```

3. Go to the **Body** tab → Select **raw** → Choose **JSON**

4. Enter this payload:

```json
{
  "username": "john",
  "password": "password"
}
```

5. Click **Send**

### ✅ Expected Response:

```http
200 OK
Bearer eyJhbGciOiJIUzI1NiJ9.eyJ...etc...
```

---

### ❌ Example: Invalid Login

Try:

```json
{
  "username": "john",
  "password": "wrongpassword"
}
```

You’ll receive:

```http
401 Unauthorized
Invalid credentials
```

---

## ✅ Summary of Responsibilities

| Method        | What it Does                                                       |
| ------------- | ------------------------------------------------------------------ |
| `POST /login` | Accepts credentials, compares to hardcoded user, returns JWT       |
| `jwtUtil`     | Generates signed JWT token with `username` + `roles`               |
| Response      | Returns `Bearer <token>` so it can be used in Authorization header |

---

## 🛠️ Step 6: Create a Protected Controller

```java
package com.example.jwtauthlab.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This controller provides protected endpoints that require a valid JWT.
 * 
 * Once a user logs in and receives a JWT, they can use it to access
 * these routes by including it in the Authorization header of their request.
 */
@RestController // Marks this class as a REST controller that returns JSON/text responses
@RequestMapping("/api/secure") // Base path for all endpoints in this controller
public class SecureController {

    /**
     * Protected endpoint that requires authentication.
     * 
     * To access this endpoint, the user must include a valid JWT
     * in the Authorization header (e.g. "Bearer eyJhbGciOi...").
     * 
     * @return A welcome message for authenticated users
     */
    @GetMapping("/hello")
    public String hello() {
        // This method is called only if the user is authenticated
        return "Hello, authenticated user!";
    }

    /**
     * Admin-only endpoint (for future enhancement).
     * 
     * Currently accessible to any authenticated user.
     * Later, we can restrict it using roles with @PreAuthorize or config rules.
     * 
     * @return A message intended for admin users
     */
    @GetMapping("/admin")
    public String admin() {
        return "Hello, ADMIN user!";
    }
}
```

---

### 🧪 How to Test with Postman

After you’ve logged in via `/login` and received a JWT token:

---

#### ✅ Access `/api/secure/hello`

* **Method**: `GET`
* **URL**: `http://localhost:8080/api/secure/hello`
* **Headers**:

  * `Authorization`: `Bearer <paste-your-token-here>`

**Response:**

```
Hello, authenticated user!
```

---

#### ❌ If You Forget the Token

You’ll receive:

```
403 Forbidden
```

This is because Spring Security knows the endpoint requires authentication, but the request didn’t provide valid credentials.

---

## ✅ What This Teaches

| Concept              | What They Learn                                                   |
| -------------------- | ----------------------------------------------------------------- |
| Controller security  | How Spring Security protects endpoints using the filter chain     |
| JWT usage            | How to include JWTs in Authorization headers                      |
| Stateless API design | How authentication is handled **without** sessions or login state |
| Route structure      | How to organize APIs with `@RequestMapping` and `@GetMapping`     |


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
