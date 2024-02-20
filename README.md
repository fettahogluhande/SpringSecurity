#  Security 
This project includes a security configuration for securing web applications using Spring Security. The configuration provides in-memory user authentication and authorization.

## BCrypt Password Encoder
The project utilizes the BCryptPasswordEncoder to securely encode passwords. This ensures that user passwords are stored securely in the system.
```
@Bean
public BCryptPasswordEncoder bCryptPasswordEncoder(){
    return new BCryptPasswordEncoder();
}
```

## User Details Service
In-memory user details are provided using the InMemoryUserDetailsManager. Two users, one with the role "USER" and another with the role "ADMIN," are created with encoded passwords.
```
@Bean
public UserDetailsService users(){
    UserDetails user1 = User.builder()
            .username("fsk")
            .password(bCryptPasswordEncoder().encode("pass"))
            .roles("USER")
            .build();

    UserDetails admin = User.builder()
            .username("hande")
            .password(bCryptPasswordEncoder().encode("pass"))
            .roles("ADMIN")
            .build();

    return new InMemoryUserDetailsManager(user1, admin);
}
```

## Security Filter Chain
The security configuration defines a custom SecurityFilterChain using the HttpSecurity class. It includes settings to disable certain security features, permit access to specific endpoints, and enforce role-based access control.
```
@Bean
public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
    security
            .headers(x -> x.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(x -> x.requestMatchers("/public/**", "/auth/**").permitAll())
            .authorizeHttpRequests(x -> x.requestMatchers("/private/user/**").hasRole("USER"))
            .authorizeHttpRequests(x -> x.requestMatchers("/private/admin/**").hasRole("ADMIN"))
            .authorizeHttpRequests(x -> x.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults());

    return security.build();
}
```

## Testing Public Endpoint with Postman
You can use Postman to send a GET request to the public endpoint and private endpoint.
1. Ensure the Application is Running:
Make sure your Spring Boot application is up and running on http://localhost:8020.
2. Open Postman:
Open Postman on your local machine.
3. Send GET Request:
Create a new GET request and enter the following URL: http://localhost:8020/public.
4. Receive Response:
```
Hello World! from public endpoint
```
This confirms that the public endpoint is accessible.<br> <br> 
**note:** Try the same things by typing http://localhost:8020/private. However, do not forget to select basic auth from Authorization and enter the username and password we specified in the code.

![image](https://github.com/fettahogluhande/SpringSecurity/assets/75665898/4ac48c4d-ddc5-4e22-8781-d785bb6483dc)

<hr>

## Spring Security Basic Authentication Example

- **Basic Authentication:** Securing the application with username and password.
- **Role-based Authorization:** Implementing role-based access control for different parts of the application.
- **Endpoint Security:** Configuring security for specific endpoints.
- **H2 Console Integration:** Allowing access to the H2 Console for development purposes.

### H2 Console
For development purposes, the H2 Console is accessible.<br>
The security configuration allows access to the H2 Console at http://localhost:8080/h2-console with the following credentials:

* URL: jdbc:h2:mem:testdb
* User: sa
* Password: (empty)
