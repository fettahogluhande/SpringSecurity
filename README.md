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

<br>

<p>
    This security configuration employs role-based access control for regulating endpoint access. Roles such as ROLE_USER, ROLE_FSK, and ROLE_ADMIN determine authorization levels. For example, /public endpoints are open to all users, while /private/admin requires ROLE_ADMIN. /private endpoints are accessible to ROLE_USER, ROLE_FSK, and ROLE_ADMIN. H2 Console access is restricted to "ADMIN" users. This role-centric approach allows administrators to flexibly control and secure application sections based on user roles.
</p>


<br>

```
      private void createDumyData() {
        CreateUserRequest request = CreateUserRequest.builder()
                .name("Emin")
                .username("emin")
                .password("pass")
                .authorities(Set.of(Role.ROLE_USER))
                .build();
        userService.createUser(request);

        CreateUserRequest request2 = CreateUserRequest.builder()
                .name("FSK")
                .username("fsk")
                .password("pass")
                .authorities(Set.of(Role.ROLE_FSK))
                .build();
        userService.createUser(request2);

        CreateUserRequest request3 = CreateUserRequest.builder()
                .name("No Name")
                .username("noname")
                .password("pass")
                .authorities(Set.of(Role.ROLE_ADMIN))
                .build();
        userService.createUser(request3);
    }
```
![image](https://github.com/fettahogluhande/SpringSecurity/assets/75665898/5f4ee4d9-9e7a-45ee-891f-f9802bd18491)
```
.requestMatchers(mvcRequestBuilder.pattern("/public/**")).permitAll(): Any request matching the pattern /public/** 
```
is permitted without authentication. This means that these endpoints are accessible to everyone without the need for authentication.
```
.requestMatchers(mvcRequestBuilder.pattern("/private/admin/**")).hasRole(Role.ROLE_ADMIN.getValue()): 
```
require the user to have the role ROLE_ADMIN. This means only users with the ROLE_ADMIN role will be authorized to access these endpoints.
```
.requestMatchers(mvcRequestBuilder.pattern("/private/**")).hasAnyRole(Role.ROLE_USER.getValue(), Role.ROLE_FSK.getValue(), Role.ROLE_ADMIN.getValue()):
```
can be accessed by users with any of the specified roles (ROLE_USER, ROLE_FSK, ROLE_ADMIN). It uses hasAnyRole to check for multiple roles.
```
.requestMatchers(PathRequest.toH2Console()).hasRole("ADMIN"):
```
Requests to the H2 Console path require the user to have the role "ADMIN". This ensures that access to the H2 Console is restricted to users with the specified role.

