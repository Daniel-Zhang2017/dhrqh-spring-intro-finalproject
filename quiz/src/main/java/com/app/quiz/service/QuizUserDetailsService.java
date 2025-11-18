package com.app.quiz.service;

import com.app.quiz.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;

@Service
public class QuizUserDetailsService implements UserDetailsService {

    // Data structure to store user details
    private final Map<String, User> users = new HashMap<>();
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Loads user by username for authentication
     * @param username the username identifying the user whose data is required
     * @return UserDetails object containing user information
     * @throws UsernameNotFoundException if the user is not found
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole())
                .build();
    }

    /**
     * Registers a new user with the system
     * @param username the username for the new user
     * @param password the password for the new user
     * @param email the email address for the new user
     * @param role the role for the new user (e.g., "USER", "ADMIN")
     * @return the registered User object
     * @throws IllegalArgumentException if username already exists
     */
    public User registerUser(String username, String password, String email, String role) {
        if (users.containsKey(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        // Validate input parameters
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }
        if (role == null || role.trim().isEmpty()) {
            throw new IllegalArgumentException("Role cannot be null or empty");
        }

        // Encode the password before storing
        String encodedPassword = passwordEncoder.encode(password);
        
        // Create and store the new user
        User newUser = new User(username, encodedPassword, email, role);
        users.put(username, newUser);
        
        return newUser;
    }

    /**
     * Helper method to check if a username exists
     * @param username the username to check
     * @return true if the username exists, false otherwise
     */
    public boolean userExists(String username) {
        return users.containsKey(username);
    }

    /**
     * Helper method to get all registered users (for debugging/admin purposes)
     * @return map of all registered users
     */
    public Map<String, User> getAllUsers() {
        return new HashMap<>(users);
    }

    /**
     * Helper method to get user count
     * @return number of registered users
     */
    public int getUserCount() {
        return users.size();
    }
}