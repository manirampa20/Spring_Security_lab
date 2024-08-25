//package com.springsecurity.spring.security.project.service;
//
//import com.springsecurity.spring.security.project.model.User;
//import com.springsecurity.spring.security.project.repository.UserRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
//import java.util.List;
//import java.util.Optional;
//
////@Service
//public class UserService implements UserDetailsService {
//
//    @Autowired
//    private UserRepository userRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        Optional<User> user = userRepository.findByUsername(username);
//        if (user.isEmpty()) {
//            throw new UsernameNotFoundException("User not found.");
//        }
//        User existingUser = user.get();
//        return org.springframework.security.core.userdetails.User.withUsername(existingUser.getUsername())
//                .password(existingUser.getPassword())
//                .roles(existingUser.getRole())
//                .build();
//    }
//
//    // Save or update a user
//    public User saveUser(User user) {
//        return userRepository.save(user);
//    }
//
//    // Find all users
//    public List<User> findAllUsers() {
//        return userRepository.findAll();
//    }
//
//    // Find user by ID
//    public Optional<User> findUserById(Long id) {
//        return userRepository.findById(id);
//    }
//
//    // Delete a user by ID
//    public boolean deleteUserById(Long id) {
//        if (userRepository.existsById(id)) {
//            userRepository.deleteById(id);
//            return true;
//        }
//        return false;
//    }
//}
