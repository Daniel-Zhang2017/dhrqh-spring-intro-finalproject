package com.app.quiz.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ui.Model;
import org.springframework.security.core.Authentication;
import com.app.quiz.service.QuizUserDetailsService;
import com.app.quiz.model.Quiz;
import com.app.quiz.service.QuestionsService;

@Controller
public class QuizController {

    private final QuizUserDetailsService userDetailsService;
    private final QuestionsService questionsService;
    private final AuthenticationManager authenticationManager;

    public QuizController(QuizUserDetailsService userDetailsService, AuthenticationManager authenticationManager, QuestionsService questionsService) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.questionsService = questionsService;
    }
    
    @GetMapping("/home")
    public String homepage(Model model) {
        // Get the authenticated user's details
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Get the username
        String username = authentication.getName();
        model.addAttribute("username", username);

        // Get the user's role
        String role = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .findFirst()
            .orElse("ROLE_USER"); // Default role if no authority is found

        // Redirect to the appropriate page based on the role
        if (role.equals("ROLE_ADMIN")) {
            // Fetch the latest quizzes from the service
            List<Quiz> quizzes = questionsService.getQuizzesList();
        
            // Add the quizzes to the model
            model.addAttribute("quizzes", quizzes);
            return "QuizList"; // Return the QuizList.html template
        } else {
            // Fetch the latest quizzes from the service
            List<Quiz> quizzes = questionsService.getQuizzesList();
        
            // Add the quizzes to the model
            model.addAttribute("quizzes", quizzes);
            return "Quiz"; // Return the Quiz.html template
        }
    }

    @GetMapping("/login")
    public String login() {
        return "login"; // Returns the login.html template
    }

    @GetMapping("/register")
    public String register(Model model) {
        return "register"; // Returns the register.html template
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access-denied"; // Returns the access-denied.html template
    }

    // POST endpoint to handle user registration and auto-login
    @PostMapping("/register")
    public String registerUser(
            @RequestParam String username, // Username from the form
            @RequestParam String password, // Password from the form
            @RequestParam String email,
            @RequestParam String role // Role from the form
    ) {
        // Register the user by storing their details in the HashMap
        try {
            userDetailsService.registerUser(username, password, email, role);
        } catch (Exception userExistsAlready) {
            // Redirect to the /register endpoint
            return "redirect:/register?error";
        }

        // Authenticate the user programmatically
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );

        // Set the authentication in the SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Redirect to the home page (用户已自动登录，直接跳转到首页)
        return "redirect:/home";
    }    

    @GetMapping("/addQuiz")
    public String showAddQuizForm(Model model) {
        model.addAttribute("quiz", new Quiz()); // Add a new Quiz object to the model
        return "addQuiz"; // Return the addQuiz.html template
    }

    @PostMapping("/addQuiz")
    public String addQuiz(@ModelAttribute Quiz quiz, Model model, Authentication authentication) {
        // Get the user's role
        String role = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .findFirst()
            .orElse("ROLE_USER"); // Default role if no authority is found

        // Redirect to the appropriate page based on the role
        if (role.equals("ROLE_ADMIN")) {
            quiz.setId(questionsService.getNextId());
            // Add the quiz to the service
            questionsService.addQuiz(quiz);

            // Add a success message to the model
            model.addAttribute("success", "Quiz added successfully!");

            // Redirect to the quiz list page
            return "redirect:/home";
        } else {
            // Add an error message to the model
            model.addAttribute("error", "You do not have permission to add a quiz.");

            // Redirect to the add quiz page
            return "redirect:/addQuiz?error";
        }
    }

    // Display the edit quiz page
    @GetMapping("/editQuiz/{id}")
    public String showEditQuizForm(@PathVariable("id") int id, Model model) {
        // Find the quiz by ID
        Quiz quiz = questionsService.getQuizById(id);
        
        // Add the quiz to the model
        model.addAttribute("quiz", quiz);
        
        // Return the editQuiz.html template
        return "editQuiz";
    }

    @PostMapping("/editQuestion")
    public String editQuestion(@ModelAttribute("quiz") Quiz quiz) {
        // Get the authenticated user's details
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Get the user's role
        String role = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .findFirst()
            .orElse("ROLE_USER"); // Default role if no authority is found

        // Redirect to the appropriate page based on the role
        if (role.equals("ROLE_ADMIN")) {
            // Update the quiz in the service
            questionsService.editQuiz(quiz);
            // Redirect to the quiz list page
            return "redirect:/home";
        } else {
            // Redirect to the quiz page
            return "redirect:/home";
        }
    }

    @GetMapping("/deleteQuiz/{id}")
    public String deleteQuiz(@PathVariable("id") int id, Model model) {
        // Get the authenticated user's details
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Get the user's role
        String role = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .findFirst()
            .orElse("ROLE_USER"); // Default role if no authority is found
    
        // Redirect to the appropriate page based on the role
        if (role.equals("ROLE_ADMIN")) {
            // Delete the quiz by ID
            questionsService.deleteQuiz(id);
            return "redirect:/home"; // Redirect to the quiz list page
        } else {
            return "redirect:/home"; // Redirect to the home page
        }
    }

    @PostMapping("/submitQuiz")
    public String evaluateQuiz(@RequestParam Map<String, String> allParams, Model model) {
        int correctAnswers = 0;
        List<String> userAnswers = new ArrayList<>();
        ArrayList<Quiz> quizzes = questionsService.getQuizzesList();

        // Iterate through the quizzes and compare answers
        for (int i = 0; i < quizzes.size(); i++) {
            String userAnswer = allParams.get("answer" + i); // Get the answer for question i
            userAnswers.add(userAnswer); // Store user's answer
            if (quizzes.get(i).getCorrectAnswer().equals(userAnswer)) {
                correctAnswers++;
            }
        }

        // Add data to the model
        model.addAttribute("quizzes", quizzes);
        model.addAttribute("userAnswers", userAnswers);
        model.addAttribute("correctAnswers", correctAnswers);
        model.addAttribute("totalQuestions", quizzes.size());

        // Return the result template
        return "result";
    }
}