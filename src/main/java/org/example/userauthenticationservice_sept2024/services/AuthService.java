package org.example.userauthenticationservice_sept2024.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.antlr.v4.runtime.misc.Pair;
import org.example.userauthenticationservice_sept2024.clients.KafkaProducerClient;
import org.example.userauthenticationservice_sept2024.dtos.EmailDto;
import org.example.userauthenticationservice_sept2024.dtos.RequestStatus;
import org.example.userauthenticationservice_sept2024.dtos.ValidateTokenResponseDto;
import org.example.userauthenticationservice_sept2024.exceptions.UserAlreadyExistsException;
import org.example.userauthenticationservice_sept2024.exceptions.UserNotFoundException;
import org.example.userauthenticationservice_sept2024.exceptions.WrongPasswordException;
import org.example.userauthenticationservice_sept2024.models.Session;
import org.example.userauthenticationservice_sept2024.models.SessionState;
import org.example.userauthenticationservice_sept2024.models.User;
import org.example.userauthenticationservice_sept2024.repositories.SessionRepository;
import org.example.userauthenticationservice_sept2024.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bcryptPasswordEncoder;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    SecretKey secretKey;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private KafkaProducerClient kafkaProducerClient;

//    public AuthService(UserRepository userRepository,BCryptPasswordEncoder bcryptPasswordEncoder) {
//        this.userRepository = userRepository;
//        this.bcryptPasswordEncoder = bcryptPasswordEncoder;
//    }

    public boolean signUp(String email, String password) throws UserAlreadyExistsException {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new UserAlreadyExistsException("User with email: " + email + " already exists");
        }
        User user = new User();
        user.setEmail(email);
        String hashedPassword = bcryptPasswordEncoder.encode(password);
        //user.setPassword(password);
        user.setPassword(hashedPassword);
        userRepository.save(user);

        //sending email logic
        try {
            EmailDto emailDto = new EmailDto();
            emailDto.setTo(email);
            emailDto.setFrom("anuragbatch@gmail.com");
            emailDto.setSubject("Welcome to Scaler !!");
            emailDto.setBody("Hope you have great stay.");
            kafkaProducerClient.sendMessage("signup", objectMapper.writeValueAsString(emailDto));
        }catch (JsonProcessingException exception) {
            throw new RuntimeException(exception.getMessage());
        }

        return true;
    }

    public Pair<Boolean,String> login(String email, String password) throws UserNotFoundException, WrongPasswordException {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            throw new UserNotFoundException("User with email: " + email + " not found.");
        }
        //boolean matches = password.equals(userOptional.get().getPassword());
        boolean matches = bcryptPasswordEncoder.matches(password,userOptional.get().getPassword());


        //JWT Generation
//        String message = "{\n" +
//                "   \"email\": \"anurag@gmail.com\",\n" +
//                "   \"roles\": [\n" +
//                "      \"instructor\",\n" +
//                "      \"ta\"\n" +
//                "   ],\n" +
//                "   \"expirationDate\": \"2ndApril2025\"\n" +
//                "}";

       // byte[] content = message.getBytes(StandardCharsets.UTF_8);

        Map<String,Object> claims  = new HashMap<>();
        Long currentTimeInMillis = System.currentTimeMillis();
        claims.put("iat",currentTimeInMillis);
        claims.put("exp",currentTimeInMillis+864000);
        claims.put("user_id",userOptional.get().getId());
        claims.put("issuer","scaler");

        String token  = Jwts.builder().claims(claims).signWith(secretKey).compact();

        Session session = new Session();
        session.setToken(token);
        session.setUser(userOptional.get());
        session.setSessionState(SessionState.ACTIVE);
        sessionRepository.save(session);

        if (matches) {
            return new Pair<Boolean,String>(true,token);
        } else {
            throw new WrongPasswordException("Wrong password.");
        }
    }
    public ValidateTokenResponseDto validateToken(Long userId, String token) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token,userId);

        ValidateTokenResponseDto responseDto= new ValidateTokenResponseDto();
        if (sessionOptional.isEmpty()) {
            responseDto.setRequestStatus(RequestStatus.FAILURE);
            return responseDto;
        }
        if (sessionOptional.get().getUser().getId() != userId) {
            responseDto.setRequestStatus(RequestStatus.FAILURE);
            return responseDto;
        }
        JwtParser jwtParser = Jwts.parser().verifyWith(secretKey).build();
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();
        Long expiry = claims.get("exp",Long.class);
        Long currentTime = System.currentTimeMillis();
        if (expiry < currentTime) {
            System.out.println(expiry);
            System.out.println(currentTime);
            System.out.println("Token Expired");
            sessionOptional.get().setSessionState(SessionState.EXPIRED);
            sessionRepository.save(sessionOptional.get());
            responseDto.setRequestStatus(RequestStatus.FAILURE);
            return responseDto;
        }
        responseDto.setRequestStatus(RequestStatus.SUCCESS);
        responseDto.setUser(sessionOptional.get().getUser());
        responseDto.setToken(token);
        return responseDto;
    }
}






//stored token somewhere
//
//validateToken(inputtoken)
//
//    inputtoken == token_persisted ->(valid token)
//    token is expired or not  ?
//         -> decode token (using same secretkey) and get payload
//             -> from payload -> get expiry and check if it's expired or not

