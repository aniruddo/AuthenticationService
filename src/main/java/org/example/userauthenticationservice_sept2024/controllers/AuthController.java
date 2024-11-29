package org.example.userauthenticationservice_sept2024.controllers;

import org.antlr.v4.runtime.misc.Pair;
import org.example.userauthenticationservice_sept2024.dtos.*;
import org.example.userauthenticationservice_sept2024.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/sign_up")
    public ResponseEntity<SignUpResponseDto> signUp(@RequestBody SignUpRequestDto request) {
        SignUpResponseDto response = new SignUpResponseDto();
        try {
            if (authService.signUp(request.getEmail(), request.getPassword())) {
                response.setRequestStatus(RequestStatus.SUCCESS);
            } else {
                response.setRequestStatus(RequestStatus.FAILURE);
            }
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            response.setRequestStatus(RequestStatus.FAILURE);
            return new ResponseEntity<>(response, HttpStatus.CONFLICT);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto request) {
        LoginResponseDto response = new LoginResponseDto();
        try {
            Pair<Boolean,String> tokenWithResult = authService.login(request.getEmail(), request.getPassword());

            response.setRequestStatus(RequestStatus.SUCCESS);

            MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
            headers.add(HttpHeaders.SET_COOKIE,tokenWithResult.b);
            return new ResponseEntity<>(
                    response ,headers, HttpStatus.OK
            );
        } catch (Exception e) {
            response.setRequestStatus(RequestStatus.FAILURE);
            return new ResponseEntity<>(
                    response , HttpStatus.BAD_REQUEST
            );
        }
    }

    @PostMapping("/validateToken")
    public ResponseEntity<ValidateTokenResponseDto> validateToken(@RequestBody ValidateTokenRequestDto request) {
        ValidateTokenResponseDto response = new ValidateTokenResponseDto();
        try {
            response = authService.validateToken(request.getUserId(), request.getToken());
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            response.setRequestStatus(RequestStatus.FAILURE);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }
}
