package org.example.userauthenticationservice_sept2024.models;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class Session extends BaseModel{
    SessionState sessionState;
    String token;
    @ManyToOne
    User user;
}
