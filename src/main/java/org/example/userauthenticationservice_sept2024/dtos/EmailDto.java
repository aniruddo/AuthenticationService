package org.example.userauthenticationservice_sept2024.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EmailDto {
    String to;
    String from;
    String subject;
    String body;
}
