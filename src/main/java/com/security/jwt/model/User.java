package com.security.jwt.model;

import lombok.Data;
import lombok.Generated;

import javax.persistence.*;
import java.util.Set;

@Data
@Entity
@Table(name = "usertab")
public class User {

    @Id
    @GeneratedValue
    private Integer id;
    private String name;
    private String username;
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "rolestab",
            joinColumns = @JoinColumn(name = "id")
    )
    @Column(name = "role")
    private Set<String> roles;
}
