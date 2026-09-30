package com.portal.customStorage.model;

import jakarta.persistence.*;
import lombok.Data;


@Data
@Entity
@Table(name="customer")
public class Customer {

    @Id
    @Column(name="id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Basic
    @Column(name="username")
    private String userName;

    @Basic
    @Column(name="email")
    private String email;

    @Basic
    @Column(name="first_name")
    private String firstName;

    @Basic
    @Column(name="last_name")
    private String lastName;

    @Basic
    @Column(name="active")
    private int active;

    @Basic
    private String password;
}