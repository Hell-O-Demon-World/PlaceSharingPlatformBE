package com.golfzonaca.officesharingplatform.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@Table(name = "MANAGER", uniqueConstraints = {@UniqueConstraint(name = "MANGER", columnNames = {"EMAIL", "TEL"})})
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class Manager {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "NAME", nullable = false)
    private String name;

    @Column(name = "EMAIL", nullable = false, unique = true)
    private String email;

    @Column(name = "PW", nullable = false)
    private String password;

    @Column(name = "TEL", nullable = false)
    private String phoneNumber;

    @OneToOne
    @JoinColumn(name = "ROLE_ID")
    private Role role;

    public Manager(String name, String email, String password, String phoneNumber, Role role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.phoneNumber = phoneNumber;
        this.role = role;
    }

    public void updatePassword(String password) {
        this.password = password;
    }

    public void updatePhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }
}
