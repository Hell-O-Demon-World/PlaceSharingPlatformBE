package com.golfzonaca.officesharingplatform.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.LinkedList;
import java.util.List;

@Getter
@Entity
@Table(name = "USER", uniqueConstraints = {@UniqueConstraint(name = "USER", columnNames = {"USER_MAIL", "USER_TEL", "MILEAGE_ID"})})
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "USER_NAME", nullable = false)
    private String username;
    @Column(name = "USER_MAIL", nullable = false, unique = true)
    private String email;
    @Column(name = "USER_PW", nullable = false)
    private String password;
    @Column(name = "USER_TEL", nullable = false)
    private String phoneNumber;
    @Column(name = "USER_JOB", nullable = false)
    private String job;
    @Column(name = "PREFER_TYPE", nullable = false)
    private String userPlace;
    @Column(name = "JOIN_DATE", nullable = false)
    private LocalDateTime joinDate;
    @OneToOne
    @JoinColumn(name = "MILEAGE_ID")
    private Mileage mileage;
    @ManyToOne
    @JoinColumn(name = "ROLE_ID")
    private Role role;
    @OneToMany(mappedBy = "user")
    private List<Reservation> reservationList = new LinkedList<>();

    @OneToMany(mappedBy = "writer")
    private List<Comment> commentList = new LinkedList<>();

    @OneToMany(mappedBy = "user")
    private List<Inquiry> inquiryList = new LinkedList<>();

    public User(Long id) {
        this.id = id;
    }

    public User(String username, String email, String password, String phoneNumber, String job, String userPlace, Mileage mileage, Role role) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.phoneNumber = phoneNumber;
        this.job = job;
        this.userPlace = userPlace;
        this.mileage = mileage;
        this.role = role;
    }

    public void updatePassword(String password) {
        this.password = password;
    }

    public void updateMileage(Mileage mileage) {
        this.mileage = mileage;
    }

    public void updateRole(Role role) {
        this.role = role;
    }

    public void updateDate(LocalDateTime joinDate) {
        this.joinDate = joinDate;
    }

    public void updatePhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public void updateJob(String job) {
        this.job = job;
    }

    public void updateUserPlace(String userPlace) {
        this.userPlace = userPlace;
    }

    public void changePassword(String newPassword) {
        this.password = newPassword;
    }
}
