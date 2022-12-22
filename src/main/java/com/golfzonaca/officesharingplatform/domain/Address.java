package com.golfzonaca.officesharingplatform.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@Table(uniqueConstraints = {@UniqueConstraint(name = "ADDRESS", columnNames = {"ADDRESS"})})
@NoArgsConstructor
public class Address {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ADDRESS", nullable = false, length = 100)
    private String address;

    @Column(name = "POSTALCODE", nullable = false, length = 5)
    private String postalCode;

    @Column(name = "longitude")
    private Double longitude;

    @Column(name = "latitude")
    private Double latitude;

    @Builder
    public Address(String address, String postalCode, Double longitude, Double latitude) {
        this.address = address;
        this.postalCode = postalCode;
        this.longitude = longitude;
        this.latitude = latitude;
    }

    public void updateAddress(String postalCode, String address, Double longitude, Double latitude) {
        this.postalCode = postalCode;
        this.address = address;
        this.longitude = longitude;
        this.latitude = latitude;
    }
}
