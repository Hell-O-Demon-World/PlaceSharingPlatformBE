package com.golfzonaca.officesharingplatform.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.LinkedList;
import java.util.List;

@Getter
@Entity
@Builder
@AllArgsConstructor
@Table(uniqueConstraints = {@UniqueConstraint(name = "Company", columnNames = {"COMPANY_LOGINID", "COMPANY_NAME", "COMPANY_TEL", "COMPANY_REGNUM"})})
@NoArgsConstructor
public class Company {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "COMPANY_LOGINID", nullable = false, length = 15)
    private String loginId;

    @Column(name = "COMPANY_PW", nullable = false, length = 15)
    private String Pw;

    @Column(name = "COMPANY_NAME", nullable = false, length = 30)
    private String Name;

    @Column(name = "COMPANY_TEL", nullable = false, length = 22)
    private String tel;

    @Column(name = "COMPANY_REGNUM", nullable = false, length = 12)
    private String regNum;

    @Column(name = "COMPANY_REPNAME", nullable = false, length = 20)
    private String repName;

    @OneToOne
    @JoinColumn(name = "ADDRESS_ID")
    private Address address;

    @OneToMany(mappedBy = "company")
    private List<Place> placeList = new LinkedList<>();

    public Company(String loginId, String pw, String name, String tel, String regNum, String repName, Address address) {
        this.loginId = loginId;
        Pw = pw;
        Name = name;
        this.tel = tel;
        this.regNum = regNum;
        this.repName = repName;
        this.address = address;
    }
}
