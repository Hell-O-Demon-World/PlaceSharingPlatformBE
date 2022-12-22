package com.golfzonaca.officesharingplatform.domain;


import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@Table(name = "inquirystatus")
@NoArgsConstructor
public class InquiryStatus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "INQUIRY_ID")
    private Inquiry inquiry;

    @Column(name = "STATUS", nullable = false)
    private Boolean status;

    @Builder
    public InquiryStatus(Inquiry inquiry, Boolean status) {
        this.inquiry = inquiry;
        this.status = status;
    }

    public void updateStatus(boolean status) {
        this.status = status;
    }
}
