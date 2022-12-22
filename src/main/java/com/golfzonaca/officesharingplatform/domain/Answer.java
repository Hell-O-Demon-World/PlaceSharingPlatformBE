package com.golfzonaca.officesharingplatform.domain;


import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@NoArgsConstructor
public class Answer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "INQUIRY_ID")
    private Inquiry inquiry;

    @Column(name = "ANSWER", length = 400, nullable = false)
    private String answer;

    @Builder
    public Answer(Inquiry inquiry, String answer) {
        this.inquiry = inquiry;
        this.answer = answer;
    }

    public void updateAnswer(String answer) {
        this.answer = answer;
    }
}
