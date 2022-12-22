package com.golfzonaca.officesharingplatform.domain;


import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;


@Getter
@Entity
@NoArgsConstructor
public class Inquiry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "USER_ID")
    private User user;

    @Column(name = "TITLE", length = 40, nullable = false)
    private String title;

    @Column(name = "QUESTION", length = 400, nullable = false)
    private String content;

    @Column(name = "WRITETIME", nullable = false)
    private LocalDateTime dateTime;

    @OneToOne(mappedBy = "inquiry")
    private Answer answer;

    @OneToOne(mappedBy = "inquiry")
    private InquiryStatus inquiryStatus;

    @Builder
    public Inquiry(User user, String title, String content, LocalDateTime dateTime) {
        this.user = user;
        this.title = title;
        this.content = content;
        this.dateTime = dateTime;
    }

    public void UpdateInquiry(String title, String content) {
        this.title = title;
        this.content = content;
    }
}
