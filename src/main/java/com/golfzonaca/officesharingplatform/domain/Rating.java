package com.golfzonaca.officesharingplatform.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.LinkedList;
import java.util.List;

@Getter
@Entity
@NoArgsConstructor
public class Rating {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "RESERVATION_ID")
    private Reservation reservation;

    @Column(name = "RATING_SCORE", nullable = false)
    private Float ratingScore;

    @Column(name = "RATING_REVIEW", nullable = false)
    private String ratingReview;

    @Column(name = "RATING_TIME", nullable = false)
    private LocalDateTime ratingTime;
    
    @OneToMany(mappedBy = "rating")
    private List<Comment> commentList = new LinkedList<>();

    @Builder
    public Rating(Reservation reservation, Float ratingScore, String ratingReview, LocalDateTime ratingTime) {
        this.reservation = reservation;
        this.ratingScore = (float) (Math.round(ratingScore * 10) / 10);
        this.ratingReview = ratingReview;
        this.ratingTime = ratingTime;
    }

    public void UpdateRating(Float ratingScore, String ratingReview) {
        this.ratingScore = (float) (Math.round(ratingScore * 10) / 10);
        this.ratingReview = ratingReview;
    }
}
