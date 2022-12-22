package com.golfzonaca.officesharingplatform.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;

import javax.persistence.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "REFRESH_TOKEN")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "ENCODED_TOKEN", unique = true, nullable = false)
    private String encodedToken;
    @ManyToOne
    @JoinColumn(name = "USER_ID", unique = true, nullable = false)
    @NotFound(action = NotFoundAction.IGNORE)
    private User user;

    public RefreshToken toEntity(Long id, Long userId, String encodedToken) {
        User entityUser = User.builder().id(userId).build();
        return RefreshToken.builder()
                .id(id)
                .user(entityUser)
                .encodedToken(encodedToken)
                .build();
    }

    public void updateToken(String encodedToken) {
        this.encodedToken = encodedToken;
    }

    public void updateUser(User findUser) {
        this.user = findUser;
    }
}
