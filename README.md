# OfficeSharingPlatform

## Repository for Deploying Project

### BE : 오령기, 최한성, 이동훈

### FE : 이찬형

### 개발 일정

```mermaid
gantt
dateFormat MM-DD
title OfficeSharingPlatform

    section 공통
    환경 설정(Git)             :chap1, 11-16, 1d
    개발 및 리팩토링             :chap2, 11-16, 12-17
    배포 (테스트)               :chap3, 12-17, 12-18
    QA                       :chap4, 12-17, 12-22
    배포                      :chap5, 12-18, 12-22

    section 오령기
    Spring Jpa, QueryDsl 적용 (Main Platform)                     : chap1, 11-16, 3d
    Spring Security - deprecated 해결                             : chap2, 11-19, 1d
    Spring Security - Argument Resolver & Custom Annotation 도입  : chap3, 11-20, 2d
    Reservation Part.2 리팩토링                                    : chap4, 11-21, 1d
    Spring Security -  인가 처리 (My Page, Reservation)            : chap5, 11-22, 1d
    Spring Security - RefreshToken 도입                           : chap6, 11-21, 3d
    이메일 검증                                                     : chap7, 11-25, 1d
    Reservation Part.2 - 투포인터 알고리즘 적용                        : chap8, 11-28, 1d
    Reservation Part.3 - 투포인터 알고리즘 적용                        : chap8, 11-29, 1d
    인증(시큐리티) 수정 (Back Office)                : chap1, 11-16, 1d
    인증(시큐리티) 수정 (Back Office)                : chap2, 12-14, 2d
    정보 암호화 (ID, PW, API KEY 등) (Back Office)  : chap3, 12-16, 1d

    section 최한성
    KakaoPay 도입        : chap1, 11-16, 5d
    KakaoPay 로직 리팩토링 : chap2, 11-22, 3d
    IamPort 도입         : chap3, 11-25, 4d
    KakaoPay 환불        : chap4, 11-29, 3d
    
    section 이동훈
    Spring Jpa, QueryDsl 적용 (Main Platform)                                : chap1, 11-16, 4d
    Search & Filter (Main Platform)                                         : chap2, 11-20, 2d
    Reservation Part.1 & 3 (Main Platform)                                  : chap3, 11-22, 2d
    Custom Validator & Anntation 추가 (Main Platform)                        : chap4, 11-23, 1d
    Comment, Rating, Inquiry (Main Platform)                                : chap5, 11-24, 2d
    Spring Jpa, QueryDsl 적용 (Back Office)                                  : chap6, 11-26, 1d
    예약 제외 설정 추가 (Back Office)                                            : chap7, 11-27, 1d
    예약 관리 대시보드 추가 (Back Office)                                         : chap8, 11-27, 1d
    수익금 조회 추가 (Back Office)                                              : chap9, 11-28, 1d
    공간 상세 정보 조회 (Main Platform)                                          : chap10, 11-29, 1d
    Filter 수정 (Main Platform)                                              : chap11, 11-30, 1d
    Exception 처리 (Main Platform)                                           : chap12, 11-30, 1d
    이미지 업로드 추가 (Back Office)                                             : chap13, 12-01, 2d
    공간 상세 정보와 Reservation Part.1 통합 (Main Platform)                      : chap14, 12-03, 2d
    마이페이지  - 예약 내역 조회 (Main Platform)                                   : chap15, 12-07, 2d
    이미지 업로드 수정 (Back Office)                : chap6, 12-08, 1d
    Spring Cache (CaffeineCache) 도입 (Main Platform)                         : chap16, 12-08, 2d
    마이페이지 - 조회(오버뷰, 후기, 댓글), 수정(회원정보) (Main Platform)                : chap17, 12-10, 3d
    Place Details - 후기 & 댓글 Pagination, 부가 정보(맛집, 카페) (Main Platform)   : chap18, 12-12, 3d
    문의 & 필터 수정, 정기결제 추가 (Main Platform)                                 : chap19, 12-15, 1d
    주소 저장 로직 변경 (Admin Page, Back Office)                                : chap20, 12-16, 1d
    마이페이지 - 예약 내역 조회 수정 (Main Platform)                                : chap21, 12-17, 1d
    예외 처리 (Back Office)                       : chap8, 12-16, 1d
    배포 (테스트) (Back Office)                    : chap9, 12-17, 1d
    배포 (Back Office)                            : chap10, 12-18, 1d

```