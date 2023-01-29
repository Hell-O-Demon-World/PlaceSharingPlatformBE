# [Place Sharing Platform](https://place-sharing-platform.vercel.app)

## 0. Update log

- 2023.01.19 ~ 2023.01.20 : DB 서버 이전 (from Local PC to Oracle Cloud)
- 2022.12.22 ~ 2022.12.23 : 배포
- 2022.12.17 ~ 2022.12.22 : QA 및 버그 픽스
- 2022.11.17 ~ 2022.12.17 : 개발 및 리팩토링
- 2022.11.16 ~ 2022.11.16 : 개발 환경 설정

## 1. 팀 구성

- - -

| 구분  | 성명                                     | 담당  |
|-----|----------------------------------------|-----|
| 팀장  | [오령기](https://github.com/ryeongee)     | BE  |
| 팀원  | [최한성](https://github.com/hansung0904)  | BE  |
| 팀원  | [이동훈](https://github.com/darkblose)    | BE  |
| 팀원  | [이찬형](https://github.com/LEECHANHYUNG) | FE  |

## 2. 프로젝트 소개

- - -

#### 주제 : 사무공간 대여 서비스

#### 개발 기간 : 2022-11-16 ~ 2022-12-22

#### 서비스 구조

| 서버 구분                           	     | 서버 역할             	 | 비고                                                                                                                                                         	                                                                                                                              |
|---------------------------------------|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Next.js App                         	 | 메인 플랫폼 VIEW 서버 	    | [서비스](https://place-sharing-platform.vercel.app), [깃허브](https://github.com/Hell-O-Demon-World/OfficeSharingPlatformFETest) 	                                                                                                                                                              |
| Spring Boot Application             	 | 메인 플랫폼 API 서버  	    | [깃허브](https://github.com/Hell-O-Demon-World/OfficeSharingPlatformBETest)                                                                                                                                                   	                                                              |
| Spring Boot Application + Thymeleaf 	 | 백오피스 WAS          	 | [서비스](https://port-0-psp-back-office-883524lbtbkgal.gksl2.cloudtype.app), [깃허브](https://github.com/Hell-O-Demon-World/BackOfficeTest)                                                                                                                                                   	 |
| Spring Boot Application + Thymeleaf 	 | 관리자 페이지 WAS     	   | [서비스](https://port-0-psp-admin-page-883524lbtbkgal.gksl2.cloudtype.app), [깃허브](https://github.com/Hell-O-Demon-World/AdminPageTest)                                                                                                                                                   	   |

### 3. 개발 내용

- - -

#### 메인 플랫폼

<img width="1189" alt="PSP 메인 플랫폼 개발 내용" src="https://user-images.githubusercontent.com/56018219/215302292-4d9a031c-ef34-4e9f-9af1-3172e6d403af.png">

#### 백오피스

<img width="1189" alt="PSP 백오피스 개발 내용" src="https://user-images.githubusercontent.com/56018219/215302299-1568f5a4-fde3-4d23-95b1-773297a4e03f.png">

#### 관리자 페이지

<img width="1190" alt="PSP 관리자 페이지 개발 내용" src="https://user-images.githubusercontent.com/56018219/215302304-b83cf833-d6ea-4e28-8b44-653d514c96ba.png">

### 4. 개발 환경

- - -

#### 사용 기술 - BE

<img width="1189" alt="PSP BE 사용 기술" src="https://user-images.githubusercontent.com/56018219/215302338-c19e3dad-c688-4570-ac5a-bf215ed27861.png">

#### 사용 기술 - FE

<img width="1189" alt="PSP FE 사용 기술" src="https://user-images.githubusercontent.com/56018219/215302314-200d4085-52a6-4214-a51c-adac01c151fb.png">

#### 개발 환경

<img width="670" alt="PSP 개발 환경" src="https://user-images.githubusercontent.com/56018219/215302348-e0f7917f-9ac5-4e12-8672-13dd4da04499.png">

#### E-R 다이어그램

![PSP E-R 다이어그램](https://user-images.githubusercontent.com/56018219/215302678-8fc2aca6-7689-4281-9f28-9f1b559777fc.jpeg)

### 5. 개발 일정 및 담당

- - -

#### 개발 일정

```mermaid  
gantt  
	dateFormat YYYY-MM-DD  
	title Place Sharing Platform  
  
    section 공통  
    개발 환경 설정 :chap1, 2022-11-16, 1d  
    개발 및 리팩토링 :chap2, 2022-11-17, 2022-12-17
	QA 및 버그 픽스: chap3, 2022-12-17, 2022-12-22
	배포: chap4, 2022-12-22, 2022-12-23
	DB 이전 : chap5, 2023-01-19, 2023-01-21

```

#### 개발 담당

<img width="1268" alt="PSP 개발 담당" src="https://user-images.githubusercontent.com/56018219/215302365-1a53f767-c4b7-4bd9-82f3-5d91edbb3800.png">