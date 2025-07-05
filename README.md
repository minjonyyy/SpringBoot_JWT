# SpringBoot_JWT

JWT 기반 인증/인가 기능을 구현한 Spring Boot 백엔드 API 프로젝트입니다.

## 📌 프로젝트 개요

- Spring Security 기반 로그인/회원가입 구현
- JWT를 활용한 AccessToken 인증
- 예외 처리 및 인증/인가 관련 예외 커스터마이징
- Swagger UI로 API 테스트 가능
- AWS EC2 서버에 배포하여 외부에서도 접근 가능

---

## 🚀 실행 방법

### 1. Git Clone

```bash
git clone https://github.com/minjonyyy/SpringBoot_JWT.git
```

### 2. 실행 전 세팅

`src/main/resources/application.yml` 파일에 아래와 같은 형식으로 DB 및 JWT 정보를 입력합니다.

```yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/test
    username: root
    password: 비밀번호
    driver-class-name: com.mysql.cj.jdbc.Driver

jwt:
  secret-key: Base64-인코딩된-시크릿키
  access-token-expiration: 7200000
```

### 3. 실행

```bash
./gradlew clean build
java -jar build/libs/SpringBoot_JWT-0.0.1-SNAPSHOT.jar
```

---

## 📮 제출 정보

- 🔗 **GitHub Repository 링크**: [https://github.com/minjonyyy/SpringBoot_JWT](https://github.com/minjonyyy/SpringBoot_JWT)
- 🔗 **Swagger UI 주소**: [http://13.124.60.255:8080/swagger-ui/index.html](http://13.124.60.255:8080/swagger-ui/index.html)
- 🔗 **API 엔드포인트 URL (Base URL)**: [http://13.124.60.255:8080](http://3.36.123.8:8080)

---

## 📘 주요 기술 스택

- Spring Boot
- Spring Security
- JWT (jjwt)
- MySQL
- JPA (Hibernate)
- Swagger (springdoc-openapi)
- AWS EC2 (Ubuntu 22.04)

---

## 📑 API 명세 예시

Swagger UI에서 확인 가능합니다.  
회원가입, 로그인, JWT 인증 테스트 등이 가능합니다.
