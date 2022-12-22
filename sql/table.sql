create table address
(
    ID         bigint unsigned auto_increment primary key,
    ADDRESS    varchar(100)     not null,
    POSTALCODE varchar(5)       not null,
    longitude  double default 0 not null,
    latitude   double default 0 not null
) charset = utf8mb3;

create table role
(
    ID   bigint unsigned not null primary key,
    role enum ('ROLE_USER', 'ROLE_MANAGER', 'ROLE_REGISTER', 'ROLE_ADMIN') not null,
    constraint ROLE
        unique (role)
) charset = utf8mb3;

create table room_kind
(
    ID        bigint unsigned not null primary key,
    ROOM_TYPE enum ('DESK', 'MEETINGROOM4', 'MEETINGROOM6', 'MEETINGROOM10', 'MEETINGROOM20', 'OFFICE20', 'OFFICE40', 'OFFICE70', 'OFFICE100') not null,
    PRICE     enum ('10000', '20000', '30000', '50000', '100000', '200000', '300000', '500000') not null,
    constraint ROOM_TYPE
        unique (ROOM_TYPE)
) charset = utf8mb3;

create table email_authentication_code
(
    ID         bigint unsigned auto_increment primary key,
    EMAIL      varchar(30) not null,
    CODE       varchar(4)  not null,
    EXPIRATION tinyint(1) not null
) charset = utf8mb3;

create table company
(
    ID              bigint unsigned auto_increment primary key,
    ADDRESS_ID      bigint unsigned not null,
    COMPANY_LOGINID varchar(15)  not null,
    COMPANY_PW      varchar(100) not null,
    COMPANY_NAME    varchar(30)  not null,
    COMPANY_TEL     varchar(22)  not null,
    COMPANY_REGNUM  varchar(12)  not null,
    COMPANY_REPNAME varchar(20)  not null,
    constraint COMPANY_LOGINID
        unique (COMPANY_LOGINID),
    constraint COMPANY_NAME
        unique (COMPANY_NAME),
    constraint COMPANY_REGNUM
        unique (COMPANY_REGNUM),
    constraint COMPANY_TEL
        unique (COMPANY_TEL),
    constraint FK_ADDRESS_TO_COMPANY_1
        foreign key (ADDRESS_ID) references address (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table ratepoint
(
    ID          bigint unsigned auto_increment primary key,
    RATINGPOINT float unsigned not null
) charset = utf8mb3;

create table place
(
    ID                bigint unsigned auto_increment primary key,
    COMPANY_ID        bigint unsigned not null,
    ADDRESS_ID        bigint unsigned not null,
    RATEPOINT_ID      bigint unsigned not null,
    PLACE_NAME        varchar(30) not null,
    PLACE_DESCRIPTION varchar(50) not null,
    PLACE_OPENDAYS    varchar(50) not null,
    PLACE_START       time        not null,
    PLACE_END         time        not null,
    PLACE_ADDINFO     varchar(50) not null,
    constraint PLACE_NAME
        unique (PLACE_NAME),
    constraint FK_ADDRESS_TO_PLACE_1
        foreign key (ADDRESS_ID) references address (ID)
            on update cascade on delete cascade,
    constraint FK_COMPANY_TO_PLACE_1
        foreign key (COMPANY_ID) references company (ID)
            on update cascade on delete cascade,
    constraint FK_RATEPOINT_TO_PLACE_1
        foreign key (RATEPOINT_ID) references ratepoint (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table placeimage
(
    ID              bigint unsigned auto_increment primary key,
    UPLOAD_FILENAME varchar(100) not null,
    STORE_FILENAME  varchar(100) not null,
    SAVED_PATH      mediumtext   not null,
    PLACE_ID        bigint unsigned not null,
    constraint FK_PLACE_TO_PLACEIMAGE_1
        foreign key (PLACE_ID) references place (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table room
(
    ID           bigint unsigned auto_increment primary key,
    ROOM_KIND_ID bigint unsigned not null,
    PLACE_ID     bigint unsigned not null,
    constraint FK_PLACE_TO_ROOM_1
        foreign key (PLACE_ID) references place (ID)
            on update cascade on delete cascade,
    constraint FK_ROOM_KIND_TO_ROOM_1
        foreign key (ROOM_KIND_ID) references room_kind (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table roomimage
(
    ID              bigint unsigned auto_increment primary key,
    UPLOAD_FILENAME varchar(100) not null,
    STORE_FILENAME  varchar(100) not null,
    SAVED_PATH      mediumtext   not null,
    PLACE_ID        bigint unsigned not null,
    ROOMKIND_ID     bigint unsigned not null,
    constraint FK_PLACE_TO_ROOMIMAGE_1
        foreign key (PLACE_ID) references place (ID)
            on update cascade on delete cascade,
    constraint FK_ROOMKIND_TO_ROOMIMAGE_1
        foreign key (ROOMKIND_ID) references room_kind (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table roomstatus
(
    ID      bigint unsigned auto_increment
        primary key,
    ROOM_ID bigint unsigned not null,
    STATUS  tinyint(1) default 1 not null,
    constraint ROOM_ID
        unique (ROOM_ID),
    constraint FK_ROOM_TO_ROOMSTATUS_1
        foreign key (ROOM_ID) references room (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table manager
(
    ID      bigint unsigned auto_increment primary key,
    ROLE_ID bigint unsigned default 2 not null,
    NAME    varchar(20)  not null,
    EMAIL   varchar(32)  not null,
    PW      varchar(100) not null,
    TEL     varchar(22)  not null,
    constraint EMAIL
        unique (EMAIL),
    constraint TEL
        unique (TEL),
    constraint FK_ROLE_TO_MANAGER_1
        foreign key (ROLE_ID) references role (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table mileage
(
    ID                 bigint unsigned auto_increment primary key,
    POINT              bigint unsigned not null,
    LATEST_UPDATE_DATE datetime not null
) charset = utf8mb3;

create table mileage_update_history
(
    ID           bigint unsigned auto_increment primary key,
    MILEAGE_ID   bigint unsigned not null,
    UPDATE_POINT bigint unsigned not null,
    STATUS_TYPE  enum ('NEW_MEMBER', 'EARNING', 'USE', 'EXPIRATION') not null,
    UPDATE_DATE  datetime not null,
    constraint FK_MILEAGE_TO_MILEAGE_UPDATE_1
        foreign key (MILEAGE_ID) references mileage (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table mileage_event_update
(
    ID                bigint unsigned auto_increment primary key,
    MILEAGE_UPDATE_ID bigint unsigned not null,
    UPDATE_POINT      bigint unsigned not null,
    INCREASE_REASON   varchar(50) not null,
    constraint FK_MILEAGE_TO_MILEAGE_EVENT_UPDATE_1
        foreign key (MILEAGE_UPDATE_ID) references mileage_update_history (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table mileage_earning_usage_history
(
    ID                bigint unsigned auto_increment primary key,
    MILEAGE_UPDATE_ID bigint unsigned not null,
    CURRENT_POINT     bigint unsigned not null,
    UPDATE_DATE       datetime not null,
    EXPIRE_DATE       datetime not null,
    constraint FK_MILEAGE_TO_MILEAGE_UPDATE_HISTORY_1
        foreign key (MILEAGE_UPDATE_ID) references mileage_update_history (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table user
(
    ID          bigint unsigned auto_increment primary key,
    MILEAGE_ID  bigint unsigned not null,
    ROLE_ID     bigint unsigned default 1 not null,
    USER_MAIL   varchar(32)                          not null,
    USER_PW     varchar(100)                         not null,
    USER_NAME   varchar(20)                          not null,
    USER_TEL    varchar(22)                          not null,
    USER_JOB    varchar(20)                          not null,
    prefer_type varchar(50)                          not null,
    JOIN_DATE   datetime default current_timestamp() not null,
    constraint USER_MAIL
        unique (USER_MAIL),
    constraint USER_TEL
        unique (USER_TEL),
    constraint FK_MILEAGE_TO_USER_1
        foreign key (MILEAGE_ID) references mileage (ID)
            on update cascade on delete cascade,
    constraint FK_ROLE_TO_USER_1
        foreign key (ROLE_ID) references role (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table reservation
(
    ID            bigint unsigned auto_increment primary key,
    USER_ID       bigint unsigned not null,
    ROOM_ID       bigint unsigned not null,
    RES_COMPLETED datetime default current_timestamp() not null,
    RES_STARTDATE date                                 not null,
    RES_STARTTIME time                                 not null,
    RES_ENDDATE   date                                 not null,
    RES_ENDTIME   time                                 not null,
    RES_STATUS    enum ('PROGRESSING', 'COMPLETED', 'CANCELED') not null,
    FIX_STATUS    enum ('FIXED', 'UNFIXED', 'CANCELED') default 'UNFIXED' not null,
    constraint FK_ROOM_TO_RESERVATION_1
        foreign key (ROOM_ID) references room (ID)
            on delete cascade,
    constraint FK_USER_TO_RESERVATION_1
        foreign key (USER_ID) references user (ID)
            on delete cascade
) charset = utf8mb3;

create table payment
(
    ID             bigint unsigned auto_increment primary key,
    RESERVATION_ID bigint unsigned not null,
    PAY_DATE       date                     not null,
    PAY_TIME       time                     not null,
    PAY_PRICE      bigint unsigned not null,
    PAY_MILEAGE    bigint unsigned not null,
    PAY_WAY        enum ('PREPAYMENT', 'POSTPAYMENT') not null,
    SAVED_MILEAGE  bigint unsigned not null,
    PAY_TYPE       enum ('DEPOSIT', 'BALANCE', 'FULL_PAYMENT') not null,
    PAY_API_CODE   varchar(30)              not null,
    PG             enum ('KAKAOPAY', 'NICEPAY') not null,
    PAY_STATUS     enum ('PROGRESSING', 'COMPLETED', 'CANCELED') not null,
    RECEIPT        varchar(255) default ' ' not null,
    constraint PAY_API_CODE
        unique (PAY_API_CODE),
    constraint FK_RESERVATION_TO_PAYMENT_1
        foreign key (RESERVATION_ID) references reservation (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table refund
(
    ID              bigint unsigned auto_increment primary key,
    PAYMENT_ID      bigint unsigned not null,
    REFUND_DATETIME datetime not null,
    REFUND_PRICE    bigint unsigned not null,
    REFUND_MILEAGE  bigint unsigned not null,
    RECALL_MILEAGE  bigint unsigned not null,
    REFUND_STATUS   tinyint(1) default 1 not null,
    constraint FK_PAYMENT_TO_REFUND_1
        foreign key (PAYMENT_ID) references payment (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table inquiry
(
    ID        bigint unsigned auto_increment primary key,
    USER_ID   bigint unsigned not null,
    TITLE     varchar(40)   not null,
    QUESTION  varchar(2000) not null,
    WRITETIME datetime      not null,
    constraint FK_USER_TO_INQUIRY_1
        foreign key (USER_ID) references user (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table answer
(
    ID         bigint unsigned auto_increment primary key,
    INQUIRY_ID bigint unsigned not null,
    ANSWER     varchar(400) not null,
    constraint INQUIRY_ID
        unique (INQUIRY_ID),
    constraint FK_INQUIRY_TO_ANSWER_1
        foreign key (INQUIRY_ID) references inquiry (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table rating
(
    ID             bigint unsigned auto_increment primary key,
    RESERVATION_ID bigint unsigned not null,
    RATING_SCORE   varchar(3)   not null,
    RATING_REVIEW  varchar(200) not null,
    RATING_TIME    datetime     not null,
    constraint FK_RESERVATION_TO_RATING_1
        foreign key (RESERVATION_ID) references reservation (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table refresh_token
(
    ID            bigint unsigned auto_increment primary key,
    USER_ID       bigint unsigned not null,
    ENCODED_TOKEN varchar(240) not null,
    constraint user_id
        unique (USER_ID),
    constraint FK_USER_TO_REFRESH_TOKEN_1
        foreign key (USER_ID) references user (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table inquirystatus
(
    ID         bigint unsigned auto_increment primary key,
    INQUIRY_ID bigint unsigned not null,
    STATUS     tinyint(1) default 0 not null,
    constraint INQUIRY_ID
        unique (INQUIRY_ID),
    constraint FK_INQUIRY_TO_INQUIRYSTATUS_1
        foreign key (INQUIRY_ID) references inquiry (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table comment
(
    ID               bigint unsigned auto_increment primary key,
    RATING_ID        bigint unsigned not null,
    USER_ID          bigint unsigned not null,
    COMMENT_TEXT     varchar(40)                          not null,
    COMMENT_DATETIME datetime default current_timestamp() not null,
    constraint FK_PLACE_TO_COMMENT_1
        foreign key (RATING_ID) references rating (ID)
            on update cascade on delete cascade,
    constraint FK_USER_TO_COMMENT_1
        foreign key (USER_ID) references user (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table mileage_payment_update
(
    ID                bigint unsigned auto_increment primary key,
    MILEAGE_UPDATE_ID bigint unsigned not null,
    PAYMENT_ID        bigint unsigned not null,
    UPDATE_POINT      bigint unsigned not null,
    UPDATE_REASON     enum ('FULL_PAYMENT', 'REFUND', 'USE_MILEAGE') not null,
    constraint FK_MILEAGE_TO_PAYMENT_1
        foreign key (PAYMENT_ID) references payment (ID)
            on update cascade on delete cascade,
    constraint FK_MILEAGE_UPDATE_TO_MILEAGE_PAYMENT_UPDATE_1
        foreign key (MILEAGE_UPDATE_ID) references mileage_update_history (ID)
            on update cascade on delete cascade
) charset = utf8mb3;

create table mileage_transaction_usage_history
(
    ID                        bigint unsigned auto_increment primary key,
    MILEAGE_PAYMENT_UPDATE_ID bigint unsigned not null,
    MILEAGE_EARNING_USAGE_ID  bigint unsigned not null,
    USED_POINT                bigint unsigned not null,
    constraint FK_MILEAGE_EARNING_USAGE_TO_MILEAGE_TRANSACTION_USAGE_1
        foreign key (MILEAGE_EARNING_USAGE_ID) references mileage_earning_usage_history (ID),
    constraint FK_MILEAGE_PAYMENT_UPDATE_TO_MILEAGE_TRANSACTION_USAGE_1
        foreign key (MILEAGE_PAYMENT_UPDATE_ID) references mileage_payment_update (ID)
            on update cascade on delete cascade
) charset = utf8mb3;
