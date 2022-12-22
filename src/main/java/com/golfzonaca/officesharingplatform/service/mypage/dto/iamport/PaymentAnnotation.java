package com.golfzonaca.officesharingplatform.service.mypage.dto.iamport;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
public class PaymentAnnotation {
    private String imp_uid;
    private String merchant_uid;
    private Optional<String> pay_method;
    private Optional<String> channel;
    private Optional<String> pg_provider;
    private Optional<String> emb_pg_provider;
    private Optional<String> pg_tid;
    private Optional<String> pg_id;
    private Optional<Boolean> escrow;
    private Optional<String> apply_num;
    private Optional<String> bank_code;
    private Optional<String> bank_name;
    private Optional<String> card_code;
    private Optional<String> card_name;
    private Optional<Integer> card_quota;
    private Optional<String> card_number;
    private Optional<Integer> card_type;
    private Optional<String> vbank_code;
    private Optional<String> vbank_name;
    private Optional<String> vbank_num;
    private Optional<String> vbank_holder;
    private Optional<Integer> vbank_date;
    private Optional<Integer> vbank_issued_at;
    private Optional<String> name;
    private Number amount;
    private Number cancel_amount;
    private String currency;
    private Optional<String> buyer_name;
    private Optional<String> buyer_email;
    private Optional<String> buyer_tel;
    private Optional<String> buyer_addr;
    private Optional<String> buyer_postcode;
    private Optional<String> custom_data;
    private Optional<String> user_agent;
    private String status;
    private Optional<Integer> started_at;
    private Optional<Integer> paid_at;
    private Optional<Integer> failed_at;
    private Optional<Integer> cancelled_at;
    private Optional<String> fail_reason;
    private Optional<String> cancel_reason;
    private Optional<String> receipt_url;
    private Optional<List<PaymentAnnotation>> cancel_history;
    private Optional<List<String>> cancel_receipt_urls;
    private Optional<Boolean> cash_receipt_issued;
    private Optional<String> customer_uid;
    private Optional<String> customer_uid_usage;
}
