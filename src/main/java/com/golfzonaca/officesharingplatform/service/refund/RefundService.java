package com.golfzonaca.officesharingplatform.service.refund;

import com.golfzonaca.officesharingplatform.domain.Payment;
import com.golfzonaca.officesharingplatform.domain.Refund;

public interface RefundService {

    Refund processingRefundData(Payment findPayment);
}
