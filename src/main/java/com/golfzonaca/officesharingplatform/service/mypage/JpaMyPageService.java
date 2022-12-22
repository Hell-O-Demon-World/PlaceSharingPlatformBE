package com.golfzonaca.officesharingplatform.service.mypage;

import com.golfzonaca.officesharingplatform.domain.*;
import com.golfzonaca.officesharingplatform.domain.type.*;
import com.golfzonaca.officesharingplatform.exception.CalculateRoomNumErrorException;
import com.golfzonaca.officesharingplatform.exception.InvalidResCancelRequest;
import com.golfzonaca.officesharingplatform.exception.NonExistedReservationException;
import com.golfzonaca.officesharingplatform.repository.comment.CommentRepository;
import com.golfzonaca.officesharingplatform.repository.inquiry.InquiryRepository;
import com.golfzonaca.officesharingplatform.repository.inquirystatus.InquiryStatusRepository;
import com.golfzonaca.officesharingplatform.repository.mileage.MileageRepository;
import com.golfzonaca.officesharingplatform.repository.payment.PaymentRepository;
import com.golfzonaca.officesharingplatform.repository.rating.RatingRepository;
import com.golfzonaca.officesharingplatform.repository.refund.RefundRepository;
import com.golfzonaca.officesharingplatform.repository.reservation.ReservationRepository;
import com.golfzonaca.officesharingplatform.repository.room.RoomRepository;
import com.golfzonaca.officesharingplatform.repository.user.UserRepository;
import com.golfzonaca.officesharingplatform.service.mileage.MileageService;
import com.golfzonaca.officesharingplatform.service.mypage.dto.comment.CommentDataByRating;
import com.golfzonaca.officesharingplatform.service.mypage.dto.comment.MyCommentData;
import com.golfzonaca.officesharingplatform.service.mypage.dto.edituserinfo.EditUserInfo;
import com.golfzonaca.officesharingplatform.service.mypage.dto.iamport.PagedPaymentAnnotation;
import com.golfzonaca.officesharingplatform.service.mypage.dto.iamport.PaymentAnnotation;
import com.golfzonaca.officesharingplatform.service.mypage.dto.iamport.PaymentListResponse;
import com.golfzonaca.officesharingplatform.service.mypage.dto.mileage.MileageHistoryDto;
import com.golfzonaca.officesharingplatform.service.mypage.dto.qna.AnswerData;
import com.golfzonaca.officesharingplatform.service.mypage.dto.qna.QnAData;
import com.golfzonaca.officesharingplatform.service.mypage.dto.qna.QuestionData;
import com.golfzonaca.officesharingplatform.service.mypage.dto.rating.RatingData;
import com.golfzonaca.officesharingplatform.service.mypage.dto.usage.MyPaymentDetail;
import com.golfzonaca.officesharingplatform.service.mypage.dto.usage.MyRefundDetail;
import com.golfzonaca.officesharingplatform.service.mypage.dto.usage.MyReservationDetail;
import com.golfzonaca.officesharingplatform.service.mypage.dto.usage.MyReservationList;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.siot.IamportRestClient.IamportClient;
import com.siot.IamportRestClient.exception.IamportResponseException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class JpaMyPageService implements MyPageService {
    private final UserRepository userRepository;
    private final RoomRepository roomRepository;
    private final ReservationRepository reservationRepository;
    private final CommentRepository commentRepository;
    private final RatingRepository ratingRepository;
    private final InquiryRepository inquiryRepository;
    private final InquiryStatusRepository inquiryStatusRepository;
    private final MileageRepository mileageRepository;
    private final PaymentRepository paymentRepository;
    private final RefundRepository refundRepository;
    private final MileageService mileageService;

    @Value("${iamport.api.apiKey}")
    private String apiKey;

    @Value("${iamport.api.apiSecret}")
    private String apiSecret;

    @Override
    public Map<String, JsonObject> getOverViewData(Long userId) {
        User user = userRepository.findById(userId);
        Map<String, JsonObject> overViewMap = processingUserData(user);
        putReservationAtNow(overViewMap, user);
        putRecentReservations(overViewMap, user);
        return overViewMap;
    }

    @Override
    public void cancelByReservationAndUserId(Long reservationId, Long userId) {
        Reservation findReservation = reservationRepository.findById(reservationId);
        Mileage mileage = findReservation.getUser().getMileage();
        List<Payment> payments = paymentRepository.findByReservationId(findReservation.getId());
        if (payments.size() != 1) {
            throw new InvalidResCancelRequest("취소할 수 없는 예약입니다.");
        }
        Payment payment = payments.get(0);
        Long targetUserID = findReservation.getUser().getId();
        if (targetUserID.equals(userId)) {
            reservationRepository.delete(findReservation);
            mileageService.recoveryMileage(mileage, payment);
        } else {
            log.error("token 정보가 해당 예약 정보와 일치하지 않습니다.");
            throw new NonExistedReservationException("");
        }
    }

    @Override
    public Map<String, JsonObject> getResViewData(long userId, Integer page) {
        User user = userRepository.findById(userId);
        Map<String, JsonObject> myResMap = processingUserData(user);
        putReservationData(user, myResMap, page);
        return myResMap;
    }

    @Override
    public Map<String, JsonObject> getResDetailViewData(Long userId, long reservationId) {
        User user = userRepository.findById(userId);
        Map<String, JsonObject> usageDetail = processingUserData(user);
        putResDetailData(user, reservationId, usageDetail);
        putPaymentAndRefundDetailData(user, reservationId, usageDetail);
        return usageDetail;
    }

    @Override
    public Map<String, JsonObject> getReviewData(Long userId, Integer page) {
        User user = userRepository.findById(userId);
        Map<String, JsonObject> reviewMap = processingUserData(user);
        putReviewData(user, reviewMap, page);
        return reviewMap;
    }

    @Override
    public Map<String, JsonObject> getCommentDataByReview(Long ratingId, Integer page) {
        Rating rating = ratingRepository.findById(ratingId);
        return processingCommentDataByRating(rating, page);
    }

    @Override
    public Map<String, JsonObject> getCommentViewData(Long userId, Integer page) {
        User user = userRepository.findById(userId);
        Map<String, JsonObject> myCommentMap = processingUserData(user);
        putCommentData(page, user, myCommentMap);
        return myCommentMap;
    }

    @Override
    public Map<String, JsonObject> getQnAViewData(Long userId, Integer page) {
        User user = userRepository.findById(userId);
        Map<String, JsonObject> myQnAMap = processingUserData(user);
        putQnAData(user, myQnAMap, page);
        return myQnAMap;
    }

    @Override
    public Map<String, JsonObject> getEditUserInfo(Long userId) {
        User user = userRepository.findById(userId);
        Map<String, JsonObject> editUserInfoMap = processingUserData(user);
        putUserInfoData(user, editUserInfoMap);
        return editUserInfoMap;
    }

    @Override
    public void updateUserInfo(Long userId, String tel, String job, Map<String, Boolean> preferType) {
        User user = userRepository.findById(userId);
        if (StringUtils.hasText(tel)) {
            user.updatePhoneNumber(tel);
        }
        if (StringUtils.hasText(job)) {
            user.updateJob(job);
        }
        if (!preferType.isEmpty()) {
            user.updateUserPlace(processingPreferType(preferType));
        }
    }

    @Override
    public void saveInquiry(Long userId, String title, String question) {
        Inquiry inquiry = inquiryRepository.save(new Inquiry(userRepository.findById(userId), title, question, LocalDateTime.now()));
        inquiryStatusRepository.save(new InquiryStatus(inquiry, false));
    }

    @Override
    public void leaveMembership(Long userId) {
        User findUser = userRepository.findById(userId);
        userRepository.delete(findUser.getId());
    }

    @Override
    public Map<String, JsonObject> getMileageHistory(Long userId, Long page, Long items) {
        User findUser = userRepository.findById(userId);

        return putMileageData(findUser, page, items);
    }

    @CacheEvict(cacheNames = {"resDataByPlaceAndTypeAndDate", "resAllDataByPlaceAndTypeAndDate"}, allEntries = true)
    @Override
    public void clearPreoccupiedReservation(Long userId) {
        User user = userRepository.findById(userId);
        for (Reservation reservation : user.getReservationList()) {
            if (reservation.getStatus().equals(ReservationStatus.PROGRESSING) && reservation.getFixStatus().equals(FixStatus.UNFIXED)) {
                reservationRepository.delete(reservation);
            }
        }
    }

    @Override
    public void getReceiptForSubscribe(Long userId, long reservationId) {
        try {
            IamportClient iamportClient = new IamportClient(apiKey, apiSecret);
            String accessToken = iamportClient.getAuth().getResponse().getToken();
            String customerUid = userRepository.findById(userId).getEmail().replace("@", "").replace(".", "") + reservationId;

            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            String url = UriComponentsBuilder.fromHttpUrl("https://api.iamport.kr/subscribe/customers/" + customerUid + "/payments").queryParam("page", "{page}").encode().toUriString();

            headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
            headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
            headers.set("Authorization", accessToken);
            HttpEntity<Object> request = new HttpEntity<>(headers);
            Map<String, Object> params = new HashMap<>();
            params.put("page", 1);
            PaymentListResponse paymentListResponse = restTemplate.exchange(url, HttpMethod.GET, request, PaymentListResponse.class, params).getBody();
            PagedPaymentAnnotation pagedPaymentAnnotation = Objects.requireNonNull(paymentListResponse).getResponse().orElseThrow(() -> new NoSuchElementException("예약 결제 정보를 찾을 수 없습니다."));
            List<PaymentAnnotation> paymentAnnotations = pagedPaymentAnnotation.getList().orElseThrow(() -> new NoSuchElementException("예약 결제 정보를 찾을 수 없습니다."));
            if (!paymentAnnotations.isEmpty()) {
                PaymentAnnotation paymentAnnotation = paymentAnnotations.get(0);
                String receipt = paymentAnnotation.getReceipt_url().orElse("결제 영수증을 확인할 수 없습니다.");
                List<Payment> paymentList = reservationRepository.findById(reservationId).getPaymentList();
                for (Payment payment : paymentList) {
                    if (payment.getPayWay().equals(PayWay.POSTPAYMENT)) {
                        payment.addReceipt(receipt);
                        payment.updatePayStatus(PaymentStatus.COMPLETED);
                    }
                }
            }
        } catch (IamportResponseException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void fixReservation(Long userId, Long reservationId) {
        Reservation findReservation = reservationRepository.findById(reservationId);
        RoomType findRoomType = findReservation.getRoom().getRoomKind().getRoomType();
        if (!findRoomType.name().contains("OFFICE") && findReservation.getFixStatus().equals(FixStatus.UNFIXED)) {
            List<Payment> paymentList = findReservation.getPaymentList();
            for (Payment payment : paymentList) {
                if (payment.getReservation().getStatus().equals(ReservationStatus.COMPLETED) && payment.getType().equals(PayType.FULL_PAYMENT) || payment.getType().equals(PayType.DEPOSIT) && payment.getPayStatus().equals(PaymentStatus.COMPLETED)) {
                    if (payment.getType().equals(PayType.FULL_PAYMENT)) {
                        mileageService.savingFullPaymentMileage(payment);
                    }
                    findReservation.updateFixStatus(FixStatus.FIXED);
                    break;
                }
            }
        }
    }

    @Override
    public void forceFixReservationStarted(Long userId) {
        User user = userRepository.findById(userId);
        for (Reservation reservation : user.getReservationList()) {
            if (reservation.getStatus().equals(ReservationStatus.COMPLETED) && reservation.getFixStatus().equals(FixStatus.UNFIXED)) {
                if (LocalDateTime.of(reservation.getResStartDate(), reservation.getResStartTime()).equals(LocalDateTime.now()) || LocalDateTime.of(reservation.getResStartDate(), reservation.getResStartTime()).isBefore(LocalDateTime.now()) || LocalDateTime.of(reservation.getResEndDate(), reservation.getResEndTime()).equals(LocalDateTime.now()) || LocalDateTime.of(reservation.getResEndDate(), reservation.getResEndTime()).isBefore(LocalDateTime.now())) {
                    reservation.updateFixStatus(FixStatus.FIXED);
                    List<Payment> paymentList = reservation.getPaymentList();
                    for (Payment payment : paymentList) {
                        if (payment.getType().equals(PayType.FULL_PAYMENT) && payment.getPayWay().equals(PayWay.PREPAYMENT)) {
                            mileageService.savingFullPaymentMileage(payment);
                        }
                    }
                }
            }
        }
    }

    private Map<Long, JsonObject> getMileageHistoryDtoMap(List<MileageUpdate> mileageUpdateList) {
        Map<Long, JsonObject> result = new LinkedHashMap<>();
        Gson gson = new Gson();

        long count = 0;
        for (MileageUpdate mileageUpdate : mileageUpdateList) {
            MileageHistoryDto mileageHistoryDto = getMileageHistoryDto(mileageUpdate);
            result.put(count, gson.toJsonTree(mileageHistoryDto).getAsJsonObject());
            count++;
        }
        return result;
    }

    private MileageHistoryDto getMileageHistoryDto(MileageUpdate mileageUpdate) {
        MileageStatusType historyStatus = mileageUpdate.getStatusType();
        String info = getInfo(historyStatus, mileageUpdate);
        Long updatePoint = mileageUpdate.getUpdatePoint();
        LocalDateTime updateDate = mileageUpdate.getUpdateDate();
        String issuer = getIssuer(historyStatus, mileageUpdate);

        return new MileageHistoryDto(historyStatus, updatePoint, info, issuer, updateDate);
    }

    private List<MileageUpdate> getMileageUpdateList(User user, Long page, Long items) {
        Mileage findMileage = user.getMileage();
        return mileageRepository.findAllMileageUpdateByMileage(findMileage, page, items);
    }

    private Map<String, JsonObject> putMileageData(User user, Long page, Long items) {
        List<MileageUpdate> mileageUpdateList = getMileageUpdateList(user, page, items);
        Map<String, Integer> mileagePaginationInfo = getMileagePagenationInfo(user.getMileage());
        Map<Long, JsonObject> mileageHistoryDtoMap = getMileageHistoryDtoMap(mileageUpdateList);
        Gson gson = new Gson();
        Map<String, JsonObject> result = processingUserData(user);
        result.put("paginationData", gson.toJsonTree(mileagePaginationInfo).getAsJsonObject());
        result.put("mileageData", gson.toJsonTree(mileageHistoryDtoMap).getAsJsonObject());
        return result;
    }

    private Map<String, Integer> getMileagePagenationInfo(Mileage mileage) {
        List<MileageUpdate> totalMileageUpdateList = mileageRepository.findAllMileageUpdateByMileage(mileage);
        return Map.of("maxPage", (int) Math.ceil((double) totalMileageUpdateList.size() / 8));
    }

    private String getIssuer(MileageStatusType historyStatus, MileageUpdate mileageUpdate) {
        if (historyStatus.equals(MileageStatusType.NEW_MEMBER)) {
            return "OFFICESHARINGPLATFORM";
        } else if (historyStatus.equals(MileageStatusType.EXPIRATION)) {
            return "OFFICESHARINGPLATFORM";
        } else {
            MileagePaymentUpdate findMileagePayment = mileageRepository.findMileagePaymentByMileageUpdate(mileageUpdate);
            return findMileagePayment.getPayment().getReservation().getRoom().getPlace().getPlaceName();
        }
    }

    private String getInfo(MileageStatusType historyStatus, MileageUpdate mileageUpdate) {
        if (historyStatus.equals(MileageStatusType.NEW_MEMBER)) {
            return "신규회원";
        } else if (historyStatus.equals(MileageStatusType.EXPIRATION)) {
            return "유효기간 만료";
        } else {
            return mileageRepository.findMileagePaymentByMileageUpdate(mileageUpdate).getPaymentReason().getDescription();
        }
    }

    private void putUserInfoData(User user, Map<String, JsonObject> editUserInfoMap) {
        Gson gson = new Gson();
        Map<String, Boolean> preferType = processingPreferType(user);
        editUserInfoMap.put("userInfoData", gson.toJsonTree(new EditUserInfo(user.getPhoneNumber(), user.getJob(), preferType)).getAsJsonObject());
    }

    private void putReservationAtNow(Map<String, JsonObject> overViewMap, User user) {
        Gson gson = new Gson();
        Map<String, JsonObject> currentResMap = processingCurrentReservationData(user);
        overViewMap.put("currentResData", gson.toJsonTree(currentResMap).getAsJsonObject());

    }

    private void putRecentReservations(Map<String, JsonObject> overViewMap, User user) {
        Gson gson = new Gson();
        Map<String, JsonObject> recentResMap = processingRecentReservationData(user, LocalDate.now());
        overViewMap.put("recentResData", gson.toJsonTree(recentResMap).getAsJsonObject());
    }

    private void putResDetailData(User user, long reservationId, Map<String, JsonObject> usageDetail) {
        Gson gson = new Gson();
        MyReservationDetail myReservationDetail = getMyReservationDetail(user, reservationId);
        usageDetail.put("resData", gson.toJsonTree(myReservationDetail).getAsJsonObject());
    }

    private void putPaymentAndRefundDetailData(User user, long reservationId, Map<String, JsonObject> usageDetail) {
        Gson gson = new Gson();
        Map<String, JsonObject> myPaymentAndRefundDetail = getMyPaymentAndRefundDetail(user, reservationId);
        usageDetail.put("payData", gson.toJsonTree(myPaymentAndRefundDetail).getAsJsonObject());
    }

    private void putReservationData(User user, Map<String, JsonObject> myResMap, Integer page) {
        Gson gson = new Gson();
        Map<String, JsonObject> myUsage = processingAllReservationData(user, page);
        myResMap.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) user.getReservationList().size() / 8))).getAsJsonObject());
        myResMap.put("reservationData", gson.toJsonTree(myUsage).getAsJsonObject());
    }

    private void putQnAData(User user, Map<String, JsonObject> myInquiryMap, Integer page) {
        Gson gson = new Gson();
        Map<String, JsonObject> qnaMap = processingQnAData(user, page);
        myInquiryMap.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) user.getInquiryList().size() / 8))).getAsJsonObject());
        myInquiryMap.put("qnaData", gson.toJsonTree(qnaMap).getAsJsonObject());
    }

    private void putReviewData(User user, Map<String, JsonObject> reviewMap, Integer page) {
        Gson gson = new Gson();
        List<Rating> ratingList = ratingRepository.findAllByUserWithPagination(user, page);
        reviewMap.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) ratingRepository.countByUser(user) / 8))).getAsJsonObject());
        Map<String, JsonObject> reviewData = processingReviewData(ratingList);
        reviewMap.put("reviewData", gson.toJsonTree(reviewData).getAsJsonObject());
    }

    private Map<String, JsonObject> processingQnAData(User user, Integer page) {
        Gson gson = new Gson();
        Map<String, JsonObject> qnaMap = new LinkedHashMap<>();
        List<Inquiry> inquiryList = inquiryRepository.findAllByUserWithPagination(user, page);
        for (int i = 0; i < inquiryList.size(); i++) {
            Inquiry inquiry = inquiryList.get(i);
            AnswerData answerData = new AnswerData("");
            if (inquiry.getAnswer() != null) {
                answerData.setAnswerContext(inquiry.getAnswer().getAnswer());
            }
            QnAData qnAData = new QnAData(new QuestionData(inquiry.getId(), inquiry.getTitle(), inquiry.getContent(), inquiry.getDateTime().toLocalDate().toString(), inquiry.getDateTime().toLocalTime().toString(), inquiry.getInquiryStatus().getStatus()), answerData);
            qnaMap.put(String.valueOf(i), gson.toJsonTree(qnAData).getAsJsonObject());
        }
        return qnaMap;
    }

    private Map<String, JsonObject> processingUserData(User user) {
        Gson gson = new Gson();
        Map<String, JsonObject> myDataMap = new LinkedHashMap<>();
        JsonObject userData = gson.toJsonTree(getUserData(user)).getAsJsonObject();
        myDataMap.put("userData", userData);
        return myDataMap;
    }

    private Map<String, JsonObject> processingCurrentReservationData(User user) {
        Gson gson = new Gson();
        Map<String, JsonObject> myUsage = new LinkedHashMap<>();
        List<Reservation> reservationList = reservationRepository.findByUserAndDateTime(user, LocalDate.now(), LocalTime.now());
        for (int i = 0; i < reservationList.size(); i++) {
            Reservation reservation = reservationList.get(i);
            UsageStatus usageStatus = getUsageStatus(reservation);
            RatingStatus ratingStatus = getRatingStatus(reservation, usageStatus);
            JsonObject myReservationViewData = gson.toJsonTree(MyReservationList.builder().reservationId(reservation.getId()).productType(reservation.getRoom().getRoomKind().getRoomType().getDescription()).placeName(reservation.getRoom().getPlace().getPlaceName()).reservationCompletedDate(reservation.getResCompleted().toLocalDate().toString()).reservationCompletedTime(reservation.getResCompleted().toLocalTime().toString()).reservationStartDate(reservation.getResStartDate().toString()).reservationStartTime(reservation.getResStartTime().toString()).reservationEndDate(reservation.getResEndDate().toString()).reservationEndTime(reservation.getResEndTime().toString()).usageStatus(usageStatus.getDescription()).ratingStatus(ratingStatus.equals(RatingStatus.WRITABLE)).ratingStatusDescription(ratingStatus.getDescription()).build()).getAsJsonObject();
            myUsage.put(String.valueOf(i), myReservationViewData);
        }
        return myUsage;
    }

    private Map<String, JsonObject> processingRecentReservationData(User user, LocalDate date) {
        Gson gson = new Gson();
        Map<String, JsonObject> myUsage = new LinkedHashMap<>();
        for (int i = 0; i < reservationRepository.findRecentDataByUserWithPagination(user, 1, date).size(); i++) {
            Reservation reservation = reservationRepository.findRecentDataByUserWithPagination(user, 1, date).get(i);
            UsageStatus usageStatus = getUsageStatus(reservation);
            RatingStatus ratingStatus = getRatingStatus(reservation, usageStatus);
            JsonObject myReservationViewData = gson.toJsonTree(MyReservationList.builder().reservationId(reservation.getId()).productType(reservation.getRoom().getRoomKind().getRoomType().getDescription()).placeName(reservation.getRoom().getPlace().getPlaceName()).reservationCompletedDate(reservation.getResCompleted().toLocalDate().toString()).reservationCompletedTime(reservation.getResCompleted().toLocalTime().toString()).reservationStartDate(reservation.getResStartDate().toString()).reservationStartTime(reservation.getResStartTime().toString()).reservationEndDate(reservation.getResEndDate().toString()).reservationEndTime(reservation.getResEndTime().toString()).usageStatus(usageStatus.getDescription()).ratingStatus(ratingStatus.equals(RatingStatus.WRITABLE)).ratingStatusDescription(ratingStatus.getDescription()).build()).getAsJsonObject();
            myUsage.put(String.valueOf(i), myReservationViewData);
        }
        return myUsage;
    }

    private Map<String, JsonObject> processingAllReservationData(User user, Integer page) {
        Map<String, JsonObject> myUsage = new LinkedHashMap<>();
        for (int i = 0; i < reservationRepository.findAllByUserWithPagination(user, page).size(); i++) {
            Reservation reservation = reservationRepository.findAllByUserWithPagination(user, page).get(i);
            UsageStatus usageStatus = getUsageStatus(reservation);
            RatingStatus ratingStatus = getRatingStatus(reservation, usageStatus);
            Boolean cancelStatus = isCompleteAndUnfixed(reservation);
            Boolean completeStatus = isCompleteAndUnfixed(reservation);
            JsonObject myReservationViewData = getMyReservationViewData(reservation, usageStatus, ratingStatus, cancelStatus, completeStatus);
            myUsage.put(String.valueOf(i), myReservationViewData);
        }
        return myUsage;
    }

    private static JsonObject getMyReservationViewData(Reservation reservation, UsageStatus
            usageStatus, RatingStatus ratingStatus, Boolean cancelStatus, Boolean completeStatus) {
        Gson gson = new Gson();
        Long reservationId = reservation.getId();
        String productType = reservation.getRoom().getRoomKind().getRoomType().getDescription();
        String placeName = reservation.getRoom().getPlace().getPlaceName();
        LocalDate reservationCompletedDate = reservation.getResCompleted().toLocalDate();
        LocalTime reservationCompletedTime = reservation.getResCompleted().toLocalTime();
        LocalDate reservationStartDate = reservation.getResStartDate();
        LocalTime reservationStartTime = reservation.getResStartTime();
        LocalDate reservationEndDate = reservation.getResEndDate();
        LocalTime reservationEndTime = reservation.getResEndTime();
        String description = usageStatus.getDescription();
        boolean isWritable = ratingStatus.equals(RatingStatus.WRITABLE);
        String ratingStatusDescription = ratingStatus.getDescription();

        MyReservationList resultMyReservationList = MyReservationList.builder()
                .reservationId(reservationId)
                .productType(productType)
                .placeName(placeName)
                .reservationCompletedDate(reservationCompletedDate.toString())
                .reservationCompletedTime(reservationCompletedTime.toString())
                .reservationStartDate(reservationStartDate.toString())
                .reservationStartTime(reservationStartTime.toString())
                .reservationEndDate(reservationEndDate.toString())
                .reservationEndTime(reservationEndTime.toString())
                .usageStatus(description)
                .ratingStatus(isWritable)
                .cancelStatus(cancelStatus)
                .completeStatus(completeStatus)
                .ratingStatusDescription(ratingStatusDescription).build();
        return gson.toJsonTree(resultMyReservationList).getAsJsonObject();
    }

    private Boolean isCompleteAndUnfixed(Reservation reservation) {
        boolean result = false;
        List<Payment> paymentList = reservation.getPaymentList();
        if (reservation.getStatus().equals(ReservationStatus.COMPLETED) && reservation.getFixStatus().equals(FixStatus.UNFIXED)) {
            for (Payment payment : paymentList) {
                if (!payment.getType().equals(PayType.BALANCE) && payment.getPayStatus().equals(PaymentStatus.COMPLETED)) {
                    result = true;
                    break;
                }
            }
        }
        return result;
    }

    private Boolean isCancelation(Reservation reservation) {
        boolean result = false;
        List<Payment> paymentList = reservation.getPaymentList();
        if (reservation.getStatus().equals(ReservationStatus.COMPLETED) && reservation.getFixStatus().equals(FixStatus.UNFIXED)) {
            for (Payment payment : paymentList) {
                if (!payment.getType().equals(PayType.BALANCE) && payment.getPayStatus().equals(PaymentStatus.COMPLETED)) {
                    result = true;
                    break;
                }
            }
        }
        return result;
    }

    @NotNull
    private Map<String, JsonObject> processingCommentDataByRating(Rating rating, Integer page) {
        Gson gson = new Gson();
        Map<String, JsonObject> commentData = new LinkedHashMap<>();
        commentData.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) commentRepository.findAllByRating(rating).size() / 8))).getAsJsonObject());
        Map<String, JsonObject> commentDataMap = new LinkedHashMap<>();
        for (int i = 0; i < commentRepository.findAllByRatingWithPagination(rating, page).size(); i++) {
            Comment comment = commentRepository.findAllByRatingWithPagination(rating, page).get(i);
            commentDataMap.put(String.valueOf(i), gson.toJsonTree(new CommentDataByRating(processingUserIdentification(comment.getWriter()), comment.getText(), comment.getDateTime().toLocalDate().toString(), comment.getDateTime().toLocalTime().toString())).getAsJsonObject());
        }
        commentData.put("commentData", gson.toJsonTree(commentDataMap).getAsJsonObject());
        return commentData;
    }

    @NotNull
    private Map<String, Boolean> processingPreferType(User user) {
        Map<String, Boolean> preferType = new LinkedHashMap<>();
        String userPlace = user.getUserPlace();
        while (userPlace.contains(":")) {
            int infoSplitPoint = userPlace.indexOf(":");
            String key = userPlace.substring(0, infoSplitPoint);
            userPlace = userPlace.substring(infoSplitPoint + 1);
            int separatePoint = userPlace.indexOf("&");
            String value;
            if (separatePoint == -1) {
                value = userPlace;
            } else {
                value = userPlace.substring(0, separatePoint);
            }
            userPlace = userPlace.substring(separatePoint + 1);
            preferType.put(key, Boolean.parseBoolean(value));
        }
        return preferType;
    }

    private String processingPreferType(Map<String, Boolean> preferType) {
        StringBuilder userPreferType = new StringBuilder();
        for (String roomType : preferType.keySet()) {
            userPreferType.append(roomType).append(":").append(preferType.get(roomType)).append("&");
        }
        return userPreferType.substring(0, userPreferType.lastIndexOf("&"));
    }

    @NotNull
    private Map<String, JsonObject> processingReviewData(List<Rating> ratingList) {
        Gson gson = new Gson();
        Map<String, JsonObject> reviewData = new LinkedHashMap<>();
        for (int i = 0; i < ratingList.size(); i++) {
            Rating rating = ratingList.get(i);
            JsonObject myRatingData = gson.toJsonTree(new RatingData(rating.getReservation().getRoom().getPlace().getPlaceName(), rating.getReservation().getRoom().getRoomKind().getRoomType().getDescription(), rating.getReservation().getResStartDate().toString(), rating.getReservation().getResEndDate().toString(), rating.getReservation().getResStartTime().toString(), rating.getReservation().getResEndTime().toString(), String.valueOf(rating.getId()), rating.getRatingTime().toLocalDate().toString(), rating.getRatingTime().toLocalTime().toString(), String.valueOf(rating.getRatingScore()), rating.getRatingReview(), String.valueOf(rating.getCommentList().size()))).getAsJsonObject();
            reviewData.put(String.valueOf(i), myRatingData);
        }
        return reviewData;
    }

    private void putCommentData(Integer page, User user, Map<String, JsonObject> myCommentMap) {
        Gson gson = new Gson();
        List<Comment> commentList = commentRepository.findAllByUserWithPagination(user, page);
        myCommentMap.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) commentRepository.countByUser(user) / 8))).getAsJsonObject());
        Map<String, JsonObject> commentDataMap = new LinkedHashMap<>();
        for (int i = 0; i < commentList.size(); i++) {
            Comment comment = commentList.get(i);
            MyCommentData myCommentData = new MyCommentData(comment.getRating().getReservation().getRoom().getPlace().getPlaceName(), comment.getRating().getReservation().getRoom().getRoomKind().getRoomType().getDescription(), comment.getText(), comment.getDateTime().toLocalDate().toString(), comment.getDateTime().toLocalTime().toString());
            commentDataMap.put(String.valueOf(i), gson.toJsonTree(myCommentData).getAsJsonObject());
        }
        myCommentMap.put("commentData", gson.toJsonTree(commentDataMap).getAsJsonObject());
    }

    private UserData getUserData(User user) {
        Mileage mileage = user.getMileage();
        int totalReviewQuantity = 0;
        for (Reservation reservation : user.getReservationList()) {
            if (Optional.ofNullable(reservation.getRating()).isPresent()) {
                totalReviewQuantity++;
            }
        }
        return UserData.builder().userName(user.getUsername()).joinDate(user.getJoinDate().toLocalDate().toString()).mileagePoint(mileage.getPoint()).totalReviewNumber(totalReviewQuantity).build();
    }

    private MyReservationDetail getMyReservationDetail(User user, long reservationId) {
        Reservation reservation = reservationInfoValidation(user, reservationId);
        long totalPrice;
        if (reservation.getRoom().getRoomKind().getRoomType().toString().contains("OFFICE")) {
            totalPrice = reservation.getRoom().getRoomKind().getPrice() * (ChronoUnit.DAYS.between(reservation.getResStartDate(), reservation.getResEndDate()));
        } else {
            totalPrice = reservation.getRoom().getRoomKind().getPrice() * (ChronoUnit.HOURS.between(LocalDateTime.of(reservation.getResStartDate(), reservation.getResStartTime()), LocalDateTime.of(reservation.getResEndDate(), reservation.getResEndTime())));
        }
        double savedMileage = 0;
        for (Payment payment : reservation.getPaymentList()) {
            if (payment.getPayWay().equals(PayWay.PREPAYMENT) && payment.getType().equals(PayType.FULL_PAYMENT)) {
                savedMileage = totalPrice * 0.05;
                break;
            }
        }
        return loadReservationDetail(reservation, totalPrice, savedMileage);
    }

    private MyReservationDetail loadReservationDetail(Reservation reservation, Long totalPrice, Double savedMileage) {
        List<Room> roomList = roomRepository.findByPlace(reservation.getRoom().getPlace());
        Long roomIdInPlace = null;
        for (int i = 0; i < roomList.size(); i++) {
            Room room = roomList.get(i);
            if (reservation.getRoom() == room) {
                roomIdInPlace = (long) i + 1;
            }
        }
        if (roomIdInPlace == null) {
            throw new CalculateRoomNumErrorException("잠시 후 다시 시도해주시기 바랍니다.");
        }
        RatingStatus ratingStatus = getRatingStatus(reservation);
        UsageStatus usageStatus = getUsageStatus(reservation);
        Boolean cancelStatus = isCompleteAndUnfixed(reservation);
        Boolean completeStatus = isCompleteAndUnfixed(reservation);
        return MyReservationDetail.builder()
                .placeName(reservation.getRoom().getPlace().getPlaceName())
                .roomType(reservation.getRoom().getRoomKind().getRoomType().getDescription())
                .roomId(roomIdInPlace)
                .resCompletedDate(reservation.getResCompleted().toLocalDate().toString())
                .resCompletedTime(reservation.getResCompleted().toLocalTime().toString())
                .resStartDate(reservation.getResStartDate().toString())
                .resStartTime(reservation.getResStartTime().toString())
                .resEndDate(reservation.getResEndDate().toString())
                .resEndTime(reservation.getResEndTime().toString())
                .usageState(usageStatus.getDescription())
                .ratingStatus(ratingStatus.equals(RatingStatus.WRITABLE))
                .ratingStatusDescription(ratingStatus.getDescription())
                .totalPrice(totalPrice)
                .savedMileage(savedMileage)
                .cancelStatus(cancelStatus)
                .completeStatus(completeStatus)
                .build();
    }

    private RatingStatus getRatingStatus(Reservation reservation) {
        if (reservation.getRating() == null) {
            if (LocalDateTime.of(reservation.getResEndDate(), reservation.getResEndTime()).isBefore(LocalDateTime.now()) && reservation.getFixStatus().equals(FixStatus.FIXED)) {
                return RatingStatus.WRITABLE;
            } else {
                return RatingStatus.YET;
            }
        }
        return RatingStatus.WRITTEN;
    }

    private Map<String, JsonObject> getMyPaymentAndRefundDetail(User user, long reservationId) {
        Gson gson = new Gson();
        Map<String, JsonObject> myPaymentAndRefundDetailData = new LinkedHashMap<>();
        List<Payment> paymentList = paymentRepository.findByReservationId(reservationId);
        for (int i = 0; i < paymentList.size(); i++) {
            Map<String, JsonObject> myPaymentAndRefundDetail = new LinkedHashMap<>();
            Payment payment = paymentList.get(i);
            if (reservationRepository.findById(reservationId).getRoom().getRoomKind().getRoomType().toString().contains("OFFICE")) {
                myPaymentAndRefundDetail.put("payment", gson.toJsonTree(new MyPaymentDetail(payment.getPayDate().toString(), payment.getPayTime().toString(), payment.getPrice(), payment.getPayMileage(), "후결제", payment.getReceipt())).getAsJsonObject());
            } else {
                myPaymentAndRefundDetail.put("payment", gson.toJsonTree(new MyPaymentDetail(payment.getPayDate().toString(), payment.getPayTime().toString(), payment.getPrice(), payment.getPayMileage(), payment.getType().getDescription(), payment.getReceipt())).getAsJsonObject());
            }
            Optional<Refund> refund = refundRepository.findByPayment(payment);
            refund.ifPresent(value -> myPaymentAndRefundDetail.put("refund", gson.toJsonTree(new MyRefundDetail(value.getRefundDateTime().toLocalDate().toString(), value.getRefundDateTime().toLocalTime().toString(), value.getRefundPrice(), payment.getPayMileage(), payment.getReceipt())).getAsJsonObject()));
            myPaymentAndRefundDetailData.put(String.valueOf(i), gson.toJsonTree(myPaymentAndRefundDetail).getAsJsonObject());
        }
        return myPaymentAndRefundDetailData;
    }

    private UsageStatus getUsageStatus(Reservation reservation) {
        UsageStatus usageState = null;
        if (reservation.getStatus().equals(ReservationStatus.CANCELED)) {
            usageState = UsageStatus.CANCELED;
        } else if (reservation.getStatus().equals(ReservationStatus.PROGRESSING)) {
            usageState = UsageStatus.UNFIXED;
        } else if (reservation.getStatus().equals(ReservationStatus.COMPLETED)) {
            if (LocalDateTime.of(reservation.getResStartDate(), reservation.getResStartTime()).isAfter(LocalDateTime.now())) {
                usageState = UsageStatus.BEFORE;
            } else if (LocalDateTime.of(reservation.getResStartDate(), reservation.getResStartTime()).isBefore(LocalDateTime.now()) || LocalDateTime.of(reservation.getResStartDate(), reservation.getResStartTime()).isEqual(LocalDateTime.now())) {
                if (LocalDateTime.of(reservation.getResEndDate(), reservation.getResEndTime()).isAfter(LocalDateTime.now())) {
                    usageState = UsageStatus.NOW;
                } else {
                    usageState = UsageStatus.AFTER;
                }
            }
        }
        if (usageState == null) {
            throw new IllegalStateException("예약 상태를 확인할 수 없습니다.");
        }
        return usageState;
    }

    private RatingStatus getRatingStatus(Reservation reservation, UsageStatus usageStatus) {
        RatingStatus ratingStatus = RatingStatus.YET;
        if (usageStatus.equals(UsageStatus.AFTER)) {
            if (reservation.getRating() == null) {
                ratingStatus = RatingStatus.WRITABLE;
            } else {
                ratingStatus = RatingStatus.WRITTEN;
            }
        }
        return ratingStatus;
    }

    private Reservation reservationInfoValidation(User user, Long reservationId) {
        Reservation reservation = reservationRepository.findById(reservationId);
        if (reservation.getUser() != user) {
            throw new NoSuchElementException("회원정보와 예약정보가 불일치합니다.");
        }
        return reservation;
    }

    private String processingUserIdentification(User user) {
        String username = user.getUsername();
        String email = user.getEmail();
        int startMailDomain = email.lastIndexOf("@");
        String mailId = email.substring(0, startMailDomain);
        String mailDomain = email.substring(startMailDomain + 1);
        if (mailId.length() <= 4) {
            mailId = mailId + "***";
        } else {
            mailId = mailId.substring(0, 3) + "***";
        }
        mailDomain = mailDomain.charAt(0) + "*****";
        return username + "(" + mailId + mailDomain + ")";
    }
}
