package com.golfzonaca.officesharingplatform.web.mypage;

import com.golfzonaca.officesharingplatform.annotation.TokenUserId;
import com.golfzonaca.officesharingplatform.batch.BatchManager;
import com.golfzonaca.officesharingplatform.service.mypage.MyPageService;
import com.golfzonaca.officesharingplatform.web.mypage.dto.EditUserInfoData;
import com.golfzonaca.officesharingplatform.web.mypage.dto.SaveInquiryData;
import com.golfzonaca.officesharingplatform.web.mypage.validation.MypageRequestValidation;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("mypage")
public class MyPageController {
    private final MyPageService myPageService;
    private final MypageRequestValidation mypageRequestValidation;
    private final BatchManager batchManager;

    @GetMapping
    public Map<String, JsonObject> overView(@TokenUserId Long userId) {
        mypageRequestValidation.validationUser(userId);
        batchManager.reservationClear(userId);
        return myPageService.getOverViewData(userId);
    }

    @GetMapping("/usage")
    public Map<String, JsonObject> resHistory(@TokenUserId Long userId, @RequestParam Integer page) {
        mypageRequestValidation.validationUser(userId);
        myPageService.clearPreoccupiedReservation(userId);
        myPageService.forceFixReservationStarted(userId);
        return myPageService.getResViewData(userId, page);
    }

    @GetMapping("/{reservationId}")
    public Map<String, JsonObject> resDetail(@TokenUserId Long userId, @PathVariable long reservationId) {
        mypageRequestValidation.validationMypageDetail(userId, reservationId);
        myPageService.forceFixReservationStarted(userId);
        myPageService.getReceiptForSubscribe(userId, reservationId);
        return myPageService.getResDetailViewData(userId, reservationId);
    }

    @GetMapping("/review")
    public Map<String, JsonObject> reviewHistory(@TokenUserId Long userId, @RequestParam Integer page) {
        mypageRequestValidation.validationUser(userId);
        return myPageService.getReviewData(userId, page);
    }

    @GetMapping("/review/{ratingId}")
    public Map<String, JsonObject> commentDataByReview(@PathVariable Long ratingId, @RequestParam Integer page) {
        mypageRequestValidation.validationReviewRating(ratingId);
        return myPageService.getCommentDataByReview(ratingId, page);
    }

    @GetMapping("/comment")
    public Map<String, JsonObject> commentHistory(@TokenUserId Long userId, @RequestParam Integer page) {
        mypageRequestValidation.validationUser(userId);
        return myPageService.getCommentViewData(userId, page);
    }

    @GetMapping("/qna")
    public Map<String, JsonObject> inquiryHistory(@TokenUserId Long userId, @RequestParam Integer page) {
        mypageRequestValidation.validationUser(userId);
        return myPageService.getQnAViewData(userId, page);
    }

    @PostMapping("/qna")
    public void saveInquiry(@TokenUserId Long userId, @Validated @RequestBody SaveInquiryData inquiry, BindingResult bindingResult) {
        mypageRequestValidation.validationUserAndBindingResult(userId, bindingResult);
        myPageService.saveInquiry(userId, inquiry.getTitle(), inquiry.getQuestion());
    }


    @GetMapping("/edit")
    public Map<String, JsonObject> editUserInfo(@TokenUserId Long userId) {
        mypageRequestValidation.validationUser(userId);
        return myPageService.getEditUserInfo(userId);
    }

    @PostMapping("/edit")
    public void editUser(@TokenUserId Long userId, @Validated @RequestBody EditUserInfoData editUserInfoData, BindingResult bindingResult) {
        mypageRequestValidation.validationUserAndBindingResult(userId, bindingResult);
        String tel = editUserInfoData.getTel();
        String job = editUserInfoData.getJob();
        Map<String, Boolean> preferType = editUserInfoData.getPreferType();
        myPageService.updateUserInfo(userId, tel, job, preferType);
    }

    @PostMapping("/withdrawal")
    public void withdrawalMember(@TokenUserId Long userId) {
        mypageRequestValidation.validationUser(userId);
        myPageService.leaveMembership(userId);
    }

    @GetMapping("/mileage")
    public Map<String, JsonObject> mileageHistory(@TokenUserId Long userId, @RequestParam Integer page) {
        mypageRequestValidation.validationUser(userId);
        return myPageService.getMileageHistory(userId, Long.parseLong(String.valueOf(page)), 8L);
    }

    @PostMapping("/reservation/fix")
    public Map<String, JsonObject> reservationFix(@TokenUserId Long userId, @RequestBody Map<String, Long> reservation) {
        mypageRequestValidation.validationReservation(userId, reservation.get("reservationId"));
        myPageService.fixReservation(userId, reservation.get("reservationId"));
        return myPageService.getResDetailViewData(userId, reservation.get("reservationId"));
    }
}
