package com.golfzonaca.officesharingplatform.web.main;

import com.golfzonaca.officesharingplatform.batch.BatchManager;
import com.golfzonaca.officesharingplatform.service.auth.AuthService;
import com.golfzonaca.officesharingplatform.service.place.PlaceService;
import com.golfzonaca.officesharingplatform.service.place.dto.place.PlaceListDto;
import com.golfzonaca.officesharingplatform.service.search.SearchService;
import com.golfzonaca.officesharingplatform.web.main.dto.request.*;
import com.golfzonaca.officesharingplatform.web.main.validation.MainPageValidation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("main")
public class MainController {
    private final MainPageValidation mainPageValidation;
    private final PlaceService placeService;
    private final SearchService searchService;
    private final AuthService authService;
    private final BatchManager batchManager;

    @GetMapping()
    public Map<Integer, PlaceListDto> allPlace() {
        return placeService.processingMainPlaceData(placeService.findAllPlaces());
    }

    @PostMapping("/search")
    public Map<Integer, PlaceListDto> searchPlaces(@RequestBody @Validated RequestSearchData requestSearchData, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            throw new IllegalArgumentException("검색어를 입력해주시기 바랍니다.");
        }
        if (requestSearchData.getSearchWord().equals("")) {
            return placeService.processingMainPlaceData(placeService.findAllPlaces());
        }
        return placeService.processingMainPlaceData(searchService.findPlaces(requestSearchData));
    }

    @PostMapping("/filter")
    public Map<Integer, PlaceListDto> filterPlaces(@RequestBody @Validated RequestFilterData requestFilterData, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            throw new IllegalArgumentException("필터 조건을 하나 이상 선택해주시기 바랍니다.");
        }
        if (requestFilterData.getDay().equals("0") && requestFilterData.getStartTime().equals("24") && requestFilterData.getEndTime().equals("0") && requestFilterData.getCity().equals("0") && requestFilterData.getSubCity().equals("0") && requestFilterData.getType().equals("0")) {
            return placeService.processingMainPlaceData(placeService.findAllPlaces());
        }
        return placeService.processingMainPlaceData(searchService.filterPlaces(requestFilterData.getDay(), requestFilterData.getStartTime(), requestFilterData.getEndTime(), requestFilterData.getCity(), requestFilterData.getSubCity(), requestFilterData.getType()));
    }

    @PostMapping("/findemail")
    public Map<String, String> findUserEmailId(@RequestBody @Validated RequestFindIdForm findIdForm, BindingResult bindingResult) {
        Map<String, String> resultMap = new HashMap<>();
        String name = findIdForm.getName();
        String tel = findIdForm.getTel();
        mainPageValidation.validationBindingResult(name, tel, bindingResult);
        resultMap.put("findUserMail", authService.findUserEmail(name, tel));
        return resultMap;
    }

    @PostMapping("/precheck")
    public Map<String, String> checkingIdAndPw(@RequestBody @Validated PwPreCheckForm pwPreCheckForm, BindingResult bindingResult) {
        Map<String, String> resultMap = new LinkedHashMap<>();
        String email = pwPreCheckForm.getEmail();
        String tel = pwPreCheckForm.getTel();
        mainPageValidation.validationEmailTelBindingResult(email, tel, bindingResult);
        resultMap.put("email", email);
        resultMap.put("tel", tel);
        resultMap.put("msg", "확인 완료!");
        return resultMap;
    }

    @PostMapping("/findpw")
    public Map<String, String> findPassword(@RequestBody @Validated PwCheckForm pwPreCheckForm, BindingResult bindingResult) {
        Map<String, String> resultMap = new HashMap<>();
        String pw = pwPreCheckForm.getPassword();
        String pw2 = pwPreCheckForm.getCheckPassword();
        String email = pwPreCheckForm.getEmail();
        String tel = pwPreCheckForm.getTel();
        mainPageValidation.validationEmailTelBindingResult(email, tel, pw, pw2, bindingResult);
        authService.createNewPassword(email, pw);
        resultMap.put("msg", "비밀번호 수정 완료!");
        return resultMap;
    }
}
