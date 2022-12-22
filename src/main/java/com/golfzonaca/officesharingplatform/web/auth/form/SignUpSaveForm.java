package com.golfzonaca.officesharingplatform.web.auth.form;

import com.golfzonaca.officesharingplatform.annotation.PhoneNum;
import com.golfzonaca.officesharingplatform.domain.Mileage;
import com.golfzonaca.officesharingplatform.domain.Role;
import com.golfzonaca.officesharingplatform.domain.User;
import com.golfzonaca.officesharingplatform.domain.type.RoleType;
import com.golfzonaca.officesharingplatform.web.auth.form.prefertype.PreferType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignUpSaveForm {
    @NotNull(message = "이메일은 Null일 수 없습니다.")
    @Email(message = "이메일 형식을 지켜주세요.")
    @Size(max = 32, message = "이메일 길이는 최대 32자 이내 입니다.")
    private String email;
    @NotBlank(message = "비밀번호에 빈 문자나 공백 또는 Null 값이 들어갈 수 없습니다.")
    @Size(min = 8, max = 15, message = "비밀번호의 길이는 8 ~ 15 자리여야 합니다.")
    private String password;
    @NotBlank(message = "비밀번호에 빈 문자나 공백 또는 Null 값이 들어갈 수 없습니다.")
    @Size(min = 8, max = 15, message = "비밀번호의 길이는 8 ~ 15 자리여야 합니다.")
    private String checkedPassword;
    @NotBlank(message = "이름에 빈 문자나 공백 또는 Null 값이 들어갈 수 없습니다.")
    @Size(max = 20, message = "이름의 길이는 최대 20자 이내 입니다.")
    private String name;
    @PhoneNum(message = "전화번호는 '-' 없이 숫자만 입력해주시기 바랍니다.")
    @Size(min = 9, max = 11, message = "전화번호의 길이는 최소 9자, 최대 11자 입니다.")
    private String phoneNumber;
    @NotNull(message = "직업은 Null일 수 없습니다.")
    @Size(max = 20, message = "직업명의 길이는 최대 20자 이내 입니다.")
    private String job;
    @NotNull(message = "선호 유형은 Null일 수 없습니다.")
    private List<PreferType> preferType;

    public User toEntity() {

        String changePreferString = getChangePreferString(preferType);
        return new User(name, email, password, phoneNumber, job, changePreferString, new Mileage(0L), new Role(1L, RoleType.ROLE_USER));
    }

    private String getChangePreferString(List<PreferType> preferType) {
        String changePreferString = "".concat("desk:" + (preferType.get(0).isDesk()) + "&"
                + "meetingroom:" + (preferType.get(0).isMeetingroom()) + "&"
                + "office:" + (preferType.get(0).isOffice()));
        return changePreferString;
    }
}
