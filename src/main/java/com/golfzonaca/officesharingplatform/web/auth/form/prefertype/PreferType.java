package com.golfzonaca.officesharingplatform.web.auth.form.prefertype;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PreferType {
    private boolean desk;
    private boolean meetingroom;
    private boolean office;
}
