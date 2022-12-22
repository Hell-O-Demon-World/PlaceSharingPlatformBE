package com.golfzonaca.officesharingplatform.web.reservation.form;

public class DefaultTimeOfDay {
    private static final int[] times = new int[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23};
    private static final int size = 24;

    public static int[] getTimes() {
        return times;
    }

    public static int getStartTime() {
        return times[0];
    }
    public static int getEndTime() {
        return times[23];
    }
    public static int getTotalTimeSize() {
        return size;
    }
}
