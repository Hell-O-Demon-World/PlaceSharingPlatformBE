package com.golfzonaca.officesharingplatform.service.place;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.golfzonaca.officesharingplatform.domain.*;
import com.golfzonaca.officesharingplatform.domain.type.RoomType;
import com.golfzonaca.officesharingplatform.domain.type.kakaoapi.MapCategoryGroupCode;
import com.golfzonaca.officesharingplatform.exception.UnavailablePlaceException;
import com.golfzonaca.officesharingplatform.repository.comment.CommentRepository;
import com.golfzonaca.officesharingplatform.repository.place.PlaceRepository;
import com.golfzonaca.officesharingplatform.repository.rating.RatingRepository;
import com.golfzonaca.officesharingplatform.repository.room.RoomRepository;
import com.golfzonaca.officesharingplatform.repository.roomkind.RoomKindRepository;
import com.golfzonaca.officesharingplatform.service.place.dto.comment.CommentDto;
import com.golfzonaca.officesharingplatform.service.place.dto.place.PlaceListDto;
import com.golfzonaca.officesharingplatform.service.place.dto.place.PlaceMainInfo;
import com.golfzonaca.officesharingplatform.service.place.dto.place.PlaceSubInfo;
import com.golfzonaca.officesharingplatform.service.place.dto.rating.RatingDto;
import com.golfzonaca.officesharingplatform.service.place.dto.roomtype.Desk;
import com.golfzonaca.officesharingplatform.service.place.dto.roomtype.MeetingRoom;
import com.golfzonaca.officesharingplatform.service.place.dto.roomtype.Office;
import com.golfzonaca.officesharingplatform.service.place.dto.roomtype.RoomTypeResponse;
import com.golfzonaca.officesharingplatform.web.formatter.TimeFormatter;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.querydsl.core.Tuple;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.*;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class JpaPlaceService implements PlaceService {
    private final PlaceRepository placeRepository;
    private final RoomKindRepository roomKindRepository;
    private final RoomRepository roomRepository;
    private final RatingRepository ratingRepository;
    private final CommentRepository commentRepository;

    @Value("${kakao.map.apiKey}")
    private String kakaoMapApiKey;

    @Override
    public List<Place> findAllPlaces() {
        return placeRepository.findAllPlaces();
    }

    @Override
    public Place findById(long placeId) {
        return placeRepository.findById(placeId);
    }

    @Override
    public boolean isOpenDay(Long id, String day) {
        LocalDate date = TimeFormatter.toLocalDate(day);
        String dayOfTheWeek = TimeFormatter.toDayOfTheWeek(date);
        String strOpenDays = placeRepository.findOpenDayById(id);
        String[] split = strOpenDays.split(", ");
        for (String openDay : split) {
            if (openDay.equals(dayOfTheWeek)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isOpenToday(Long id, String startTime) {
        LocalTime localStartTime = TimeFormatter.toLocalTime(startTime);
        Tuple startAndEndTime = placeRepository.findStartAndEndTimeById(id);
        LocalTime start = startAndEndTime.get(0, LocalTime.class);
        LocalTime end = startAndEndTime.get(1, LocalTime.class);
        if (Objects.requireNonNull(end).getHour() - Objects.requireNonNull(start).getHour() == 0) {
            return true;
        }
        return localStartTime.isAfter(Objects.requireNonNull(start)) && localStartTime.isBefore(Objects.requireNonNull(end));
    }

    @Override
    public boolean selectedDateValidation(String startDate, String endDate) {
        LocalDate startLocalDate = TimeFormatter.toLocalDate(startDate);
        LocalDate endLocalDate = TimeFormatter.toLocalDate(endDate);

        return startLocalDate.isBefore(endLocalDate.plusDays(1));
    }

    @Override
    public Map<String, JsonObject> getPlaceInfo(long placeId) {
        Gson gson = new Gson();
        Map<String, JsonObject> placeInfo = new LinkedHashMap<>();
        PlaceMainInfo placeMainInfo = getPlaceMainInfo(placeId);
        placeInfo.put("placeMainInfo", gson.toJsonTree(placeMainInfo).getAsJsonObject());
        Map<String, JsonObject> placeSubInfo = getInfoNearPlace(placeRepository.findById(placeId).getAddress().getLongitude(), placeRepository.findById(placeId).getAddress().getLatitude());
        if (placeSubInfo.isEmpty()) {
            placeSubInfo.put("NoSuchData", gson.toJsonTree(Map.of("PlaceCoordinateError", "주변 데이터 로딩에 실패하였습니다.")).getAsJsonObject());
        }
        placeInfo.put("placeSubInfo", gson.toJsonTree(placeSubInfo).getAsJsonObject());
        return placeInfo;
    }

    private Map<String, JsonObject> getInfoNearPlace(Double lng, Double lat) {
        if (lng == 0 && lat == 0) {
            return new LinkedHashMap<>();
        }
        Gson gson = new Gson();
        Map<String, JsonObject> placeSubInfoData = new LinkedHashMap<>();
        for (MapCategoryGroupCode category : MapCategoryGroupCode.values()) {
            Map<String, JsonObject> infoDataForCategory = getSubInfoForCategory(lng, lat, category.getCode());
            placeSubInfoData.put(category.toString().toLowerCase() + "Data", gson.toJsonTree(infoDataForCategory).getAsJsonObject());
        }
        return placeSubInfoData;
    }

    @NotNull
    private Map<String, JsonObject> getSubInfoForCategory(Double lng, Double lat, String code) {
        Gson gson = new Gson();

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        String url = UriComponentsBuilder.fromHttpUrl("https://dapi.kakao.com/v2/local/search/category.json")
                .queryParam("category_group_code", "{category_group_code}")
                .queryParam("x", "{x}")
                .queryParam("y", "{y}")
                .queryParam("radius", "{radius}")
                .queryParam("size", "{size}")
                .encode()
                .toUriString();

        headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
        headers.set("AUTHORIZATION", kakaoMapApiKey);

        HttpEntity<Object> request = new HttpEntity<>(headers);

        Map<String, Object> params = new HashMap<>();
        params.put("category_group_code", code);
        params.put("x", lng);
        params.put("y", lat);
        params.put("radius", 500);
        params.put("size", 5);

        Object object = restTemplate.exchange(url, HttpMethod.GET, request, Object.class, params).getBody();
        ObjectMapper objectMapper = new ObjectMapper();
        Map map = objectMapper.convertValue(object, Map.class);
        List<Object> elements = (List<Object>) map.get("documents");

        Map<String, JsonObject> placeSubInfoList = new LinkedHashMap<>();
        for (int i = 0; i < elements.size(); i++) {
            Map documents = objectMapper.convertValue(elements.get(i), Map.class);
            PlaceSubInfo placeSubInfo = new PlaceSubInfo(documents.get("place_name").toString(), documents.get("road_address_name").toString(), documents.get("phone").toString(), documents.get("distance").toString());
            placeSubInfoList.put(String.valueOf(i), gson.toJsonTree(placeSubInfo).getAsJsonObject());
        }
        return placeSubInfoList;
    }

    @NotNull
    private PlaceMainInfo getPlaceMainInfo(long placeId) {
        Place place = placeRepository.findById(placeId);
        List<String> imagesPath = getImagesPath(place);
        List<RatingDto> ratingList = getPlaceRating(place);
        return new PlaceMainInfo(place.getId().toString(), place.getPlaceName(), place.getAddress().getPostalCode(), place.getAddress().getAddress(), stringToList(place.getPlaceAddInfo()), imagesPath, String.valueOf(place.getRatePoint().getRatingPoint()), String.valueOf(ratingList.size()), getQuantityByRoomType(place, "DESK"), getQuantityByRoomType(place, "MEETINGROOM"), getQuantityByRoomType(place, "OFFICE"), place.getDescription(), excludeOpenDays(stringToList(place.getOpenDays())), place.getPlaceStart().toString(), place.getPlaceEnd().toString(), findRoom(placeId));
    }

    @Override
    public Map<String, JsonObject> getReviewData(Long placeId, Integer page) {
        Gson gson = new Gson();
        Place place = placeRepository.findById(placeId);
        if (getPlaceRating(place).size() == 0) {
            throw new NoSuchElementException("현재 선택하신 Place의 리뷰는 존재하지 않습니다.");
        }
        Map<String, JsonObject> reviewData = new LinkedHashMap<>();
        reviewData.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) ratingRepository.countByPlace(place) / 4))).getAsJsonObject());
        reviewData.put("reviewData", gson.toJsonTree(processingReviewData(place, page)).getAsJsonObject());
        return reviewData;
    }

    private Map<String, JsonObject> processingReviewData(Place place, Integer page) {
        Gson gson = new Gson();
        Map<String, JsonObject> reviewData = new LinkedHashMap<>();
        List<Rating> ratingList = ratingRepository.findAllByPlaceWithPagination(place, page);
        for (int i = 0; i < ratingList.size(); i++) {
            Rating rating = ratingList.get(i);
            JsonObject myRatingData = gson.toJsonTree(new RatingDto(rating.getId(), String.valueOf(rating.getRatingScore()), processingUserIdentification(rating.getReservation().getUser()), rating.getRatingTime().toLocalDate().toString(), rating.getRatingTime().toLocalTime().toString(), rating.getReservation().getRoom().getRoomKind().getRoomType().getDescription(), rating.getRatingReview(), String.valueOf(rating.getCommentList().size()))).getAsJsonObject();
            reviewData.put(String.valueOf(i), myRatingData);
        }
        return reviewData;
    }

    @Override
    public Map<String, JsonObject> getCommentData(Long reviewId, Integer page) {
        Gson gson = new Gson();
        Rating rating = ratingRepository.findById(reviewId);
        if (rating.getCommentList().size() == 0) {
            throw new NoSuchElementException("현재 선택하신 리뷰는 댓글이 존재하지 않습니다.");
        }
        Map<String, JsonObject> commentData = new LinkedHashMap<>();
        commentData.put("paginationData", gson.toJsonTree(Map.of("maxPage", (int) Math.ceil((double) rating.getCommentList().size() / 8))).getAsJsonObject());
        commentData.put("commentData", gson.toJsonTree(processingCommentData(rating, page)).getAsJsonObject());
        return commentData;
    }

    private Map<String, JsonObject> processingCommentData(Rating rating, Integer page) {
        Gson gson = new Gson();
        Map<String, JsonObject> commentData = new LinkedHashMap<>();
        List<Comment> commentList = commentRepository.findAllByRatingWithPagination(rating, page);
        for (int i = 0; i < commentList.size(); i++) {
            Comment comment = commentList.get(i);
            JsonObject myCommentData = gson.toJsonTree(new CommentDto(processingUserIdentification(comment.getWriter()), comment.getText(), comment.getDateTime().toLocalDate().toString(), comment.getDateTime().toLocalTime().toString())).getAsJsonObject();
            commentData.put(String.valueOf(i), myCommentData);
        }
        return commentData;
    }

    private RoomTypeResponse findRoom(long placeId) {
        Place findPlace = placeRepository.findById(placeId);
        return getRoomTypeResponse(findPlace);
    }

    private RoomTypeResponse getRoomTypeResponse(Place place) {
        int price = 0;

        RoomTypeResponse roomTypeResponse = new RoomTypeResponse();
        Set<String> nonDuplicatedRoomSet = getNonDuplicatedRoomSet(roomRepository.findAvailableRoomsByPlace(place));

        Desk resultDesk = new Desk(false, price, new LinkedList<>());
        SortedSet<MeetingRoom> responseMeetingRoom = new TreeSet<>();
        SortedSet<Office> responseOffice = new TreeSet<>();

        for (String roomType : nonDuplicatedRoomSet) {
            price = roomKindRepository.findByRoomType(RoomType.valueOf(roomType)).getPrice();

            List<String> images = new LinkedList<>();
            for (RoomImage roomImage : place.getRoomImages()) {
                if (roomImage.getRoomKind().getRoomType().toString().contains(roomType)) {
                    images.add(roomImage.getSavedPath());
                }
            }
            if (roomType.equals("DESK")) {
                resultDesk = new Desk(true, price, images);
            } else {
                String roomKindTag = roomType.replaceAll("[^0-9]", "");
                if (roomType.contains("MEETINGROOM")) {
                    responseMeetingRoom.add(new MeetingRoom(roomKindTag, price, images));
                } else {
                    responseOffice.add(new Office(roomKindTag, price, images));
                }
            }
        }

        roomTypeResponse.toEntity(resultDesk, responseMeetingRoom, responseOffice);
        return roomTypeResponse;
    }

    private Set<String> getNonDuplicatedRoomSet(List<Room> roomList) {
        SortedSet<String> nonDuplicatedRoomSet = new TreeSet<>();
        for (Room room : roomList) {
            nonDuplicatedRoomSet.add(room.getRoomKind().getRoomType().toString());
        }
        return nonDuplicatedRoomSet;
    }

    private String getQuantityByRoomType(Place place, String roomType) {
        int quantity = 0;
        List<Room> availableRoomList = roomRepository.findAvailableRoomsByPlace(place);
        if (!availableRoomList.isEmpty()) {
            for (Room room : availableRoomList) {
                if (room.getRoomKind().getRoomType().toString().contains(roomType)) {
                    quantity++;
                }
            }
            return String.valueOf(quantity);
        }
        throw new UnavailablePlaceException("현재 해당 PLACE 는 사용 불가합니다.");
    }

    public Map<Integer, PlaceListDto> processingMainPlaceData(List<Place> places) {
        Map<Integer, PlaceListDto> mainPlaceData = new LinkedHashMap<>();
        for (int i = 0; i < places.size(); i++) {
            Place place = places.get(i);
            List<String> imagesPath = getImagesPath(place);
            mainPlaceData.put(i, new PlaceListDto(imagesPath, place.getId().toString(), place.getPlaceName(), String.valueOf(place.getRatePoint().getRatingPoint()), place.getAddress().getAddress(), stringToList(place.getPlaceAddInfo()), place.getDescription(), excludeOpenDays(stringToList(place.getOpenDays())), place.getPlaceStart().toString(), place.getPlaceEnd().toString(), processingRoomInfo(place.getRooms())));
        }
        return mainPlaceData;
    }

    public List<RatingDto> getPlaceRating(Place place) {
        List<RatingDto> ratingList = new LinkedList<>();
        for (Room room : place.getRooms()) {
            for (Reservation reservation : room.getReservationList()) {
                if (reservation.getRating() != null) {
                    ratingList.add(new RatingDto(reservation.getRating().getId(), String.valueOf(reservation.getRating().getRatingScore()), reservation.getUser().getUsername(), reservation.getRating().getRatingTime().toLocalDate().toString(), reservation.getRating().getRatingTime().toLocalTime().toString(), reservation.getRoom().getRoomKind().getRoomType().toString(), reservation.getRating().getRatingReview(), String.valueOf(reservation.getRating().getCommentList().size())));
                }
            }
        }
        return ratingList;
    }

    @NotNull
    private List<String> getImagesPath(Place place) {
        List<String> imagesPath = new LinkedList<>();
        for (PlaceImage placeImage : place.getPlaceImages()) {
            imagesPath.add(placeImage.getSavedPath());
        }
        for (RoomImage roomImage : place.getRoomImages()) {
            imagesPath.add(roomImage.getSavedPath());
        }
        return imagesPath;
    }

    private List<String> stringToList(String string) {
        return new ArrayList<>(Arrays.asList(string.split(", ")));
    }

    private List<String> excludeOpenDays(List<String> openDays) {
        List<String> daysOfWeek = new ArrayList<>(Arrays.asList("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"));
        for (String openDay : openDays) {
            daysOfWeek.remove(openDay);
        }
        return daysOfWeek;
    }

    private Map<String, String> processingRoomInfo(List<Room> rooms) {
        Map<String, String> roomInfo = new LinkedHashMap<>();
        calculateMinPriceByType(rooms, roomInfo, "DESK");
        calculateMinPriceByType(rooms, roomInfo, "MEETINGROOM");
        calculateMinPriceByType(rooms, roomInfo, "OFFICE");
        return roomInfo;
    }

    private void calculateMinPriceByType(List<Room> rooms, Map<String, String> roomInfo, String type) {
        for (Room room : rooms) {
            if (room.getRoomKind().getRoomType().toString().contains(type)) {
                if (roomInfo.containsKey(type)) {
                    if (room.getRoomKind().getPrice() < Integer.parseInt(roomInfo.get(type))) {
                        roomInfo.put(type, String.valueOf(room.getRoomKind().getPrice()));
                    }
                } else {
                    roomInfo.put(type, String.valueOf(room.getRoomKind().getPrice()));
                }
            }
        }
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
