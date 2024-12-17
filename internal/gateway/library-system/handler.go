package library_system

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Erlendum/rsoi-lab-02/internal/gateway/config"
	my_time "github.com/Erlendum/rsoi-lab-02/pkg/time"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	defaultTimeout         = 4 * time.Second
	defaultMaxConnsPerHost = 100
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type handler struct {
	httpClient httpClient
	config     *config.Config
}

const (
	rentedStatus   = "RENTED"
	expiredStatus  = "EXPIRED"
	returnedStatus = "RETURNED"
)

var (
	errNotOkStatusCode = errors.New("not ok status code")
	conditionMap       = map[string]int{
		"BAD":       1,
		"GOOD":      2,
		"EXCELLENT": 3,
	}
)

func NewHandler(config *config.Config) *handler {
	return &handler{
		httpClient: &http.Client{
			Timeout:   defaultTimeout,
			Transport: &http.Transport{MaxConnsPerHost: defaultMaxConnsPerHost},
		},
		config: config,
	}
}

func compareConditions(a, b string) (int, error) {
	weightA, okA := conditionMap[a]
	weightB, okB := conditionMap[b]

	if !okA || !okB {
		return 0, errors.New("one or both conditions are not valid")
	}

	if weightA < weightB {
		return -1, nil
	} else if weightA > weightB {
		return 1, nil
	}
	return 0, nil
}

func (h *handler) Register(echo *echo.Echo) {
	api := echo.Group("/api/v1")

	api.GET("/libraries", h.GetLibraries)
	api.GET("/libraries/:libraryUid/books", h.GetBooksByLibrary)
	api.GET("/reservations", h.GetBooksByUser)
	api.POST("/reservations", h.ReserveBookByUser)
	api.POST("/reservations/:reservationUid/return", h.ReturnBookByUser)
	api.GET("/rating", h.GetRatingByUser)
}

func (h *handler) GetLibraries(c echo.Context) error {
	queryParams := url.Values{}
	queryParams.Add("city", c.QueryParam("city"))
	queryParams.Add("page", c.QueryParam("page"))
	queryParams.Add("size", c.QueryParam("size"))
	reqURL, err := url.Parse(h.config.LibrarySystemURL + "/libraries")
	if err != nil {
		log.Err(err).Msg("failed to parse request to library service")
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "failed to parse request"})
	}

	reqURL.RawQuery = queryParams.Encode()

	req, err := http.NewRequest(http.MethodGet, reqURL.String(), nil)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "failed to process request"})
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	c.Response().Header().Set("Content-Type", "application/json")
	return c.String(resp.StatusCode, string(body))
}

func (h *handler) GetBooksByLibrary(c echo.Context) error {
	queryParams := url.Values{}
	queryParams.Add("page", c.QueryParam("page"))
	queryParams.Add("size", c.QueryParam("size"))
	queryParams.Add("showAll", c.QueryParam("showAll"))
	reqURL, err := url.Parse(h.config.LibrarySystemURL + "/libraries/" + c.Param("libraryUid") + "/books")
	if err != nil {
		log.Err(err).Msg("failed to parse request to library service")
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "failed to parse request"})
	}

	reqURL.RawQuery = queryParams.Encode()

	req, err := http.NewRequest(http.MethodGet, reqURL.String(), nil)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "failed to process request"})
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	c.Response().Header().Set("Content-Type", "application/json")
	return c.String(resp.StatusCode, string(body))
}

type bookResp struct {
	BookUid string `json:"bookUid"`
	Name    string `json:"name"`
	Author  string `json:"author"`
	Genre   string `json:"genre"`
}

func (h *handler) getBooksByUids(uids []string) (map[string]bookResp, error) {
	reqURL, err := url.Parse(h.config.LibrarySystemURL + "/books/")
	if err != nil {
		return nil, err
	}

	q := reqURL.Query()
	for _, bookUid := range uids {
		q.Add("bookUids", bookUid)
	}
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	type booksResp struct {
		Data []bookResp `json:"data"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var booksRespData booksResp
	err = json.Unmarshal(body, &booksRespData)
	if err != nil {
		return nil, err
	}
	booksMap := map[string]bookResp{}
	for _, book := range booksRespData.Data {
		booksMap[book.BookUid] = book
	}

	return booksMap, nil
}

type libraryResp struct {
	LibraryUid string `json:"libraryUid"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	City       string `json:"city"`
}

func (h *handler) getLibrariesByUids(uids []string) (map[string]libraryResp, error) {
	reqURL, err := url.Parse(h.config.LibrarySystemURL + "/libraries/by-uids")
	if err != nil {
		return nil, err
	}

	q := reqURL.Query()
	for _, libraryUid := range uids {
		q.Add("libraryUids", libraryUid)
	}
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	type librariesResp struct {
		Data []libraryResp `json:"data"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var librariesRespData librariesResp
	err = json.Unmarshal(body, &librariesRespData)
	if err != nil {
		return nil, err
	}

	librariesMap := map[string]libraryResp{}
	for _, library := range librariesRespData.Data {
		librariesMap[library.LibraryUid] = library
	}

	return librariesMap, nil
}

type reservationResp struct {
	ReservationUid string `json:"reservationUid"`
	Status         string `json:"status"`
	StartDate      string `json:"startDate"`
	TillDate       string `json:"tillDate"`
	BookUid        string `json:"bookUid"`
	LibraryUid     string `json:"libraryUid"`
}

func (h *handler) getReservationsByUser(userName string) ([]reservationResp, int, error) {
	reqURL, err := url.Parse(h.config.ReservationSystemURL + "/reservations/by-user/" + userName)
	if err != nil {
		return nil, 0, err
	}

	q := reqURL.Query()
	q.Add("status", rentedStatus)
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, 0, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, errors.Join(err, fmt.Errorf("%s", string(body)))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, errNotOkStatusCode
	}

	var reservations []reservationResp
	err = json.Unmarshal(body, &reservations)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return reservations, http.StatusOK, nil
}

func (h *handler) getReservationsByUid(uid string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, h.config.ReservationSystemURL+"/reservations/"+uid, nil)
	if err != nil {
		return 0, nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, errNotOkStatusCode
	}

	return resp.StatusCode, body, nil
}

func (h *handler) GetBooksByUser(c echo.Context) error {
	reservations, statusCode, err := h.getReservationsByUser(c.Request().Header.Get("X-User-Name"))
	if err != nil {
		log.Err(err).Msg("failed to process request to reservation service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.JSON(statusCode, echo.Map{"message": err.Error()})
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	booksUids := make([]string, 0, len(reservations))
	librariesUids := make([]string, 0, len(reservations))
	for _, r := range reservations {
		booksUids = append(booksUids, r.BookUid)
		librariesUids = append(librariesUids, r.LibraryUid)
	}

	booksMap, err := h.getBooksByUids(booksUids)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	librariesMap, err := h.getLibrariesByUids(librariesUids)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	type reservationExtended struct {
		ReservationUid string      `json:"reservationUid"`
		Status         string      `json:"status"`
		StartDate      string      `json:"startDate"`
		TillDate       string      `json:"tillDate"`
		Book           bookResp    `json:"book"`
		Library        libraryResp `json:"library"`
	}

	reservationsExtended := make([]reservationExtended, 0, len(reservations))
	for _, r := range reservations {
		reservationsExtended = append(reservationsExtended, reservationExtended{
			ReservationUid: r.ReservationUid,
			Status:         r.Status,
			StartDate:      r.StartDate,
			TillDate:       r.TillDate,
			Book:           booksMap[r.BookUid],
			Library:        librariesMap[r.LibraryUid],
		})
	}

	return c.JSON(http.StatusOK, reservationsExtended)
}

func (h *handler) createUser(userName string) (int, []byte, error) {
	type createUserReq struct {
		UserName string `json:"userName"`
	}

	reqBody, err := json.Marshal(createUserReq{UserName: userName})
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, h.config.RatingSystemURL+"/rating/", bytes.NewBuffer(reqBody))
	if err != nil {
		return 0, nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, errNotOkStatusCode
	}

	return resp.StatusCode, body, nil
}

func (h *handler) createReservation(reqBody []byte, userName string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, h.config.ReservationSystemURL+"/reservations/", bytes.NewBuffer(reqBody))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-User-Name", userName)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, errors.Join(err, fmt.Errorf("%s", string(body)))
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, errNotOkStatusCode
	}

	return resp.StatusCode, body, nil
}

func (h *handler) ReserveBookByUser(c echo.Context) error {
	reservations, statusCode, err := h.getReservationsByUser(c.Request().Header.Get("X-User-Name"))
	if err != nil {
		log.Err(err).Msg("failed to process request to reservation service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.JSON(statusCode, echo.Map{"message": err.Error()})
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	statusCode, body, err := h.getRatingByUser(c.Request().Header.Get("X-User-Name"))
	if err != nil && !errors.Is(err, errNotOkStatusCode) {
		log.Err(err).Msg("failed to process request to rating service")
		return c.JSON(http.StatusServiceUnavailable, echo.Map{"message": "Bonus Service unavailable"})
	}

	if statusCode != http.StatusOK && statusCode != http.StatusNotFound {
		return c.String(statusCode, string(body))
	}

	stars := 0
	// если пользователь не найден, создаем его
	if statusCode == http.StatusNotFound {
		statusCode, body, err = h.createUser(c.Request().Header.Get("X-User-Name"))
		if err != nil {
			log.Err(err).Msg("failed to process request to rating service")
			if errors.Is(err, errNotOkStatusCode) {
				return c.String(statusCode, string(body))
			}
			return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
		}
		type createUserResp struct {
			ID       int    `json:"id"`
			UserName string `json:"userName"`
			Stars    int    `json:"stars"`
		}
		createdUser := createUserResp{}
		err = json.Unmarshal(body, &createdUser)
		if err != nil {
			log.Err(err).Msg("failed to process request to rating service")
			return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
		}
		stars = createdUser.Stars
	} else {
		type ratingResp struct {
			Stars int `json:"stars"`
		}
		rating := ratingResp{}
		err = json.Unmarshal(body, &rating)
		if err != nil {
			log.Err(err).Msg("failed to process request to rating service")
			return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
		}
		stars = rating.Stars
	}

	// количество текущих бронирований + 1 (которое сейчас хочет сделать пользователь) не должно превышать количество звезд (макс. количество одновременных бронирований)
	if len(reservations)+1 > stars {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "reservations over limit"})
	}

	reqBody, err := io.ReadAll(c.Request().Body)
	if err != nil {
		log.Err(err).Msg("failed to parse request")
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "failed to parse request"})
	}

	statusCode, body, err = h.createReservation(reqBody, c.Request().Header.Get("X-User-Name"))
	if err != nil {
		log.Err(err).Msg("failed to process request to reservation service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.String(statusCode, string(body))
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	type createReservationResp struct {
		ReservationUid string `json:"reservationUid"`
		Status         string `json:"status"`
		StartDate      string `json:"startDate"`
		TillDate       string `json:"tillDate"`
		BookUid        string `json:"bookUid"`
		LibraryUid     string `json:"libraryUid"`
	}

	createdReservation := createReservationResp{}
	err = json.Unmarshal(body, &createdReservation)
	if err != nil {
		log.Err(err).Msg("failed to process request to reservation service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	statusCode, body, err = h.updateAvailableCount(createdReservation.LibraryUid, createdReservation.BookUid, -1)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.String(statusCode, string(body))
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	type response struct {
		ReservationUid string      `json:"reservationUid"`
		Status         string      `json:"status"`
		StartDate      string      `json:"startDate"`
		TillDate       string      `json:"tillDate"`
		Book           bookResp    `json:"book"`
		Library        libraryResp `json:"library"`
		Rating         struct {
			Stars int `json:"stars"`
		} `json:"rating"`
	}

	books, err := h.getBooksByUids([]string{createdReservation.BookUid})
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	libraries, err := h.getLibrariesByUids([]string{createdReservation.LibraryUid})
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	return c.JSON(http.StatusOK, response{
		ReservationUid: createdReservation.ReservationUid,
		Status:         createdReservation.Status,
		StartDate:      createdReservation.StartDate,
		TillDate:       createdReservation.TillDate,
		Book:           books[createdReservation.BookUid],
		Library:        libraries[createdReservation.LibraryUid],
		Rating: struct {
			Stars int `json:"stars"`
		}{
			Stars: stars,
		},
	})
}

func (h *handler) updateAvailableCount(libraryUid, bookUid string, countDiff int) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPut, h.config.LibrarySystemURL+"/libraries/"+libraryUid+"/books/"+bookUid+"?countDiff="+strconv.Itoa(countDiff), nil)
	if err != nil {
		return 0, nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, errNotOkStatusCode
	}

	return resp.StatusCode, body, nil
}

func (h *handler) updateReservationStatus(reservationUid, status, username string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPut, h.config.ReservationSystemURL+"/reservations/"+reservationUid+"/status?status="+status, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-User-Name", username)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, errNotOkStatusCode
	}

	return resp.StatusCode, body, nil
}

func (h *handler) updateUserRating(username string, starsDiff int) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPut, h.config.RatingSystemURL+"/rating/"+username+"?starsDiff="+strconv.Itoa(starsDiff), nil)
	if err != nil {
		return 0, nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, body, errNotOkStatusCode
	}

	return resp.StatusCode, body, nil
}

func (h *handler) ReturnBookByUser(c echo.Context) error {
	statusCode, body, err := h.getReservationsByUid(c.Param("reservationUid"))
	if err != nil {
		log.Err(err).Msg("failed to process request to reservation service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.String(statusCode, string(body))
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	reservation := reservationResp{}
	err = json.Unmarshal(body, &reservation)
	if err != nil {
		log.Err(err).Msg("failed to process request to reservation service")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	type req struct {
		Condition string `json:"condition"`
		Date      string `json:"date"`
	}

	reqBody, err := io.ReadAll(c.Request().Body)
	if err != nil {
		log.Err(err).Msg("failed to parse request")
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "failed to parse request"})
	}

	reqData := req{}
	err = json.Unmarshal(reqBody, &reqData)
	if err != nil {
		log.Err(err).Msg("failed to parse request")
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "failed to parse request"})
	}

	starsDiff := 0
	targetStatus := returnedStatus
	tillDate, err := my_time.NewDate(reservation.TillDate)
	if err != nil {
		log.Err(err).Msg("failed to parse till date")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}
	reqDate, err := my_time.NewDate(reqData.Date)
	if err != nil {
		log.Err(err).Msg("failed to parse date")
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}
	if time.Time(*reqDate).After(time.Time(*tillDate)) {
		targetStatus = expiredStatus
		starsDiff -= 10
	}

	if starsDiff == 0 {
		starsDiff = 1
	}

	statusCode, body, err = h.updateReservationStatus(reservation.ReservationUid, targetStatus, c.Request().Header.Get("X-User-Name"))
	if err != nil {
		log.Err(err).Msg("failed to process request to reservation service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.String(statusCode, string(body))
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	statusCode, body, err = h.updateAvailableCount(reservation.LibraryUid, reservation.BookUid, 1)
	if err != nil {
		log.Err(err).Msg("failed to process request to library service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.String(statusCode, string(body))
		}
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "failed to process request"})
	}

	statusCode, body, err = h.updateUserRating(c.Request().Header.Get("X-User-Name"), starsDiff)
	if err != nil {
		log.Err(err).Msg("failed to process request to rating service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.String(statusCode, string(body))
		}
		return c.JSON(http.StatusServiceUnavailable, echo.Map{"message": "Bonus Service unavailable"})
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *handler) getRatingByUser(userName string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, h.config.RatingSystemURL+"/rating/"+userName, nil)
	if err != nil {
		return 0, nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, errors.Join(errNotOkStatusCode, fmt.Errorf("status code = %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, body, nil
}

func (h *handler) GetRatingByUser(c echo.Context) error {
	statusCode, body, err := h.getRatingByUser(c.Request().Header.Get("X-User-Name"))
	if err != nil {
		log.Err(err).Msg("failed to process request to rating service")
		if errors.Is(err, errNotOkStatusCode) {
			return c.String(statusCode, string(body))
		}
		return c.JSON(http.StatusServiceUnavailable, echo.Map{"message": "Bonus Service unavailable"})
	}

	c.Response().Header().Set("Content-Type", "application/json")
	return c.String(http.StatusOK, string(body))
}
