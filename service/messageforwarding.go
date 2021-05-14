package service

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/yangalan0903/openapi/models"
	"github.com/yangalan0903/sepp/jsonhandler"
	"github.com/yangalan0903/sepp/logger"
)

func HandleMessageForwarding(rspWriter http.ResponseWriter, request *http.Request) {
	var dataToIntegrityProtectBlock models.DataToIntegrityProtectBlock

	requestBody, err := ioutil.ReadAll(request.Body)
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.Handshake.Errorf("Get Request Body error: %+v", err)
		rspWriter.WriteHeader(http.StatusInternalServerError)
		rsp, err := json.Marshal(problemDetail)
		if err != nil {
			logger.Handshake.Errorf("Encode problemDetail error: %+v", err)
		}
		rspWriter.Write(rsp)
		// ctx.JSON(http.StatusInternalServerError, problemDetail)
		return
	}
	dataToIntegrityProtectBlock.Payload = jsonhandler.ParseJsonBody(requestBody)
	// request.RequestURI

}
