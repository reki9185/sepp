package producer

import (
	"bitbucket.org/free5gc-team/http_wrapper"
	"github.com/yangalan0903/sepp/models"
)

func HandleN32fCtxTerminate(request *http_wrapper.Request) *http_wrapper.Response {
	logger.PostN32fTerminate.Infof("handle PostN32fTerminate")

	N32fContextInfo := request.Body.(models.N32fContextInfo)

	response, problemDetails := N32fCtxTerminateProcedure(N32fContextInfo)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)  
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func N32fCtxTerminateProcedure(N32fContextInfo models.N32fContextInfo) (*models.N32fContextInfo, 
	*models.ProblemDetails) {

}

func HandleExchangeCapability(request *http_wrapper.Request) *http_wrapper.Response {
	logger.ExchangeCapability.Infof("handle ExchangeCapability")

	secNegotiateReqData := request.Body.(models.secNegotiateReqData)

	response, problemDetails := ExchangeCapabilityProcedure(secNegotiateReqData)

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)  
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func ExchangeCapabilityProcedure(secNegotiateReqData models.secNegotiateReqData) (*models.SecNegotiateRspData, 
	*models.ProblemDetails) {
	var responseBody models.SecNegotiateRspData

}