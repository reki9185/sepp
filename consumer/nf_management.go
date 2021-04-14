package consumer

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	sepp_context "github.com/yangalan0903/sepp/context"
	"github.com/yangalan0903/sepp/logger"
	"github.com/yangalan0903/sepp/openapi"
	"github.com/yangalan0903/sepp/openapi/Nnrf_NFManagement"
	"github.com/yangalan0903/sepp/openapi/models"
)

func BuildNFInstance(seppContext *sepp_context.SEPPContext) (profile models.NfProfile, err error) {
	profile.NfInstanceId = seppContext.NfId
	profile.NfType = models.NfType_SEPP
	profile.NfStatus = models.NfStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, seppContext.RegisterIPv4)
	profile.PlmnList = &seppContext.PlmnList
	return
}

//func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile models.NfProfile) (resouceNrfUri string,
//    retrieveNfInstanceID string, err error) {
func SendRegisterNFInstance(nrfUri, nfInstanceId string, profile models.NfProfile) (string, string, error) {
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	for {
		if _, resTmp, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), nfInstanceId,
			profile); err != nil || resTmp == nil {
			//TODO : add log
			fmt.Println(fmt.Errorf("SEPP register to NRF Error[%v]", err))
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = resTmp
		}
		status := res.StatusCode
		if status == http.StatusOK {
			// NFUpdate
			break
		} else if status == http.StatusCreated {
			// NFRegister
			resourceUri := res.Header.Get("Location")
			resourceNrfUri := resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
			retrieveNfInstanceID := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
			return resourceNrfUri, retrieveNfInstanceID, nil
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("NRF return wrong status code %d", status))
		}
	}
	return "", "", nil
}

func SendDeregisterNFInstance() (*models.ProblemDetails, error) {

	logger.AppLog.Infof("Send Deregister NFInstance")

	seppSelf := sepp_context.GetSelf()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(seppSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	var err error
	res, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(context.Background(), seppSelf.NfId)
	if err == nil {
		return nil, err
	} else if res != nil {
		if res.Status != err.Error() {
			return nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return &problem, err
	} else {
		return nil, openapi.ReportError("server no response")
	}
}
