package consumer

import (
	"context"
	"fmt"
	"net/http" //"net/http"
	"time"

	"github.com/yangalan0903/openapi/N32_Handshake"
	"github.com/yangalan0903/openapi/models"
	sepp_context "github.com/yangalan0903/sepp/context"
)

func SendExchangeCapability(seppUri string) {
	configuration := N32_Handshake.NewConfiguration()
	configuration.SetBasePath(seppUri)
	client := N32_Handshake.NewAPIClient(configuration)

	self := sepp_context.GetSelf()
	var secNegotiateReqData models.SecNegotiateReqData
	secNegotiateReqData.Sender = self.SelfFqdn
	secNegotiateReqData.SupportedSecCapabilityList = append(secNegotiateReqData.SupportedSecCapabilityList, models.SecurityCapability_TLS, models.SecurityCapability_PRINS)
	secNegotiateReqData.Var3GppSbiTargetApiRootSupported = true

	var res *http.Response
	for {
		rsp, resTmp, err := client.SecurityCapabilityNegotiationApi.PostExchangeCapability(context.TODO(), secNegotiateReqData)
		if err != nil || resTmp == nil {
			//TODO : add log
			fmt.Println(fmt.Errorf("SEPP connect to remote sepp Error[%v]", err))
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = resTmp
		}
		status := res.StatusCode
		if status == http.StatusOK {
			self := sepp_context.GetSelf()
			var secInfo sepp_context.SecInfo
			secInfo.SecCap = rsp.SelectedSecCapability
			secInfo.Var3GppSbiTargetApiRootSupported = rsp.Var3GppSbiTargetApiRootSupported
			self.PLMNSecInfo[rsp.Sender] = secInfo
			break
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("remote sepp return wrong status code %d", status))
		}
	}
}
