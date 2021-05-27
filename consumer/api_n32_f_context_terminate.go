package consumer

import (
	"github.com/yangalan0903/openapi/models"
	sepp_context "github.com/yangalan0903/sepp/context"
)

func SendN32fContextTerminate(seppUri string, fqdn sepp_context.FQDN, n32fContextInfo models.N32fContextInfo) {
	// configuration := N32_Handshake.NewConfiguration()
	// configuration.SetBasePath(seppUri)
	// client := N32_Handshake.NewAPIClient(configuration)

	// var res *http.Response
	// for {

	// 	rsp, resTmp, err := client.N32FContextTerminateApi.PostN32fTerminate(context.TODO(), n32fContextInfo)
	// 	if err != nil || resTmp == nil {
	// 		//TODO : add log
	// 		fmt.Println(fmt.Errorf("SEPP connect to remote sepp Error[%v]", err))
	// 		time.Sleep(2 * time.Second)
	// 		continue
	// 	} else {
	// 		res = resTmp
	// 	}
	// 	status := res.StatusCode
	// 	if status == http.StatusOK {
	// 		self := sepp_context.GetSelf()
	// 		delete(self.PLMNSecInfo, fqdn)
	// 		delete(self.N32fContextPool)
	// 		break
	// 	} else {
	// 		fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
	// 		fmt.Println(fmt.Errorf("remote sepp return wrong status code %d", status))
	// 	}
	// }
}
