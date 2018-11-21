package zendesk

import (
	// "net/http/httptest"
	"testing"
	"time"

	"github.com/nyaruka/courier"
	. "github.com/nyaruka/courier/handlers"
)

var testChannels = []courier.Channel{
	courier.NewMockChannel("8eb23e93-5ecb-45ba-b726-3b064e0c56ab", "ZD", "2020", "US", map[string]interface{}{
		"username": "zd-username",
		"password": "zd-password",
		"base_url": "https://my.zendesk.com",
	}),
	// author-id
}

var (
	receiveURL = "/c/zd/8eb23e93-5ecb-45ba-b726-3b064e0c56ab/receive/"

	notJSON = "empty"
)

// var wrongJSONSchema = `{}`

// var validWithMoreFieldsStatus = `{
// 	"callbackMtRequest": {
//         "status": "03",
//         "statusMessage": "Delivered",
//         "statusDetail": "120",
//         "statusDetailMessage": "Message received by mobile",
//         "id": "hs765939216",
//         "received": "2014-08-26T12:55:48.593-03:00",
//         "mobileOperatorName": "Claro"
//     }
// }`

// var validStatus = `{
//     "callbackMtRequest": {
//         "status": "03",
//         "id": "hs765939216"
//     }
// }`

// var unknownStatus = `{
//     "callbackMtRequest": {
//         "status": "038",
//         "id": "hs765939216"
//     }
// }`

// var missingFieldsStatus = `{
// 	"callbackMtRequest": {
//         "status": "",
//         "id": "hs765939216"
//     }
// }`

var validReceive = `{
"id" : "4",
"title": "I haz attachments",
"comment" : "I haz attachments",
"attachments": [
    {
        "filename": "attachment",
        "url": "https://my.zendesk.com/attachments/token/eehgzAdzzTxHaVLqNbENiH0zS/?name=attachment"
    }
],
"requester_id" : "372518027891",
"requester_name": "Apple Business Chat User urn:mbid:AQAAY1cfW9pjMDJ…"
}`

// var invalidURN = `{
//     "callbackMoRequest": {
//         "id": "20690090",
//         "mobile": "MTN",
//         "shortCode": "40001",
//         "account": "zenvia.envio",
//         "body": "Msg",
//         "received": "2017-05-03T03:04:45.123-03:00",
//         "correlatedMessageSmsId": "hs765939061"
//     }
// }`

// var invalidDateReceive = `{
//     "callbackMoRequest": {
//         "id": "20690090",
//         "mobile": "254791541111",
//         "shortCode": "40001",
//         "account": "zenvia.envio",
//         "body": "Msg",
//         "received": "yesterday?",
//         "correlatedMessageSmsId": "hs765939061"
//     }
// }`

// var missingFieldsReceive = `{
// 	"callbackMoRequest": {
//         "id": "",
//         "mobile": "254791541111",
//         "shortCode": "40001",
//         "account": "zenvia.envio",
//         "body": "Msg",
//         "received": "2017-05-03T03:04:45.123-03:00",
//         "correlatedMessageSmsId": "hs765939061"
//     }
// }`

var testCases = []ChannelHandleTestCase{
	{Label: "Receive Valid", URL: receiveURL, Data: validReceive, Status: 200, Response: "Message Accepted",
		Text: Sp("Msg"), URN: Sp("zd:254791541111"), Date: Tp(time.Date(2017, 5, 3, 06, 04, 45, 123000000, time.UTC))},

	// {Label: "Invalid URN", URL: receiveURL, Data: invalidURN, Status: 400, Response: "phone number supplied is not a number"},
	// {Label: "Not JSON body", URL: receiveURL, Data: notJSON, Status: 400, Response: "unable to parse request JSON"},
	// {Label: "Wrong JSON schema", URL: receiveURL, Data: wrongJSONSchema, Status: 400, Response: "request JSON doesn't match required schema"},
	// {Label: "Missing field", URL: receiveURL, Data: missingFieldsReceive, Status: 400, Response: "validation for 'ID' failed on the 'required'"},
	// {Label: "Bad Date", URL: receiveURL, Data: invalidDateReceive, Status: 400, Response: "invalid date format"},

	// {Label: "Valid Status", URL: statusURL, Data: validStatus, Status: 200, Response: `Accepted`, MsgStatus: Sp("D")},
	// {Label: "Valid Status with more fields", URL: statusURL, Data: validWithMoreFieldsStatus, Status: 200, Response: `Accepted`, MsgStatus: Sp("D")},
	// {Label: "Unkown Status", URL: statusURL, Data: unknownStatus, Status: 200, Response: "Accepted", MsgStatus: Sp("E")},
	// {Label: "Not JSON body", URL: statusURL, Data: notJSON, Status: 400, Response: "unable to parse request JSON"},
	// {Label: "Wrong JSON schema", URL: statusURL, Data: wrongJSONSchema, Status: 400, Response: "request JSON doesn't match required schema"},
	// {Label: "Missing field", URL: statusURL, Data: missingFieldsStatus, Status: 400, Response: "validation for 'StatusCode' failed on the 'required'"},
}

func TestHandler(t *testing.T) {
	RunChannelTestCases(t, testChannels, newHandler(), testCases)
}

func BenchmarkHandler(b *testing.B) {
	RunChannelBenchmarks(b, testChannels, newHandler(), testCases)
}

// setSendURL takes care of setting the sendURL to call
// func setSendURL(s *httptest.Server, h courier.ChannelHandler, c courier.Channel, m courier.Msg) {
// 	sendURL = s.URL
// }

var defaultSendTestCases = []ChannelSendTestCase{
	{Label: "Plain Send",
		Text:           "Simple Message ☺",
		URN:            "zd:250788383383",
		Status:         "W",
		ExternalID:     "",
		ResponseBody:   `{"sendSmsResponse":{"statusCode":"00","statusDescription":"Ok","detailCode":"000","detailDescription":"Message Sent"}}`,
		ResponseStatus: 200,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Accept":        "application/json",
			"Authorization": "Basic enYtdXNlcm5hbWU6enYtcGFzc3dvcmQ=",
		},
		RequestBody: `{"sendSmsRequest":{"to":"250788383383","schedule":"","msg":"Simple Message ☺","callbackOption":"FINAL","id":"10","aggregateId":""}}`,
		// SendPrep:    setSendURL,
	},
}

func TestSending(t *testing.T) {
	// maxMsgLength = 160
	var defaultChannel = courier.NewMockChannel("8eb23e93-5ecb-45ba-b726-3b064e0c56ab", "ZD", "2020", "US", map[string]interface{}{
		"username": "zd-username",
		"password": "zd-password",
		"base_url": "https://my.zendesk.com",
	})
	RunChannelSendTestCases(t, defaultChannel, newHandler(), defaultSendTestCases, nil)
}
