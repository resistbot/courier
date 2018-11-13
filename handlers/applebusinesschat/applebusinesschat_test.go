package applebusinesschat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/nyaruka/courier"
	. "github.com/nyaruka/courier/handlers"
)

var testChannels = []courier.Channel{
	courier.NewMockChannel("8eb23e93-5ecb-45ba-b726-3b064e0c568c", "ABC", "abc", "",
		map[string]interface{}{
			"business_id": "BUSINESS-ID",
			"csp_id":      "MY_CSP_ID",
			"api_key":     "MY_APPLE_SECRET_KEY",
		}),
}

var helloMsg = `{
  "id": "UUID-IDENTIFIER-FOR-MESSAGE",
  "sourceId": "OPAQUE-USER-ID",
  "destinationId": "BUSINESS-ID",
  "type": "text",
  "body": "Hello, Business!",
  "v": 1
}`

var sampleRBSendMsg = `{
    "v": 1,
    "id": "5933ce5e-f00e-4676-9dc9-c836c691ff74",
    "destinationId": "urn:mbid:AQAAY1NqPSTSeQwkQncvKV7EFJV7I6fo9MuOxr36/6inR8bDgP2rrxWJyoKFWr9E7SEdJ2dh/zZ2sWodRUfsfZbZ0Guj+Rmx8HI0wvXuQQoq+CbApyZTUjZw0ngDx2fs8sTO8lgcQz17L4fFkycFSsCLqJOVDLw=",
    "body": "Hi, welcome to Resistbot!",
    "type": "text"
}`

var sampleUserResponseMsg = `{
    "type": "text",
    "id": "3895ba60-39b3-43f5-9f95-2680d034b5f2",
    "v": 1,
    "sourceId": "urn:mbid:AQAAY1NqPSTSeQwkQncvKV7EFJV7I6fo9MuOxr36/6inR8bDgP2rrxWJyoKFWr9E7SEdJ2dh/zZ2sWodRUfsfZbZ0Guj+Rmx8HI0wvXuQQoq+CbApyZTUjZw0ngDx2fs8sTO8lgcQz17L4fFkycFSsCLqJOVDLw=",
    "destinationId": "f8a50971-30ec-11e7-b4f4-d718e535f270",
    "body": "Yes",
    "locale": "en_US"
}`

var typingStartMsg = `{
  "id": "UUID-IDENTIFIER-FOR-MESSAGE",
  "sourceId": "OPAQUE-USER-ID",
  "destinationId": "BUSINESS-ID",
  "type": "typing_start",
  "v": 1
}`

var testCases = []ChannelHandleTestCase{
	{Label: "Receive Valid Message", URL: "/c/ac/8eb23e93-5ecb-45ba-b726-3b064e0c568c/receive/", Data: helloMsg, Status: 200, Response: "Accepted",
		Text: Sp("Hello Business!"), URN: Sp("applebusinesschat:OPAQUE-USER-ID"),
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Accept":        "application/json",
			"Authorization": "Bearer ACCESS_TOKEN",
		},
	},

	{Label: "Receive Start Typing Message", URL: "/c/ac/8eb23e93-5ecb-45ba-b726-3b064e0c568c/receive/", Data: typingStartMsg, Status: 200, Response: "Ignoring"},

	{Label: "Receive Invalid JSON", URL: "/c/ac/8eb23e93-5ecb-45ba-b726-3b064e0c568c/receive/", Data: "foo", Status: 400, Response: "unable to parse"},
}

func buildMockAppleBusinessChatService(testCases []ChannelHandleTestCase) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		defer r.Body.Close()

		if authorizationHeader != "Bearer ACCESS_TOKEN" {
			http.Error(w, "invalid file", 403)
			return
		}

		if strings.HasSuffix(r.URL.Path, "user/info.action") {
			openID := r.URL.Query().Get("openid")

			// user has a name
			if strings.HasSuffix(openID, "1337") {
				w.Write([]byte(`{ "nickname": "John Doe"}`))
				return
			}

			// no name
			w.Write([]byte(`{ "nickname": ""}`))

		}

	}))
	sendURL = server.URL

	return server
}

func generateMockServerToken(cspid string, authSecret string) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": time.Now().Unix(),
		"iss": cspid,
	})

	tokenString, err := tok.SignedString(authSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

generateFakeServerToken

func TestHandler(t *testing.T) {
	telegramService := buildMockAppleBusinessChatService(testCases)
	defer telegramService.Close()

	RunChannelTestCases(t, testChannels, newHandler(), testCases)
}

func BenchmarkHandler(b *testing.B) {
	telegramService := buildMockAppleBusinessChatService(testCases)
	defer telegramService.Close()

	RunChannelBenchmarks(b, testChannels, newHandler(), testCases)
}

// setSendURL takes care of setting the send_url to our test server host
func setSendURL(s *httptest.Server, h courier.ChannelHandler, c courier.Channel, m courier.Msg) {
	sendURL = s.URL
}

var defaultSendTestCases = []ChannelSendTestCase{
	{Label: "Plain Send",
		Text: "Simple Message", URN: "applebusinesschat:12345",
		Status: "W", ExternalID: "133",
		ResponseBody: `{ "ok": true, "result": { "message_id": 133 } }`, ResponseStatus: 200,
		PostParams: map[string]string{
			"text":         "Simple Message",
			"chat_id":      "12345",
			"reply_markup": `{"remove_keyboard":true}`,
		},
		SendPrep: setSendURL},
	{Label: "Quick Reply",
		Text: "Are you happy?", URN: "applebusinesschat:12345", QuickReplies: []string{"Yes", "No"},
		Status: "W", ExternalID: "133",
		ResponseBody: `{ "ok": true, "result": { "message_id": 133 } }`, ResponseStatus: 200,
		PostParams: map[string]string{
			"text":         "Are you happy?",
			"chat_id":      "12345",
			"reply_markup": `{"resize_keyboard":true,"one_time_keyboard":true,"keyboard":[[{"text":"Yes"},{"text":"No"}]]}`,
		},
		SendPrep: setSendURL},
	{Label: "Unicode Send",
		Text: "☺", URN: "applebusinesschat:12345",
		Status: "W", ExternalID: "133",
		ResponseBody: `{ "ok": true, "result": { "message_id": 133 } }`, ResponseStatus: 200,
		PostParams: map[string]string{"text": "☺", "chat_id": "12345"},
		SendPrep:   setSendURL},
	{Label: "Error",
		Text: "Error", URN: "applebusinesschat:12345",
		Status:       "E",
		ResponseBody: `{ "ok": false }`, ResponseStatus: 403,
		PostParams: map[string]string{"text": `Error`, "chat_id": "12345"},
		SendPrep:   setSendURL},
	{Label: "Send Photo",
		Text: "My pic!", URN: "applebusinesschat:12345", Attachments: []string{"image/jpeg:https://foo.bar/image.jpg"},
		Status:       "W",
		ResponseBody: `{ "ok": true, "result": { "message_id": 133 } }`, ResponseStatus: 200,
		PostParams: map[string]string{"caption": "My pic!", "chat_id": "12345", "photo": "https://foo.bar/image.jpg"},
		SendPrep:   setSendURL},
	{Label: "Send Video",
		Text: "My vid!", URN: "applebusinesschat:12345", Attachments: []string{"video/mpeg:https://foo.bar/video.mpeg"},
		Status:       "W",
		ResponseBody: `{ "ok": true, "result": { "message_id": 133 } }`, ResponseStatus: 200,
		PostParams: map[string]string{"caption": "My vid!", "chat_id": "12345", "video": "https://foo.bar/video.mpeg"},
		SendPrep:   setSendURL},
	{Label: "Send Audio",
		Text: "My audio!", URN: "applebusinesschat:12345", Attachments: []string{"audio/mp3:https://foo.bar/audio.mp3"},
		Status:       "W",
		ResponseBody: `{ "ok": true, "result": { "message_id": 133 } }`, ResponseStatus: 200,
		PostParams: map[string]string{"caption": "My audio!", "chat_id": "12345", "audio": "https://foo.bar/audio.mp3"},
		SendPrep:   setSendURL},
	{Label: "Unknown Attachment",
		Text: "My pic!", URN: "applebusinesschat:12345", Attachments: []string{"unknown/foo:https://foo.bar/unknown.foo"},
		Status:   "E",
		SendPrep: setSendURL},
}

func TestSending(t *testing.T) {
	var defaultChannel = courier.NewMockChannel("8eb23e93-5ecb-45ba-b726-3b064e0c56ab", "TG", "2020", "US",
		map[string]interface{}{courier.ConfigAuthToken: "auth_token"})

	RunChannelSendTestCases(t, defaultChannel, newHandler(), defaultSendTestCases, nil)
}
