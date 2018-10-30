package applebusinesschat

/*
GET /handlers/applebusinesschat/received/uuid?account=12345&dest=8500&message=Msg&sender=256778021111
*/

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/nyaruka/courier"
	"github.com/nyaruka/courier/handlers"
	"github.com/nyaruka/courier/utils"
	"github.com/pkg/errors"
)

var ()

func init() {
	courier.RegisterHandler(newHandler())
}

type handler struct {
	handlers.BaseHandler
}

func newHandler() courier.ChannelHandler {
	return &handler{handlers.NewBaseHandler(courier.ChannelType("AC"), "Apple Business Chat")}
}

func (h *handler) Initialize(s courier.Server) error {
	h.SetServer(s)
	s.AddHandlerRoute(h, http.MethodPost, "receive", h.receiveMessage)
	return nil
}

//MessageTypes:
const (
	messageTypeText        = "text"         //Indicates that this is a text message, with or without attachments.
	messageTypeInteractive = "interactive"  //Indicates that this is an interactive message.
	messageTypeTypingStart = "typing_start" //Indicates that the customer is actively entering text in Messages.
	messageTypeTypingEnd   = "typing_end"   //Indicates that the customer cleared the text they were entering.
	messageTypeClose       = "close"        //Indicates that the customer closed the chat. Only a customer can close a chat. The CSP should never send a message with this type to Business Chat
)

// userMessage is the top level message object for all received Apple Business Chat messages
type userMessage struct {
	SourceID           string             `json:"sourceId"`           //The customer’s opaque ID identifying the customer as the message sender.
	DestinationID      string             `json:"destinationId"`      //The business ID of the message recipient.
	ID                 string             `json:"id"`                 //A UUID string that identifies the message.
	Body               string             `json:"body"`               //The message text. This field is required when the type is text. There is no predetermined maximum for this field, but there may be a maximum size for the payload. This field supports the Basic Multilingual Plane of unicode.
	Type               string             `json:"type"`               //A string that identifies the message type. For the list of possible values, see Message Type Values.
	V                  int                `json:"v"`                  //The message schema version number. Must be 1, which is the current version of the message JSON.
	Group              string             `json:"group"`              //The group identifier for the message as specified by the business, such as the department name. This parameter is optional.
	Attachments        []attachment       `json:"attachments"`        //An array of attachment dictionaries. See Attachment Dictionary for more information. This parameter is optional.
	InteractiveData    interactiveData    `json:"interactiveData"`    //A dictionary representing the properties of an interactive message. See Interactive Data Dictionary for more information. This parameter is optional.
	InteractiveDataRef interactiveDataRef `json:"interactiveDataRef"` //A dictionary representing the properties of an interactive message. See Interactive Data Dictionary for more information. This parameter is optional.
	Intent             string             `json:"intent"`             //The intention, or purpose, of the chat as specified by the business. This parameter is optional.
	Locale             string             `json:"locale"`             //The customers locale. This parameter is optional.

}

type attachment struct {
	Name            string `json:"name"`             //The name of the file.
	MimeType        string `json:"mimeType"`         //The MIME type.
	Size            string `json:"size"`             //The size of the encrypted attachment, in bytes.
	Key             string `json:"key"`              //The single-use, 256-bit AES key represented as a hex-encoded string. To decrypt a downloaded attachment file using key, remove the 00 prefix from the hex-encoded string, then decode the string into its original value. Use the decoded key value to decrypt the downloaded attachment file.
	URL             string `json:"url"`              //A string, in URL format, assigned by Business Chat to identify the attachment.
	Owner           string `json:"owner"`            //A string, in URL format, of the attachment owner.
	SignatureBase64 string `json:"signature-base64"` //The file checksum, represented as a Base64-encoded string. (Optional)
	Signature       string `json:"signature"`        //The file checksum, represented as a hex-encoded string. (Optional)
}

type interactiveData struct {
	Bid               string          `json:"bid"`               //A string identifying the iMessage extension that the customer interacts with while using Messages. The bid value format is: com.apple.messages.MSMessageExtensionBalloonPlugin:team-id:extension-id When using your custom interactive message, replace team-id and extension-id with your team and extension IDs. When using a Business Chat interactive message, set team-id to 0000000000 and the extension-id to com.apple.icloud.apps.messages.business.extension. For example: com.apple.messages.MSMessageExtensionBalloonPlugin:0000000000:com.apple.icloud.apps.messages.business.extension
	Data              interface{}     `json:"data"`              //A dictionary containing additional information for Business Chat interactive messages. Messages ignores this field for custom interactive messages. See Data Dictionary for more information.
	URL               string          `json:"URL"`               //A URL string containing data that Messages sends to the iMessage extension. Use query string parameters as keys and values to the data. The maximum size of the data is 64 KB. Messages requires this key to launch the extension with a specific context. For more information, see Messages.
	ReceivedMessage   receivedMessage `json:"receivedMessage"`   //A dictionary with information telling Messages how and what content to display the received message bubble.
	ReplyMessage      interface{}     `json:"replyMessage"`      //A dictionary with information telling Messages how and what to display in the reply message bubble.
	AppID             string          `json:"appId"`             //The App Store identifier of the iMessage extension. The CSP must include this key when sending an interactive message that uses an iMessage extension provided by the business. Don’t include this key when sending an interactive message that uses a Business Chat iMessage extension. For more information, see Using a Custom Interactive Message.
	AppName           string          `json:"appName"`           //The name of the iMessage extension. The CSP must include this key when sending an interactive message that uses an iMessage extension provided by the business. Don’t include this key when sending an interactive message that uses a Business Chat iMessage extension. For more information, see Using a Custom Interactive Message.
	AppIcon           string          `json:"appIcon"`           //A Base64-encoded string representing the app icon of the iMessage extension. Messages displays the icon when a customer's device receives a custom interactive message that uses an iMessage extension not installed on the device. The CSP must include this key when sending an interactive message that uses an iMessage extension provided by the business. Don’t include this key when sending an interactive message that uses a Business Chat iMessage extension. For more information, see Using a Custom Interactive Message.
	UseLiveLayout     bool            `json:"useLiveLayout"`     //A Boolean that determines whether Messages should use Live Layout. The default is true. This key is optional.
	SessionIdentifier string          `json:"sessionIdentifier"` //Identifies the session or transaction. The CSP determines the value of this key. Replies from the customer’s device includes this key and its value. This key is optional.
}

type receivedMessage struct {
	Title             string `json:"title"`
	Subtitle          string `json:"subtitle"`
	ImageTitle        string `json:"imageTitle"`
	ImageSubtitle     string `json:"imageSubtitle"`
	SecondarySubtitle string `json:"secondarySubtitle"`
	TertiarySubtitle  string `json:"tertiarySubtitle"`
}

type interactiveDataRef struct {
	Owner           string `json:"owner"`            //The owner of the attachment.
	URL             string `json:"url"`              //A URL assigned by Business Chat to identify the attachment.
	Key             string `json:"key"`              //The key needed to decrypt the encrypted attachment. For information, see Downloading and Decrypting the Attachment.
	Size            string `json:"size"`             //The size, in bytes, of the encrypted attachment.
	SignatureBase64 string `json:"signature-base64"` //The file checksum, represented as a Base64-encoded string.
	Title           string `json:"title"`            //The title for the interaction. It should match the value in interactiveData.receivedMessage.title.
	Bid             string `json:"bid"`              //Identifies the iMessage extension.
}

type moForm struct {
	From    string `name:"from"`
	Sender  string `name:"sender"`
	Message string `name:"message"`
	Date    string `name:"date"`
	Time    string `name:"time"`
}

// receiveMessage is our HTTP handler function for incoming messages
// https://developer.apple.com/documentation/businesschat/receiving_messages
func (h *handler) receiveMessage(ctx context.Context, channel courier.Channel, w http.ResponseWriter, r *http.Request) ([]courier.Event, error) {

	// 1. Validate message
	// Verify that the destination-id field in the HTTP request header matches a valid business ID
	// Validate the Authorization header field
	// Check for required HTTP request header fields
	// Verify that the HTTP request body contains JSON data

	// // make sure we have an auth token
	// authToken := channel.StringConfigForKey(courier.ConfigAuthToken, "")
	// if authToken == "" {
	// 	return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, fmt.Errorf("missing auth token for FB channel"))
	// }

	// form := &moForm{}
	// if err := handlers.DecodeAndValidateForm(form, r); err != nil {
	// 	return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	// }

	// // must have one of from or sender set, error if neither
	// sender := form.Sender
	// if sender == "" {
	// 	sender = form.From
	// }
	// if sender == "" {
	// 	return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, errors.New("must have one of 'sender' or 'from'"))
	// }

	// // if we have a date, parse it
	// dateString := form.Date
	// if dateString == "" {
	// 	dateString = form.Time
	// }

	// var err error
	// date := time.Now()
	// if dateString != "" {
	// 	date, err = time.Parse(time.RFC3339Nano, dateString)
	// 	if err != nil {
	// 		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, errors.New("invalid date format, must be RFC 3339"))
	// 	}
	// }

	// // create our URN
	// urn, err := handlers.StrictTelForCountry(sender, channel.Country())
	// if err != nil {
	// 	return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	// }

	// // build our msg
	// dbMsg := h.Backend().NewIncomingMsg(channel, urn, form.Message).WithReceivedOn(date)

	// // and finally write our message
	// return handlers.WriteMsgsAndResponse(ctx, h, []courier.Msg{dbMsg}, w, r)
	return nil, nil
}

// SendMsg sends the passed in message, returning any error
func (h *handler) SendMsg(ctx context.Context, msg courier.Msg) (courier.MsgStatus, error) {

	// urlStr := msg.Channel().StringConfigForKey(courier.ConfigBaseURL, "")
	// baseURL, err := url.Parse(urlStr)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid base url set for AC channel: %s", err)
	// }

	// username := msg.Channel().StringConfigForKey(courier.ConfigUsername, "")
	// if username == "" {
	// 	return nil, fmt.Errorf("no username set for YO channel")
	// }

	// password := msg.Channel().StringConfigForKey(courier.ConfigPassword, "")
	// if password == "" {
	// 	return nil, fmt.Errorf("no password set for YO channel")
	// }

	// status := h.Backend().NewMsgStatusForID(msg.Channel(), msg.ID(), courier.MsgErrored)

	// for _, part := range handlers.SplitMsg(handlers.GetTextAndAttachments(msg), maxMsgLength) {
	// 	form := url.Values{
	// 		"origin":       []string{strings.TrimPrefix(msg.Channel().Address(), "+")},
	// 		"sms_content":  []string{part},
	// 		"destinations": []string{strings.TrimPrefix(msg.URN().Path(), "+")},
	// 		"ybsacctno":    []string{username},
	// 		"password":     []string{password},
	// 	}

	// 	for _, sendURL := range sendURLs {
	// 		sendURL, _ := url.Parse(sendURL)
	// 		sendURL.RawQuery = form.Encode()

	// 		req, _ := http.NewRequest(http.MethodGet, sendURL.String(), nil)
	// 		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 		rr, err := utils.MakeHTTPRequest(req)
	// 		log := courier.NewChannelLogFromRR("Message Sent", msg.Channel(), msg.ID(), rr).WithError("Message Send Error", err)
	// 		status.AddLog(log)

	// 		if err != nil {
	// 			continue
	// 		}

	// 		responseQS, _ := url.ParseQuery(string(rr.Body))

	// 		// check whether we were blacklisted
	// 		createMessage, _ := responseQS["ybs_autocreate_message"]
	// 		if len(createMessage) > 0 && strings.Contains(createMessage[0], "BLACKLISTED") {
	// 			status.SetStatus(courier.MsgFailed)

	// 			// create a stop channel event
	// 			channelEvent := h.Backend().NewChannelEvent(msg.Channel(), courier.StopContact, msg.URN())
	// 			err = h.Backend().WriteChannelEvent(ctx, channelEvent)
	// 			if err != nil {
	// 				return nil, err
	// 			}

	// 			return status, nil
	// 		}

	// 		// finally check that we were sent
	// 		createStatus, _ := responseQS["ybs_autocreate_status"]
	// 		if len(createStatus) > 0 && createStatus[0] == "OK" {
	// 			status.SetStatus(courier.MsgWired)
	// 			return status, nil
	// 		}
	// 	}
	// }

	// return status, err

	return nil, nil
}
