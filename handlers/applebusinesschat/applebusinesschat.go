package applebusinesschat

/*
GET /handlers/applebusinesschat/received/uuid?account=12345&dest=8500&message=Msg&sender=256778021111
*/

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/nyaruka/courier"
	"github.com/nyaruka/courier/handlers"
	"github.com/nyaruka/courier/utils"
	"github.com/nyaruka/gocommon/urns"
	"github.com/pkg/errors"
)

const (
	configCSPID      = "csp_id"
	configBusinessID = "business_id"
	mspAgentName     = "rp-bot"
)

var (
	sendURL          = "https://mspgw.push.apple.com/v1/message"
	decodePayloadURL = "https://mspgw.push.apple.com/v1/decodePayload"
	preDownloadURL   = "https://mspgw.push.apple.com/v1/preDownload"
	preUploadURL     = "https://mspgw.push.apple.com/v1/preUpload"
)

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
	messageTypeClose       = "close"        //Receive Only - Indicates that the customer closed the chat. Only a customer can close a chat. The CSP should never send a message with this type to Business Chat
	messageRichLink        = "richLink"     //Send Only - Indicates the message contains rich link data.
)

// Header Keys
const (
	headerAuthorization = "Authorization"  //Credentials used to authenticate the request. See Authorize a Message.
	headerID            = "id"             //A UUID string that identifies the message.
	headerSourceID      = "source-id"      //A string that identifies the message sender. When a customer sends a message, the source-id is the customer’s opaque ID. When a business sends a reply to the customer, the source-id is the business ID.
	headerDestinationID = "destination-id" //A string that identifies the message recipient. When a customer sends a message, the destination-id is the business ID. When a business sends a reply to the customer, the value is the customer’s opaque ID.
	headerMSPAgent      = "msp-agent"      //A string that identifies the agent or system sending the request. The CSP should set the field to a string value that is meaningful to them. Business Chat logs up to the first 64 characters of the string.
	headerDeviceAgent   = "device-agent"   //A string that identifies the operating system type of the customer’s device. Possible values include: "iPhone OS", "Mac OS X", "Watch OS", and "Apple TVOS". Business Chat includes this header key in each request it sends to the CSP.
	headerAutoReply     = "auto-reply"     //A Boolean that determines whether the reply is sent by a person or an automated bot. Set the value to true when an automated agent (a bot) sends the reply.
)

// message is the top level message object for all sent/received Apple Business Chat messages
type message struct {
	ID                 string             `json:"id"`                 //A UUID string that identifies the message.
	SourceID           string             `json:"sourceId"`           //The customer’s opaque ID identifying the customer as the message sender.
	DestinationID      string             `json:"destinationId"`      //The business ID of the message recipient.
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

// receiveMessage is our HTTP handler function for incoming messages
// https://developer.apple.com/documentation/businesschat/receiving_messages
func (h *handler) receiveMessage(ctx context.Context, channel courier.Channel, w http.ResponseWriter, r *http.Request) ([]courier.Event, error) {

	// make sure we have config keys
	secretKey := channel.StringConfigForKey(courier.ConfigSecret, "")
	if secretKey == "" {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, fmt.Errorf("missing secretKey config for AC channel"))
	}

	cspID := channel.StringConfigForKey(configCSPID, "")
	if cspID == "" {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, fmt.Errorf("missing csp_id config for AC channel"))
	}

	businessID := channel.StringConfigForKey(configBusinessID, "")
	if businessID == "" {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, fmt.Errorf("missing business_id config for AC channel"))
	}

	// 1. Validate message
	// Verify that the destination-id field in the HTTP request header matches a valid business ID
	// Validate the Authorization header field
	// Check for required HTTP request header fields
	// Verify that the HTTP request body contains JSON data
	msgDestinationID := r.Header.Get(headerDestinationID)
	if msgDestinationID != businessID {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, fmt.Errorf("business_id does not match destination-id header for AC channel"))
	}

	// Other headers
	// NOTE: We can re-enable these if we use them
	// msgID := r.Header.Get(headerID)
	// msgSourceID := r.Header.Get(headerSourceID)
	// msgMSPAgent := r.Header.Get(headerMSPAgent)
	// msgDeviceAgent := r.Header.Get(headerDeviceAgent)
	// msgAutoReply := r.Header.Get(headerAutoReply)

	// 2. Verify Authorization
	// CSP-ID
	// secretKey

	reqToken := r.Header.Get(headerAuthorization)
	splitToken := strings.Split(reqToken, " ")
	if len(splitToken) != 2 || strings.ToLower(splitToken[0]) != "bearer" {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, fmt.Errorf("Authorization header must be in the format Bearer <token>"))
	}
	reqToken = splitToken[1]
	if err := validateToken(reqToken, cspID, secretKey); err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, errors.Wrap(err, "Invalid Token:"))
	}

	msg := &message{}
	if err := handlers.DecodeAndValidateForm(msg, r); err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}

	// ignore anything other than text messages
	if msg.Type != messageTypeText {
		return nil, handlers.WriteAndLogRequestIgnored(ctx, h, channel, w, r, fmt.Sprintf("ignoring non-text request: %s", msg.Type))
	}

	// create our URN
	urn, err := newAppleBusinessChatURN(msg.SourceID)
	if err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}

	// build our msg
	dbMsg := h.Backend().NewIncomingMsg(channel, urn, msg.Body).WithExternalID(msg.ID)

	// and finally write our message
	return handlers.WriteMsgsAndResponse(ctx, h, []courier.Msg{dbMsg}, w, r)
}

// TODO: Move this to github.com/nyaruka/gocommon/urns
func newAppleBusinessChatURN(identifier string) (urns.URN, error) {
	AppleBusinessChatScheme := "applebusinesschat"
	return urns.NewURNFromParts(AppleBusinessChatScheme, identifier, "", "")
}

// SendMsg sends the passed in message, returning any error
func (h *handler) SendMsg(ctx context.Context, msg courier.Msg) (courier.MsgStatus, error) {

	// make sure we have config keys
	secretKey := msg.Channel().StringConfigForKey(courier.ConfigSecret, "")
	if secretKey == "" {
		return nil, fmt.Errorf("missing secretKey config for AC channel")
	}

	cspID := msg.Channel().StringConfigForKey(configCSPID, "")
	if cspID == "" {
		return nil, fmt.Errorf("missing csp_id config for AC channel")
	}

	businessID := msg.Channel().StringConfigForKey(configBusinessID, "")
	if businessID == "" {
		return nil, fmt.Errorf("missing business_id config for AC channel")
	}

	recipientID := msg.URN().Path()
	text := handlers.GetTextAndAttachments(msg)

	status := h.Backend().NewMsgStatusForID(msg.Channel(), msg.ID(), courier.MsgErrored)

	// get auth token
	authToken, err := generateAuthToken(cspID, secretKey)
	if err != nil {
		return status, err
	}

	// build message payload
	payload := message{V: 1}
	payload.Type = messageTypeText
	payload.DestinationID = recipientID
	payload.SourceID = businessID
	payload.Body = text
	payload.ID = msg.UUID().String()

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return status, err
	}

	req, err := http.NewRequest(http.MethodPost, sendURL, bytes.NewReader(jsonBody))
	if err != nil {
		return status, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	req.Header.Set(headerAuthorization, fmt.Sprintf("Bearer %s", authToken))

	// Set Apple headers
	// req.Header.Set(headerDestinationID, recipientID)
	// req.Header.Set(headerSourceID, businessID)
	req.Header.Set(headerMSPAgent, mspAgentName)

	// TODO: change auto-reply to false if human responding instead of bot
	req.Header.Set(headerAutoReply, "true")

	rr, err := utils.MakeHTTPRequest(req)
	log := courier.NewChannelLogFromRR("Message Sent", msg.Channel(), msg.ID(), rr).WithError("Message Send Error", err)
	status.AddLog(log)

	if err != nil {
		return status, nil
	}

	// this was wired successfully
	status.SetStatus(courier.MsgWired)

	return status, nil
}

var (
	cachedAuthTokenTime time.Time
	cachedAuthToken     string
	muAuthToken         *sync.RWMutex //goroutine safe token access
)

// generateAuthToken creates or re-uses a cached valid JWT with valid Apple Business Chat claims
//
// Valid Claims:
//"alg" - A string identifying the algorithm used to encode the payload.
//"aud" - A string, or array of strings, identifying the recipients of the JWT. The value should be a string when the JWT has one recipient; otherwise, it should be an array of strings where each string represents a recipient. The aud value is always the CSP ID when exchanging messages with Business Chat.
//"iss" - A string identifying the principal that issued the JWT. The value is always the CSP ID when exchanging messages with Business Chat.
//"iat" - A numeric date—that is, an integer—identifying the time at which the JWT was issued. The value is the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC date and time, ignoring leap seconds. For more information, see the Terminology section in RFC 7519.
func generateAuthToken(cspid string, secretKey string) (string, error) {
	// Token older than 1 hour? expire
	oneHourAgo := time.Now().Add(-time.Minute * 55)

	// cached token still valid?
	muAuthToken.RLock()
	if cachedAuthTokenTime.After(oneHourAgo) {
		token := cachedAuthToken
		muAuthToken.RUnlock()
		return token, nil
	}
	muAuthToken.RUnlock()

	// regenerate auth token
	muAuthToken.Lock()
	defer muAuthToken.Unlock()
	// check that another goroutine didnt already generate time/token
	if cachedAuthTokenTime.Before(oneHourAgo) {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iat": now.Unix(),
			"iss": cspid,
		})

		tokenString, err := tok.SignedString(secretKey)
		if err != nil {
			return "", err
		}

		cachedAuthToken = tokenString
		cachedAuthTokenTime = now
	}

	token := cachedAuthToken
	return token, nil
}

// validateToken verifies a JWT
func validateToken(tokenString string, cspid string, secretKey string) error {

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok {

		if !token.Valid {
			return errors.New("Auth token invalid")
		}

		if !claims.VerifyAudience(cspid, true) {
			return errors.New("Invalid auth token aud")
		}

	} else {
		return errors.New("Could not parse JWT claims")
	}

	return nil
}
