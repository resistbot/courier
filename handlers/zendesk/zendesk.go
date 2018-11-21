package zendesk

/*
GET /handlers/zendesk/received/
*/

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/nyaruka/courier"
	// "github.com/nyaruka/courier/backends/rapidpro"
	"github.com/nyaruka/courier/handlers"
	"github.com/nyaruka/courier/utils"
	"github.com/nyaruka/gocommon/urns"
	"github.com/sirupsen/logrus"
	// "github.com/pkg/errors"
)

var (
	configAuthorID = "author-id" //zendesk user id of the agent (if different than api user)

	sendCommentURL   = "/api/v2/tickets"
	sendTicketURL    = "/api/v2/tickets.json"
	searchTicketsURL = "/api/v2/search.json"
	// sendUploadURL = "/api/v2/tickets/"
)

func init() {
	courier.RegisterHandler(newHandler())
}

type handler struct {
	handlers.BaseHandler
}

func newHandler() courier.ChannelHandler {
	return &handler{handlers.NewBaseHandler(courier.ChannelType("ZD"), "Zendesk")}
}

func (h *handler) Initialize(s courier.Server) error {
	h.SetServer(s)
	s.AddHandlerRoute(h, http.MethodPost, "receive", h.receiveMessage)
	return nil
}

// message is an incoming message from zendesk
type message struct {
	ID          string `json:"id"` //ticket id
	Title       string `json:"title"`
	Comment     string `json:"comment"`
	Attachments []struct {
		Filename string `json:"filename"`
		URL      string `json:"url"`
	} `json:"attachments"`
	RequesterID   string `json:"requester_id"`
	RequesterName string `json:"requester_name"`
}

// commentPayload is used to create a new zendesk comment on an existing ticket
// TODO: Attaching files via "Uploads" - https://developer.zendesk.com/rest_api/docs/core/tickets#attaching-files
type commentPayload struct {
	Body     string `json:"body,omitempty"`
	HTMLBody string `json:"html_body,omitempty"`
	Public   bool   `json:"public,omitempty"`
	AuthorID int64  `json:"author_id,omitempty"`
	// CreatedAt time.Time `json:"created_at,omitempty"`
	// Uploads   []string  `json:"uploads,omitempty"`
}

// newTicketPayload is used to create a new ticket
type newTicketPayload struct {
	Ticket ticketPayload `json:"ticket"`
}

type ticketPayload struct {
	Comment commentPayload `json:"comment"`

	ExternalID      string        `json:"external_id,omitempty"`      //An id you can use to link Zendesk Support tickets to local records
	Type            string        `json:"type,omitempty"`             //The type of this ticket. Possible values: "problem", "incident", "question" or "task"
	Subject         string        `json:"subject,omitempty"`          //The value of the subject field for this ticket
	RawSubject      string        `json:"raw_subject,omitempty"`      //The dynamic content placeholder, if present, or the "subject" value, if not. See Dynamic Content
	Priority        string        `json:"priority,omitempty"`         //The urgency with which the ticket should be addressed. Possible values: "urgent", "high", "normal", "low"
	Status          string        `json:"status,omitempty"`           //The state of the ticket. Possible values: "new", "open", "pending", "hold", "solved", "closed"
	Recipient       string        `json:"recipient,omitempty"`        //The original recipient e-mail address of the ticket
	RequesterID     int64         `json:"requester_id,omitempty"`     //The user who requested this ticket
	SubmitterID     int64         `json:"submitter_id,omitempty"`     //The user who submitted the ticket. The submitter always becomes the author of the first comment on the ticket
	AssigneeID      int64         `json:"assignee_id,omitempty"`      //The agent currently assigned to the ticket
	OrganizationID  int64         `json:"organization_id,omitempty"`  //The organization of the requester. You can only specify the ID of an organization associated with the requester. See Organization Memberships
	GroupID         int64         `json:"group_id,omitempty"`         //The group this ticket is assigned to
	CollaboratorIDs []int64       `json:"collaborator_ids,omitempty"` //The ids of users currently cc'ed on the ticket
	Collaborators   []interface{} `json:"collaborators,omitempty"`    //POST requests only. Users to add as cc's when creating a ticket. See Setting Collaborators
	FollowerIDs     []int64       `json:"follower_ids,omitempty"`     //Agents currently following the ticket
	ForumTopicID    int64         `json:"forum_topic_id,omitempty"`   //The topic this ticket originated from, if any
	ProblemID       int64         `json:"problem_id,omitempty"`       //For tickets of type "incident", the ID of the problem the incident is linked to
	// DueAt               time.Time     `json:"due_at,omitempty"`                 //If this is a ticket of type "task" it has a due date. Due date format uses ISO 8601 format.
	Tags                []string      `json:"tags,omitempty"`                   //The array of tags applied to this ticket
	CustomFields        []interface{} `json:"custom_fields,omitempty"`          //Custom fields for the ticket. See Setting custom field values
	ViaFollowupSourceID int64         `json:"via_followup_source_id,omitempty"` //POST requests only. The id of a closed ticket when creating a follow-up ticket. See Creating Follow-up Tickets
	MacroIDs            []int64       `json:"macro_ids,omitempty"`              //POST requests only. List of macro IDs to be recorded in the ticket audit
}

type searchTicketResult struct {
	URL        string      `json:"url"`
	ID         int         `json:"id"`
	ExternalID interface{} `json:"external_id"`
	Via        struct {
		Channel string `json:"channel"`
		Source  struct {
			From struct {
				ServiceInfo struct {
					SupportsChannelback                    bool   `json:"supports_channelback"`
					SupportsClickthrough                   bool   `json:"supports_clickthrough"`
					RegisteredIntegrationServiceName       string `json:"registered_integration_service_name"`
					RegisteredIntegrationServiceExternalID string `json:"registered_integration_service_external_id"`
					IntegrationServiceInstanceName         string `json:"integration_service_instance_name"`
				} `json:"service_info"`
			} `json:"from"`
		} `json:"source"`
	} `json:"via"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
	Type                interface{}   `json:"type"`
	Subject             string        `json:"subject"`
	RawSubject          string        `json:"raw_subject"`
	Description         string        `json:"description"`
	Priority            interface{}   `json:"priority"`
	Status              string        `json:"status"`
	Recipient           interface{}   `json:"recipient"`
	RequesterID         int64         `json:"requester_id"`
	SubmitterID         int64         `json:"submitter_id"`
	AssigneeID          interface{}   `json:"assignee_id"`
	OrganizationID      interface{}   `json:"organization_id"`
	GroupID             int64         `json:"group_id"`
	CollaboratorIds     []interface{} `json:"collaborator_ids"`
	FollowerIds         []interface{} `json:"follower_ids"`
	EmailCcIds          []interface{} `json:"email_cc_ids"`
	ForumTopicID        interface{}   `json:"forum_topic_id"`
	ProblemID           interface{}   `json:"problem_id"`
	HasIncidents        bool          `json:"has_incidents"`
	IsPublic            bool          `json:"is_public"`
	DueAt               interface{}   `json:"due_at"`
	Tags                []interface{} `json:"tags"`
	CustomFields        []interface{} `json:"custom_fields"`
	SatisfactionRating  interface{}   `json:"satisfaction_rating"`
	SharingAgreementIds []interface{} `json:"sharing_agreement_ids"`
	Fields              []interface{} `json:"fields"`
	FollowupIds         []interface{} `json:"followup_ids"`
	BrandID             int64         `json:"brand_id"`
	AllowChannelback    bool          `json:"allow_channelback"`
	AllowAttachments    bool          `json:"allow_attachments"`
	ResultType          string        `json:"result_type"`
}

type searchResults struct {
	Results []searchTicketResult `json:"results"`
}

// https://developer.zendesk.com/rest_api/docs/core/ticket_comments#json-format
// type TicketComment struct {
// 	ID          int64        `json:"id,omitempty"`
// 	Type        string       `json:"type,omitempty"` //Comment or VoiceComment
// 	Body        string       `json:"body,omitempty"`
// 	HTMLBody    string       `json:"html_body,omitempty"`
// 	PlainBody   string       `json:"plain_body,omitempty"`
// 	Public      bool         `json:"public,omitempty"`
// 	AuthorID    int64        `json:"author_id,omitempty"`
// 	Attachments []Attachment `json:"attachments,omitempty"`
// 	CreatedAt   time.Time    `json:"created_at,omitempty"`
// }

// type Attachment struct {
// 	ID          int64  `json:"id,omitempty"`
// 	FileName    string `json:"file_name,omitempty"`
// 	ContentURL  string `json:"content_url,omitempty"`
// 	ContentType string `json:"content_type,omitempty"`
// 	Size        int64  `json:"size,omitempty"`
// 	Inline      bool   `json:"inline,omitempty"`
// }

// type Upload struct {
// 	Token       *string      `json:"token"`
// 	Attachment  *Attachment  `json:"attachment"`
// 	Attachments []Attachment `json:"attachments"`
// }

// receiveMessage is our HTTP handler function for incoming messages
func (h *handler) receiveMessage(ctx context.Context, channel courier.Channel, w http.ResponseWriter, r *http.Request) ([]courier.Event, error) {

	msg := &message{}
	if err := handlers.DecodeAndValidateJSON(msg, r); err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}

	// logrus.Debugf("zd receiveMessage, %+v", msg)
	// ignore anything other than text messages
	// if msg.Type != messageTypeText {
	// 	return nil, handlers.WriteAndLogRequestIgnored(ctx, h, channel, w, r, fmt.Sprintf("ignoring non-text request: %s", msg.Type))
	// }

	// create our URN
	urn, err := urns.NewZendeskURN(msg.RequesterID)
	if err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}

	// build our msg
	dbMsg := h.Backend().NewIncomingMsg(channel, urn, msg.Comment).WithExternalID(msg.ID)

	// and finally write our message
	return handlers.WriteMsgsAndResponse(ctx, h, []courier.Msg{dbMsg}, w, r)
}

// SendMsg sends the passed in message, returning any error
func (h *handler) SendMsg(ctx context.Context, msg courier.Msg) (courier.MsgStatus, error) {

	username := msg.Channel().StringConfigForKey(courier.ConfigUsername, "")
	if username == "" {
		return nil, fmt.Errorf("missing 'username' config for ZD channel")
	}

	authToken := msg.Channel().StringConfigForKey(courier.ConfigAuthToken, "")
	if authToken == "" {
		return nil, fmt.Errorf("missing 'auth_token' config for ZD channel")
	}

	urlStr := msg.Channel().StringConfigForKey(courier.ConfigBaseURL, "")
	if urlStr == "" {
		return nil, fmt.Errorf("Missing base_url for ZD")
	}
	baseURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid base url set for ZD channel: %s", err)
	}

	// text := handlers.GetTextAndAttachments(msg)
	status := h.Backend().NewMsgStatusForID(msg.Channel(), msg.ID(), courier.MsgErrored)

	var req *http.Request
	var rErr error

	// Comment or new ticket
	if msg.ExternalID() != "" {
		// Comment on existing ticket
		req, rErr = createCommentRequest(msg, baseURL, "")
		if rErr != nil {
			return nil, rErr
		}
	} else {
		// Create new ticket
		req, rErr = createTicketRequest(msg, baseURL)
		if rErr != nil {
			return nil, rErr
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(username+"/token", authToken)

	dump, _ := httputil.DumpRequest(req, true)

	// logrus.Debugf("Send Msg %s", dump)

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

func createCommentRequest(msg courier.Msg, baseURL *url.URL, overrideTicketID string) (*http.Request, error) {
	ticketID := msg.ExternalID()
	if overrideTicketID != "" {
		ticketID = overrideTicketID
	}
	if ticketID == "" {
		return nil, fmt.Errorf("missing ticket id/external id")
	}
	text := msg.Text()

	// build message payload
	payload := commentPayload{
		Body:   text,
		Public: true,
	}

	// optional config: use different author instead of api user via channel.config['author-id']
	if sAuthorID := msg.Channel().StringConfigForKey(configAuthorID, ""); sAuthorID != "" {
		authorID, err := strconv.ParseInt(msg.URN().Path(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("config '%s' is an invalid int64", configAuthorID)
		}
		payload.AuthorID = authorID
	}

	ticketPayload := newTicketPayload{
		Ticket: ticketPayload{
			Comment: payload,
		},
	}

	jsonBody, err := json.Marshal(ticketPayload)
	if err != nil {
		return nil, err
	}

	sendCommentURL, err := resolveCommentURL(baseURL, ticketID)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPut, sendCommentURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	return req, nil
}

func createTicketRequest(msg courier.Msg, baseURL *url.URL) (*http.Request, error) {
	// text := msg.Text()
	// Get end user
	recipientID, err := strconv.ParseInt(msg.URN().Path(), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("urn is not a valid int64")
	}
	username := msg.Channel().StringConfigForKey(courier.ConfigUsername, "")
	if username == "" {
		return nil, fmt.Errorf("missing 'username' config for ZD channel")
	}

	authToken := msg.Channel().StringConfigForKey(courier.ConfigAuthToken, "")
	if authToken == "" {
		return nil, fmt.Errorf("missing 'auth_token' config for ZD channel")
	}

	ticketID, err := getTicketIDFirstTicket(baseURL, recipientID, username, authToken)
	if err != nil {
		return nil, err
	}

	return createCommentRequest(msg, baseURL, ticketID)

	// build message payload
	// payload := newTicketPayload{
	// 	Ticket: ticketPayload{
	// 		Comment: commentPayload{
	// 			Body:   text,
	// 			Public: true,
	// 		},
	// 		CollaboratorIDs: []int64{recipientID},
	// 		RequesterID:     recipientID,
	// 		ExternalID:      msg.ID().String(),
	// 	},
	// }

	// // optional config: use different author instead of api user via channel.config['author-id']
	// if sAuthorID := msg.Channel().StringConfigForKey(configAuthorID, ""); sAuthorID != "" {
	// 	authorID, err := strconv.ParseInt(msg.URN().Path(), 10, 64)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("config '%s' is an invalid int64", configAuthorID)
	// 	}
	// 	payload.Ticket.Comment.AuthorID = authorID
	// }

	// jsonBody, err := json.Marshal(payload)
	// if err != nil {
	// 	return nil, err
	// }

	// sendTicketURL, err := resolveTicketURL(baseURL)
	// if err != nil {
	// 	return nil, err
	// }

	// req, err := http.NewRequest(http.MethodPost, sendTicketURL, bytes.NewReader(jsonBody))
	// if err != nil {
	// 	return nil, err
	// }

	// return req, nil
}

func getTicketIDFirstTicket(baseURL *url.URL, recipientID int64, username string, authToken string) (string, error) {

	// query=requester:%d type:ticket" -d "sort_by=created_at" -d "sort_order=asc"
	sendTicketURL, err := resolveSearchTicketsURL(baseURL, recipientID)
	if err != nil {
		return "", err
	}

	// logrus.Debugf("zd getTicketIDFirstTicket %s", sendTicketURL)

	req, err := http.NewRequest(http.MethodGet, sendTicketURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(username+"/token", authToken)

	rr, err := utils.MakeHTTPRequest(req)
	if err != nil {
		return "", err
	}

	response := searchResults{}
	if err := json.Unmarshal(rr.Body, &response); err != nil {
		return "", err
	}

	if len(response.Results) == 0 {
		return "", fmt.Errorf("Existing ticket not found for requestor: %d", recipientID)
	}

	return strconv.Itoa(response.Results[0].ID), nil
}

func resolveCommentURL(baseURL *url.URL, ticketID string) (string, error) {

	commentPath, _ := baseURL.Parse(sendCommentURL)
	commentEndpoint := baseURL.ResolveReference(commentPath).String()

	commentURL := fmt.Sprintf("%s/%s.json", commentEndpoint, ticketID)

	return commentURL, nil
}

func resolveTicketURL(baseURL *url.URL) (string, error) {

	ticketURL, err := baseURL.Parse(sendTicketURL)
	if err != nil {
		return "", err
	}

	return ticketURL.String(), nil
}

func resolveSearchTicketsURL(baseURL *url.URL, recipientID int64) (string, error) {

	u, err := baseURL.Parse(searchTicketsURL)
	if err != nil {
		return "", err
	}
	// query=requester:372518027891 type:ticket" -d "sort_by=created_at" -d "sort_order=asc"

	q := u.Query()
	q.Set("query", fmt.Sprintf("requester:%d type:ticket", recipientID))
	q.Set("type", "ticket")
	q.Set("sort_by", "created_at")
	q.Set("sort_order", "asc")
	u.RawQuery = q.Encode()

	return u.String(), nil
}
