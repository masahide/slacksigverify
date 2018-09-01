package slacksigverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/nlopes/slack"
	"github.com/nlopes/slack/slackevents"
)

var (
	nowUnix = func() int64 { return time.Now().Unix() }
)

// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func abs(n int64) int64 {
	y := n >> 63
	return (n ^ y) - y
}

func isOutOfRangeTimestamp(s string) bool {
	// https://github.com/slackapi/python-slack-events-api/blob/6a269ed11fc46d7b14edd1fc11caf655922bf1a6/slackeventsapi/server.py#L94-L98
	i, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return abs(nowUnix()-int64(i)) > 60*5
}

func verifySSS(signingSecret, slackRequest, slackSignature []byte) bool {
	sig := hmac.New(sha256.New, signingSecret)
	sig.Write(slackRequest)
	tokenResult := hex.EncodeToString(sig.Sum(nil))
	requestHash := append([]byte("v0="), tokenResult...)
	//log.Printf("requestHash: %s", requestHash)
	return hmac.Equal(requestHash, slackSignature)
}

// ParseEvent parses the outter and inner events (if applicable) of an events
// api event returning a EventsAPIEvent type. If the event is a url_verification event,
// the inner event is empty.
func ParseEvent(rawEvent json.RawMessage, signingSecret, timestamp, requestBody, signature string) (slackevents.EventsAPIEvent, error) {
	if isOutOfRangeTimestamp(timestamp) {
		return slackevents.EventsAPIEvent{}, errors.New("timestamp is out of current time")
	}
	verifySlackRequest := fmt.Sprintf("v0:%v:%v", timestamp, requestBody)
	if !verifySSS([]byte(signingSecret), []byte(verifySlackRequest), []byte(signature)) {
		return slackevents.EventsAPIEvent{}, errors.New("Invalid request signature")
	}
	e, err := parseOuterEvent(rawEvent)
	if err != nil {
		return slackevents.EventsAPIEvent{}, err
	}

	if e.Type == slackevents.CallbackEvent {
		cbEvent := e.Data.(*slackevents.EventsAPICallbackEvent)
		innerEvent, err := parseInnerEvent(cbEvent)
		if err != nil {
			err := fmt.Errorf("EventsAPI Error parsing inner event: %s, %s", innerEvent.Type, err)
			return slackevents.EventsAPIEvent{
				Token:      "",
				TeamID:     "",
				Type:       "unmarshalling_error",
				Data:       &slack.UnmarshallingErrorEvent{ErrorObj: err},
				InnerEvent: slackevents.EventsAPIInnerEvent{},
			}, err
		}
		return innerEvent, nil
	}
	urlVerificationEvent := &slackevents.EventsAPIURLVerificationEvent{}
	err = json.Unmarshal(rawEvent, urlVerificationEvent)
	if err != nil {
		return slackevents.EventsAPIEvent{
			Token:      "",
			TeamID:     "",
			Type:       "unmarshalling_error",
			Data:       &slack.UnmarshallingErrorEvent{ErrorObj: err},
			InnerEvent: slackevents.EventsAPIInnerEvent{},
		}, err
	}
	return slackevents.EventsAPIEvent{
		Token:      e.Token,
		TeamID:     e.TeamID,
		Type:       e.Type,
		Data:       urlVerificationEvent,
		InnerEvent: slackevents.EventsAPIInnerEvent{},
	}, nil
}

// eventsMap checks both slack.EventsMapping and
// and slackevents.EventsAPIInnerEventMapping. If the event
// exists, returns the the unmarshalled struct instance of
// target for the matching event type.
// TODO: Consider moving all events into its own package?
func eventsMap(t string) (interface{}, bool) {
	// Must parse EventsAPI FIRST as both RTM and EventsAPI
	// have a type: "Message" event.
	// TODO: Handle these cases more explicitly.
	v, exists := slackevents.EventsAPIInnerEventMapping[t]
	if exists {
		return v, exists
	}
	v, exists = slack.EventMapping[t]
	if exists {
		return v, exists
	}
	return v, exists
}

func parseOuterEvent(rawE json.RawMessage) (slackevents.EventsAPIEvent, error) {
	e := &slackevents.EventsAPIEvent{}
	err := json.Unmarshal(rawE, e)
	if err != nil {
		return slackevents.EventsAPIEvent{
			Token:      "",
			TeamID:     "",
			Type:       "unmarshalling_error",
			Data:       &slack.UnmarshallingErrorEvent{ErrorObj: err},
			InnerEvent: slackevents.EventsAPIInnerEvent{},
		}, err
	}
	if e.Type == slackevents.CallbackEvent {
		cbEvent := &slackevents.EventsAPICallbackEvent{}
		err = json.Unmarshal(rawE, cbEvent)
		if err != nil {
			return slackevents.EventsAPIEvent{
				Token:      "",
				TeamID:     "",
				Type:       "unmarshalling_error",
				Data:       &slack.UnmarshallingErrorEvent{ErrorObj: err},
				InnerEvent: slackevents.EventsAPIInnerEvent{},
			}, err
		}
		return slackevents.EventsAPIEvent{
			Token:      e.Token,
			TeamID:     e.TeamID,
			Type:       e.Type,
			Data:       cbEvent,
			InnerEvent: slackevents.EventsAPIInnerEvent{},
		}, nil
	}
	urlVE := &slackevents.EventsAPIURLVerificationEvent{}
	err = json.Unmarshal(rawE, urlVE)
	if err != nil {
		return slackevents.EventsAPIEvent{
			Token:      "",
			TeamID:     "",
			Type:       "unmarshalling_error",
			Data:       &slack.UnmarshallingErrorEvent{ErrorObj: err},
			InnerEvent: slackevents.EventsAPIInnerEvent{},
		}, err
	}
	return slackevents.EventsAPIEvent{
		Token:      e.Token,
		TeamID:     e.TeamID,
		Type:       e.Type,
		Data:       urlVE,
		InnerEvent: slackevents.EventsAPIInnerEvent{},
	}, nil
}

func parseInnerEvent(e *slackevents.EventsAPICallbackEvent) (slackevents.EventsAPIEvent, error) {
	iE := &slack.Event{}
	rawInnerJSON := e.InnerEvent
	err := json.Unmarshal(*rawInnerJSON, iE)
	if err != nil {
		return slackevents.EventsAPIEvent{
			Token:      e.Token,
			TeamID:     e.TeamID,
			Type:       "unmarshalling_error",
			Data:       &slack.UnmarshallingErrorEvent{ErrorObj: err},
			InnerEvent: slackevents.EventsAPIInnerEvent{},
		}, err
	}
	v, exists := eventsMap(iE.Type)
	if !exists {
		return slackevents.EventsAPIEvent{
			Token:      e.Token,
			TeamID:     e.TeamID,
			Type:       iE.Type,
			Data:       nil,
			InnerEvent: slackevents.EventsAPIInnerEvent{},
		}, fmt.Errorf("Inner Event does not exist! %s", iE.Type)
	}
	t := reflect.TypeOf(v)
	recvEvent := reflect.New(t).Interface()
	err = json.Unmarshal(*rawInnerJSON, recvEvent)
	if err != nil {
		return slackevents.EventsAPIEvent{
			Token:      e.Token,
			TeamID:     e.TeamID,
			Type:       "unmarshalling_error",
			Data:       &slack.UnmarshallingErrorEvent{ErrorObj: err},
			InnerEvent: slackevents.EventsAPIInnerEvent{},
		}, err
	}
	return slackevents.EventsAPIEvent{
		Token:      e.Token,
		TeamID:     e.TeamID,
		Type:       e.Type,
		Data:       e,
		InnerEvent: slackevents.EventsAPIInnerEvent{Type: iE.Type, Data: recvEvent},
	}, nil
}
