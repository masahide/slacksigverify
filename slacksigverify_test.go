package slacksigverify

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/nlopes/slack"
	"github.com/nlopes/slack/slackevents"
)

var (
	signingSecret = "1111111111111111111111111111111"
	requestBody   = `dummy body`
	signature     = "v0=d1efdfee3e5d339a96d6cad2a1c03acbf86cee500d582a9ca3595aa2cb0d6274"
)

func TestParserOuterCallBackEvent(t *testing.T) {
	eventsAPIRawCallbackEvent := `
			{
				"token": "XXYYZZ",
				"team_id": "TXXXXXXXX",
				"api_app_id": "AXXXXXXXXX",
				"event": {
								"type": "app_mention",
								"event_ts": "1234567890.123456",
								"user": "UXXXXXXX1"
				},
				"type": "event_callback",
				"authed_users": [ "UXXXXXXX1" ],
				"event_id": "Ev08MFMKH6",
				"event_time": 1234567890
		}
	`
	NowUnix = func() int64 { return int64(1533878462) }
	timestamp := strconv.Itoa(int(NowUnix()))
	msg, e := ParseEvent(json.RawMessage(eventsAPIRawCallbackEvent), signingSecret, timestamp, requestBody, signature)

	if e != nil {
		fmt.Println(e)
		t.Fail()
	}
	switch ev := msg.Data.(type) {
	case *slackevents.EventsAPICallbackEvent:
		{
		}
	case *slack.UnmarshallingErrorEvent:
		{
			fmt.Println("Unmarshalling Error!")
			fmt.Println(ev)
			t.Fail()
		}
	default:
		{
			fmt.Println(ev)
			t.Fail()
		}
	}
}

func TestParseURLVerificationEvent(t *testing.T) {
	urlVerificationEvent := `
		{
			"token": "fake-token",
			"challenge": "aljdsflaji3jj",
			"type": "url_verification"
		}
	`
	NowUnix = func() int64 { return int64(1533878462) }
	timestamp := strconv.Itoa(int(NowUnix()))
	msg, e := ParseEvent(json.RawMessage(urlVerificationEvent), signingSecret, timestamp, requestBody, signature)
	if e != nil {
		fmt.Println(e)
		t.Fail()
	}
	switch ev := msg.Data.(type) {
	case *slackevents.EventsAPIURLVerificationEvent:
		{
		}
	default:
		{
			fmt.Println(ev)
			t.Fail()
		}
	}
}

func TestThatOuterCallbackEventHasInnerEvent(t *testing.T) {
	eventsAPIRawCallbackEvent := `
			{
				"token": "XXYYZZ",
				"team_id": "TXXXXXXXX",
				"api_app_id": "AXXXXXXXXX",
				"event": {
								"type": "app_mention",
								"event_ts": "1234567890.123456",
								"user": "UXXXXXXX1"
				},
				"type": "event_callback",
				"authed_users": [ "UXXXXXXX1" ],
				"event_id": "Ev08MFMKH6",
				"event_time": 1234567890
		}
	`
	NowUnix = func() int64 { return int64(1533878462) }
	timestamp := strconv.Itoa(int(NowUnix()))
	msg, e := ParseEvent(json.RawMessage(eventsAPIRawCallbackEvent), signingSecret, timestamp, requestBody, signature)
	if e != nil {
		fmt.Println(e)
		t.Fail()
	}
	switch outterEvent := msg.Data.(type) {
	case *slackevents.EventsAPICallbackEvent:
		{
			switch innerEvent := msg.InnerEvent.Data.(type) {
			case *slackevents.AppMentionEvent:
				{
				}
			default:
				fmt.Println(innerEvent)
				t.Fail()
			}
		}
	default:
		{
			fmt.Println(outterEvent)
			t.Fail()
		}
	}
}

func TestBadTokenVerification(t *testing.T) {
	urlVerificationEvent := `
		{
			"token": "fake-token",
			"challenge": "aljdsflaji3jj",
			"type": "url_verification"
		}
	`
	NowUnix = func() int64 { return int64(1533878462) }
	timestamp := strconv.Itoa(int(NowUnix()))
	signingSecret = "hoge"
	_, e := ParseEvent(json.RawMessage(urlVerificationEvent), signingSecret, timestamp, requestBody, signature)
	if e == nil {
		t.Fail()
	}
}
