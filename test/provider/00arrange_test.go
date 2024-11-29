package provider_test

import (
	"os"
	"time"
)

var Keys string

var OnDemandTestData = []struct {
	FetchInterval    time.Duration
	HTTPTimeout      time.Duration
	RequestTime      time.Duration
	SleepTime        time.Duration
	ExpectedRequests int
}{
	{
		FetchInterval:    time.Minute,
		HTTPTimeout:      time.Second * 5,
		RequestTime:      0,
		SleepTime:        0,
		ExpectedRequests: 1,
	},
	{
		FetchInterval:    time.Millisecond * 10,
		HTTPTimeout:      time.Second * 5,
		RequestTime:      0,
		SleepTime:        time.Millisecond * 20,
		ExpectedRequests: 1,
	},
	{
		FetchInterval:    time.Millisecond * 30,
		HTTPTimeout:      time.Millisecond * 10,
		RequestTime:      time.Millisecond * 50,
		SleepTime:        time.Millisecond * 20,
		ExpectedRequests: 0,
	},
}

var RemoteTestData = []struct {
	FetchInterval    time.Duration
	HTTPTimeout      time.Duration
	SleepTime        time.Duration
	ExpectedRequests int
}{
	{
		FetchInterval:    time.Minute,
		HTTPTimeout:      time.Second * 5,
		SleepTime:        0,
		ExpectedRequests: 1,
	},
	{
		FetchInterval:    time.Millisecond * 10,
		HTTPTimeout:      time.Second * 5,
		SleepTime:        time.Millisecond * 20,
		ExpectedRequests: 2,
	},
}

func init() {
	response, _ := os.ReadFile("../00_files/provider/rsa.json")
	Keys = string(response)
}
