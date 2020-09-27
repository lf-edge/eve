// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"bytes"
	"strings"
	"testing"

	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type Agent struct {
	AgentName   string
	AgentNumber int
	AgentAge    int
	IsBrosnan   bool
}

func (agent Agent) LogKey() string {
	return "james-bond-007"
}

func (agent Agent) LogCreate(logBase *LogObject) {
	logObject := EnsureLogObject(logBase, "secret_agent", "Pierce Brosnan", uuid.UUID{}, agent.LogKey())
	logObject.CloneAndAddField("agent_name", agent.AgentName).
		AddField("agent_number", agent.AgentNumber).
		AddField("agent_is_brosnan", true).AddField("agent_age", agent.AgentAge).Noticef("I am Bond, James Bond")
}

func (agent Agent) LogModify(logBase *LogObject, old interface{}) {
	logObject := EnsureLogObject(logBase, "secret_agent", "Pierce Brosnan", uuid.UUID{}, agent.LogKey())
	logObject.CloneAndAddField("agent_name", agent.AgentName).
		AddField("agent_number", agent.AgentNumber).
		AddField("agent_is_brosnan", true).AddField("agent_age", agent.AgentAge).Noticef("James Bond gets old!")
}

func (agent Agent) LogDelete(logBase *LogObject) {
	logObject := EnsureLogObject(logBase, "secret_agent", "Pierce Brosnan", uuid.UUID{}, agent.LogKey())
	logObject.CloneAndAddField("agent_name", agent.AgentName).
		AddField("agent_number", agent.AgentNumber).
		AddField("agent_is_brosnan", true).AddField("agent_age", agent.AgentAge).Noticef("James Bond dies!")
	DeleteLogObject(logBase, agent.LogKey())
}

var (
	agent = Agent{
		AgentName:   "James Bond",
		AgentAge:    30,
		AgentNumber: 007,
		IsBrosnan:   true,
	}
	logBuffer *bytes.Buffer
	log       *LogObject
)

func initLog() {
	formatter := logrus.JSONFormatter{DisableTimestamp: true}
	logrus.SetFormatter(&formatter)
	logBuffer = bytes.NewBuffer(make([]byte, 1000))
	logrus.SetOutput(logBuffer)
	logrus.SetLevel(logrus.TraceLevel)
	logger := logrus.StandardLogger()
	log = NewSourceLogObject(logger, "test", 1234)
}

func TestSpecialAgent(t *testing.T) {
	initLog()

	testMatrix := map[string]struct {
		agent  Agent
		action string
	}{
		"New Bond": {
			agent:  agent,
			action: "create",
		},
		"Old Bond": {
			agent:  agent,
			action: "modify",
		},
		"Kill Bond": {
			agent:  agent,
			action: "kill",
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		logBuffer.Reset()
		switch test.action {
		case "create":
			test.agent.LogCreate(log)
			expected := "{\"agent_age\":30,\"agent_is_brosnan\":true,\"agent_name\":\"James Bond\",\"agent_number\":7,\"level\":\"info\",\"log_event_type\":\"log\",\"msg\":\"I am Bond, James Bond\",\"obj_key\":\"james-bond-007\",\"obj_name\":\"Pierce Brosnan\",\"obj_type\":\"secret_agent\",\"pid\":1234,\"source\":\"test\"}"
			assert.Equal(t, expected, strings.TrimSpace(logBuffer.String()))
		case "modify":
			test.agent.AgentAge = 100
			test.agent.LogModify(log, "old agent")
			expected := "{\"agent_age\":100,\"agent_is_brosnan\":true,\"agent_name\":\"James Bond\",\"agent_number\":7,\"level\":\"info\",\"log_event_type\":\"log\",\"msg\":\"James Bond gets old!\",\"obj_key\":\"james-bond-007\",\"obj_name\":\"Pierce Brosnan\",\"obj_type\":\"secret_agent\",\"pid\":1234,\"source\":\"test\"}"
			assert.Equal(t, expected, strings.TrimSpace(logBuffer.String()))
		case "kill":
			test.agent.LogDelete(log)
			expected := "{\"agent_age\":30,\"agent_is_brosnan\":true,\"agent_name\":\"James Bond\",\"agent_number\":7,\"level\":\"info\",\"log_event_type\":\"log\",\"msg\":\"James Bond dies!\",\"obj_key\":\"james-bond-007\",\"obj_name\":\"Pierce Brosnan\",\"obj_type\":\"secret_agent\",\"pid\":1234,\"source\":\"test\"}"
			assert.Equal(t, expected, strings.TrimSpace(logBuffer.String()))
		default:
		}
	}
}
