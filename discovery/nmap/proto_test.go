package nmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/zero-day-ai/tools/discovery/nmap/gen"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
)

func TestProtoRegistration_NmapRequest(t *testing.T) {
	// Verify NmapRequest is registered in GlobalTypes
	msgType, err := protoregistry.GlobalTypes.FindMessageByName("gibson.tools.nmap.NmapRequest")
	require.NoError(t, err, "NmapRequest should be registered in GlobalTypes")
	require.NotNil(t, msgType)

	// Verify we can create instances
	msg := msgType.New().Interface()
	require.NotNil(t, msg)

	// Verify it's the correct type
	_, ok := msg.(*gen.NmapRequest)
	assert.True(t, ok, "Message should be *gen.NmapRequest")
}

func TestProtoRegistration_NmapResponse(t *testing.T) {
	// Verify NmapResponse is registered in GlobalTypes
	msgType, err := protoregistry.GlobalTypes.FindMessageByName("gibson.tools.nmap.NmapResponse")
	require.NoError(t, err, "NmapResponse should be registered in GlobalTypes")
	require.NotNil(t, msgType)

	// Verify we can create instances
	msg := msgType.New().Interface()
	require.NotNil(t, msg)

	// Verify it's the correct type
	_, ok := msg.(*gen.NmapResponse)
	assert.True(t, ok, "Message should be *gen.NmapResponse")
}

func TestProtoMarshalUnmarshal_Roundtrip(t *testing.T) {
	// Create a request
	req := &gen.NmapRequest{
		Targets: []string{"192.168.1.1", "192.168.1.2"},
		Args:    []string{"-sV", "-sC"},
	}

	// Marshal to JSON
	data, err := protojson.Marshal(req)
	require.NoError(t, err)

	// Unmarshal back
	var decoded gen.NmapRequest
	err = protojson.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify roundtrip
	assert.Equal(t, req.Targets, decoded.Targets)
	assert.Equal(t, req.Args, decoded.Args)
}

func TestDiscoveryFieldCompatibility(t *testing.T) {
	// Create a response with DiscoveryResult in field 100
	hostname := "test.local"
	resp := &gen.NmapResponse{
		TotalHosts: 1,
		HostsUp:    1,
		Discovery: &graphragpb.DiscoveryResult{
			Hosts: []*graphragpb.Host{
				{
					Ip:       "192.168.1.1",
					Hostname: &hostname,
				},
			},
		},
	}

	// Verify field 100 serializes correctly
	data, err := protojson.Marshal(resp)
	require.NoError(t, err)

	// Verify discovery field is present
	jsonStr := string(data)
	assert.Contains(t, jsonStr, "discovery")
	assert.Contains(t, jsonStr, "192.168.1.1")
	assert.Contains(t, jsonStr, "test.local")

	// Verify unmarshal works
	var decoded gen.NmapResponse
	err = protojson.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.Discovery)
	require.Len(t, decoded.Discovery.Hosts, 1)
	assert.Equal(t, "192.168.1.1", decoded.Discovery.Hosts[0].Ip)
}

func TestInputMessageTypeMatchesRegistration(t *testing.T) {
	tool := &ToolImpl{}

	// Get the declared input message type
	inputType := tool.InputMessageType()

	// Verify it matches what's in GlobalTypes
	msgType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(inputType))
	require.NoError(t, err, "InputMessageType() should return a registered type name")
	require.NotNil(t, msgType)
}

func TestOutputMessageTypeMatchesRegistration(t *testing.T) {
	tool := &ToolImpl{}

	// Get the declared output message type
	outputType := tool.OutputMessageType()

	// Verify it matches what's in GlobalTypes
	msgType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(outputType))
	require.NoError(t, err, "OutputMessageType() should return a registered type name")
	require.NotNil(t, msgType)
}
