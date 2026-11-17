// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saiserver

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/openconfig/gnmi/errdiff"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/openconfig/lemming/dataplane/dplaneopts"
	"github.com/openconfig/lemming/dataplane/forwarding/fwdconfig"
	"github.com/openconfig/lemming/dataplane/forwarding/infra/fwdcontext"
	saipb "github.com/openconfig/lemming/dataplane/proto/sai"
	"github.com/openconfig/lemming/dataplane/saiserver/attrmgr"
	fwdpb "github.com/openconfig/lemming/proto/forwarding"
)

func TestCreateTunnel(t *testing.T) {
	tests := []struct {
		desc    string
		req     *saipb.CreateTunnelRequest
		wantReq *fwdpb.TableEntryAddRequest
		types   map[string]saipb.ObjectType
		wantErr string
	}{{
		desc:    "invalid request",
		req:     &saipb.CreateTunnelRequest{},
		wantErr: "InvalidArgument",
	}, {
		desc: "ipinip tunnel",
		req: &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_IPINIP.Enum(),
			EncapEcnMode:      saipb.TunnelEncapEcnMode_TUNNEL_ENCAP_ECN_MODE_STANDARD.Enum(),
			EncapDscpMode:     saipb.TunnelDscpMode_TUNNEL_DSCP_MODE_UNIFORM_MODEL.Enum(),
			EncapTtlMode:      saipb.TunnelTtlMode_TUNNEL_TTL_MODE_UNIFORM_MODEL.Enum(),
			UnderlayInterface: proto.Uint64(10),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: TunnelEncap}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID},
								},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
							}},
						},
					},
				},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_COPY,
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_QOS,
								Instance: 1,
							}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_QOS}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_COPY,
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_HOP,
								Instance: 1,
							}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_HOP}},
						},
					},
				}},
			}},
		},
	}, {
		desc: "vxlan tunnel",
		req: &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(10),
			VxlanUdpSport:     proto.Uint32(1234),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: TunnelEncap}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID},
								},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
							}},
						},
					},
				},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_COPY,
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_HOP,
								Instance: 1,
							}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_HOP}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0xb5},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_SRC}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xd2},
						},
					},
				}},
			}},
		},
	}, {
		desc: "vxlan tunnel pipe ttl",
		req: &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			EncapTtlMode:      saipb.TunnelTtlMode_TUNNEL_TTL_MODE_PIPE_MODEL.Enum(),
			EncapTtlVal:       proto.Uint32(32),
			UnderlayInterface: proto.Uint64(10),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: TunnelEncap}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID},
								},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
							}},
						},
					},
				},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_HOP}},
							Value:   []byte{32},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0xb5},
						},
					},
				}},
			}},
		},
	}, {
		desc: "vxlan tunnel pipe default ttl",
		req: &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			EncapTtlMode:      saipb.TunnelTtlMode_TUNNEL_TTL_MODE_PIPE_MODEL.Enum(),
			UnderlayInterface: proto.Uint64(10),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: TunnelEncap}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID},
								},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
							}},
						},
					},
				},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_HOP}},
							Value:   []byte{defaultEncapTTL},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST}},
							Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0xb5},
						},
					},
				}},
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestTunnel(t, dplane)
			defer stopFn()
			for k, v := range tt.types {
				mgr.SetType(k, v)
			}
			mgr.StoreAttributes(1, &saipb.SwitchAttribute{
				CpuPort: proto.Uint64(10),
			})
			_, gotErr := c.CreateTunnel(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateTunnel() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(dplane.gotEntryAddReqs[0], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("CreateTunnel() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestRemoveTunnel(t *testing.T) {
	tests := []struct {
		desc    string
		req     *saipb.RemoveTunnelRequest
		wantErr string
	}{{
		desc:    "invalid request",
		req:     &saipb.RemoveTunnelRequest{},
		wantErr: "not found",
	}, {
		desc: "success",
		req: &saipb.RemoveTunnelRequest{
			Oid: 1,
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, _, stopFn := newTestTunnel(t, dplane)
			defer stopFn()
			_, err := c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
				Type:              saipb.TunnelType_TUNNEL_TYPE_IPINIP.Enum(),
				EncapEcnMode:      saipb.TunnelEncapEcnMode_TUNNEL_ENCAP_ECN_MODE_STANDARD.Enum(),
				EncapDscpMode:     saipb.TunnelDscpMode_TUNNEL_DSCP_MODE_UNIFORM_MODEL.Enum(),
				EncapTtlMode:      saipb.TunnelTtlMode_TUNNEL_TTL_MODE_UNIFORM_MODEL.Enum(),
				UnderlayInterface: proto.Uint64(10),
			})
			if err != nil {
				t.Fatalf("CreateTunnel() unexpected err: %s", err)
			}
			_, gotErr := c.RemoveTunnel(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("RemoveTunnel() unexpected err: %s", diff)
			}
		})
	}
}

func TestTunnelTermTableEntry(t *testing.T) {
	tests := []struct {
		desc           string
		req            *saipb.CreateTunnelTermTableEntryRequest
		wantAddReqs    []*fwdpb.TableEntryAddRequest
		wantRemoveReqs []*fwdpb.TableEntryRemoveRequest
		wantErr        string
	}{
		{
			desc: "vxlan p2mp ipv4 with action tunnel id",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType:     saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
				Type:           saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP.Enum(),
				DstIp:          []byte{10, 0, 0, 1},
				VrId:           proto.Uint64(10),
				ActionTunnelId: proto.Uint64(100),
			},
			wantAddReqs: []*fwdpb.TableEntryAddRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 2, // (MaxUint32 - 3) - 0 + termRankP2MP
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{17}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST).WithBytes([]byte{0x12, 0xB5}, []byte{0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
						},
					},
				}},
				Actions: []*fwdpb.ActionDesc{
					fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64Value(100)).Build(),
					fwdconfig.Action(fwdconfig.LookupAction(vniToVrfTable)).Build(),
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_UDP}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_VXLAN}},
					},
				},
			}},
			wantRemoveReqs: []*fwdpb.TableEntryRemoveRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 2,
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{17}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST).WithBytes([]byte{0x12, 0xB5}, []byte{0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
						},
					},
				}},
			}},
		},
		{
			desc: "vxlan p2p ipv6 with action tunnel id",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType:     saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
				Type:           saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
				SrcIp:          net.ParseIP("2001:db8::1"),
				DstIp:          net.ParseIP("2001:db8::2"),
				VrId:           proto.Uint64(10),
				ActionTunnelId: proto.Uint64(200),
			},
			wantAddReqs: []*fwdpb.TableEntryAddRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 3, // (MaxUint32 - 3) - 0 + termRankP2P
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{6}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{17}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST).WithBytes([]byte{0x12, 0xB5}, []byte{0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes(net.ParseIP("2001:db8::1"), ipV6ExactMask).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(net.ParseIP("2001:db8::2"), ipV6ExactMask).Build(),
						},
					},
				}},
				Actions: []*fwdpb.ActionDesc{
					fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64Value(200)).Build(),
					fwdconfig.Action(fwdconfig.LookupAction(vniToVrfTable)).Build(),
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP6}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_UDP}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_VXLAN}},
					},
				},
			}},
			wantRemoveReqs: []*fwdpb.TableEntryRemoveRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 3,
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{6}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{17}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST).WithBytes([]byte{0x12, 0xB5}, []byte{0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes(net.ParseIP("2001:db8::1"), ipV6ExactMask).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(net.ParseIP("2001:db8::2"), ipV6ExactMask).Build(),
						},
					},
				}},
			}},
		},
		{
			desc: "vxlan without action tunnel id",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType: saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
				Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP.Enum(),
				DstIp:      []byte{10, 0, 0, 1},
			},
			wantErr: "action_tunnel_id is required",
		},
		{
			desc: "gre mp2p ipv4",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType: saipb.TunnelType_TUNNEL_TYPE_IPINIP_GRE.Enum(),
				Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_MP2P.Enum(),
				SrcIp:      []byte{10, 0, 0, 1},
				DstIp:      []byte{20, 0, 0, 0},
				DstIpMask:  []byte{255, 255, 255, 0},
				VrId:       proto.Uint64(5),
			},
			wantAddReqs: []*fwdpb.TableEntryAddRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 2, // (MaxUint32 - 3) - 0 + termRankMP2P
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{20, 0, 0, 0}, []byte{255, 255, 255, 0}).Build(),
						},
					},
				}},
				Actions: []*fwdpb.ActionDesc{
					fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(5)).Build(),
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_GRE}},
					},
				},
			}},
			wantRemoveReqs: []*fwdpb.TableEntryRemoveRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 2,
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{20, 0, 0, 0}, []byte{255, 255, 255, 0}).Build(),
						},
					},
				}},
			}},
		},
		{
			desc: "gre p2p ipv4 nil vrid",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType: saipb.TunnelType_TUNNEL_TYPE_IPINIP_GRE.Enum(),
				Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
				SrcIp:      []byte{10, 0, 0, 1},
				DstIp:      []byte{20, 0, 0, 2},
			},
			wantAddReqs: []*fwdpb.TableEntryAddRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 3, // (MaxUint32 - 3) - 0 + termRankP2P
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{20, 0, 0, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
						},
					},
				}},
				Actions: []*fwdpb.ActionDesc{
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_GRE}},
					},
				},
			}},
			wantRemoveReqs: []*fwdpb.TableEntryRemoveRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 3,
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{20, 0, 0, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
						},
					},
				}},
			}},
		},
		{
			desc: "ipinip p2p ipv4",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType: saipb.TunnelType_TUNNEL_TYPE_IPINIP.Enum(),
				Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
				SrcIp:      []byte{192, 168, 1, 1},
				DstIp:      []byte{192, 168, 1, 2},
				VrId:       proto.Uint64(0),
			},
			wantAddReqs: []*fwdpb.TableEntryAddRequest{
				{
					ContextId: &fwdpb.ContextId{Id: "foo"},
					TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
					EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
						Flow: &fwdpb.FlowEntryDesc{
							Id:       1,
							Priority: math.MaxUint32 - 3,
							Bank:     0,
							Fields: []*fwdpb.PacketFieldMaskedBytes{
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{4}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{192, 168, 1, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{192, 168, 1, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							},
						},
					}},
					Actions: []*fwdpb.ActionDesc{
						fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(0)).Build(),
						{
							ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
							Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4}},
						},
					},
				},
				{
					ContextId: &fwdpb.ContextId{Id: "foo"},
					TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
					EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
						Flow: &fwdpb.FlowEntryDesc{
							Id:       1,
							Priority: math.MaxUint32 - 3,
							Bank:     0,
							Fields: []*fwdpb.PacketFieldMaskedBytes{
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{41}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{192, 168, 1, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{192, 168, 1, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							},
						},
					}},
					Actions: []*fwdpb.ActionDesc{
						fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(0)).Build(),
						{
							ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
							Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4}},
						},
					},
				},
			},
			wantRemoveReqs: []*fwdpb.TableEntryRemoveRequest{
				{
					ContextId: &fwdpb.ContextId{Id: "foo"},
					TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
					EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
						Flow: &fwdpb.FlowEntryDesc{
							Id:       1,
							Priority: math.MaxUint32 - 3,
							Bank:     0,
							Fields: []*fwdpb.PacketFieldMaskedBytes{
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{4}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{192, 168, 1, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{192, 168, 1, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							},
						},
					}},
				},
				{
					ContextId: &fwdpb.ContextId{Id: "foo"},
					TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
					EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
						Flow: &fwdpb.FlowEntryDesc{
							Id:       1,
							Priority: math.MaxUint32 - 3,
							Bank:     0,
							Fields: []*fwdpb.PacketFieldMaskedBytes{
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{41}, []byte{0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{192, 168, 1, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
								fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{192, 168, 1, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							},
						},
					}},
				},
			},
		},
		{
			desc: "ipv4 16-byte representation normalization",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType: saipb.TunnelType_TUNNEL_TYPE_IPINIP_GRE.Enum(),
				Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
				SrcIp:      net.ParseIP("10.0.0.1"), // 16-byte slice without .To4()
				DstIp:      net.ParseIP("10.0.0.2"), // 16-byte slice without .To4()
			},
			wantAddReqs: []*fwdpb.TableEntryAddRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 3,
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{10, 0, 0, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
						},
					},
				}},
				Actions: []*fwdpb.ActionDesc{
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_GRE}},
					},
				},
			}},
			wantRemoveReqs: []*fwdpb.TableEntryRemoveRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 3,
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{4}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes([]byte{10, 0, 0, 1}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes([]byte{10, 0, 0, 2}, []byte{0xFF, 0xFF, 0xFF, 0xFF}).Build(),
						},
					},
				}},
			}},
		},
		{
			desc: "ipv6 dst with sai default 4-byte zero mask",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType: saipb.TunnelType_TUNNEL_TYPE_IPINIP_GRE.Enum(),
				Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP.Enum(),
				DstIp:      net.ParseIP("2001:db8::2"),
				SrcIpMask:  []byte{0, 0, 0, 0},
			},
			wantAddReqs: []*fwdpb.TableEntryAddRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 2, // (MaxUint32 - 3) - 0 + termRankP2MP
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{6}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes(make([]byte, 16), make([]byte, 16)).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(net.ParseIP("2001:db8::2"), ipV6ExactMask).Build(),
						},
					},
				}},
				Actions: []*fwdpb.ActionDesc{
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP6}},
					},
					{
						ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
						Action:     &fwdpb.ActionDesc_Decap{Decap: &fwdpb.DecapActionDesc{HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_GRE}},
					},
				},
			}},
			wantRemoveReqs: []*fwdpb.TableEntryRemoveRequest{{
				ContextId: &fwdpb.ContextId{Id: "foo"},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: tunTermTable}},
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Flow{
					Flow: &fwdpb.FlowEntryDesc{
						Id:       1,
						Priority: math.MaxUint32 - 2,
						Bank:     0,
						Fields: []*fwdpb.PacketFieldMaskedBytes{
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_VERSION).WithBytes([]byte{6}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_PROTO).WithBytes([]byte{47}, []byte{0xFF}).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithBytes(make([]byte, 16), make([]byte, 16)).Build(),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(net.ParseIP("2001:db8::2"), ipV6ExactMask).Build(),
						},
					},
				}},
			}},
		},
		{
			desc: "mixed ipv4 and ipv6",
			req: &saipb.CreateTunnelTermTableEntryRequest{
				TunnelType: saipb.TunnelType_TUNNEL_TYPE_IPINIP_GRE.Enum(),
				Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
				SrcIp:      []byte{10, 0, 0, 1},
				DstIp:      net.ParseIP("2001:db8::2"),
			},
			wantErr: "mismatched IP address families",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, _, stopFn := newTestTunnel(t, dplane)
			defer stopFn()

			resp, err := c.CreateTunnelTermTableEntry(context.TODO(), tt.req)
			if diff := errdiff.Check(err, tt.wantErr); diff != "" {
				t.Fatalf("CreateTunnelTermTableEntry() unexpected err: %s", diff)
			}
			if err != nil {
				return
			}
			if len(dplane.gotEntryAddReqs) != len(tt.wantAddReqs) {
				t.Fatalf("CreateTunnelTermTableEntry() got %d add requests, want %d", len(dplane.gotEntryAddReqs), len(tt.wantAddReqs))
			}
			for i := range tt.wantAddReqs {
				if diff := cmp.Diff(dplane.gotEntryAddReqs[i], tt.wantAddReqs[i], protocmp.Transform()); diff != "" {
					t.Errorf("CreateTunnelTermTableEntry() addReq[%d] diff (-got +want):\n%s", i, diff)
				}
			}

			_, err = c.RemoveTunnelTermTableEntry(context.TODO(), &saipb.RemoveTunnelTermTableEntryRequest{
				Oid: resp.GetOid(),
			})
			if err != nil {
				t.Fatalf("RemoveTunnelTermTableEntry() unexpected err: %v", err)
			}
			if len(dplane.gotEntryRemoveReqs) != len(tt.wantRemoveReqs) {
				t.Fatalf("RemoveTunnelTermTableEntry() got %d remove requests, want %d", len(dplane.gotEntryRemoveReqs), len(tt.wantRemoveReqs))
			}
			for i := range tt.wantRemoveReqs {
				if diff := cmp.Diff(dplane.gotEntryRemoveReqs[i], tt.wantRemoveReqs[i], protocmp.Transform()); diff != "" {
					t.Errorf("RemoveTunnelTermTableEntry() removeReq[%d] diff (-got +want):\n%s", i, diff)
				}
			}
		})
	}
}

func TestTunnelTermDuplicateAndPriority(t *testing.T) {
	t.Run("duplicate entry rejection", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		req := &saipb.CreateTunnelTermTableEntryRequest{
			TunnelType: saipb.TunnelType_TUNNEL_TYPE_IPINIP_GRE.Enum(),
			Type:       saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
			SrcIp:      []byte{10, 0, 0, 1},
			DstIp:      []byte{20, 0, 0, 2},
		}
		_, err := c.CreateTunnelTermTableEntry(context.TODO(), req)
		if err != nil {
			t.Fatalf("CreateTunnelTermTableEntry() first call failed: %v", err)
		}
		_, err = c.CreateTunnelTermTableEntry(context.TODO(), req)
		if s, ok := status.FromError(err); !ok || s.Code() != codes.AlreadyExists {
			t.Fatalf("CreateTunnelTermTableEntry() second call expected AlreadyExists, got: %v", err)
		}
	})

	t.Run("term specificity and sai priority ordering", func(t *testing.T) {
		p2pReq := &saipb.CreateTunnelTermTableEntryRequest{
			Type: saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
		}
		p2mpReq := &saipb.CreateTunnelTermTableEntryRequest{
			Type: saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP.Enum(),
		}
		mp2mpReq := &saipb.CreateTunnelTermTableEntryRequest{
			Type: saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_MP2MP.Enum(),
		}

		p2pPrio, _ := termEntryPriority(p2pReq)
		p2mpPrio, _ := termEntryPriority(p2mpReq)
		mp2mpPrio, _ := termEntryPriority(mp2mpReq)

		if p2pPrio >= p2mpPrio || p2mpPrio >= mp2mpPrio {
			t.Errorf("term priority rank order invalid: p2p=%d, p2mp=%d, mp2mp=%d", p2pPrio, p2mpPrio, mp2mpPrio)
		}

		highSaiPrioReq := &saipb.CreateTunnelTermTableEntryRequest{
			Type:     saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
			Priority: proto.Uint32(100),
		}
		lowSaiPrioReq := &saipb.CreateTunnelTermTableEntryRequest{
			Type:     saipb.TunnelTermTableEntryType_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P.Enum(),
			Priority: proto.Uint32(10),
		}
		highPrio, _ := termEntryPriority(highSaiPrioReq)
		lowPrio, _ := termEntryPriority(lowSaiPrioReq)
		if highPrio >= lowPrio {
			t.Errorf("higher SAI priority must yield lower numeric Lucius priority: highSAI=%d, lowSAI=%d", highPrio, lowPrio)
		}
	})
}

func TestTunnelMapAndEntry(t *testing.T) {
	t.Run("vlan id to vni map and entry create and remove", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap() unexpected err: %v", err)
		}
		if mapResp.GetOid() == 0 {
			t.Errorf("CreateTunnelMap() returned 0 OID")
		}

		entryResp, err := c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(mapResp.GetOid()),
			VlanIdKey: proto.Uint32(100),
			VniIdKey:  proto.Uint32(1000),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMapEntry() unexpected err: %v", err)
		}
		if entryResp.GetOid() == 0 {
			t.Errorf("CreateTunnelMapEntry() returned 0 OID")
		}

		// Non-VNI_TO_VRF map entries shouldn't program vni-to-vrf table.
		if len(dplane.gotEntryAddReqs) != 0 {
			t.Errorf("CreateTunnelMapEntry() added %d entries, want 0", len(dplane.gotEntryAddReqs))
		}

		_, err = c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{
			Oid: entryResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnelMapEntry() unexpected err: %v", err)
		}

		_, err = c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{
			Oid: mapResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnelMap() unexpected err: %v", err)
		}
	})

	t.Run("vni to vrf: tunnel then map entry (orchagent order)", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap() unexpected err: %v", err)
		}

		tunResp, err := c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(10),
			DecapMappers:      []uint64{mapResp.GetOid()},
		})
		if err != nil {
			t.Fatalf("CreateTunnel() unexpected err: %v", err)
		}

		// Only TunnelEncap entry added so far.
		if len(dplane.gotEntryAddReqs) != 1 {
			t.Fatalf("CreateTunnel() got %d add requests, want 1", len(dplane.gotEntryAddReqs))
		}

		entryResp, err := c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap:            proto.Uint64(mapResp.GetOid()),
			VniIdKey:             proto.Uint32(5000),
			VirtualRouterIdValue: proto.Uint64(42),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMapEntry() unexpected err: %v", err)
		}

		if len(dplane.gotEntryAddReqs) != 2 {
			t.Fatalf("CreateTunnelMapEntry() got %d add requests, want 2", len(dplane.gotEntryAddReqs))
		}

		wantVniEntry := fwdconfig.TableEntryAddRequest("foo", vniToVrfTable).AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64(tunResp.GetOid()),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VXLAN_VNI).WithBytes(vniToBytes(5000)),
			)),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(42),
		).Build()

		if diff := cmp.Diff(dplane.gotEntryAddReqs[1], wantVniEntry, protocmp.Transform()); diff != "" {
			t.Errorf("vniToVrfTable entry diff (-got +want):\n%s", diff)
		}

		// Remove entry: verifies table entry removal.
		_, err = c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{
			Oid: entryResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnelMapEntry() unexpected err: %v", err)
		}

		wantVniRemove := &fwdpb.TableEntryRemoveRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: vniToVrfTable}},
			EntryDesc: fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64(tunResp.GetOid()),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VXLAN_VNI).WithBytes(vniToBytes(5000)),
			)).Build(),
		}
		if len(dplane.gotEntryRemoveReqs) != 1 {
			t.Fatalf("RemoveTunnelMapEntry() got %d remove requests, want 1", len(dplane.gotEntryRemoveReqs))
		}
		if diff := cmp.Diff(dplane.gotEntryRemoveReqs[0], wantVniRemove, protocmp.Transform()); diff != "" {
			t.Errorf("vniToVrfTable remove diff (-got +want):\n%s", diff)
		}

		_, err = c.RemoveTunnel(context.TODO(), &saipb.RemoveTunnelRequest{
			Oid: tunResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnel() unexpected err: %v", err)
		}

		_, err = c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{
			Oid: mapResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnelMap() unexpected err: %v", err)
		}
	})

	t.Run("vni to vrf: map entry then tunnel", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap() unexpected err: %v", err)
		}

		entryResp, err := c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap:            proto.Uint64(mapResp.GetOid()),
			VniIdKey:             proto.Uint32(6000),
			VirtualRouterIdValue: proto.Uint64(55),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMapEntry() unexpected err: %v", err)
		}

		// No tunnel attached yet, so no table entries added.
		if len(dplane.gotEntryAddReqs) != 0 {
			t.Fatalf("CreateTunnelMapEntry() got %d add requests, want 0", len(dplane.gotEntryAddReqs))
		}

		tunResp, err := c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(10),
			DecapMappers:      []uint64{mapResp.GetOid()},
		})
		if err != nil {
			t.Fatalf("CreateTunnel() unexpected err: %v", err)
		}

		// TableEntryAdd #0 is TunnelEncap, #1 is vniToVrfTable.
		if len(dplane.gotEntryAddReqs) != 2 {
			t.Fatalf("CreateTunnel() got %d add requests, want 2", len(dplane.gotEntryAddReqs))
		}

		wantVniEntry := fwdconfig.TableEntryAddRequest("foo", vniToVrfTable).AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64(tunResp.GetOid()),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VXLAN_VNI).WithBytes(vniToBytes(6000)),
			)),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(55),
		).Build()

		if diff := cmp.Diff(dplane.gotEntryAddReqs[1], wantVniEntry, protocmp.Transform()); diff != "" {
			t.Errorf("vniToVrfTable entry diff (-got +want):\n%s", diff)
		}

		// RemoveTunnel first: should remove both TunnelEncap (#0) and vniToVrfTable (#1).
		_, err = c.RemoveTunnel(context.TODO(), &saipb.RemoveTunnelRequest{
			Oid: tunResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnel() unexpected err: %v", err)
		}

		if len(dplane.gotEntryRemoveReqs) != 2 {
			t.Fatalf("RemoveTunnel() got %d remove requests, want 2", len(dplane.gotEntryRemoveReqs))
		}

		wantVniRemove := &fwdpb.TableEntryRemoveRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: vniToVrfTable}},
			EntryDesc: fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64(tunResp.GetOid()),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VXLAN_VNI).WithBytes(vniToBytes(6000)),
			)).Build(),
		}
		if diff := cmp.Diff(dplane.gotEntryRemoveReqs[1], wantVniRemove, protocmp.Transform()); diff != "" {
			t.Errorf("vniToVrfTable remove diff (-got +want):\n%s", diff)
		}

		_, err = c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{
			Oid: entryResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnelMapEntry() unexpected err: %v", err)
		}

		_, err = c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{
			Oid: mapResp.GetOid(),
		})
		if err != nil {
			t.Fatalf("RemoveTunnelMap() unexpected err: %v", err)
		}
	})

	t.Run("map entry validation and error codes", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		// Unknown tunnel map -> NotFound.
		_, err := c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(9999),
			VniIdKey:  proto.Uint32(100),
		})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
			t.Errorf("CreateTunnelMapEntry with unknown map expected NotFound, got %v", err)
		}

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap() failed: %v", err)
		}

		// Entry type mismatch -> InvalidArgument.
		_, err = c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap:     proto.Uint64(mapResp.GetOid()),
			TunnelMapType: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI.Enum(),
		})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
			t.Errorf("CreateTunnelMapEntry with mismatched type expected InvalidArgument, got %v", err)
		}

		// VNI > 0xFFFFFF -> InvalidArgument.
		_, err = c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(mapResp.GetOid()),
			VniIdKey:  proto.Uint32(0x1000000),
		})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
			t.Errorf("CreateTunnelMapEntry with VNI > 24-bit expected InvalidArgument, got %v", err)
		}

		// Add valid entry.
		entryResp, err := c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(mapResp.GetOid()),
			VniIdKey:  proto.Uint32(5000),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMapEntry failed: %v", err)
		}

		// Duplicate VNI in same map -> AlreadyExists.
		_, err = c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(mapResp.GetOid()),
			VniIdKey:  proto.Uint32(5000),
		})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.AlreadyExists {
			t.Errorf("CreateTunnelMapEntry with duplicate VNI expected AlreadyExists, got %v", err)
		}

		// Remove entry.
		if _, err := c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{Oid: entryResp.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnelMapEntry failed: %v", err)
		}
		// Removing already-removed entry -> NotFound.
		_, err = c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{Oid: entryResp.GetOid()})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
			t.Errorf("RemoveTunnelMapEntry already removed expected NotFound, got %v", err)
		}
	})

	t.Run("map in use and deletion restrictions", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		// Unknown map -> NotFound.
		_, err := c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{Oid: 9999})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
			t.Errorf("RemoveTunnelMap with unknown OID expected NotFound, got %v", err)
		}

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap() failed: %v", err)
		}

		tunResp, err := c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(10),
			DecapMappers:      []uint64{mapResp.GetOid()},
		})
		if err != nil {
			t.Fatalf("CreateTunnel() failed: %v", err)
		}

		// Cannot remove map referenced by tunnel -> FailedPrecondition.
		_, err = c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{Oid: mapResp.GetOid()})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.FailedPrecondition {
			t.Errorf("RemoveTunnelMap referenced by tunnel expected FailedPrecondition, got %v", err)
		}

		if _, err := c.RemoveTunnel(context.TODO(), &saipb.RemoveTunnelRequest{Oid: tunResp.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnel() failed: %v", err)
		}

		// Add entry to map.
		entryResp, err := c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(mapResp.GetOid()),
			VniIdKey:  proto.Uint32(2000),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMapEntry() failed: %v", err)
		}

		// Cannot remove map with entries -> FailedPrecondition.
		_, err = c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{Oid: mapResp.GetOid()})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.FailedPrecondition {
			t.Errorf("RemoveTunnelMap with entries expected FailedPrecondition, got %v", err)
		}

		if _, err := c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{Oid: entryResp.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnelMapEntry() failed: %v", err)
		}

		// Now removable.
		if _, err := c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{Oid: mapResp.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnelMap() failed: %v", err)
		}
	})

	t.Run("shared tunnel map across two tunnels", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap() failed: %v", err)
		}

		tun1, err := c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(1),
			DecapMappers:      []uint64{mapResp.GetOid()},
		})
		if err != nil {
			t.Fatalf("CreateTunnel 1 failed: %v", err)
		}

		tun2, err := c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(2),
			DecapMappers:      []uint64{mapResp.GetOid()},
		})
		if err != nil {
			t.Fatalf("CreateTunnel 2 failed: %v", err)
		}

		// 2 TunnelEncap entries added so far.
		if len(dplane.gotEntryAddReqs) != 2 {
			t.Fatalf("got %d add requests, want 2", len(dplane.gotEntryAddReqs))
		}

		entryResp, err := c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap:            proto.Uint64(mapResp.GetOid()),
			VniIdKey:             proto.Uint32(7000),
			VirtualRouterIdValue: proto.Uint64(99),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMapEntry failed: %v", err)
		}

		// Now 4 entries total (2 tunnels + 2 vniToVrfTable entries).
		if len(dplane.gotEntryAddReqs) != 4 {
			t.Fatalf("got %d add requests, want 4", len(dplane.gotEntryAddReqs))
		}

		// Remove entry: removes 2 entries from vniToVrfTable.
		if _, err := c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{Oid: entryResp.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnelMapEntry failed: %v", err)
		}
		if len(dplane.gotEntryRemoveReqs) != 2 {
			t.Fatalf("got %d remove requests, want 2", len(dplane.gotEntryRemoveReqs))
		}

		if _, err := c.RemoveTunnel(context.TODO(), &saipb.RemoveTunnelRequest{Oid: tun1.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnel 1 failed: %v", err)
		}
		if _, err := c.RemoveTunnel(context.TODO(), &saipb.RemoveTunnelRequest{Oid: tun2.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnel 2 failed: %v", err)
		}
		if _, err := c.RemoveTunnelMap(context.TODO(), &saipb.RemoveTunnelMapRequest{Oid: mapResp.GetOid()}); err != nil {
			t.Fatalf("RemoveTunnelMap failed: %v", err)
		}
	})

	t.Run("dataplane error rollback on CreateTunnel", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap failed: %v", err)
		}

		_, err = c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(mapResp.GetOid()),
			VniIdKey:  proto.Uint32(8000),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMapEntry failed: %v", err)
		}

		// Call 1 will be TunnelEncap (succeeds), Call 2 will be vniToVrfTable (fails).
		dplane.addErrOnCall = 2

		_, err = c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(10),
			DecapMappers:      []uint64{mapResp.GetOid()},
		})
		if err == nil {
			t.Fatalf("CreateTunnel expected error from injected dataplane failure, got nil")
		}

		// Verify TunnelEncap was rolled back via TableEntryRemove.
		if len(dplane.gotEntryRemoveReqs) != 1 {
			t.Fatalf("got %d remove requests during rollback, want 1", len(dplane.gotEntryRemoveReqs))
		}
	})

	t.Run("dataplane error rollback on CreateTunnelMapEntry", func(t *testing.T) {
		dplane := &fakeSwitchDataplane{}
		c, _, stopFn := newTestTunnel(t, dplane)
		defer stopFn()

		mapResp, err := c.CreateTunnelMap(context.TODO(), &saipb.CreateTunnelMapRequest{
			Type: saipb.TunnelMapType_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID.Enum(),
		})
		if err != nil {
			t.Fatalf("CreateTunnelMap failed: %v", err)
		}

		_, err = c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
			Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
			UnderlayInterface: proto.Uint64(10),
			DecapMappers:      []uint64{mapResp.GetOid()},
		})
		if err != nil {
			t.Fatalf("CreateTunnel failed: %v", err)
		}

		// Call 1 was TunnelEncap. Call 2 will be vniToVrfTable TableEntryAdd from CreateTunnelMapEntry.
		dplane.addErrOnCall = 2

		_, err = c.CreateTunnelMapEntry(context.TODO(), &saipb.CreateTunnelMapEntryRequest{
			TunnelMap: proto.Uint64(mapResp.GetOid()),
			VniIdKey:  proto.Uint32(9000),
		})
		if err == nil {
			t.Fatalf("CreateTunnelMapEntry expected error from injected dataplane failure, got nil")
		}

		// Verify no phantom entry was stored in entryToMap by trying to remove OID 3 (mgr next ID).
		_, err = c.RemoveTunnelMapEntry(context.TODO(), &saipb.RemoveTunnelMapEntryRequest{Oid: 3})
		if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
			t.Errorf("RemoveTunnelMapEntry for failed entry expected NotFound, got %v", err)
		}
	})
}

func TestCreateTunnelLoopbackUnderlay(t *testing.T) {
	dplane := &fakeSwitchDataplane{}
	c, mgr, stopFn := newTestTunnel(t, dplane)
	defer stopFn()

	// Register OID 20 as a LOOPBACK RIF in VRF 7.
	mgr.SetType("20", saipb.ObjectType_OBJECT_TYPE_ROUTER_INTERFACE)
	mgr.StoreAttributes(20, &saipb.RouterInterfaceAttribute{
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_LOOPBACK.Enum(),
		VirtualRouterId: proto.Uint64(7),
	})

	_, err := c.CreateTunnel(context.TODO(), &saipb.CreateTunnelRequest{
		Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
		UnderlayInterface: proto.Uint64(20),
		EncapSrcIp:        net.ParseIP("10.10.10.1").To4(),
		EncapTtlMode:      saipb.TunnelTtlMode_TUNNEL_TTL_MODE_PIPE_MODEL.Enum(),
		EncapTtlVal:       proto.Uint32(64),
	})
	if err != nil {
		t.Fatalf("CreateTunnel() unexpected err: %v", err)
	}

	got := dplane.gotEntryAddReqs[0]
	want := &fwdpb.TableEntryAddRequest{
		ContextId: &fwdpb.ContextId{Id: "foo"},
		TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: TunnelEncap}},
		Entries: []*fwdpb.TableEntryAddRequest_Entry{{
			EntryDesc: fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64(1),
			)).Build(),
			Actions: []*fwdpb.ActionDesc{
				fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_HOP).WithValue([]byte{64})).Build(),
				fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC).WithValue(net.ParseIP("10.10.10.1").To4())).Build(),
				fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST).WithUint64Value(4789)).Build(),
				fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(7)).Build(),
				fwdconfig.Action(fwdconfig.LookupAction(FIBSelectorTable)).Build(),
			},
		}},
	}
	if d := cmp.Diff(got, want, protocmp.Transform()); d != "" {
		t.Errorf("CreateTunnel(loopback underlay) failed: diff(-got,+want)\n%s", d)
	}
}

type capturingFakePort struct {
	txCh chan []byte
	done chan struct{}
	once sync.Once
}

func (p *capturingFakePort) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	<-p.done
	return nil, gopacket.CaptureInfo{}, io.EOF
}

func (p *capturingFakePort) WritePacketData(data []byte) error {
	cp := append([]byte(nil), data...)
	select {
	case p.txCh <- cp:
	case <-p.done:
	}
	return nil
}

func (p *capturingFakePort) Close() {
	p.once.Do(func() { close(p.done) })
}

type capturingFakePortMgr struct {
	mu    sync.Mutex
	ports map[string]*capturingFakePort
}

func (m *capturingFakePortMgr) CreatePort(name string) (fwdcontext.Port, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ports == nil {
		m.ports = make(map[string]*capturingFakePort)
	}
	p := &capturingFakePort{
		txCh: make(chan []byte, 16),
		done: make(chan struct{}),
	}
	m.ports[name] = p
	return p, nil
}

func (m *capturingFakePortMgr) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.ports {
		p.Close()
	}
}

func TestVXLANLoopbackUnderlayAndTTLPacket(t *testing.T) {
	ctx := context.Background()
	mgr := attrmgr.New()
	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(mgr.Interceptor))
	srv, err := New(ctx, mgr, grpcSrv, &dplaneopts.Options{PortType: fwdpb.PortType_PORT_TYPE_FAKE})
	if err != nil {
		t.Fatalf("saiserver.New() failed: %v", err)
	}
	fwdCtx, err := srv.FindContext(&fwdpb.ContextId{Id: srv.ID()})
	if err != nil {
		t.Fatalf("FindContext() failed: %v", err)
	}
	portMgr := &capturingFakePortMgr{}
	fwdCtx.FakePortManager = portMgr
	t.Cleanup(portMgr.Close)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	go func() {
		_ = grpcSrv.Serve(lis)
	}()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	swClient := saipb.NewSwitchClient(conn)
	portClient := saipb.NewPortClient(conn)
	vrClient := saipb.NewVirtualRouterClient(conn)
	rifClient := saipb.NewRouterInterfaceClient(conn)
	tunClient := saipb.NewTunnelClient(conn)
	nhClient := saipb.NewNextHopClient(conn)
	nhgClient := saipb.NewNextHopGroupClient(conn)
	routeClient := saipb.NewRouteClient(conn)
	neighClient := saipb.NewNeighborClient(conn)

	swMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	port1MAC := net.HardwareAddr{0x02, 0x00, 0x01, 0x01, 0x01, 0x01}
	port2MAC := net.HardwareAddr{0x02, 0x00, 0x02, 0x02, 0x02, 0x02}
	ateMAC := net.HardwareAddr{0x02, 0x00, 0xaa, 0x00, 0x00, 0x01}
	nhMAC := net.HardwareAddr{0x02, 0x00, 0xbb, 0x00, 0x00, 0x02}
	tunMAC := net.HardwareAddr{0x02, 0x00, 0xaa, 0xbb, 0xcc, 0xdd}

	swResp, err := swClient.CreateSwitch(ctx, &saipb.CreateSwitchRequest{
		InitSwitch:    proto.Bool(true),
		SrcMacAddress: swMAC,
	})
	if err != nil {
		t.Fatalf("CreateSwitch() failed: %v", err)
	}
	swAttr, err := swClient.GetSwitchAttribute(ctx, &saipb.GetSwitchAttributeRequest{
		Oid:      swResp.Oid,
		AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID},
	})
	if err != nil {
		t.Fatalf("GetSwitchAttribute() failed: %v", err)
	}
	defaultVR := swAttr.GetAttr().GetDefaultVirtualRouterId()

	p1Resp, err := portClient.CreatePort(ctx, &saipb.CreatePortRequest{
		Switch:     swResp.Oid,
		HwLaneList: []uint32{1},
		AdminState: proto.Bool(true),
	})
	if err != nil {
		t.Fatalf("CreatePort(1) failed: %v", err)
	}
	p2Resp, err := portClient.CreatePort(ctx, &saipb.CreatePortRequest{
		Switch:     swResp.Oid,
		HwLaneList: []uint32{2},
		AdminState: proto.Bool(true),
	})
	if err != nil {
		t.Fatalf("CreatePort(2) failed: %v", err)
	}

	overlayVRResp, err := vrClient.CreateVirtualRouter(ctx, &saipb.CreateVirtualRouterRequest{Switch: swResp.Oid})
	if err != nil {
		t.Fatalf("CreateVirtualRouter() failed: %v", err)
	}

	p1RifResp, err := rifClient.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch:          swResp.Oid,
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
		PortId:          proto.Uint64(p1Resp.Oid),
		VirtualRouterId: proto.Uint64(overlayVRResp.Oid),
		SrcMacAddress:   port1MAC,
	})
	if err != nil {
		t.Fatalf("CreateRouterInterface(p1) failed: %v", err)
	}
	_ = p1RifResp

	p2RifResp, err := rifClient.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch:          swResp.Oid,
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
		PortId:          proto.Uint64(p2Resp.Oid),
		VirtualRouterId: proto.Uint64(defaultVR),
		SrcMacAddress:   port2MAC,
	})
	if err != nil {
		t.Fatalf("CreateRouterInterface(p2) failed: %v", err)
	}

	loRifResp, err := rifClient.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch:          swResp.Oid,
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_LOOPBACK.Enum(),
		VirtualRouterId: proto.Uint64(defaultVR),
	})
	if err != nil {
		t.Fatalf("CreateRouterInterface(lo) failed: %v", err)
	}

	tunPipeResp, err := tunClient.CreateTunnel(ctx, &saipb.CreateTunnelRequest{
		Switch:            swResp.Oid,
		Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
		UnderlayInterface: proto.Uint64(loRifResp.Oid),
		EncapSrcIp:        net.ParseIP("10.10.10.1").To4(),
		EncapTtlMode:      saipb.TunnelTtlMode_TUNNEL_TTL_MODE_PIPE_MODEL.Enum(),
		EncapTtlVal:       proto.Uint32(64),
	})
	if err != nil {
		t.Fatalf("CreateTunnel(pipe) failed: %v", err)
	}

	tunUniformResp, err := tunClient.CreateTunnel(ctx, &saipb.CreateTunnelRequest{
		Switch:            swResp.Oid,
		Type:              saipb.TunnelType_TUNNEL_TYPE_VXLAN.Enum(),
		UnderlayInterface: proto.Uint64(loRifResp.Oid),
		EncapSrcIp:        net.ParseIP("10.10.10.1").To4(),
		EncapTtlMode:      saipb.TunnelTtlMode_TUNNEL_TTL_MODE_UNIFORM_MODEL.Enum(),
	})
	if err != nil {
		t.Fatalf("CreateTunnel(uniform) failed: %v", err)
	}

	nhPipeResp, err := nhClient.CreateNextHop(ctx, &saipb.CreateNextHopRequest{
		Switch:    swResp.Oid,
		Type:      saipb.NextHopType_NEXT_HOP_TYPE_TUNNEL_ENCAP.Enum(),
		TunnelId:  proto.Uint64(tunPipeResp.Oid),
		Ip:        net.ParseIP("20.20.20.2").To4(),
		TunnelVni: proto.Uint32(5000),
		TunnelMac: tunMAC,
	})
	if err != nil {
		t.Fatalf("CreateNextHop(pipe) failed: %v", err)
	}

	nhUniformResp, err := nhClient.CreateNextHop(ctx, &saipb.CreateNextHopRequest{
		Switch:    swResp.Oid,
		Type:      saipb.NextHopType_NEXT_HOP_TYPE_TUNNEL_ENCAP.Enum(),
		TunnelId:  proto.Uint64(tunUniformResp.Oid),
		Ip:        net.ParseIP("20.20.20.3").To4(),
		TunnelVni: proto.Uint32(5001),
		TunnelMac: tunMAC,
	})
	if err != nil {
		t.Fatalf("CreateNextHop(uniform) failed: %v", err)
	}

	underlayNHResp, err := nhClient.CreateNextHop(ctx, &saipb.CreateNextHopRequest{
		Switch:            swResp.Oid,
		Type:              saipb.NextHopType_NEXT_HOP_TYPE_IP.Enum(),
		RouterInterfaceId: proto.Uint64(p2RifResp.Oid),
		Ip:                net.ParseIP("192.0.2.6").To4(),
	})
	if err != nil {
		t.Fatalf("CreateNextHop(underlay) failed: %v", err)
	}

	if _, err := neighClient.CreateNeighborEntry(ctx, &saipb.CreateNeighborEntryRequest{
		Entry: &saipb.NeighborEntry{
			SwitchId:  swResp.Oid,
			RifId:     p2RifResp.Oid,
			IpAddress: net.ParseIP("192.0.2.6").To4(),
		},
		DstMacAddress: nhMAC,
	}); err != nil {
		t.Fatalf("CreateNeighborEntry() failed: %v", err)
	}

	nhgResp, err := nhgClient.CreateNextHopGroup(ctx, &saipb.CreateNextHopGroupRequest{
		Switch:                  swResp.Oid,
		Type:                    saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_ECMP_WITH_MEMBERS.Enum(),
		NextHopList:             []uint64{underlayNHResp.Oid},
		NextHopMemberWeightList: []uint32{1},
	})
	if err != nil {
		t.Fatalf("CreateNextHopGroup() failed: %v", err)
	}

	for _, ipStr := range []string{"20.20.20.2", "20.20.20.3"} {
		if _, err := routeClient.CreateRouteEntry(ctx, &saipb.CreateRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: swResp.Oid,
				VrId:     defaultVR,
				Destination: &saipb.IpPrefix{
					Addr: net.ParseIP(ipStr).To4(),
					Mask: []byte{0xff, 0xff, 0xff, 0xff},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(nhgResp.Oid),
		}); err != nil {
			t.Fatalf("CreateRouteEntry(underlay %s) failed: %v", ipStr, err)
		}
	}

	for dstIP, nhID := range map[string]uint64{
		"198.51.100.2": nhPipeResp.Oid,
		"198.51.100.3": nhUniformResp.Oid,
	} {
		if _, err := routeClient.CreateRouteEntry(ctx, &saipb.CreateRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: swResp.Oid,
				VrId:     overlayVRResp.Oid,
				Destination: &saipb.IpPrefix{
					Addr: net.ParseIP(dstIP).To4(),
					Mask: []byte{0xff, 0xff, 0xff, 0xff},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(nhID),
		}); err != nil {
			t.Fatalf("CreateRouteEntry(overlay %s) failed: %v", dstIP, err)
		}
	}

	inject := func(dstMAC net.HardwareAddr, dstIP string, ttl uint8) {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		ethL := &layers.Ethernet{SrcMAC: ateMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
		ipL := &layers.IPv4{Version: 4, TTL: ttl, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.2").To4(), DstIP: net.ParseIP(dstIP).To4()}
		udpL := &layers.UDP{SrcPort: 12345, DstPort: 54321}
		if err := udpL.SetNetworkLayerForChecksum(ipL); err != nil {
			t.Fatalf("SetNetworkLayerForChecksum() failed: %v", err)
		}
		if err := gopacket.SerializeLayers(buf, opts,
			ethL,
			ipL,
			udpL,
			gopacket.Payload([]byte("hello-vxlan")),
		); err != nil {
			t.Fatalf("SerializeLayers() failed: %v", err)
		}
		if err := srv.InjectPacket(
			&fwdpb.ContextId{Id: srv.ID()},
			&fwdpb.PortId{ObjectId: &fwdpb.ObjectId{Id: fmt.Sprint(p1Resp.Oid)}},
			fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET,
			buf.Bytes(),
			nil,
			false,
			fwdpb.PortAction_PORT_ACTION_INPUT,
		); err != nil {
			t.Fatalf("InjectPacket() failed: %v", err)
		}
	}

	port2 := portMgr.ports["2"]
	if port2 == nil {
		t.Fatalf("port 2 not created in fake port manager")
	}

	// 1. MyMacTable miss -> dropped.
	inject(net.HardwareAddr{0x02, 0x00, 0x99, 0x99, 0x99, 0x99}, "198.51.100.2", 64)
	select {
	case pkt := <-port2.txCh:
		t.Fatalf("expected drop on MyMacTable miss, got packet of len %d", len(pkt))
	case <-time.After(100 * time.Millisecond):
	}

	// 2. Inner TTL=1 -> dropped by innerTTLCheckTable before encap.
	inject(port1MAC, "198.51.100.2", 1)
	select {
	case pkt := <-port2.txCh:
		t.Fatalf("expected drop on inner TTL=1, got packet of len %d", len(pkt))
	case <-time.After(100 * time.Millisecond):
	}

	// 2b. M-9: Inner TTL=2 -> forwarded with inner TTL=1 and outer PIPE TTL=64.
	inject(port1MAC, "198.51.100.2", 2)
	var ttl2Frame []byte
	select {
	case ttl2Frame = <-port2.txCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for PIPE_MODEL VXLAN packet with inner TTL=2")
	}
	ttl2Pkt := gopacket.NewPacket(ttl2Frame, layers.LayerTypeEthernet, gopacket.Default)
	ttl2OuterIP := ttl2Pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ttl2Vxlan := ttl2Pkt.Layer(layers.LayerTypeVXLAN).(*layers.VXLAN)
	ttl2InnerIP := gopacket.NewPacket(ttl2Vxlan.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ttl2OuterIP.TTL != 64 || ttl2InnerIP.TTL != 1 {
		t.Fatalf("TTL=2 case got outerTTL=%d innerTTL=%d, want outerTTL=64 innerTTL=1", ttl2OuterIP.TTL, ttl2InnerIP.TTL)
	}

	// 3. PIPE_MODEL: inner TTL 64 -> 63, outer TTL stays 64 (not decremented to 63).
	inject(port1MAC, "198.51.100.2", 64)
	var pipeFrame []byte
	select {
	case pipeFrame = <-port2.txCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for PIPE_MODEL VXLAN packet")
	}
	pipePkt := gopacket.NewPacket(pipeFrame, layers.LayerTypeEthernet, gopacket.Default)
	outerIP, ok := pipePkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		t.Fatalf("missing outer IPv4 layer in PIPE packet")
	}
	if !outerIP.SrcIP.Equal(net.ParseIP("10.10.10.1").To4()) || !outerIP.DstIP.Equal(net.ParseIP("20.20.20.2").To4()) {
		t.Fatalf("unexpected outer IPs: src=%v dst=%v", outerIP.SrcIP, outerIP.DstIP)
	}
	if outerIP.TTL != 64 {
		t.Fatalf("PIPE outer TTL = %d, want 64", outerIP.TTL)
	}
	vxlanL, ok := pipePkt.Layer(layers.LayerTypeVXLAN).(*layers.VXLAN)
	if !ok || vxlanL.VNI != 5000 {
		t.Fatalf("unexpected VXLAN layer: ok=%v vni=%v", ok, vxlanL)
	}
	innerPkt := gopacket.NewPacket(vxlanL.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)
	innerIP, ok := innerPkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		t.Fatalf("missing inner IPv4 layer in PIPE packet")
	}
	if innerIP.TTL != 63 {
		t.Fatalf("PIPE inner TTL = %d, want 63", innerIP.TTL)
	}
	innerEth := innerPkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if innerEth.DstMAC.String() != tunMAC.String() {
		t.Fatalf("inner DstMAC = %s, want %s", innerEth.DstMAC, tunMAC)
	}

	// 4. UNIFORM_MODEL: inner TTL 64 -> 63, outer TTL copies decremented inner TTL (63).
	inject(port1MAC, "198.51.100.3", 64)
	var uniformFrame []byte
	select {
	case uniformFrame = <-port2.txCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for UNIFORM_MODEL VXLAN packet")
	}
	uPkt := gopacket.NewPacket(uniformFrame, layers.LayerTypeEthernet, gopacket.Default)
	uOuterIP := uPkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if uOuterIP.TTL != 63 {
		t.Fatalf("UNIFORM outer TTL = %d, want 63", uOuterIP.TTL)
	}
	uVxlan := uPkt.Layer(layers.LayerTypeVXLAN).(*layers.VXLAN)
	uInnerPkt := gopacket.NewPacket(uVxlan.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)
	uInnerIP := uInnerPkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if uInnerIP.TTL != 63 {
		t.Fatalf("UNIFORM inner TTL = %d, want 63", uInnerIP.TTL)
	}
}

func newTestTunnel(t testing.TB, api switchDataplaneAPI) (saipb.TunnelClient, *attrmgr.AttrMgr, func()) {
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		newTunnel(mgr, api, srv)
	})
	return saipb.NewTunnelClient(conn), mgr, stopFn
}
