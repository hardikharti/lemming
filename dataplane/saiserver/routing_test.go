// Copyright 2023 Google LLC
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
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/openconfig/gnmi/errdiff"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/openconfig/lemming/dataplane/dplaneopts"
	"github.com/openconfig/lemming/dataplane/forwarding/fwdconfig"
	"github.com/openconfig/lemming/dataplane/forwarding/infra/fwdcontext"
	"github.com/openconfig/lemming/dataplane/forwarding/infra/fwdobject"
	"github.com/openconfig/lemming/dataplane/saiserver/attrmgr"

	saipb "github.com/openconfig/lemming/dataplane/proto/sai"
	fwdpb "github.com/openconfig/lemming/proto/forwarding"
)

func TestCreateNeighborEntry(t *testing.T) {
	tests := []struct {
		desc     string
		req      *saipb.CreateNeighborEntryRequest
		want     *saipb.CreateNeighborEntryResponse
		wantAttr *saipb.NeighborEntryAttribute
		wantErr  string
	}{{
		desc:     "existing interface",
		req:      &saipb.CreateNeighborEntryRequest{},
		want:     &saipb.CreateNeighborEntryResponse{},
		wantAttr: &saipb.NeighborEntryAttribute{},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestNeighbor(t, dplane)
			defer stopFn()
			got, gotErr := c.CreateNeighborEntry(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateNeighborEntry() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(got, tt.want, protocmp.Transform()); d != "" {
				t.Errorf("CreateNeighborEntry() failed: diff(-got,+want)\n:%s", d)
			}
			attr := &saipb.NeighborEntryAttribute{}
			if err := mgr.PopulateAllAttributes("1", attr); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(attr, tt.wantAttr, protocmp.Transform()); d != "" {
				t.Errorf("CreateNeighborEntry() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestCreateNextHopGroup(t *testing.T) {
	tests := []struct {
		desc     string
		req      *saipb.CreateNextHopGroupRequest
		wantAttr *saipb.NextHopGroupAttribute
		wantErr  string
	}{{
		desc:    "unspecified type",
		req:     &saipb.CreateNextHopGroupRequest{},
		wantErr: "InvalidArgument",
	}, {
		desc: "dynamic unordered",
		req: &saipb.CreateNextHopGroupRequest{
			Type: saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP.Enum(),
		},
		wantAttr: &saipb.NextHopGroupAttribute{
			Type: saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP.Enum(),
		},
	}, {
		desc: "ecmp with members",
		req: &saipb.CreateNextHopGroupRequest{
			Type:                    saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_ECMP_WITH_MEMBERS.Enum(),
			NextHopList:             []uint64{10},
			NextHopMemberWeightList: []uint32{1},
		},
		wantAttr: &saipb.NextHopGroupAttribute{
			Type:                    saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_ECMP_WITH_MEMBERS.Enum(),
			NextHopList:             []uint64{10},
			NextHopMemberWeightList: []uint32{1},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestNextHopGroup(t, dplane)
			defer stopFn()
			swID := mgr.NextID()
			mgr.StoreAttributes(swID, &saipb.SwitchAttribute{
				EcmpHashIpv4: proto.Uint64(5),
				EcmpHashIpv6: proto.Uint64(5),
			})
			mgr.SetType(fmt.Sprint(swID), saipb.ObjectType_OBJECT_TYPE_SWITCH)
			mgr.StoreAttributes(5, &saipb.HashAttribute{
				NativeHashFieldList: []saipb.NativeHashField{saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IP},
			})
			mgr.StoreAttributes(10, &saipb.NextHopAttribute{
				Ip: []byte{127, 0, 0, 1},
			})

			got, gotErr := c.CreateNextHopGroup(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateNextHopGroup() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			attr := &saipb.NextHopGroupAttribute{}
			if err := mgr.PopulateAllAttributes(fmt.Sprint(got.GetOid()), attr); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(attr, tt.wantAttr, protocmp.Transform()); d != "" {
				t.Errorf("CreateNextHopGroup() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestRemoveNextHopGroup(t *testing.T) {
	tests := []struct {
		desc      string
		memberReq *saipb.CreateNextHopGroupMemberRequest
		oid       uint64 // specify this if you want an arbitrary OID to remove.
		wantErr   string
	}{{
		desc: "success",
	}, {
		desc:    "fail: group not found",
		oid:     15, // a non-existing OID.
		wantErr: "group 15 does not exist",
	}}
	nhgReq := &saipb.CreateNextHopGroupRequest{
		Type: saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP.Enum(),
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, _, stopFn := newTestNextHopGroup(t, dplane)
			defer stopFn()
			ctx := context.Background()
			resp, err := c.CreateNextHopGroup(ctx, nhgReq)
			if err != nil {
				t.Fatalf("unexpected err: %s", err)
			}
			oid := tt.oid
			if oid == 0 {
				oid = resp.Oid
			}
			if tt.memberReq != nil {
				tt.memberReq.NextHopGroupId = proto.Uint64(oid)
				if _, err := c.CreateNextHopGroupMember(ctx, tt.memberReq); err != nil {
					t.Fatalf("unexpected err: %s", err)
				}
			}
			_, gotErr := c.RemoveNextHopGroup(context.TODO(), &saipb.RemoveNextHopGroupRequest{Oid: oid})
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("RemoveNextHopGroup() unexpected err: %s", diff)
			}
		})
	}
}

func TestSetNextHopGroupAttribute(t *testing.T) {
	tests := []struct {
		desc     string
		req      *saipb.SetNextHopGroupAttributeRequest
		wantAttr *saipb.NextHopGroupAttribute
		wantErr  string
	}{{
		desc: "replace members",
		req: &saipb.SetNextHopGroupAttributeRequest{
			NextHopList: []uint64{3},
		},
		wantAttr: &saipb.NextHopGroupAttribute{
			NextHopList:             []uint64{3},
			NextHopMemberWeightList: []uint32{1},
			Type:                    saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP.Enum(),
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestNextHopGroup(t, dplane)
			defer stopFn()

			swID := mgr.NextID()
			mgr.StoreAttributes(swID, &saipb.SwitchAttribute{EcmpHashIpv4: proto.Uint64(10), EcmpHashIpv6: proto.Uint64(9)})
			mgr.SetType(fmt.Sprint(swID), saipb.ObjectType_OBJECT_TYPE_SWITCH)
			mgr.StoreAttributes(3, &saipb.CreateNextHopRequest{Ip: []byte{127, 0, 0, 1}})
			mgr.StoreAttributes(4, &saipb.CreateNextHopRequest{Ip: []byte{127, 0, 0, 2}})
			mgr.StoreAttributes(10, &saipb.CreateHashRequest{
				NativeHashFieldList: []saipb.NativeHashField{saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IP},
			})

			ctx := context.Background()
			resp, err := c.CreateNextHopGroup(ctx, &saipb.CreateNextHopGroupRequest{Type: saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP.Enum()})
			if err != nil {
				t.Fatal(err)
			}
			tt.req.Oid = resp.Oid

			_, err = c.CreateNextHopGroupMember(ctx, &saipb.CreateNextHopGroupMemberRequest{
				NextHopGroupId: proto.Uint64(resp.Oid),
				NextHopId:      proto.Uint64(4),
				Weight:         proto.Uint32(1),
			})
			if err != nil {
				t.Fatal(err)
			}

			_, gotErr := c.SetNextHopGroupAttribute(ctx, tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("SetNextHopGroupAttribute() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}

			attr := &saipb.NextHopGroupAttribute{}
			if err := mgr.PopulateAllAttributes(fmt.Sprint(resp.Oid), attr); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(attr, tt.wantAttr, protocmp.Transform()); d != "" {
				t.Errorf("SetNextHopGroupAttribute() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestCreateNextHopGroupMember(t *testing.T) {
	tests := []struct {
		desc     string
		req      *saipb.CreateNextHopGroupMemberRequest
		wantAttr *saipb.NextHopGroupMemberAttribute
		wantReq  *fwdpb.TableEntryAddRequest
		wantErr  string
	}{{
		desc: "success",
		req: &saipb.CreateNextHopGroupMemberRequest{
			NextHopGroupId: proto.Uint64(2),
			NextHopId:      proto.Uint64(3),
			Weight:         proto.Uint32(3),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHGTable}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_GROUP_ID,
								}},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
							}},
						},
					},
				},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_SELECT_ACTION_LIST,
					Action: &fwdpb.ActionDesc_Select{
						Select: &fwdpb.SelectActionListActionDesc{
							SelectAlgorithm: fwdpb.SelectActionListActionDesc_SELECT_ALGORITHM_CRC32,
							FieldIds: []*fwdpb.PacketFieldId{
								{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST}},
							},
							ActionLists: []*fwdpb.ActionList{{
								Weight: 3,
								Actions: []*fwdpb.ActionDesc{{
									ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
									Action: &fwdpb.ActionDesc_Update{
										Update: &fwdpb.UpdateActionDesc{
											FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID}},
											Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
											Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
											Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
										},
									},
								}},
							}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHTable}},
						},
					},
				}},
			}},
		},
		wantAttr: &saipb.NextHopGroupMemberAttribute{
			NextHopGroupId: proto.Uint64(2),
			NextHopId:      proto.Uint64(3),
			Weight:         proto.Uint32(3),
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestNextHopGroup(t, dplane)

			swID := mgr.NextID()
			mgr.StoreAttributes(swID, &saipb.SwitchAttribute{EcmpHashIpv4: proto.Uint64(10), EcmpHashIpv6: proto.Uint64(9)})
			mgr.SetType(fmt.Sprint(swID), saipb.ObjectType_OBJECT_TYPE_SWITCH)
			mgr.StoreAttributes(3, &saipb.CreateNextHopRequest{Ip: []byte{127, 0, 0, 1}})
			mgr.StoreAttributes(10, &saipb.CreateHashRequest{
				NativeHashFieldList: []saipb.NativeHashField{saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IP},
			})

			_, err := c.CreateNextHopGroup(context.Background(), &saipb.CreateNextHopGroupRequest{Type: saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP.Enum()})
			if err != nil {
				t.Fatal(err)
			}
			defer stopFn()
			_, gotErr := c.CreateNextHopGroupMember(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateNextHopGroupMember() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(dplane.gotEntryAddReqs[1], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("CreateNextHopGroupMember() failed: diff(-got,+want)\n:%s", d)
			}
			attr := &saipb.NextHopGroupMemberAttribute{}
			if err := mgr.PopulateAllAttributes("3", attr); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(attr, tt.wantAttr, protocmp.Transform()); d != "" {
				t.Errorf("CreateNextHopGroupMember() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestRemoveNextHopGroupMember(t *testing.T) {
	tests := []struct {
		desc     string
		memberID uint64
		wantAttr *saipb.NextHopGroupMemberAttribute
		wantReq  *fwdpb.TableEntryAddRequest
		wantErr  string
	}{{
		desc:     "success",
		memberID: 0,
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHGTable}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_GROUP_ID,
								}},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
							}},
						},
					},
				},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_SELECT_ACTION_LIST,
					Action: &fwdpb.ActionDesc_Select{
						Select: &fwdpb.SelectActionListActionDesc{
							SelectAlgorithm: fwdpb.SelectActionListActionDesc_SELECT_ALGORITHM_CRC32,
							FieldIds: []*fwdpb.PacketFieldId{
								{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST}},
							},
							ActionLists: []*fwdpb.ActionList{{
								Weight: 66,
								Actions: []*fwdpb.ActionDesc{{
									ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
									Action: &fwdpb.ActionDesc_Update{
										Update: &fwdpb.UpdateActionDesc{
											FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID}},
											Type:    fwdpb.UpdateType_UPDATE_TYPE_SET,
											Field:   &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
											Value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c},
										},
									},
								}},
							}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHTable}},
						},
					},
				}},
			}},
		},
		wantAttr: &saipb.NextHopGroupMemberAttribute{
			NextHopGroupId: proto.Uint64(2),
			NextHopId:      proto.Uint64(12),
			Weight:         proto.Uint32(66),
		},
	}, {
		desc:     "fail: member not found",
		memberID: 100,
		wantErr:  "cannot find member with id",
	}}
	// Creates two members.
	createReqs := []*saipb.CreateNextHopGroupMemberRequest{{
		NextHopId: proto.Uint64(11),
		Weight:    proto.Uint32(33),
	}, {
		NextHopId: proto.Uint64(12),
		Weight:    proto.Uint32(66),
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestNextHopGroup(t, dplane)
			swID := mgr.NextID()
			mgr.StoreAttributes(swID, &saipb.SwitchAttribute{EcmpHashIpv4: proto.Uint64(9), EcmpHashIpv6: proto.Uint64(10)})
			mgr.SetType(fmt.Sprint(swID), saipb.ObjectType_OBJECT_TYPE_SWITCH)
			mgr.StoreAttributes(10, &saipb.CreateNextHopRequest{Ip: []byte{127, 0, 0, 1}})
			mgr.StoreAttributes(11, &saipb.CreateNextHopRequest{Ip: []byte{127, 0, 0, 2}})
			mgr.StoreAttributes(9, &saipb.CreateHashRequest{
				NativeHashFieldList: []saipb.NativeHashField{saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IP},
			})

			ctx := context.Background()
			r, err := c.CreateNextHopGroup(ctx, &saipb.CreateNextHopGroupRequest{Type: saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP.Enum()})
			if err != nil {
				t.Fatal(err)
			}
			defer stopFn()
			memberID := tt.memberID // memberID is either the memberID specified in test case, or the memberID of the first added member.
			if memberID == 0 {
				for _, req := range createReqs {
					req.NextHopGroupId = &r.Oid
					resp, err := c.CreateNextHopGroupMember(ctx, req)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					// Stores the first member ID.
					if memberID == 0 {
						memberID = resp.GetOid()
					}
				}
			}

			_, err = c.RemoveNextHopGroupMember(ctx, &saipb.RemoveNextHopGroupMemberRequest{Oid: memberID})
			if diff := errdiff.Check(err, tt.wantErr); diff != "" {
				t.Fatalf("RemoveNextHopGroupMember() unexpected err: %s", diff)
			}
			if tt.wantErr != "" {
				return
			}

			if d := cmp.Diff(dplane.gotEntryAddReqs[3], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("RemoveNextHopGroupMember() failed: diff(-got,+want)\n:%s", d)
			}
			attr := &saipb.NextHopGroupMemberAttribute{}
			if err := mgr.PopulateAllAttributes("4", attr); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(attr, tt.wantAttr, protocmp.Transform()); d != "" {
				t.Errorf("RemoveNextHopGroupMember() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestCreateNextHop(t *testing.T) {
	tests := []struct {
		desc       string
		req        *saipb.CreateNextHopRequest
		tunnelType saipb.TunnelType
		wantAttr   *saipb.NextHopAttribute
		wantReq    *fwdpb.TableEntryAddRequest
		wantErr    string
	}{{
		desc:    "unknown type",
		req:     &saipb.CreateNextHopRequest{},
		wantErr: "InvalidArgument",
	}, {
		desc: "success ip next hop",
		req: &saipb.CreateNextHopRequest{
			Type:              saipb.NextHopType_NEXT_HOP_TYPE_IP.Enum(),
			RouterInterfaceId: proto.Uint64(10),
			Ip:                []byte{127, 0, 0, 1},
		},
		wantAttr: &saipb.NextHopAttribute{
			Type:              saipb.NextHopType_NEXT_HOP_TYPE_IP.Enum(),
			RouterInterfaceId: proto.Uint64(10),
			Ip:                []byte{127, 0, 0, 1},
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHTable}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x7f, 0x00, 0x00, 0x01},
						},
					},
				}},
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{
										FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID,
									},
								},
							}},
						},
					},
				},
			}},
		},
	}, {
		desc: "success tunnel next hop",
		req: &saipb.CreateNextHopRequest{
			Type:     saipb.NextHopType_NEXT_HOP_TYPE_TUNNEL_ENCAP.Enum(),
			TunnelId: proto.Uint64(15),
			Ip:       []byte{127, 0, 0, 1},
		},
		wantAttr: &saipb.NextHopAttribute{
			Type:     saipb.NextHopType_NEXT_HOP_TYPE_TUNNEL_ENCAP.Enum(),
			TunnelId: proto.Uint64(15),
			Ip:       []byte{127, 0, 0, 1},
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHTable}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: innerTTLCheckTable}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_8,
									Instance: skipOuterTTLDecAttr,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
					Action: &fwdpb.ActionDesc_Encap{
						Encap: &fwdpb.EncapActionDesc{
							HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4,
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x7f, 0x00, 0x00, 0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x7f, 0x00, 0x00, 0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHActionTable}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: TunnelEncap}},
						},
					},
				}},
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{
										FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID,
									},
								},
							}},
						},
					},
				},
			}},
		},
	}, {
		desc: "success tunnel next hop with vni and mac",
		req: &saipb.CreateNextHopRequest{
			Type:      saipb.NextHopType_NEXT_HOP_TYPE_TUNNEL_ENCAP.Enum(),
			TunnelId:  proto.Uint64(15),
			Ip:        []byte{127, 0, 0, 1},
			TunnelVni: proto.Uint32(0x123456),
			TunnelMac: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
		tunnelType: saipb.TunnelType_TUNNEL_TYPE_VXLAN,
		wantAttr: &saipb.NextHopAttribute{
			Type:      saipb.NextHopType_NEXT_HOP_TYPE_TUNNEL_ENCAP.Enum(),
			TunnelId:  proto.Uint64(15),
			Ip:        []byte{127, 0, 0, 1},
			TunnelVni: proto.Uint32(0x123456),
			TunnelMac: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHTable}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: innerTTLCheckTable}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_8,
									Instance: skipOuterTTLDecAttr,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_COPY,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_SRC,
								},
							},
							Field: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST,
								},
							},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
					Action: &fwdpb.ActionDesc_Encap{
						Encap: &fwdpb.EncapActionDesc{
							HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_VXLAN,
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
					Action: &fwdpb.ActionDesc_Encap{
						Encap: &fwdpb.EncapActionDesc{
							HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_UDP,
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
					Action: &fwdpb.ActionDesc_Encap{
						Encap: &fwdpb.EncapActionDesc{
							HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4,
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VXLAN_VNI,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x12, 0x34, 0x56},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x7f, 0x00, 0x00, 0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x7f, 0x00, 0x00, 0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID,
								},
							},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHActionTable}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
					Action: &fwdpb.ActionDesc_Lookup{
						Lookup: &fwdpb.LookupActionDesc{
							TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: TunnelEncap}},
						},
					},
				}},
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Exact{
						Exact: &fwdpb.ExactEntryDesc{
							Fields: []*fwdpb.PacketFieldBytes{{
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{
										FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID,
									},
								},
							}},
						},
					},
				},
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestNextHop(t, dplane)
			tType := tt.tunnelType
			if tType == saipb.TunnelType_TUNNEL_TYPE_UNSPECIFIED {
				tType = saipb.TunnelType_TUNNEL_TYPE_IPINIP
			}
			mgr.StoreAttributes(15, &saipb.TunnelAttribute{Type: tType.Enum()})
			defer stopFn()
			_, gotErr := c.CreateNextHop(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateNextHop() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(dplane.gotEntryAddReqs[0], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("CreateNextHop() failed: diff(-got,+want)\n:%s", d)
			}
			attr := &saipb.NextHopAttribute{}
			if err := mgr.PopulateAllAttributes("1", attr); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(attr, tt.wantAttr, protocmp.Transform()); d != "" {
				t.Errorf("CreateNextHop() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestRemoveNextHop(t *testing.T) {
	// Add, remove, and then check.
	tests := []struct {
		desc      string
		reqCreate *saipb.CreateNextHopRequest
		oid       uint64 // specify this if you want an arbitrary OID to remove.
		wantErr   string
	}{{
		desc: "pass",
		reqCreate: &saipb.CreateNextHopRequest{
			Type:              saipb.NextHopType_NEXT_HOP_TYPE_IP.Enum(),
			RouterInterfaceId: proto.Uint64(10),
			Ip:                []byte{127, 0, 0, 1},
		},
	}, {
		desc: "fail: non-existing next hop",
		reqCreate: &saipb.CreateNextHopRequest{
			Type:              saipb.NextHopType_NEXT_HOP_TYPE_IP.Enum(),
			RouterInterfaceId: proto.Uint64(10),
			Ip:                []byte{127, 0, 0, 1},
		},
		oid:     15, // a non-existing OID.
		wantErr: "OID not found: 15",
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, _, stopFn := newTestNextHop(t, dplane)
			defer stopFn()

			resp, err := c.CreateNextHop(context.TODO(), tt.reqCreate)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			oid := tt.oid
			if oid == 0 {
				oid = resp.Oid
			}
			_, gotErr := c.RemoveNextHop(context.TODO(), &saipb.RemoveNextHopRequest{Oid: oid})
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("RemoveNextHop() unexpected err: %s", diff)
			}
		})
	}
}

func TestCreateRouteEntry(t *testing.T) {
	tests := []struct {
		desc    string
		req     *saipb.CreateRouteEntryRequest
		wantReq *fwdpb.TableEntryAddRequest
		types   map[string]saipb.ObjectType
		wantErr string
	}{{
		desc:    "unknown action",
		req:     &saipb.CreateRouteEntryRequest{},
		wantErr: "InvalidArgument",
	}, {
		desc: "drop action",
		req: &saipb.CreateRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				Destination: &saipb.IpPrefix{
					Addr: []byte{127, 0, 0, 1},
					Mask: []byte{255, 255, 255, 255},
				},
				SwitchId: 1,
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_DROP.Enum(),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: FIBV4Table}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							FieldId:  &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ACTION}},
							Field:    &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Type:     fwdpb.UpdateType_UPDATE_TYPE_BIT_WRITE,
							Value:    []byte{0},
							BitCount: 1,
						},
					},
				}},
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Prefix{
						Prefix: &fwdpb.PrefixEntryDesc{
							Fields: []*fwdpb.PacketFieldMaskedBytes{{
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF},
								},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
								Masks: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
							}, {
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST},
								},
								Bytes: []byte{0x7f, 0x00, 0x00, 0x01},
								Masks: []byte{0xff, 0xff, 0xff, 0xff},
							}},
						},
					},
				},
			}},
		},
	}, {
		desc:  "forward port action",
		types: map[string]saipb.ObjectType{"100": saipb.ObjectType_OBJECT_TYPE_PORT},
		req: &saipb.CreateRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				Destination: &saipb.IpPrefix{
					Addr: []byte{127, 0, 0, 1},
					Mask: []byte{255, 255, 255, 255},
				},
				SwitchId: 1,
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_TRANSIT.Enum(),
			MetaData:     proto.Uint32(10),
			NextHopId:    proto.Uint64(100),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: FIBV4Table}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							FieldId:  &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ACTION}},
							Field:    &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Type:     fwdpb.UpdateType_UPDATE_TYPE_BIT_WRITE,
							Value:    []byte{1},
							BitCount: 1,
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_COPY,
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP,
							}},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST,
							}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_TRANSMIT,
					Action: &fwdpb.ActionDesc_Transmit{
						Transmit: &fwdpb.TransmitActionDesc{
							PortId: &fwdpb.PortId{ObjectId: &fwdpb.ObjectId{Id: "100"}},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type:  fwdpb.UpdateType_UPDATE_TYPE_SET,
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_32,
								Instance: routeDstMeta,
							}},
							Value: []uint8{0x00, 0x00, 0x00, 0x0a},
						},
					},
				}},
				EntryDesc: &fwdpb.EntryDesc{
					Entry: &fwdpb.EntryDesc_Prefix{
						Prefix: &fwdpb.PrefixEntryDesc{
							Fields: []*fwdpb.PacketFieldMaskedBytes{{
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF},
								},
								Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
								Masks: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
							}, {
								FieldId: &fwdpb.PacketFieldId{
									Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST},
								},
								Bytes: []byte{0x7f, 0x00, 0x00, 0x01},
								Masks: []byte{0xff, 0xff, 0xff, 0xff},
							}},
						},
					},
				},
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestRoute(t, dplane)
			defer stopFn()
			for k, v := range tt.types {
				mgr.SetType(k, v)
			}
			mgr.StoreAttributes(1, &saipb.SwitchAttribute{
				CpuPort: proto.Uint64(10),
			})
			_, gotErr := c.CreateRouteEntry(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateRouteEntry() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(dplane.gotEntryAddReqs[0], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("CreateRouteEntry() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestRemoveRouteEntry(t *testing.T) {
	tests := []struct {
		desc      string
		types     map[string]saipb.ObjectType
		reqCreate *saipb.CreateRouteEntryRequest
		reqRemove *saipb.RemoveRouteEntryRequest
		wantReq   *fwdpb.TableEntryRemoveRequest
		wantErr   string
	}{{
		desc:      "missing entry",
		reqRemove: &saipb.RemoveRouteEntryRequest{},
		wantErr:   "InvalidArgument",
	}, {
		desc:  "standard IPv4 FIB route",
		types: map[string]saipb.ObjectType{"100": saipb.ObjectType_OBJECT_TYPE_PORT},
		reqCreate: &saipb.CreateRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 0},
					Mask: []byte{255, 255, 255, 0},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(100),
		},
		reqRemove: &saipb.RemoveRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 0},
					Mask: []byte{255, 255, 255, 0},
				},
			},
		},
		wantReq: &fwdpb.TableEntryRemoveRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: FIBV4Table}},
			EntryDesc: fwdconfig.EntryDesc(
				fwdconfig.PrefixEntry(
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(0),
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
						[]byte{10, 0, 0, 0},
						[]byte{255, 255, 255, 0},
					),
				),
			).Build(),
		},
	}, {
		desc:  "standard IPv6 FIB route",
		types: map[string]saipb.ObjectType{"100": saipb.ObjectType_OBJECT_TYPE_PORT},
		reqCreate: &saipb.CreateRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Mask: []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(100),
		},
		reqRemove: &saipb.RemoveRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Mask: []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
		},
		wantReq: &fwdpb.TableEntryRemoveRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: FIBV6Table}},
			EntryDesc: fwdconfig.EntryDesc(
				fwdconfig.PrefixEntry(
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(0),
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
						[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
						[]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					),
				),
			).Build(),
		},
	}, {
		desc:  "CPU-port trap route",
		types: map[string]saipb.ObjectType{"10": saipb.ObjectType_OBJECT_TYPE_PORT},
		reqCreate: &saipb.CreateRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 1},
					Mask: []byte{255, 255, 255, 255},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(10),
		},
		reqRemove: &saipb.RemoveRouteEntryRequest{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 1},
					Mask: []byte{255, 255, 255, 255},
				},
			},
		},
		wantReq: &fwdpb.TableEntryRemoveRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: trapTableID}},
			EntryDesc: fwdconfig.EntryDesc(fwdconfig.FlowEntry(
				fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
					[]byte{10, 0, 0, 1},
					[]byte{255, 255, 255, 255},
				),
				fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(0),
			)).Build(),
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestRoute(t, dplane)
			defer stopFn()
			for k, v := range tt.types {
				mgr.SetType(k, v)
			}
			mgr.StoreAttributes(1, &saipb.SwitchAttribute{
				CpuPort: proto.Uint64(10),
			})
			if tt.reqCreate != nil {
				if _, err := c.CreateRouteEntry(context.TODO(), tt.reqCreate); err != nil {
					t.Fatalf("CreateRouteEntry() unexpected err: %v", err)
				}
			}
			_, gotErr := c.RemoveRouteEntry(context.TODO(), tt.reqRemove)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("RemoveRouteEntry() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(dplane.gotEntryRemoveReqs[0], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("RemoveRouteEntry() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestRemoveRouteEntries(t *testing.T) {
	tests := []struct {
		desc       string
		types      map[string]saipb.ObjectType
		createReqs []*saipb.CreateRouteEntryRequest
		removeReqs []*saipb.RemoveRouteEntryRequest
		wantReqs   []*fwdpb.TableEntryRemoveRequest
		wantErr    string
	}{{
		desc: "success bulk remove",
		types: map[string]saipb.ObjectType{
			"10":  saipb.ObjectType_OBJECT_TYPE_PORT,
			"100": saipb.ObjectType_OBJECT_TYPE_PORT,
		},
		createReqs: []*saipb.CreateRouteEntryRequest{{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 0},
					Mask: []byte{255, 255, 255, 0},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(100),
		}, {
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Mask: []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(100),
		}, {
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 1},
					Mask: []byte{255, 255, 255, 255},
				},
			},
			PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
			NextHopId:    proto.Uint64(10),
		}},
		removeReqs: []*saipb.RemoveRouteEntryRequest{{
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 0},
					Mask: []byte{255, 255, 255, 0},
				},
			},
		}, {
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Mask: []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
		}, {
			Entry: &saipb.RouteEntry{
				SwitchId: 1,
				VrId:     0,
				Destination: &saipb.IpPrefix{
					Addr: []byte{10, 0, 0, 1},
					Mask: []byte{255, 255, 255, 255},
				},
			},
		}},
		wantReqs: []*fwdpb.TableEntryRemoveRequest{{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: FIBV4Table}},
			EntryDesc: fwdconfig.EntryDesc(
				fwdconfig.PrefixEntry(
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(0),
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
						[]byte{10, 0, 0, 0},
						[]byte{255, 255, 255, 0},
					),
				),
			).Build(),
		}, {
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: FIBV6Table}},
			EntryDesc: fwdconfig.EntryDesc(
				fwdconfig.PrefixEntry(
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(0),
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
						[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
						[]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					),
				),
			).Build(),
		}, {
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: trapTableID}},
			EntryDesc: fwdconfig.EntryDesc(fwdconfig.FlowEntry(
				fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
					[]byte{10, 0, 0, 1},
					[]byte{255, 255, 255, 255},
				),
				fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(0),
			)).Build(),
		}},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, mgr, stopFn := newTestRoute(t, dplane)
			defer stopFn()
			for k, v := range tt.types {
				mgr.SetType(k, v)
			}
			mgr.StoreAttributes(1, &saipb.SwitchAttribute{
				CpuPort: proto.Uint64(10),
			})
			for _, req := range tt.createReqs {
				if _, err := c.CreateRouteEntry(context.TODO(), req); err != nil {
					t.Fatalf("CreateRouteEntry() unexpected err: %v", err)
				}
			}
			resp, gotErr := c.RemoveRouteEntries(context.TODO(), &saipb.RemoveRouteEntriesRequest{
				Reqs: tt.removeReqs,
			})
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("RemoveRouteEntries() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if len(resp.GetResps()) != len(tt.removeReqs) {
				t.Fatalf("RemoveRouteEntries() unexpected num responses: got %d, want %d", len(resp.GetResps()), len(tt.removeReqs))
			}
			if d := cmp.Diff(dplane.gotEntryRemoveReqs, tt.wantReqs, protocmp.Transform()); d != "" {
				t.Errorf("RemoveRouteEntries() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestCreateRouterInterface(t *testing.T) {
	tests := []struct {
		desc    string
		req     *saipb.CreateRouterInterfaceRequest
		wantReq *fwdpb.TableEntryAddRequest
		wantErr string
	}{{
		desc:    "unknown type",
		req:     &saipb.CreateRouterInterfaceRequest{},
		wantErr: "InvalidArgument",
	}, {
		desc: "success port - port",
		req: &saipb.CreateRouterInterfaceRequest{
			PortId: proto.Uint64(10),
			Type:   saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: inputIfaceTable}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Exact{
					Exact: &fwdpb.ExactEntryDesc{
						Fields: []*fwdpb.PacketFieldBytes{{
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT,
							}},
							Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						}, {
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG,
							}},
							Bytes: binary.BigEndian.AppendUint16(nil, 0),
						}},
					},
				}},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE,
							}},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_FLOW_COUNTER,
					Action: &fwdpb.ActionDesc_Flow{
						Flow: &fwdpb.FlowCounterActionDesc{
							CounterId: &fwdpb.FlowCounterId{
								ObjectId: &fwdpb.ObjectId{Id: "1-in-counter"},
							},
						},
					},
				}},
			}},
		},
	}, {
		desc: "success port - subport",
		req: &saipb.CreateRouterInterfaceRequest{
			PortId:      proto.Uint64(10),
			Type:        saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_SUB_PORT.Enum(),
			OuterVlanId: proto.Uint32(100),
		},
		wantReq: &fwdpb.TableEntryAddRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: inputIfaceTable}},
			Entries: []*fwdpb.TableEntryAddRequest_Entry{{
				EntryDesc: &fwdpb.EntryDesc{Entry: &fwdpb.EntryDesc_Exact{
					Exact: &fwdpb.ExactEntryDesc{
						Fields: []*fwdpb.PacketFieldBytes{{
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT,
							}},
							Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						}, {
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG,
							}},
							Bytes: binary.BigEndian.AppendUint16(nil, 100),
						}},
					},
				}},
				Actions: []*fwdpb.ActionDesc{{
					ActionType: fwdpb.ActionType_ACTION_TYPE_UPDATE,
					Action: &fwdpb.ActionDesc_Update{
						Update: &fwdpb.UpdateActionDesc{
							Type: fwdpb.UpdateType_UPDATE_TYPE_SET,
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE,
							}},
							Field: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{}},
							Value: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_FLOW_COUNTER,
					Action: &fwdpb.ActionDesc_Flow{
						Flow: &fwdpb.FlowCounterActionDesc{
							CounterId: &fwdpb.FlowCounterId{
								ObjectId: &fwdpb.ObjectId{Id: "1-in-counter"},
							},
						},
					},
				}, {
					ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
					Action: &fwdpb.ActionDesc_Decap{
						Decap: &fwdpb.DecapActionDesc{
							HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN,
						},
					},
				}},
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{
				ctx: fwdcontext.New("foo", "foo"),
			}
			if err := dplane.ctx.Objects.Insert(&fwdobject.Base{}, &fwdpb.ObjectId{Id: "10"}); err != nil {
		t.Fatalf("Objects.Insert failed: %v", err)
	}
			c, _, stopFn := newTestRouterInterface(t, dplane)
			defer stopFn()
			_, gotErr := c.CreateRouterInterface(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateRouterInterface() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(dplane.gotEntryAddReqs[0], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("CreateRouterInterface() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestRemoveRouterInterface(t *testing.T) {
	tests := []struct {
		desc    string
		req     *saipb.RemoveRouterInterfaceRequest
		wantReq *fwdpb.TableEntryRemoveRequest
		wantErr string
	}{{
		desc:    "unknown type",
		req:     &saipb.RemoveRouterInterfaceRequest{},
		wantErr: "attribute not set",
	}, {
		desc: "success port - port",
		req: &saipb.RemoveRouterInterfaceRequest{
			Oid: 10,
		},
		wantReq: &fwdpb.TableEntryRemoveRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: inputIfaceTable}},
			Entries: []*fwdpb.EntryDesc{{
				Entry: &fwdpb.EntryDesc_Exact{
					Exact: &fwdpb.ExactEntryDesc{
						Fields: []*fwdpb.PacketFieldBytes{{
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT,
							}},
							Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
						}, {
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG,
							}},
							Bytes: binary.BigEndian.AppendUint16(nil, 0),
						}},
					},
				},
			}},
		},
	}, {
		desc: "success port - subport",
		req: &saipb.RemoveRouterInterfaceRequest{
			Oid: 11,
		},
		wantReq: &fwdpb.TableEntryRemoveRequest{
			ContextId: &fwdpb.ContextId{Id: "foo"},
			TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: inputIfaceTable}},
			Entries: []*fwdpb.EntryDesc{{
				Entry: &fwdpb.EntryDesc_Exact{
					Exact: &fwdpb.ExactEntryDesc{
						Fields: []*fwdpb.PacketFieldBytes{{
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT,
							}},
							Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
						}, {
							FieldId: &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{
								FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG,
							}},
							Bytes: binary.BigEndian.AppendUint16(nil, 100),
						}},
					},
				},
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{
				ctx: fwdcontext.New("foo", "foo"),
			}
			c, mgr, stopFn := newTestRouterInterface(t, dplane)
			mgr.StoreAttributes(10, &saipb.RouterInterfaceAttribute{
				Type:   saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
				PortId: proto.Uint64(5),
			})
			mgr.StoreAttributes(11, &saipb.RouterInterfaceAttribute{
				Type:        saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_SUB_PORT.Enum(),
				OuterVlanId: proto.Uint32(100),
				PortId:      proto.Uint64(5),
			})
			defer stopFn()
			_, gotErr := c.RemoveRouterInterface(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateRouterInterface() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
			if d := cmp.Diff(dplane.gotEntryRemoveReqs[0], tt.wantReq, protocmp.Transform()); d != "" {
				t.Errorf("CreateRouterInterface() failed: diff(-got,+want)\n:%s", d)
			}
		})
	}
}

func TestCreateHash(t *testing.T) {
	tests := []struct {
		desc    string
		req     *saipb.CreateHashRequest
		wantErr string
	}{{
		desc: "unknown type",
		req: &saipb.CreateHashRequest{
			NativeHashFieldList: []saipb.NativeHashField{saipb.NativeHashField_NATIVE_HASH_FIELD_UNSPECIFIED},
		},
		wantErr: "InvalidArgument",
	}, {
		desc: "success",
		req: &saipb.CreateHashRequest{
			NativeHashFieldList: []saipb.NativeHashField{
				saipb.NativeHashField_NATIVE_HASH_FIELD_SRC_IP,
				saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IP,
				saipb.NativeHashField_NATIVE_HASH_FIELD_L4_SRC_PORT,
				saipb.NativeHashField_NATIVE_HASH_FIELD_L4_DST_PORT,
				saipb.NativeHashField_NATIVE_HASH_FIELD_IPV6_FLOW_LABEL,
			},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dplane := &fakeSwitchDataplane{}
			c, _, stopFn := newTestHash(t, dplane)
			defer stopFn()
			_, gotErr := c.CreateHash(context.TODO(), tt.req)
			if diff := errdiff.Check(gotErr, tt.wantErr); diff != "" {
				t.Fatalf("CreateHash() unexpected err: %s", diff)
			}
			if gotErr != nil {
				return
			}
		})
	}
}

func newTestNeighbor(t testing.TB, api switchDataplaneAPI) (saipb.NeighborClient, *attrmgr.AttrMgr, func()) {
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		newNeighbor(mgr, api, srv)
	})
	return saipb.NewNeighborClient(conn), mgr, stopFn
}

func newTestNextHopGroup(t testing.TB, api switchDataplaneAPI) (saipb.NextHopGroupClient, *attrmgr.AttrMgr, func()) {
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		newNextHopGroup(mgr, api, srv)
	})
	return saipb.NewNextHopGroupClient(conn), mgr, stopFn
}

func newTestNextHop(t testing.TB, api switchDataplaneAPI) (saipb.NextHopClient, *attrmgr.AttrMgr, func()) {
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		newNextHop(mgr, api, srv)
	})
	return saipb.NewNextHopClient(conn), mgr, stopFn
}

func newTestRoute(t testing.TB, api switchDataplaneAPI) (saipb.RouteClient, *attrmgr.AttrMgr, func()) {
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		newRoute(mgr, api, srv)
	})
	return saipb.NewRouteClient(conn), mgr, stopFn
}

func newTestRouterInterface(t testing.TB, api switchDataplaneAPI) (saipb.RouterInterfaceClient, *attrmgr.AttrMgr, func()) {
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		newRouterInterface(mgr, api, srv, nil, nil)
	})
	return saipb.NewRouterInterfaceClient(conn), mgr, stopFn
}

func newTestHash(t testing.TB, api switchDataplaneAPI) (saipb.HashClient, *attrmgr.AttrMgr, func()) {
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		newHash(mgr, api, srv)
	})
	return saipb.NewHashClient(conn), mgr, stopFn
}

func TestLoopbackRouterInterfaceAndMyMacRefCount(t *testing.T) {
	dplane := &fakeSwitchDataplane{
		ctx: fwdcontext.New("foo", "foo"),
	}
	if err := dplane.ctx.Objects.Insert(&fwdobject.Base{}, &fwdpb.ObjectId{Id: "10"}); err != nil {
		t.Fatalf("Objects.Insert failed: %v", err)
	}

	var swCli saipb.SwitchClient
	var vrCli saipb.VirtualRouterClient
	var riCli saipb.RouterInterfaceClient
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		sw, err := newSwitch(mgr, dplane, srv, &dplaneopts.Options{})
		if err != nil {
			t.Fatalf("newSwitch failed: %v", err)
		}
		_ = sw
	})
	defer stopFn()
	swCli = saipb.NewSwitchClient(conn)
	vrCli = saipb.NewVirtualRouterClient(conn)
	riCli = saipb.NewRouterInterfaceClient(conn)

	ctx := context.Background()
	macA := []byte{0x02, 0x00, 0x11, 0x22, 0x33, 0x44}
	macB := []byte{0x02, 0x00, 0x55, 0x66, 0x77, 0x88}

	swResp, err := swCli.CreateSwitch(ctx, &saipb.CreateSwitchRequest{SrcMacAddress: macA})
	if err != nil {
		t.Fatalf("CreateSwitch failed: %v", err)
	}
	countMyMacAdds := func(mac []byte) int {
		cnt := 0
		for _, r := range dplane.gotEntryAddReqs {
			if r.GetTableId().GetObjectId().GetId() == MyMacTable {
				fields := r.GetEntryDesc().GetFlow().GetFields()
				if len(fields) > 0 && cmp.Equal(fields[0].GetBytes(), mac) {
					cnt++
				}
			}
		}
		return cnt
	}
	countMyMacRemoves := func(mac []byte) int {
		cnt := 0
		for _, r := range dplane.gotEntryRemoveReqs {
			if r.GetTableId().GetObjectId().GetId() == MyMacTable {
				fields := r.GetEntryDesc().GetFlow().GetFields()
				if len(fields) > 0 && cmp.Equal(fields[0].GetBytes(), mac) {
					cnt++
				}
			}
		}
		return cnt
	}

	if got := countMyMacAdds(macA); got != 1 {
		t.Fatalf("after CreateSwitch(macA): got %d MyMacTable adds, want 1", got)
	}

	// Create VR with same macA -> ref count 2, no second TableEntryAdd.
	vrResp, err := vrCli.CreateVirtualRouter(ctx, &saipb.CreateVirtualRouterRequest{
		Switch:        swResp.Oid,
		SrcMacAddress: macA,
	})
	if err != nil {
		t.Fatalf("CreateVirtualRouter failed: %v", err)
	}
	if got := countMyMacAdds(macA); got != 1 {
		t.Fatalf("after CreateVirtualRouter(macA): got %d MyMacTable adds, want 1", got)
	}

	// Create loopback RIF with same macA -> ref count 3, no ObjectNID call.
	nidBefore := len(dplane.gotObjectNIDReqs)
	loResp, err := riCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch:          swResp.Oid,
		VirtualRouterId: proto.Uint64(vrResp.Oid),
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_LOOPBACK.Enum(),
		SrcMacAddress:   macA,
	})
	if err != nil {
		t.Fatalf("CreateRouterInterface(LOOPBACK) failed: %v", err)
	}
	if got := len(dplane.gotObjectNIDReqs); got != nidBefore {
		t.Fatalf("CreateRouterInterface(LOOPBACK) made unexpected ObjectNID calls: %d", got-nidBefore)
	}

	// Create port RIF with macA -> ref count 4.
	portRifResp, err := riCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch:          swResp.Oid,
		VirtualRouterId: proto.Uint64(vrResp.Oid),
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
		PortId:          proto.Uint64(10),
		SrcMacAddress:   macA,
	})
	if err != nil {
		t.Fatalf("CreateRouterInterface(PORT) failed: %v", err)
	}

	// SetRouterInterfaceAttribute on port RIF from macA -> macB:
	// macA still has refs (3), so not removed; macB transitions 0->1 -> added!
	if _, err := riCli.SetRouterInterfaceAttribute(ctx, &saipb.SetRouterInterfaceAttributeRequest{
		Oid:           portRifResp.Oid,
		SrcMacAddress: macB,
	}); err != nil {
		t.Fatalf("SetRouterInterfaceAttribute failed: %v", err)
	}
	if got := countMyMacAdds(macB); got != 1 {
		t.Fatalf("after SetRouterInterfaceAttribute(macB): got %d adds for macB, want 1", got)
	}
	if got := countMyMacRemoves(macA); got != 0 {
		t.Fatalf("after SetRouterInterfaceAttribute(macB): macA prematurely removed (%d)", got)
	}
	// Verify SRCMACTable updated for port RIF.
	var lastSrcMac []byte
	for _, r := range dplane.gotEntryAddReqs {
		if r.GetTableId().GetObjectId().GetId() == SRCMACTable {
			lastSrcMac = r.GetEntries()[0].GetActions()[0].GetUpdate().GetValue()
		}
	}
	if !cmp.Equal(lastSrcMac, macB) {
		t.Fatalf("SRCMACTable not updated to macB: got %x, want %x", lastSrcMac, macB)
	}
	// Verify persisted attribute in mgr.
	riAttr := &saipb.RouterInterfaceAttribute{}
	if err := mgr.PopulateAllAttributes(fmt.Sprint(portRifResp.Oid), riAttr); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(riAttr.GetSrcMacAddress(), macB) {
		t.Fatalf("persisted RIF SrcMacAddress = %x, want %x", riAttr.GetSrcMacAddress(), macB)
	}

	// Remove port RIF -> macB transitions 1->0 -> removed!
	if _, err := riCli.RemoveRouterInterface(ctx, &saipb.RemoveRouterInterfaceRequest{Oid: portRifResp.Oid}); err != nil {
		t.Fatalf("RemoveRouterInterface(PORT) failed: %v", err)
	}
	if got := countMyMacRemoves(macB); got != 1 {
		t.Fatalf("after RemoveRouterInterface(PORT): got %d removes for macB, want 1", got)
	}

	// Remove loopback RIF -> no ObjectNID call on PortId=0, ref count 3->2, macA NOT removed.
	nidBefore = len(dplane.gotObjectNIDReqs)
	if _, err := riCli.RemoveRouterInterface(ctx, &saipb.RemoveRouterInterfaceRequest{Oid: loResp.Oid}); err != nil {
		t.Fatalf("RemoveRouterInterface(LOOPBACK) failed: %v", err)
	}
	if got := len(dplane.gotObjectNIDReqs); got != nidBefore {
		t.Fatalf("RemoveRouterInterface(LOOPBACK) made unexpected ObjectNID calls")
	}
	if got := countMyMacRemoves(macA); got != 0 {
		t.Fatalf("macA prematurely removed after loopback RIF removal")
	}

	// SetSwitchAttribute to macB and RemoveVirtualRouter -> macA transitions 2->1->0 -> removed!
	if _, err := swCli.SetSwitchAttribute(ctx, &saipb.SetSwitchAttributeRequest{
		Oid:           swResp.Oid,
		SrcMacAddress: macB,
	}); err != nil {
		t.Fatalf("SetSwitchAttribute failed: %v", err)
	}
	if got := countMyMacRemoves(macA); got != 0 {
		t.Fatalf("macA prematurely removed while VR still holds it")
	}
	if _, err := vrCli.RemoveVirtualRouter(ctx, &saipb.RemoveVirtualRouterRequest{Oid: vrResp.Oid}); err != nil {
		t.Fatalf("RemoveVirtualRouter failed: %v", err)
	}
	if got := countMyMacRemoves(macA); got != 1 {
		t.Fatalf("after RemoveVirtualRouter: got %d removes for macA, want 1", got)
	}

	// I-2: Set*Attribute on removed/missing OIDs must return NotFound and NOT leak MyMac refs.
	addsBefore := len(dplane.gotEntryAddReqs)
	if _, err := riCli.SetRouterInterfaceAttribute(ctx, &saipb.SetRouterInterfaceAttributeRequest{
		Oid:           loResp.Oid,
		SrcMacAddress: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x99},
	}); errdiff.Check(err, "NotFound") != "" {
		t.Fatalf("SetRouterInterfaceAttribute(removed) got err %v, want NotFound", err)
	}
	if _, err := vrCli.SetVirtualRouterAttribute(ctx, &saipb.SetVirtualRouterAttributeRequest{
		Oid:           vrResp.Oid,
		SrcMacAddress: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x99},
	}); errdiff.Check(err, "NotFound") != "" {
		t.Fatalf("SetVirtualRouterAttribute(removed) got err %v, want NotFound", err)
	}
	if _, err := swCli.SetSwitchAttribute(ctx, &saipb.SetSwitchAttributeRequest{
		Oid:           99999,
		SrcMacAddress: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x99},
	}); errdiff.Check(err, "NotFound") != "" {
		t.Fatalf("SetSwitchAttribute(missing) got err %v, want NotFound", err)
	}
	if len(dplane.gotEntryAddReqs) != addsBefore {
		t.Fatalf("dead OID Set*Attribute mutated dataplane entries: got %d adds, want 0", len(dplane.gotEntryAddReqs)-addsBefore)
	}

	// I-3: Failed RemoveRouterInterface must NOT release MyMac prematurely.
	if err := dplane.ctx.Objects.Insert(&fwdobject.Base{}, &fwdpb.ObjectId{Id: "11"}); err != nil {
		t.Fatalf("Objects.Insert(11) failed: %v", err)
	}
	macC := []byte{0x02, 0x00, 0x99, 0xaa, 0xbb, 0xcc}
	vrC, err := vrCli.CreateVirtualRouter(ctx, &saipb.CreateVirtualRouterRequest{Switch: swResp.Oid, SrcMacAddress: macC})
	if err != nil {
		t.Fatalf("CreateVirtualRouter(macC) failed: %v", err)
	}
	portRif, err := riCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch:          swResp.Oid,
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
		PortId:          proto.Uint64(11),
		VirtualRouterId: proto.Uint64(vrC.Oid),
		SrcMacAddress:   macC,
	})
	if err != nil {
		t.Fatalf("CreateRouterInterface(port) failed: %v", err)
	}
	// Simulate ObjectNID failure on RemoveRouterInterface: macC must NOT be released prematurely.
	dplane.objectNIDErr = fmt.Errorf("injected ObjectNID error")
	removesBefore := countMyMacRemoves(macC)
	if _, err := riCli.RemoveRouterInterface(ctx, &saipb.RemoveRouterInterfaceRequest{Oid: portRif.Oid}); err == nil {
		t.Fatalf("expected RemoveRouterInterface to fail on injected ObjectNID error")
	}
	if got := countMyMacRemoves(macC); got != removesBefore {
		t.Fatalf("failed RemoveRouterInterface released macC prematurely: got %d, want %d", got, removesBefore)
	}
	// Clear error and retry RemoveRouterInterface: macC must still be held by vrC until vrC is removed.
	dplane.objectNIDErr = nil
	if _, err := riCli.RemoveRouterInterface(ctx, &saipb.RemoveRouterInterfaceRequest{Oid: portRif.Oid}); err != nil {
		t.Fatalf("retry RemoveRouterInterface failed: %v", err)
	}
	if got := countMyMacRemoves(macC); got != removesBefore {
		t.Fatalf("macC still held by vrC, expected 0 new removes, got %d", got-removesBefore)
	}
	if _, err := vrCli.RemoveVirtualRouter(ctx, &saipb.RemoveVirtualRouterRequest{Oid: vrC.Oid}); err != nil {
		t.Fatalf("RemoveVirtualRouter(vrC) failed: %v", err)
	}
	if got := countMyMacRemoves(macC); got != removesBefore+1 {
		t.Fatalf("expected macC final release after vrC removed, got %d removes", got)
	}
}

func TestVlanRouterInterfaceAndFdb(t *testing.T) {
	dplane := &fakeSwitchDataplane{
		ctx: fwdcontext.New("foo", "foo"),
	}
	var vlanCli saipb.VlanClient
	var brCli saipb.BridgeClient
	var riCli saipb.RouterInterfaceClient
	var fdbCli saipb.FdbClient
	conn, mgr, stopFn := newTestServer(t, func(mgr *attrmgr.AttrMgr, srv *grpc.Server) {
		sw, err := newSwitch(mgr, dplane, srv, &dplaneopts.Options{})
		if err != nil {
			t.Fatalf("newSwitch failed: %v", err)
		}
		if _, err := newFdb(mgr, dplane, srv, sw.vlan); err != nil {
			t.Fatalf("newFdb failed: %v", err)
		}
	})
	defer stopFn()
	vlanCli = saipb.NewVlanClient(conn)
	brCli = saipb.NewBridgeClient(conn)
	riCli = saipb.NewRouterInterfaceClient(conn)
	fdbCli = saipb.NewFdbClient(conn)

	ctx := context.Background()
	mgr.StoreAttributes(1, &saipb.SwitchAttribute{DefaultStpInstId: proto.Uint64(99)})

	bp1, err := brCli.CreateBridgePort(ctx, &saipb.CreateBridgePortRequest{PortId: proto.Uint64(11)})
	if err != nil {
		t.Fatal(err)
	}
	bp2, err := brCli.CreateBridgePort(ctx, &saipb.CreateBridgePortRequest{PortId: proto.Uint64(12)})
	if err != nil {
		t.Fatal(err)
	}

	vlanResp, err := vlanCli.CreateVlan(ctx, &saipb.CreateVlanRequest{Switch: 1, VlanId: proto.Uint32(100)})
	if err != nil {
		t.Fatal(err)
	}

	// Case 1: CreateVlanMember (untagged) BEFORE CreateRouterInterface(VLAN).
	if _, err := vlanCli.CreateVlanMember(ctx, &saipb.CreateVlanMemberRequest{
		Switch:          1,
		VlanId:          proto.Uint64(vlanResp.Oid),
		BridgePortId:    proto.Uint64(bp1.Oid),
		VlanTaggingMode: saipb.VlanTaggingMode_VLAN_TAGGING_MODE_UNTAGGED.Enum(),
	}); err != nil {
		t.Fatal(err)
	}

	smac := []byte{0x02, 0x00, 0xaa, 0xbb, 0xcc, 0x01}
	rifResp, err := riCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch:          1,
		VirtualRouterId: proto.Uint64(5),
		Type:            saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_VLAN.Enum(),
		VlanId:          proto.Uint64(vlanResp.Oid),
		SrcMacAddress:   smac,
	})
	if err != nil {
		t.Fatalf("CreateRouterInterface(VLAN) failed: %v", err)
	}

	// Case 2: CreateVlanMember (tagged) AFTER CreateRouterInterface(VLAN).
	m2Resp, err := vlanCli.CreateVlanMember(ctx, &saipb.CreateVlanMemberRequest{
		Switch:          1,
		VlanId:          proto.Uint64(vlanResp.Oid),
		BridgePortId:    proto.Uint64(bp2.Oid),
		VlanTaggingMode: saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED.Enum(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify inputIfaceTable received entries for port 11 (tag 0) and port 12 (tag 100),
	// and egressVlanTable received entry for (vid=100, port=12).
	var gotPort11Tag0, gotPort12Tag100, gotEgressTag12 bool
	for _, r := range dplane.gotEntryAddReqs {
		switch r.GetTableId().GetObjectId().GetId() {
		case inputIfaceTable:
			fields := r.GetEntries()[0].GetEntryDesc().GetExact().GetFields()
			portNID := binary.BigEndian.Uint64(fields[0].GetBytes())
			vlanTag := binary.BigEndian.Uint16(fields[1].GetBytes())
			if portNID == 11 && vlanTag == 0 {
				gotPort11Tag0 = true
			}
			if portNID == 12 && vlanTag == 100 {
				gotPort12Tag100 = true
			}
		case egressVlanTable:
			fields := r.GetEntries()[0].GetEntryDesc().GetExact().GetFields()
			vid := binary.BigEndian.Uint16(fields[0].GetBytes())
			portID := binary.BigEndian.Uint64(fields[1].GetBytes())
			if vid == 100 && portID == 12 {
				gotEgressTag12 = true
			}
		}
	}
	if !gotPort11Tag0 || !gotPort12Tag100 || !gotEgressTag12 {
		t.Fatalf("missing VLAN RIF table entries: port11Tag0=%v port12Tag100=%v egressTag12=%v", gotPort11Tag0, gotPort12Tag100, gotEgressTag12)
	}

	// Program FDB entry pointing MAC to bp2 (port 12) and verify fdbTable add/remove.
	dstMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}
	if _, err := fdbCli.CreateFdbEntry(ctx, &saipb.CreateFdbEntryRequest{
		Entry: &saipb.FdbEntry{
			SwitchId:   1,
			MacAddress: dstMAC,
			BvId:       vlanResp.Oid,
		},
		Type:         saipb.FdbEntryType_FDB_ENTRY_TYPE_STATIC.Enum(),
		PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
		BridgePortId: proto.Uint64(bp2.Oid),
	}); err != nil {
		t.Fatalf("CreateFdbEntry failed: %v", err)
	}
	var gotFdbAdd bool
	for _, r := range dplane.gotEntryAddReqs {
		if r.GetTableId().GetObjectId().GetId() == fdbTable {
			gotFdbAdd = true
		}
	}
	if !gotFdbAdd {
		t.Fatalf("expected fdbTable entry add")
	}

	// I-7: Trunk port bp2 can belong to multiple TAGGED VLANs simultaneously.
	vlan200Resp, err := vlanCli.CreateVlan(ctx, &saipb.CreateVlanRequest{Switch: 1, VlanId: proto.Uint32(200)})
	if err != nil {
		t.Fatal(err)
	}
	m2Vlan200Resp, err := vlanCli.CreateVlanMember(ctx, &saipb.CreateVlanMemberRequest{
		Switch:          1,
		VlanId:          proto.Uint64(vlan200Resp.Oid),
		BridgePortId:    proto.Uint64(bp2.Oid),
		VlanTaggingMode: saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED.Enum(),
	})
	if err != nil {
		t.Fatalf("CreateVlanMember(tagged bp2 on vlan 200) failed: %v", err)
	}
	v100Attr := &saipb.VlanAttribute{}
	if err := mgr.PopulateAllAttributes(fmt.Sprint(vlanResp.Oid), v100Attr); err != nil {
		t.Fatal(err)
	}
	if len(v100Attr.GetMemberList()) != 2 {
		t.Fatalf("VLAN 100 lost member when bp2 added as TAGGED to VLAN 200: got %v", v100Attr.GetMemberList())
	}
	if _, err := vlanCli.RemoveVlanMember(ctx, &saipb.RemoveVlanMemberRequest{Oid: m2Vlan200Resp.Oid}); err != nil {
		t.Fatalf("RemoveVlanMember(m2Vlan200) failed: %v", err)
	}

	// I-8 + M-8: FDB flush defaults to DYNAMIC (preserves STATIC), SetFdbEntryAttribute NotFound, Flush invalid BvId error.
	dynMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0xaa}
	if _, err := fdbCli.CreateFdbEntry(ctx, &saipb.CreateFdbEntryRequest{
		Entry: &saipb.FdbEntry{
			SwitchId:   1,
			MacAddress: dynMAC,
			BvId:       vlanResp.Oid,
		},
		Type:         saipb.FdbEntryType_FDB_ENTRY_TYPE_DYNAMIC.Enum(),
		PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
		BridgePortId: proto.Uint64(bp2.Oid),
	}); err != nil {
		t.Fatalf("CreateFdbEntry(dynamic) failed: %v", err)
	}
	if _, err := fdbCli.FlushFdbEntries(ctx, &saipb.FlushFdbEntriesRequest{
		Switch: 1,
		BvId:   proto.Uint64(vlanResp.Oid),
	}); err != nil {
		t.Fatalf("FlushFdbEntries(default nil EntryType) failed: %v", err)
	}
	if _, err := fdbCli.SetFdbEntryAttribute(ctx, &saipb.SetFdbEntryAttributeRequest{
		Entry:        &saipb.FdbEntry{SwitchId: 1, MacAddress: dynMAC, BvId: vlanResp.Oid},
		PacketAction: saipb.PacketAction_PACKET_ACTION_DROP.Enum(),
	}); errdiff.Check(err, "NotFound") != "" {
		t.Fatalf("SetFdbEntryAttribute(flushed dynamic) got err %v, want NotFound", err)
	}
	// Static dstMAC must still exist after default (dynamic-only) flush.
	if _, err := fdbCli.SetFdbEntryAttribute(ctx, &saipb.SetFdbEntryAttributeRequest{
		Entry:        &saipb.FdbEntry{SwitchId: 1, MacAddress: dstMAC, BvId: vlanResp.Oid},
		PacketAction: saipb.PacketAction_PACKET_ACTION_DROP.Enum(),
	}); err != nil {
		t.Fatalf("static FDB entry was unexpectedly flushed by default FlushFdbEntries: %v", err)
	}
	if _, err := fdbCli.FlushFdbEntries(ctx, &saipb.FlushFdbEntriesRequest{
		Switch: 1,
		BvId:   proto.Uint64(99999),
	}); errdiff.Check(err, "NotFound") != "" {
		t.Fatalf("FlushFdbEntries(invalid BvId) got err %v, want NotFound", err)
	}

	if _, err := fdbCli.RemoveFdbEntry(ctx, &saipb.RemoveFdbEntryRequest{
		Entry: &saipb.FdbEntry{
			SwitchId:   1,
			MacAddress: dstMAC,
			BvId:       vlanResp.Oid,
		},
	}); err != nil {
		t.Fatalf("RemoveFdbEntry failed: %v", err)
	}

	// Remove tagged member, then remove VLAN RIF and check clean teardown.
	if _, err := vlanCli.RemoveVlanMember(ctx, &saipb.RemoveVlanMemberRequest{Oid: m2Resp.Oid}); err != nil {
		t.Fatalf("RemoveVlanMember failed: %v", err)
	}
	if _, err := riCli.RemoveRouterInterface(ctx, &saipb.RemoveRouterInterfaceRequest{Oid: rifResp.Oid}); err != nil {
		t.Fatalf("RemoveRouterInterface(VLAN) failed: %v", err)
	}
	removedTables := map[string]bool{}
	for _, r := range dplane.gotEntryRemoveReqs {
		removedTables[r.GetTableId().GetObjectId().GetId()] = true
	}
	for _, tbl := range []string{inputIfaceTable, outputIfaceTable, IngressVRFTable, SRCMACTable, MyMacTable, egressVlanTable, vlanFloodTable, fdbTable} {
		if !removedTables[tbl] {
			t.Errorf("expected removal in table %s", tbl)
		}
	}
}

// I-6: Verify routed traffic to a VLAN RIF with no FDB hit floods across all VLAN members
// (reaching members[1] even when tagged), and installing an FDB entry stops flooding to members[0].
func TestVlanFloodingAndFdbPacket(t *testing.T) {
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

	swCli := saipb.NewSwitchClient(conn)
	portCli := saipb.NewPortClient(conn)
	brCli := saipb.NewBridgeClient(conn)
	vlanCli := saipb.NewVlanClient(conn)
	riCli := saipb.NewRouterInterfaceClient(conn)
	nhCli := saipb.NewNextHopClient(conn)
	routeCli := saipb.NewRouteClient(conn)
	neighCli := saipb.NewNeighborClient(conn)
	fdbCli := saipb.NewFdbClient(conn)

	swResp, err := swCli.CreateSwitch(ctx, &saipb.CreateSwitchRequest{InitSwitch: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	swAttr, err := swCli.GetSwitchAttribute(ctx, &saipb.GetSwitchAttributeRequest{
		Oid:      swResp.Oid,
		AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defaultVR := swAttr.GetAttr().GetDefaultVirtualRouterId()

	pIn, err := portCli.CreatePort(ctx, &saipb.CreatePortRequest{Switch: swResp.Oid, HwLaneList: []uint32{1}, AdminState: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	pM0, err := portCli.CreatePort(ctx, &saipb.CreatePortRequest{Switch: swResp.Oid, HwLaneList: []uint32{2}, AdminState: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	pM1, err := portCli.CreatePort(ctx, &saipb.CreatePortRequest{Switch: swResp.Oid, HwLaneList: []uint32{3}, AdminState: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}

	bpM0, err := brCli.CreateBridgePort(ctx, &saipb.CreateBridgePortRequest{PortId: proto.Uint64(pM0.Oid)})
	if err != nil {
		t.Fatal(err)
	}
	bpM1, err := brCli.CreateBridgePort(ctx, &saipb.CreateBridgePortRequest{PortId: proto.Uint64(pM1.Oid)})
	if err != nil {
		t.Fatal(err)
	}
	vlanResp, err := vlanCli.CreateVlan(ctx, &saipb.CreateVlanRequest{Switch: swResp.Oid, VlanId: proto.Uint32(100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vlanCli.CreateVlanMember(ctx, &saipb.CreateVlanMemberRequest{
		Switch: swResp.Oid, VlanId: proto.Uint64(vlanResp.Oid), BridgePortId: proto.Uint64(bpM0.Oid),
		VlanTaggingMode: saipb.VlanTaggingMode_VLAN_TAGGING_MODE_UNTAGGED.Enum(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := vlanCli.CreateVlanMember(ctx, &saipb.CreateVlanMemberRequest{
		Switch: swResp.Oid, VlanId: proto.Uint64(vlanResp.Oid), BridgePortId: proto.Uint64(bpM1.Oid),
		VlanTaggingMode: saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED.Enum(),
	}); err != nil {
		t.Fatal(err)
	}

	inMAC := net.HardwareAddr{0x02, 0x00, 0x01, 0x01, 0x01, 0x01}
	vlanMAC := net.HardwareAddr{0x02, 0x00, 0x02, 0x02, 0x02, 0x02}
	hostMAC := net.HardwareAddr{0x02, 0x00, 0xaa, 0xbb, 0xcc, 0xee}
	srcMAC := net.HardwareAddr{0x02, 0x00, 0xaa, 0x00, 0x00, 0x01}

	if _, err := riCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch: swResp.Oid, Type: saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
		PortId: proto.Uint64(pIn.Oid), VirtualRouterId: proto.Uint64(defaultVR), SrcMacAddress: inMAC,
	}); err != nil {
		t.Fatal(err)
	}
	vlanRif, err := riCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch: swResp.Oid, Type: saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_VLAN.Enum(),
		VlanId: proto.Uint64(vlanResp.Oid), VirtualRouterId: proto.Uint64(defaultVR), SrcMacAddress: vlanMAC,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := neighCli.CreateNeighborEntry(ctx, &saipb.CreateNeighborEntryRequest{
		Entry:         &saipb.NeighborEntry{SwitchId: swResp.Oid, RifId: vlanRif.Oid, IpAddress: net.ParseIP("198.51.100.2").To4()},
		DstMacAddress: hostMAC,
	}); err != nil {
		t.Fatal(err)
	}
	nhResp, err := nhCli.CreateNextHop(ctx, &saipb.CreateNextHopRequest{
		Switch: swResp.Oid, Type: saipb.NextHopType_NEXT_HOP_TYPE_IP.Enum(),
		RouterInterfaceId: proto.Uint64(vlanRif.Oid), Ip: net.ParseIP("198.51.100.2").To4(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := routeCli.CreateRouteEntry(ctx, &saipb.CreateRouteEntryRequest{
		Entry: &saipb.RouteEntry{
			SwitchId: swResp.Oid, VrId: defaultVR,
			Destination: &saipb.IpPrefix{Addr: net.ParseIP("198.51.100.2").To4(), Mask: []byte{0xff, 0xff, 0xff, 0xff}},
		},
		PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
		NextHopId:    proto.Uint64(nhResp.Oid),
	}); err != nil {
		t.Fatal(err)
	}

	inject := func() {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		ipL := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.2").To4(), DstIP: net.ParseIP("198.51.100.2").To4()}
		udpL := &layers.UDP{SrcPort: 1000, DstPort: 2000}
		if err := udpL.SetNetworkLayerForChecksum(ipL); err != nil {
			t.Fatal(err)
		}
		if err := gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{SrcMAC: srcMAC, DstMAC: inMAC, EthernetType: layers.EthernetTypeIPv4},
			ipL, udpL, gopacket.Payload([]byte("vlan-flood")),
		); err != nil {
			t.Fatal(err)
		}
		if err := srv.InjectPacket(
			&fwdpb.ContextId{Id: srv.ID()},
			&fwdpb.PortId{ObjectId: &fwdpb.ObjectId{Id: fmt.Sprint(pIn.Oid)}},
			fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET,
			buf.Bytes(), nil, false, fwdpb.PortAction_PORT_ACTION_INPUT,
		); err != nil {
			t.Fatal(err)
		}
	}

	portM0 := portMgr.ports["2"]
	portM1 := portMgr.ports["3"]

	// 1. No FDB entry: packet floods to BOTH members[0] (untagged) and members[1] (802.1Q VID=100).
	inject()
	select {
	case frame := <-portM0.txCh:
		pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		if pkt.Layer(layers.LayerTypeDot1Q) != nil {
			t.Fatalf("expected untagged packet on members[0], got Dot1Q tag")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for flooded packet on members[0]")
	}
	select {
	case frame := <-portM1.txCh:
		pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		dot1q, ok := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
		if !ok || dot1q.VLANIdentifier != 100 {
			t.Fatalf("expected Dot1Q VID=100 on members[1], got %v", dot1q)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for flooded packet on members[1]")
	}

	// 2. Install FDB entry for hostMAC -> bpM1 (members[1]): packet goes ONLY to members[1] and stops flooding to members[0].
	if _, err := fdbCli.CreateFdbEntry(ctx, &saipb.CreateFdbEntryRequest{
		Entry:        &saipb.FdbEntry{SwitchId: swResp.Oid, MacAddress: hostMAC, BvId: vlanResp.Oid},
		Type:         saipb.FdbEntryType_FDB_ENTRY_TYPE_STATIC.Enum(),
		PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
		BridgePortId: proto.Uint64(bpM1.Oid),
	}); err != nil {
		t.Fatal(err)
	}
	inject()
	select {
	case frame := <-portM1.txCh:
		pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		dot1q, ok := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
		if !ok || dot1q.VLANIdentifier != 100 {
			t.Fatalf("expected Dot1Q VID=100 on members[1] via FDB, got %v", dot1q)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for FDB-directed packet on members[1]")
	}
	select {
	case frame := <-portM0.txCh:
		t.Fatalf("expected NO flooding to members[0] after FDB entry installed, got frame len=%d", len(frame))
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSetVirtualRouterAttributeDefaultAndAttrless(t *testing.T) {
	ctx := context.Background()
	rmgr := attrmgr.New()
	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(rmgr.Interceptor))
	if _, err := New(ctx, rmgr, grpcSrv, &dplaneopts.Options{}); err != nil {
		t.Fatalf("saiserver.New() failed: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	swCli := saipb.NewSwitchClient(conn)
	vrCli := saipb.NewVirtualRouterClient(conn)
	swResp, err := swCli.CreateSwitch(ctx, &saipb.CreateSwitchRequest{InitSwitch: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	swAttr, err := swCli.GetSwitchAttribute(ctx, &saipb.GetSwitchAttributeRequest{
		Oid:      swResp.Oid,
		AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defaultVR := swAttr.GetAttr().GetDefaultVirtualRouterId()

	// Default VR is created without attribute fields; SetVirtualRouterAttribute must succeed.
	if _, err := vrCli.SetVirtualRouterAttribute(ctx, &saipb.SetVirtualRouterAttributeRequest{
		Oid:           defaultVR,
		SrcMacAddress: []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01},
	}); err != nil {
		t.Fatalf("SetVirtualRouterAttribute(defaultVR) failed: %v", err)
	}

	// Attr-less user VR must also accept SetVirtualRouterAttribute, and return NotFound after removal.
	attrlessVR1, err := vrCli.CreateVirtualRouter(ctx, &saipb.CreateVirtualRouterRequest{Switch: swResp.Oid})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vrCli.SetVirtualRouterAttribute(ctx, &saipb.SetVirtualRouterAttributeRequest{
		Oid:           attrlessVR1.Oid,
		SrcMacAddress: []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02},
	}); err != nil {
		t.Fatalf("SetVirtualRouterAttribute(attrlessVR1) failed: %v", err)
	}
	if _, err := vrCli.RemoveVirtualRouter(ctx, &saipb.RemoveVirtualRouterRequest{Oid: attrlessVR1.Oid}); err != nil {
		t.Fatal(err)
	}
	if _, err := vrCli.SetVirtualRouterAttribute(ctx, &saipb.SetVirtualRouterAttributeRequest{
		Oid:           attrlessVR1.Oid,
		SrcMacAddress: []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x03},
	}); errdiff.Check(err, "NotFound") != "" {
		t.Fatalf("SetVirtualRouterAttribute(removed VR1) got %v, want NotFound", err)
	}

	// Removing an attr-less VR that never had attributes stored must also delete its idToType so Set returns NotFound.
	attrlessVR2, err := vrCli.CreateVirtualRouter(ctx, &saipb.CreateVirtualRouterRequest{Switch: swResp.Oid})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vrCli.RemoveVirtualRouter(ctx, &saipb.RemoveVirtualRouterRequest{Oid: attrlessVR2.Oid}); err != nil {
		t.Fatal(err)
	}
	if _, err := vrCli.SetVirtualRouterAttribute(ctx, &saipb.SetVirtualRouterAttributeRequest{
		Oid:           attrlessVR2.Oid,
		SrcMacAddress: []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x04},
	}); errdiff.Check(err, "NotFound") != "" {
		t.Fatalf("SetVirtualRouterAttribute(removed attrless VR2) got %v, want NotFound", err)
	}
}

func TestUntaggedVlanMemberMigrationRoutingPacket(t *testing.T) {
	ctx := context.Background()
	rmgr := attrmgr.New()
	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(rmgr.Interceptor))
	srv, err := New(ctx, rmgr, grpcSrv, &dplaneopts.Options{PortType: fwdpb.PortType_PORT_TYPE_FAKE})
	if err != nil {
		t.Fatalf("saiserver.New() failed: %v", err)
	}
	fwdCtx, err := srv.FindContext(&fwdpb.ContextId{Id: srv.ID()})
	if err != nil {
		t.Fatal(err)
	}
	portMgr := &capturingFakePortMgr{}
	fwdCtx.FakePortManager = portMgr
	t.Cleanup(portMgr.Close)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	swCli := saipb.NewSwitchClient(conn)
	portCli := saipb.NewPortClient(conn)
	vrCli := saipb.NewVirtualRouterClient(conn)
	vlanCli := saipb.NewVlanClient(conn)
	bridgeCli := saipb.NewBridgeClient(conn)
	rifCli := saipb.NewRouterInterfaceClient(conn)
	neighCli := saipb.NewNeighborClient(conn)
	nhCli := saipb.NewNextHopClient(conn)
	routeCli := saipb.NewRouteClient(conn)

	swResp, err := swCli.CreateSwitch(ctx, &saipb.CreateSwitchRequest{InitSwitch: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}

	p1, err := portCli.CreatePort(ctx, &saipb.CreatePortRequest{Switch: swResp.Oid, HwLaneList: []uint32{1}, AdminState: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := portCli.CreatePort(ctx, &saipb.CreatePortRequest{Switch: swResp.Oid, HwLaneList: []uint32{2}, AdminState: proto.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	bp1, err := bridgeCli.CreateBridgePort(ctx, &saipb.CreateBridgePortRequest{
		PortId: proto.Uint64(p1.Oid),
	})
	if err != nil {
		t.Fatal(err)
	}

	vr100, err := vrCli.CreateVirtualRouter(ctx, &saipb.CreateVirtualRouterRequest{Switch: swResp.Oid})
	if err != nil {
		t.Fatal(err)
	}
	vr200, err := vrCli.CreateVirtualRouter(ctx, &saipb.CreateVirtualRouterRequest{Switch: swResp.Oid})
	if err != nil {
		t.Fatal(err)
	}

	vlan100, err := vlanCli.CreateVlan(ctx, &saipb.CreateVlanRequest{Switch: swResp.Oid, VlanId: proto.Uint32(100)})
	if err != nil {
		t.Fatal(err)
	}
	vlan200, err := vlanCli.CreateVlan(ctx, &saipb.CreateVlanRequest{Switch: swResp.Oid, VlanId: proto.Uint32(200)})
	if err != nil {
		t.Fatal(err)
	}

	rifMac100 := net.HardwareAddr{0x02, 0x00, 0x10, 0x00, 0x00, 0x01}
	rifMac200 := net.HardwareAddr{0x02, 0x00, 0x20, 0x00, 0x00, 0x01}
	p2MAC := net.HardwareAddr{0x02, 0x00, 0x02, 0x00, 0x00, 0x01}
	srcMAC := net.HardwareAddr{0x02, 0x00, 0xaa, 0x00, 0x00, 0x01}
	nhMAC := net.HardwareAddr{0x02, 0x00, 0xbb, 0x00, 0x00, 0x01}

	if _, err := rifCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch: swResp.Oid, Type: saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_VLAN.Enum(),
		VlanId: proto.Uint64(vlan100.Oid), VirtualRouterId: proto.Uint64(vr100.Oid), SrcMacAddress: rifMac100,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rifCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch: swResp.Oid, Type: saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_VLAN.Enum(),
		VlanId: proto.Uint64(vlan200.Oid), VirtualRouterId: proto.Uint64(vr200.Oid), SrcMacAddress: rifMac200,
	}); err != nil {
		t.Fatal(err)
	}

	// Put p1 untagged in VLAN 100 first, then migrate untagged to VLAN 200.
	if _, err := vlanCli.CreateVlanMember(ctx, &saipb.CreateVlanMemberRequest{
		Switch: swResp.Oid, VlanId: proto.Uint64(vlan100.Oid), BridgePortId: proto.Uint64(bp1.Oid),
		VlanTaggingMode: saipb.VlanTaggingMode_VLAN_TAGGING_MODE_UNTAGGED.Enum(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := vlanCli.CreateVlanMember(ctx, &saipb.CreateVlanMemberRequest{
		Switch: swResp.Oid, VlanId: proto.Uint64(vlan200.Oid), BridgePortId: proto.Uint64(bp1.Oid),
		VlanTaggingMode: saipb.VlanTaggingMode_VLAN_TAGGING_MODE_UNTAGGED.Enum(),
	}); err != nil {
		t.Fatal(err)
	}

	p2Rif, err := rifCli.CreateRouterInterface(ctx, &saipb.CreateRouterInterfaceRequest{
		Switch: swResp.Oid, Type: saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT.Enum(),
		PortId: proto.Uint64(p2.Oid), VirtualRouterId: proto.Uint64(vr200.Oid), SrcMacAddress: p2MAC,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := neighCli.CreateNeighborEntry(ctx, &saipb.CreateNeighborEntryRequest{
		Entry:         &saipb.NeighborEntry{SwitchId: swResp.Oid, RifId: p2Rif.Oid, IpAddress: net.ParseIP("198.51.100.2").To4()},
		DstMacAddress: nhMAC,
	}); err != nil {
		t.Fatal(err)
	}
	nhResp, err := nhCli.CreateNextHop(ctx, &saipb.CreateNextHopRequest{
		Switch: swResp.Oid, Type: saipb.NextHopType_NEXT_HOP_TYPE_IP.Enum(),
		RouterInterfaceId: proto.Uint64(p2Rif.Oid), Ip: net.ParseIP("198.51.100.2").To4(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := routeCli.CreateRouteEntry(ctx, &saipb.CreateRouteEntryRequest{
		Entry: &saipb.RouteEntry{
			SwitchId: swResp.Oid, VrId: vr200.Oid,
			Destination: &saipb.IpPrefix{Addr: net.ParseIP("198.51.100.2").To4(), Mask: []byte{0xff, 0xff, 0xff, 0xff}},
		},
		PacketAction: saipb.PacketAction_PACKET_ACTION_FORWARD.Enum(),
		NextHopId:    proto.Uint64(nhResp.Oid),
	}); err != nil {
		t.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipL := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.2").To4(), DstIP: net.ParseIP("198.51.100.2").To4()}
	udpL := &layers.UDP{SrcPort: 1000, DstPort: 2000}
	if err := udpL.SetNetworkLayerForChecksum(ipL); err != nil {
		t.Fatal(err)
	}
	if err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: rifMac200, EthernetType: layers.EthernetTypeIPv4},
		ipL, udpL, gopacket.Payload([]byte("vlan-migrate")),
	); err != nil {
		t.Fatal(err)
	}
	if err := srv.InjectPacket(
		&fwdpb.ContextId{Id: srv.ID()},
		&fwdpb.PortId{ObjectId: &fwdpb.ObjectId{Id: fmt.Sprint(p1.Oid)}},
		fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET,
		buf.Bytes(), nil, false, fwdpb.PortAction_PORT_ACTION_INPUT,
	); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-portMgr.ports["2"].txCh:
		pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if !cmp.Equal([]byte(eth.SrcMAC), []byte(p2MAC)) || !cmp.Equal([]byte(eth.DstMAC), []byte(nhMAC)) {
			t.Fatalf("unexpected routed frame MACs after VLAN migration: src=%v dst=%v", eth.SrcMAC, eth.DstMAC)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for packet routed via migrated VLAN 200 RIF")
	}
}
