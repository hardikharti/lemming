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
	"log/slog"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/openconfig/gnmi/errlist"

	"github.com/openconfig/lemming/dataplane/forwarding/fwdconfig"
	"github.com/openconfig/lemming/dataplane/saiserver/attrmgr"

	saipb "github.com/openconfig/lemming/dataplane/proto/sai"
	fwdpb "github.com/openconfig/lemming/proto/forwarding"
)

type neighbor struct {
	saipb.UnimplementedNeighborServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
}

func newNeighbor(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *neighbor {
	n := &neighbor{
		mgr:       mgr,
		dataplane: dataplane,
	}
	saipb.RegisterNeighborServer(s, n)
	return n
}

// CreateNeighborEntry adds a neighbor to the neighbor table.
func (n *neighbor) CreateNeighborEntry(ctx context.Context, req *saipb.CreateNeighborEntryRequest) (*saipb.CreateNeighborEntryResponse, error) {
	entry := fwdconfig.TableEntryAddRequest(n.dataplane.ID(), NeighborTable).AppendEntry(fwdconfig.EntryDesc(fwdconfig.ExactEntry(
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetEntry().GetRifId()),
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithBytes(req.GetEntry().GetIpAddress()),
	)), fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST).WithValue(req.GetDstMacAddress()),
	).Build()

	if _, err := n.dataplane.TableEntryAdd(ctx, entry); err != nil {
		return nil, err
	}
	return &saipb.CreateNeighborEntryResponse{}, nil
}

// CreateNeighborEntry adds a neighbor to the neighbor table.
func (n *neighbor) RemoveNeighborEntry(ctx context.Context, req *saipb.RemoveNeighborEntryRequest) (*saipb.RemoveNeighborEntryResponse, error) {
	entry := fwdconfig.EntryDesc(fwdconfig.ExactEntry(
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetEntry().GetRifId()),
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithBytes(req.GetEntry().GetIpAddress()),
	)).Build()

	if _, err := n.dataplane.TableEntryRemove(ctx, &fwdpb.TableEntryRemoveRequest{
		ContextId: &fwdpb.ContextId{Id: n.dataplane.ID()},
		TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NeighborTable}},
		EntryDesc: entry,
	}); err != nil {
		return nil, err
	}
	return &saipb.RemoveNeighborEntryResponse{}, nil
}

// RemoveNeighborEntries removes multiple neighbors to the neighbor table.
func (n *neighbor) RemoveNeighborEntries(ctx context.Context, re *saipb.RemoveNeighborEntriesRequest) (*saipb.RemoveNeighborEntriesResponse, error) {
	resp := &saipb.RemoveNeighborEntriesResponse{}
	for _, req := range re.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, n.mgr, n.RemoveNeighborEntry, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

// CreateNeighborEntries adds multiple neighbors to the neighbor table.
func (n *neighbor) CreateNeighborEntries(ctx context.Context, re *saipb.CreateNeighborEntriesRequest) (*saipb.CreateNeighborEntriesResponse, error) {
	resp := &saipb.CreateNeighborEntriesResponse{}
	for _, req := range re.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, n.mgr, n.CreateNeighborEntry, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

// SetNeighborEntryAttribute updates the attribute for the neighbor entry.
// TODO: Update neighbor table to use attrmgr to persist other fields besides mac address.
func (n *neighbor) SetNeighborEntryAttribute(ctx context.Context, req *saipb.SetNeighborEntryAttributeRequest) (*saipb.SetNeighborEntryAttributeResponse, error) {
	entry := fwdconfig.TableEntryAddRequest(n.dataplane.ID(), NeighborTable).AppendEntry(fwdconfig.EntryDesc(fwdconfig.ExactEntry(
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetEntry().GetRifId()),
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithBytes(req.GetEntry().GetIpAddress()),
	)), fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST).WithValue(req.GetDstMacAddress()),
	).Build()

	if _, err := n.dataplane.TableEntryAdd(ctx, entry); err != nil {
		return nil, err
	}
	return &saipb.SetNeighborEntryAttributeResponse{}, nil
}

type groupMember struct {
	nextHop uint64 // ID of the next hop
	weight  uint32
}

type nextHopGroup struct {
	saipb.UnimplementedNextHopGroupServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
	groups    map[uint64]map[uint64]*groupMember // groups is map of next hop groups to a map of next hops
	groupIsV4 map[uint64]bool                    // map from group id to IP protocol version
}

func newNextHopGroup(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *nextHopGroup {
	n := &nextHopGroup{
		mgr:       mgr,
		dataplane: dataplane,
		groups:    map[uint64]map[uint64]*groupMember{},
		groupIsV4: map[uint64]bool{},
	}
	saipb.RegisterNextHopGroupServer(s, n)
	return n
}

// CreateNextHopGroup creates a next hop group.
func (nhg *nextHopGroup) CreateNextHopGroup(ctx context.Context, req *saipb.CreateNextHopGroupRequest) (*saipb.CreateNextHopGroupResponse, error) {
	id := nhg.mgr.NextID()

	entry := fwdconfig.TableEntryAddRequest(nhg.dataplane.ID(), NHGTable).AppendEntry(
		fwdconfig.EntryDesc(fwdconfig.ExactEntry(
			fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_GROUP_ID).WithUint64(id),
		)),
	).Build()

	switch req.GetType() {
	case saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP:
		if _, err := nhg.dataplane.TableEntryAdd(ctx, entry); err != nil {
			return nil, err
		}
		nhg.groups[id] = map[uint64]*groupMember{}
		return &saipb.CreateNextHopGroupResponse{
			Oid: id,
		}, nil
	case saipb.NextHopGroupType_NEXT_HOP_GROUP_TYPE_ECMP_WITH_MEMBERS:
		if _, err := nhg.dataplane.TableEntryAdd(ctx, entry); err != nil {
			return nil, err
		}
		nhg.groups[id] = map[uint64]*groupMember{}

		memReq := &saipb.CreateNextHopGroupMembersRequest{}
		for i, nh := range req.GetNextHopList() {
			memReq.Reqs = append(memReq.Reqs, &saipb.CreateNextHopGroupMemberRequest{
				Switch:         req.GetSwitch(),
				NextHopGroupId: proto.Uint64(id),
				NextHopId:      proto.Uint64(nh),
				Weight:         proto.Uint32(req.GetNextHopMemberWeightList()[i]),
			})
		}

		_, err := attrmgr.InvokeAndSave(ctx, nhg.mgr, nhg.CreateNextHopGroupMembers, memReq)
		if err != nil {
			return nil, err
		}
		return &saipb.CreateNextHopGroupResponse{
			Oid: id,
		}, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported req type: %v", req.GetType())
	}
}

// CreateNextHopGroups creates multiple next hop groups.
func (nhg *nextHopGroup) CreateNextHopGroups(ctx context.Context, r *saipb.CreateNextHopGroupsRequest) (*saipb.CreateNextHopGroupsResponse, error) {
	resp := &saipb.CreateNextHopGroupsResponse{}
	for _, req := range r.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, nhg.mgr, nhg.CreateNextHopGroup, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

// updateNextHopGroupMember updates the next hop group.
// If m is nil, remove mid from the group(key: nhgid), otherwise add m to group with mid as the key.
func (nhg *nextHopGroup) updateNextHopGroupMember(ctx context.Context, nhgid, mid uint64, m *groupMember) error {
	group := nhg.groups[nhgid]
	if group == nil {
		return status.Errorf(codes.FailedPrecondition, "group %d does not exist", nhgid)
	}
	if m != nil {
		if _, ok := nhg.groupIsV4[nhgid]; !ok { // Use the first member added to group to determine if the group is ipv4.
			nhAttr := &saipb.GetNextHopAttributeResponse{}
			err := nhg.mgr.PopulateAttributes(&saipb.GetNextHopAttributeRequest{
				Oid:      m.nextHop,
				AttrType: []saipb.NextHopAttr{saipb.NextHopAttr_NEXT_HOP_ATTR_IP},
			}, nhAttr)
			if err != nil {
				return fmt.Errorf("failed to retrieve next hop attr: %v", err)
			}
			nhg.groupIsV4[nhgid] = len(nhAttr.GetAttr().GetIp()) == 4
		}
		group[mid] = m
	} else {
		delete(group, mid)
	}
	var actLists []*fwdpb.ActionList
	for _, member := range group {
		action := fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID).WithUint64Value(member.nextHop))
		actLists = append(actLists, &fwdpb.ActionList{
			Weight:  uint64(member.weight),
			Actions: []*fwdpb.ActionDesc{action.Build()},
		})
	}

	swAttr := &saipb.GetSwitchAttributeResponse{}
	switchID, err := nhg.mgr.GetUint64SwitchID()
	if err != nil {
		return err
	}
	err = nhg.mgr.PopulateAttributes(&saipb.GetSwitchAttributeRequest{
		Oid:      switchID,
		AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_ECMP_HASH_IPV4, saipb.SwitchAttr_SWITCH_ATTR_ECMP_HASH_IPV6},
	}, swAttr)
	if err != nil {
		return fmt.Errorf("failed to retrieve hash id: %v", err)
	}
	hashID := swAttr.GetAttr().GetEcmpHashIpv6()
	if nhg.groupIsV4[nhgid] {
		hashID = swAttr.GetAttr().GetEcmpHashIpv4()
	}
	hashAttr := &saipb.HashAttribute{}
	err = nhg.mgr.PopulateAllAttributes(fmt.Sprint(hashID), hashAttr)
	if err != nil {
		return fmt.Errorf("failed to retrieve hash attrs: %v", err)
	}

	fieldsID, err := convertHashFields(hashAttr.GetNativeHashFieldList())
	if err != nil {
		return fmt.Errorf("failed to compute hash fields: %v", err)
	}

	actions := []*fwdpb.ActionDesc{{
		ActionType: fwdpb.ActionType_ACTION_TYPE_SELECT_ACTION_LIST,
		Action: &fwdpb.ActionDesc_Select{
			Select: &fwdpb.SelectActionListActionDesc{
				SelectAlgorithm: fwdpb.SelectActionListActionDesc_SELECT_ALGORITHM_CRC32, // TODO: should algo + hash be configurable?
				FieldIds:        fieldsID,
				ActionLists:     actLists,
			},
		},
	}, {
		ActionType: fwdpb.ActionType_ACTION_TYPE_LOOKUP,
		Action: &fwdpb.ActionDesc_Lookup{
			Lookup: &fwdpb.LookupActionDesc{
				TableId: &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{
					Id: NHTable,
				}},
			},
		},
	}}

	entries := &fwdpb.TableEntryAddRequest{
		ContextId: &fwdpb.ContextId{Id: nhg.dataplane.ID()},
		TableId: &fwdpb.TableId{
			ObjectId: &fwdpb.ObjectId{
				Id: NHGTable,
			},
		},
		Entries: []*fwdpb.TableEntryAddRequest_Entry{{
			EntryDesc: &fwdpb.EntryDesc{
				Entry: &fwdpb.EntryDesc_Exact{
					Exact: &fwdpb.ExactEntryDesc{
						Fields: []*fwdpb.PacketFieldBytes{{
							Bytes: binary.BigEndian.AppendUint64(nil, nhgid),
							FieldId: &fwdpb.PacketFieldId{
								Field: &fwdpb.PacketField{
									FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_GROUP_ID,
								},
							},
						}},
					},
				},
			},
			Actions: actions,
		}},
	}
	_, err = nhg.dataplane.TableEntryAdd(ctx, entries)
	return err
}

// SetNextHopGroupAttribute sets the attribute of the next hop group.
func (nhg *nextHopGroup) SetNextHopGroupAttribute(ctx context.Context, req *saipb.SetNextHopGroupAttributeRequest) (*saipb.SetNextHopGroupAttributeResponse, error) {
	if _, ok := nhg.groups[req.GetOid()]; !ok {
		return nil, status.Errorf(codes.NotFound, "group %d does not exist", req.GetOid())
	}
	resp := &saipb.GetNextHopGroupAttributeResponse{
		Attr: &saipb.NextHopGroupAttribute{},
	}
	pBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := nhg.mgr.PopulateAllAttributes(string(pBytes), resp.Attr); err != nil {
		return nil, err
	}

	// If next hop list is set, then replace all members.
	if len(req.GetNextHopList()) > 0 {
		attr := &saipb.NextHopGroupAttribute{}
		if err := nhg.mgr.PopulateAllAttributes(fmt.Sprint(req.GetOid()), attr); err != nil {
			return nil, err
		}
		attr.NextHopList = req.GetNextHopList()
		attr.NextHopMemberWeightList = nil

		switchID, err := nhg.mgr.GetUint64SwitchID()
		if err != nil {
			return nil, err
		}
		for mid := range nhg.groups[req.GetOid()] { // Create a copy of the keys since we are deleting them.
			if _, err := nhg.RemoveNextHopGroupMember(ctx, &saipb.RemoveNextHopGroupMemberRequest{Oid: mid}); err != nil {
				return nil, err
			}
		}
		memReq := &saipb.CreateNextHopGroupMembersRequest{}
		for i, nh := range req.GetNextHopList() {
			weight := uint32(1)
			if len(req.GetNextHopMemberWeightList()) > i {
				weight = req.GetNextHopMemberWeightList()[i]
			}
			attr.NextHopMemberWeightList = append(attr.NextHopMemberWeightList, weight)
			memReq.Reqs = append(memReq.Reqs, &saipb.CreateNextHopGroupMemberRequest{
				Switch:         switchID,
				NextHopGroupId: proto.Uint64(req.GetOid()),
				NextHopId:      proto.Uint64(nh),
				Weight:         proto.Uint32(weight),
			})
		}
		if _, err := attrmgr.InvokeAndSave(ctx, nhg.mgr, nhg.CreateNextHopGroupMembers, memReq); err != nil {
			return nil, err
		}
		nhg.mgr.StoreAttributes(req.GetOid(), attr)
	}

	return &saipb.SetNextHopGroupAttributeResponse{}, nil
}

// RemoveNextHopGroup removes the next hop group specified in the OID.
func (nhg *nextHopGroup) RemoveNextHopGroup(_ context.Context, req *saipb.RemoveNextHopGroupRequest) (*saipb.RemoveNextHopGroupResponse, error) {
	oid := req.GetOid()
	if _, ok := nhg.groups[oid]; !ok {
		return nil, status.Errorf(codes.NotFound, "group %d does not exist", oid)
	}
	delete(nhg.groups, oid)

	entry := fwdconfig.EntryDesc(fwdconfig.ExactEntry(
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_GROUP_ID).WithUint64(oid))).Build()
	nhgReq := &fwdpb.TableEntryRemoveRequest{
		ContextId: &fwdpb.ContextId{Id: nhg.dataplane.ID()},
		TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHGTable}},
		EntryDesc: entry,
	}

	if _, err := nhg.dataplane.TableEntryRemove(context.Background(), nhgReq); err != nil {
		return nil, err
	}
	return &saipb.RemoveNextHopGroupResponse{}, nil
}

// RemoveNextHopGroups removes multiple next hop groups specified in the OID.
func (nhg *nextHopGroup) RemoveNextHopGroups(ctx context.Context, req *saipb.RemoveNextHopGroupsRequest) (*saipb.RemoveNextHopGroupsResponse, error) {
	resp := &saipb.RemoveNextHopGroupsResponse{}
	for _, req := range req.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, nhg.mgr, nhg.RemoveNextHopGroup, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

// CreateNextHopGroupMember adds a next hop to a next hop group.
func (nhg *nextHopGroup) CreateNextHopGroupMember(ctx context.Context, req *saipb.CreateNextHopGroupMemberRequest) (*saipb.CreateNextHopGroupMemberResponse, error) {
	nhgid := req.GetNextHopGroupId()
	mid := nhg.mgr.NextID()
	m := &groupMember{
		nextHop: req.GetNextHopId(),
		weight:  req.GetWeight(),
	}
	if err := nhg.updateNextHopGroupMember(ctx, nhgid, mid, m); err != nil {
		return nil, err
	}
	return &saipb.CreateNextHopGroupMemberResponse{Oid: mid}, nil
}

// CreateNextHopGroups creates multiple next hop groups.
func (nhg *nextHopGroup) CreateNextHopGroupMembers(ctx context.Context, r *saipb.CreateNextHopGroupMembersRequest) (*saipb.CreateNextHopGroupMembersResponse, error) {
	resp := &saipb.CreateNextHopGroupMembersResponse{}
	for _, req := range r.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, nhg.mgr, nhg.CreateNextHopGroupMember, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

// RemoveNextHopGroupMember remove the next hop group member specified in the OID.
// Only need to remove with the desc.
func (nhg *nextHopGroup) RemoveNextHopGroupMember(ctx context.Context, req *saipb.RemoveNextHopGroupMemberRequest) (*saipb.RemoveNextHopGroupMemberResponse, error) {
	locateMember := func(oid uint64) (uint64, uint64, error) {
		for nhgid, nhg := range nhg.groups {
			for mid := range nhg {
				if mid == oid {
					return nhgid, mid, nil
				}
			}
		}
		return 0, 0, fmt.Errorf("cannot find member with id=%d", oid)
	}
	nhgid, mid, err := locateMember(req.GetOid())
	if err != nil {
		return nil, err
	}

	if err := nhg.updateNextHopGroupMember(ctx, nhgid, mid, nil); err != nil {
		return nil, err
	}
	return &saipb.RemoveNextHopGroupMemberResponse{}, nil
}

// RemoveNextHopGroupMembers removes multiple next hop group members specified in the OID.
func (nhg *nextHopGroup) RemoveNextHopGroupMembers(ctx context.Context, r *saipb.RemoveNextHopGroupMembersRequest) (*saipb.RemoveNextHopGroupMembersResponse, error) {
	resp := &saipb.RemoveNextHopGroupMembersResponse{}
	for _, req := range r.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, nhg.mgr, nhg.RemoveNextHopGroupMember, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

type nextHop struct {
	saipb.UnimplementedNextHopServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
}

func newNextHop(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *nextHop {
	n := &nextHop{
		mgr:       mgr,
		dataplane: dataplane,
	}
	saipb.RegisterNextHopServer(s, n)
	return n
}

// CreateNextHop creates a new next hop, including support for IPinIP, GRE, and VXLAN tunnel encapsulation next hops.
func (nh *nextHop) CreateNextHop(ctx context.Context, req *saipb.CreateNextHopRequest) (*saipb.CreateNextHopResponse, error) {
	id := nh.mgr.NextID()

	var actions []*fwdpb.ActionDesc

	switch req.GetType() {
	case saipb.NextHopType_NEXT_HOP_TYPE_IP, saipb.NextHopType_NEXT_HOP_TYPE_IPMC:
		// TODO: IPMC might need different handling (e.g., skip setting NEXT_HOP_IP invalid for multicast).
		// Keeping it same as IP for now.
		actions = []*fwdpb.ActionDesc{
			fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64Value(req.GetRouterInterfaceId())).Build(),
			fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithValue(req.GetIp())).Build(),
		}
	case saipb.NextHopType_NEXT_HOP_TYPE_TUNNEL_ENCAP:
		tunnel := &saipb.GetTunnelAttributeResponse{}
		err := nh.mgr.PopulateAttributes(&saipb.GetTunnelAttributeRequest{Oid: req.GetTunnelId(), AttrType: []saipb.TunnelAttr{saipb.TunnelAttr_TUNNEL_ATTR_TYPE}}, tunnel)
		if err != nil {
			return nil, err
		}

		headerID := fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP6
		if len(req.Ip) == 4 {
			headerID = fwdpb.PacketHeaderId_PACKET_HEADER_ID_IP4
		}
		actions = []*fwdpb.ActionDesc{
			fwdconfig.Action(fwdconfig.LookupAction(innerTTLCheckTable)).Build(),
			fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_8).
				WithFieldIDInstance(skipOuterTTLDecAttr).WithValue([]byte{0x01})).Build(),
		}

		switch tunnel.GetAttr().GetType() {
		case saipb.TunnelType_TUNNEL_TYPE_IPINIP:
			actions = append(actions, &fwdpb.ActionDesc{
				ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
				Action: &fwdpb.ActionDesc_Encap{
					Encap: &fwdpb.EncapActionDesc{
						HeaderId: headerID,
					},
				},
			})
		case saipb.TunnelType_TUNNEL_TYPE_IPINIP_GRE:
			actions = append(actions, &fwdpb.ActionDesc{
				ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
				Action: &fwdpb.ActionDesc_Encap{
					Encap: &fwdpb.EncapActionDesc{
						HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_GRE,
					},
				},
			}, &fwdpb.ActionDesc{
				ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
				Action: &fwdpb.ActionDesc_Encap{
					Encap: &fwdpb.EncapActionDesc{
						HeaderId: headerID,
					},
				},
			})
		case saipb.TunnelType_TUNNEL_TYPE_VXLAN:
			if len(req.GetTunnelMac()) > 0 {
				actions = append(actions,
					fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_COPY, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_SRC).WithFieldSrc(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST)).Build(),
					fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST).WithValue(req.GetTunnelMac())).Build(),
				)
			}
			actions = append(actions, &fwdpb.ActionDesc{
				ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
				Action: &fwdpb.ActionDesc_Encap{
					Encap: &fwdpb.EncapActionDesc{
						HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_VXLAN,
					},
				},
			}, &fwdpb.ActionDesc{
				ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
				Action: &fwdpb.ActionDesc_Encap{
					Encap: &fwdpb.EncapActionDesc{
						HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_UDP,
					},
				},
			}, &fwdpb.ActionDesc{
				ActionType: fwdpb.ActionType_ACTION_TYPE_ENCAP,
				Action: &fwdpb.ActionDesc_Encap{
					Encap: &fwdpb.EncapActionDesc{
						HeaderId: headerID,
					},
				},
			})
			if req.GetTunnelVni() != 0 {
				vni := req.GetTunnelVni()
				vniBytes := []byte{byte(vni >> 16), byte(vni >> 8), byte(vni)}
				actions = append(actions, fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VXLAN_VNI).WithValue(vniBytes)).Build())
			}
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unsupported tunnel type: %v", tunnel.GetAttr().GetType())
		}

		actions = append(actions,
			fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithValue(req.GetIp())).Build(),
			fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithValue(req.GetIp())).Build(),
			fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TUNNEL_ID).WithUint64Value(req.GetTunnelId())).Build(),
			fwdconfig.Action(fwdconfig.LookupAction(NHActionTable)).Build(),
			fwdconfig.Action(fwdconfig.LookupAction(TunnelEncap)).Build(),
		)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported req type: %v", req.GetType())
	}

	nhReq := fwdconfig.TableEntryAddRequest(nh.dataplane.ID(), NHTable).AppendEntry(
		fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID).WithUint64(id))),
	).Build()
	nhReq.Entries[0].Actions = actions

	if _, err := nh.dataplane.TableEntryAdd(ctx, nhReq); err != nil {
		return nil, err
	}

	nh.mgr.StoreAttributes(id, req)

	return &saipb.CreateNextHopResponse{
		Oid: id,
	}, nil
}

// RemoveNextHop removes the next hop with the OID specified.
func (nh *nextHop) RemoveNextHop(ctx context.Context, r *saipb.RemoveNextHopRequest) (*saipb.RemoveNextHopResponse, error) {
	entry := fwdconfig.EntryDesc(fwdconfig.ExactEntry(
		fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID).WithUint64(r.GetOid()))).Build()
	nhReq := &fwdpb.TableEntryRemoveRequest{
		ContextId: &fwdpb.ContextId{Id: nh.dataplane.ID()},
		TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: NHTable}},
		EntryDesc: entry,
	}

	if _, err := nh.dataplane.TableEntryRemove(ctx, nhReq); err != nil {
		return nil, err
	}
	return &saipb.RemoveNextHopResponse{}, nil
}

func (nh *nextHop) CreateNextHops(ctx context.Context, r *saipb.CreateNextHopsRequest) (*saipb.CreateNextHopsResponse, error) {
	resp := &saipb.CreateNextHopsResponse{}
	for _, req := range r.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, nh.mgr, nh.CreateNextHop, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

func (nh *nextHop) RemoveNextHops(ctx context.Context, r *saipb.RemoveNextHopsRequest) (*saipb.RemoveNextHopsResponse, error) {
	resp := &saipb.RemoveNextHopsResponse{}
	for _, req := range r.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, nh.mgr, nh.RemoveNextHop, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

type route struct {
	saipb.UnimplementedRouteServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
}

func newRoute(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *route {
	r := &route{
		mgr:       mgr,
		dataplane: dataplane,
	}
	saipb.RegisterRouteServer(s, r)
	return r
}

// routeDstMeta is the key to PACKET_ATTRIBUTE_32 field for routing table metadata.
const routeDstMeta = 0

// CreateRouteEntry creates a new route entry.
func (r *route) CreateRouteEntry(ctx context.Context, req *saipb.CreateRouteEntryRequest) (*saipb.CreateRouteEntryResponse, error) {
	fib := FIBV6Table
	if len(req.GetEntry().GetDestination().GetAddr()) == 4 {
		fib = FIBV4Table
	}

	if req.PacketAction == nil {
		req.PacketAction = saipb.PacketAction_PACKET_ACTION_FORWARD.Enum()
	}

	entry := fwdconfig.TableEntryAddRequest(r.dataplane.ID(), fib).AppendEntry(fwdconfig.EntryDesc(
		fwdconfig.PrefixEntry(
			fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(req.GetEntry().GetVrId()),
			fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
				req.GetEntry().GetDestination().GetAddr(),
				req.GetEntry().GetDestination().GetMask(),
			),
		),
	))

	forward := true
	if req.GetPacketAction() == saipb.PacketAction_PACKET_ACTION_DROP ||
		req.GetPacketAction() == saipb.PacketAction_PACKET_ACTION_TRAP ||
		req.GetPacketAction() == saipb.PacketAction_PACKET_ACTION_DENY {
		forward = false
	}
	nextType := r.mgr.GetType(fmt.Sprint(req.GetNextHopId()))

	actions := []fwdconfig.ActionDescBuilder{}

	// If the packet action is drop, then next hop is optional.
	if forward {
		actions = append(actions, fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_BIT_WRITE, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ACTION).WithBitOp(1, 0).WithValue([]byte{1}))
		switch nextType {
		case saipb.ObjectType_OBJECT_TYPE_NEXT_HOP:
			actions = append(actions,
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID).WithUint64Value(req.GetNextHopId()),
				fwdconfig.LookupAction(NHTable),
			)
		case saipb.ObjectType_OBJECT_TYPE_NEXT_HOP_GROUP:
			actions = append(actions,
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_GROUP_ID).WithUint64Value(req.GetNextHopId()),
				fwdconfig.LookupAction(NHGTable),
			)
		case saipb.ObjectType_OBJECT_TYPE_ROUTER_INTERFACE:
			actions = append(actions,
				// Set the next hop IP in the packet's metadata.
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_COPY, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithFieldSrc(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST),
				// Set the output iface.
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64Value(req.GetNextHopId()),
			)
		case saipb.ObjectType_OBJECT_TYPE_PORT:
			attrReq := &saipb.GetSwitchAttributeRequest{
				Oid:      req.GetEntry().GetSwitchId(),
				AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_CPU_PORT},
			}
			resp := &saipb.GetSwitchAttributeResponse{}
			if err := r.mgr.PopulateAttributes(attrReq, resp); err != nil {
				return nil, err
			}
			if req.GetNextHopId() == *resp.Attr.CpuPort {
				_, err := r.dataplane.TableEntryAdd(ctx, fwdconfig.TableEntryAddRequest(r.dataplane.ID(), trapTableID).
					AppendEntry(
						fwdconfig.EntryDesc(fwdconfig.FlowEntry(
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
								req.GetEntry().GetDestination().GetAddr(),
								req.GetEntry().GetDestination().GetMask()),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(req.GetEntry().GetVrId()))),
						fwdconfig.TransmitAction(fmt.Sprint(req.GetNextHopId())).WithImmediate(true)).
					Build())
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to add next IP2ME route: %v", nextType)
				}
				return &saipb.CreateRouteEntryResponse{}, nil
			}
			actions = append(actions,
				// Set the next hop IP in the packet's metadata.
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_COPY, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithFieldSrc(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST),
				// Set the output port.
				fwdconfig.TransmitAction(fmt.Sprint(req.GetNextHopId())),
			)
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unknown next hop type: %v", nextType)
		}
	} else {
		actions = append(actions, fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_BIT_WRITE, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ACTION).WithBitOp(1, 0).WithValue([]byte{0}))

		isZeroMask := true
		for _, b := range req.GetEntry().GetDestination().GetMask() {
			if b != 0 {
				isZeroMask = false
				break
			}
		}
		if isZeroMask {
			counterID := "LPM6_MISS_COUNTER"
			if fib == FIBV4Table {
				counterID = "LPM4_MISS_COUNTER"
			}
			actions = append(actions, fwdconfig.FlowCounterAction(counterID))
		}
	}
	if req.MetaData != nil {
		actions = append(actions, fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_32).
			WithFieldIDInstance(routeDstMeta).WithValue(binary.BigEndian.AppendUint32(nil, req.GetMetaData())))
	}
	entry.AppendActions(actions...)

	route := entry.Build()
	_, err := r.dataplane.TableEntryAdd(ctx, route)
	if err != nil {
		return nil, err
	}
	return &saipb.CreateRouteEntryResponse{}, nil
}

func (r *route) SetRouteEntryAttribute(ctx context.Context, req *saipb.SetRouteEntryAttributeRequest) (*saipb.SetRouteEntryAttributeResponse, error) {
	resp := &saipb.GetRouteEntryAttributeResponse{
		Attr: &saipb.RouteEntryAttribute{},
	}
	pBytes, err := proto.Marshal(req.GetEntry())
	if err != nil {
		return nil, err
	}
	if r.mgr.GetType(string(pBytes)) == saipb.ObjectType_OBJECT_TYPE_NULL {
		return nil, status.Errorf(codes.NotFound, "route entry not found")
	}
	if err := r.mgr.PopulateAllAttributes(string(pBytes), resp.Attr); err != nil {
		return nil, err
	}
	// The request only has one attribute, so find the one that is set.
	// Only these three attributes are supported.
	packetAction := resp.Attr.GetPacketAction()
	if req.PacketAction != nil {
		packetAction = req.GetPacketAction()
	}
	nextHopID := resp.Attr.GetNextHopId()
	if req.NextHopId != nil {
		nextHopID = req.GetNextHopId()
	}
	metaData := resp.Attr.MetaData
	if req.MetaData != nil {
		metaData = req.MetaData
	}

	fib := FIBV6Table
	if len(req.GetEntry().GetDestination().GetAddr()) == 4 {
		fib = FIBV4Table
	}

	entry := fwdconfig.TableEntryAddRequest(r.dataplane.ID(), fib).AppendEntry(fwdconfig.EntryDesc(
		fwdconfig.PrefixEntry(
			fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(req.GetEntry().GetVrId()),
			fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
				req.GetEntry().GetDestination().GetAddr(),
				req.GetEntry().GetDestination().GetMask(),
			),
		),
	))

	forward := true
	if packetAction == saipb.PacketAction_PACKET_ACTION_DROP ||
		packetAction == saipb.PacketAction_PACKET_ACTION_TRAP ||
		packetAction == saipb.PacketAction_PACKET_ACTION_DENY {
		forward = false
	}
	nextType := r.mgr.GetType(fmt.Sprint(nextHopID))

	actions := []fwdconfig.ActionDescBuilder{}

	// If the packet action is drop, then next hop is optional.
	if forward {
		actions = append(actions, fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_BIT_WRITE, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ACTION).WithBitOp(1, 0).WithValue([]byte{1}))
		switch nextType {
		case saipb.ObjectType_OBJECT_TYPE_NEXT_HOP:
			actions = append(actions,
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_ID).WithUint64Value(nextHopID),
				fwdconfig.LookupAction(NHTable),
			)
		case saipb.ObjectType_OBJECT_TYPE_NEXT_HOP_GROUP:
			actions = append(actions,
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_GROUP_ID).WithUint64Value(nextHopID),
				fwdconfig.LookupAction(NHGTable),
			)
		case saipb.ObjectType_OBJECT_TYPE_ROUTER_INTERFACE:
			actions = append(actions,
				// Set the next hop IP in the packet's metadata.
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_COPY, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithFieldSrc(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST),
				// Set the output iface.
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64Value(nextHopID),
			)
		case saipb.ObjectType_OBJECT_TYPE_PORT:
			attrReq := &saipb.GetSwitchAttributeRequest{
				Oid:      req.GetEntry().GetSwitchId(),
				AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_CPU_PORT},
			}
			resp := &saipb.GetSwitchAttributeResponse{}
			if err := r.mgr.PopulateAttributes(attrReq, resp); err != nil {
				return nil, err
			}
			if nextHopID == *resp.Attr.CpuPort {
				_, err := r.dataplane.TableEntryAdd(ctx, fwdconfig.TableEntryAddRequest(r.dataplane.ID(), trapTableID).
					AppendEntry(
						fwdconfig.EntryDesc(fwdconfig.FlowEntry(
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
								req.GetEntry().GetDestination().GetAddr(),
								req.GetEntry().GetDestination().GetMask()),
							fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(req.GetEntry().GetVrId()))),
						fwdconfig.TransmitAction(fmt.Sprint(nextHopID)).WithImmediate(true)).
					Build())
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to add next IP2ME route: %v", nextType)
				}
				return &saipb.SetRouteEntryAttributeResponse{}, nil
			}
			actions = append(actions,
				// Set the next hop IP in the packet's metadata.
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_COPY, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_NEXT_HOP_IP).WithFieldSrc(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST),
				// Set the output port.
				fwdconfig.TransmitAction(fmt.Sprint(nextHopID)),
			)
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unknown next hop type: %v", nextType)
		}
	} else {
		actions = append(actions, fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_BIT_WRITE, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ACTION).WithBitOp(1, 0).WithValue([]byte{0}))

		isZeroMask := true
		for _, b := range req.GetEntry().GetDestination().GetMask() {
			if b != 0 {
				isZeroMask = false
				break
			}
		}
		if isZeroMask {
			counterID := "LPM6_MISS_COUNTER"
			if fib == FIBV4Table {
				counterID = "LPM4_MISS_COUNTER"
			}
			actions = append(actions, fwdconfig.FlowCounterAction(counterID))
		}
	}
	if metaData != nil {
		actions = append(actions, fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_32).
			WithFieldIDInstance(routeDstMeta).WithValue(binary.BigEndian.AppendUint32(nil, *metaData)))
	}
	entry.AppendActions(actions...)

	route := entry.Build()
	_, err = r.dataplane.TableEntryAdd(ctx, route)
	if err != nil {
		return nil, err
	}

	return &saipb.SetRouteEntryAttributeResponse{}, nil
}

func (r *route) GetRouteEntryAttribute(ctx context.Context, req *saipb.GetRouteEntryAttributeRequest) (*saipb.GetRouteEntryAttributeResponse, error) {
	resp := &saipb.GetRouteEntryAttributeResponse{
		Attr: &saipb.RouteEntryAttribute{},
	}
	pBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(req.GetEntry())
	if err != nil {
		return nil, err
	}
	if r.mgr.GetType(string(pBytes)) == saipb.ObjectType_OBJECT_TYPE_NULL {
		return nil, status.Errorf(codes.NotFound, "route entry not found")
	}
	if err := r.mgr.PopulateAllAttributes(string(pBytes), resp.Attr); err != nil {
		return nil, err
	}
	return resp, nil
}

func (r *route) CreateRouteEntries(ctx context.Context, re *saipb.CreateRouteEntriesRequest) (*saipb.CreateRouteEntriesResponse, error) {
	var errs errlist.List
	resp := &saipb.CreateRouteEntriesResponse{}
	for _, req := range re.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, r.mgr, r.CreateRouteEntry, req)
		errs.Add(err)
		resp.Resps = append(resp.Resps, res)
	}
	return resp, errs.Err()
}

func (r *route) RemoveRouteEntry(ctx context.Context, req *saipb.RemoveRouteEntryRequest) (*saipb.RemoveRouteEntryResponse, error) {
	if req.GetEntry() == nil {
		return nil, status.Error(codes.InvalidArgument, "missing route entry")
	}
	pBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(req.GetEntry())
	if err != nil {
		return nil, err
	}
	attr := &saipb.RouteEntryAttribute{}
	if err := r.mgr.PopulateAllAttributes(string(pBytes), attr); err == nil && attr.NextHopId != nil {
		attrReq := &saipb.GetSwitchAttributeRequest{
			Oid:      req.GetEntry().GetSwitchId(),
			AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_CPU_PORT},
		}
		resp := &saipb.GetSwitchAttributeResponse{}
		if err := r.mgr.PopulateAttributes(attrReq, resp); err == nil && resp.Attr.CpuPort != nil && *attr.NextHopId == *resp.Attr.CpuPort {
			_, err := r.dataplane.TableEntryRemove(ctx, &fwdpb.TableEntryRemoveRequest{
				ContextId: &fwdpb.ContextId{Id: r.dataplane.ID()},
				TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: trapTableID}},
				EntryDesc: fwdconfig.EntryDesc(fwdconfig.FlowEntry(
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
						req.GetEntry().GetDestination().GetAddr(),
						req.GetEntry().GetDestination().GetMask()),
					fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(req.GetEntry().GetVrId()))).Build(),
			})
			return &saipb.RemoveRouteEntryResponse{}, err
		}
	}

	fib := FIBV6Table
	if len(req.GetEntry().GetDestination().GetAddr()) == 4 {
		fib = FIBV4Table
	}

	_, err = r.dataplane.TableEntryRemove(ctx, &fwdpb.TableEntryRemoveRequest{
		ContextId: &fwdpb.ContextId{Id: r.dataplane.ID()},
		TableId:   &fwdpb.TableId{ObjectId: &fwdpb.ObjectId{Id: fib}},
		EntryDesc: fwdconfig.EntryDesc(
			fwdconfig.PrefixEntry(
				fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64(req.GetEntry().GetVrId()),
				fwdconfig.PacketFieldMaskedBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST).WithBytes(
					req.GetEntry().GetDestination().GetAddr(),
					req.GetEntry().GetDestination().GetMask(),
				),
			),
		).Build(),
	})
	return &saipb.RemoveRouteEntryResponse{}, err
}

func (r *route) RemoveRouteEntries(ctx context.Context, re *saipb.RemoveRouteEntriesRequest) (*saipb.RemoveRouteEntriesResponse, error) {
	var errs errlist.List
	resp := &saipb.RemoveRouteEntriesResponse{
		Resps: make([]*saipb.RemoveRouteEntryResponse, 0, len(re.GetReqs())),
	}
	for _, req := range re.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, r.mgr, r.RemoveRouteEntry, req)
		errs.Add(err)
		if res == nil {
			res = &saipb.RemoveRouteEntryResponse{}
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, errs.Err()
}

type vlanRIFInfo struct {
	rifID      uint64
	vlanOID    uint64
	vid        uint32
	inCounter  string
	outCounter string
}

type routerInterface struct {
	saipb.UnimplementedRouterInterfaceServer
	mgr        *attrmgr.AttrMgr
	dataplane  switchDataplaneAPI
	macTracker *macTracker
	vlan       *vlan
	mu         sync.Mutex
	vlanRIFs   map[uint64]*vlanRIFInfo
	vlanToRIFs map[uint64]map[uint64]struct{}
}

func newRouterInterface(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server, tracker *macTracker, vlan *vlan) *routerInterface {
	r := &routerInterface{
		mgr:        mgr,
		dataplane:  dataplane,
		macTracker: tracker,
		vlan:       vlan,
		vlanRIFs:   make(map[uint64]*vlanRIFInfo),
		vlanToRIFs: make(map[uint64]map[uint64]struct{}),
	}
	saipb.RegisterRouterInterfaceServer(s, r)
	return r
}

func (ri *routerInterface) Reset() {
	if ri == nil {
		return
	}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.vlanRIFs = make(map[uint64]*vlanRIFInfo)
	ri.vlanToRIFs = make(map[uint64]map[uint64]struct{})
}

func (ri *routerInterface) resolveVlanID(vlanOID uint64) (uint32, error) {
	if ri.vlan != nil {
		if vid, err := ri.vlan.vidByOid(vlanOID); err == nil {
			return vid, nil
		}
	}
	vResp := &saipb.GetVlanAttributeResponse{}
	if err := ri.mgr.PopulateAttributes(&saipb.GetVlanAttributeRequest{
		Oid:      vlanOID,
		AttrType: []saipb.VlanAttr{saipb.VlanAttr_VLAN_ATTR_VLAN_ID},
	}, vResp); err == nil && vResp.GetAttr().VlanId != nil {
		return vResp.GetAttr().GetVlanId(), nil
	}
	return 0, status.Errorf(codes.NotFound, "VLAN %d not found", vlanOID)
}

func vlanMemberMatchTag(vid uint32, mode saipb.VlanTaggingMode) uint16 {
	if mode == saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
		return uint16(vid)
	}
	return 0
}

func (ri *routerInterface) programVlanMemberInput(ctx context.Context, info *vlanRIFInfo, m *vlanMember) error {
	nid, err := ri.dataplane.ObjectNID(ctx, &fwdpb.ObjectNIDRequest{
		ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
		ObjectId:  &fwdpb.ObjectId{Id: fmt.Sprint(m.PortID)},
	})
	if err != nil {
		return err
	}
	tag := vlanMemberMatchTag(info.vid, m.Mode)
	inReq := fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), inputIfaceTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(nid.GetNid()),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithBytes(binary.BigEndian.AppendUint16(nil, tag)),
			)),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE).WithUint64Value(info.rifID),
			fwdconfig.FlowCounterAction(info.inCounter),
		).Build()
	if m.Mode == saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
		inReq.Entries[0].Actions = append(inReq.Entries[0].Actions, &fwdpb.ActionDesc{
			ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
			Action: &fwdpb.ActionDesc_Decap{
				Decap: &fwdpb.DecapActionDesc{
					HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN,
				},
			},
		})
	}
	_, err = ri.dataplane.TableEntryAdd(ctx, inReq)
	return err
}

func (ri *routerInterface) removeVlanMemberInput(ctx context.Context, vid uint32, m *vlanMember) error {
	nid, err := ri.dataplane.ObjectNID(ctx, &fwdpb.ObjectNIDRequest{
		ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
		ObjectId:  &fwdpb.ObjectId{Id: fmt.Sprint(m.PortID)},
	})
	if err != nil {
		return err
	}
	tag := vlanMemberMatchTag(vid, m.Mode)
	_, err = ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), inputIfaceTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(nid.GetNid()),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithBytes(binary.BigEndian.AppendUint16(nil, tag)),
			)),
		).Build())
	return err
}

func (ri *routerInterface) programVlanMemberEgressTag(ctx context.Context, vid uint32, portID uint64) error {
	req := fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), egressVlanTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_16).
					WithBytes(binary.BigEndian.AppendUint16(nil, uint16(vid))),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TARGET_EGRESS_PORT).WithUint64(portID),
			)),
			fwdconfig.EncapAction(fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithValue(binary.BigEndian.AppendUint16(nil, uint16(vid))),
		).Build()
	_, err := ri.dataplane.TableEntryAdd(ctx, req)
	return err
}

func (ri *routerInterface) removeVlanMemberEgressTag(ctx context.Context, vid uint32, portID uint64) error {
	_, err := ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), egressVlanTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_16).
					WithBytes(binary.BigEndian.AppendUint16(nil, uint16(vid))),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TARGET_EGRESS_PORT).WithUint64(portID),
			)),
		).Build())
	return err
}

func (ri *routerInterface) updateVlanOutputIface(ctx context.Context, info *vlanRIFInfo, members []*vlanMember) error {
	outActions := []fwdconfig.ActionDescBuilder{
		fwdconfig.FlowCounterAction(info.outCounter),
		fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_16).
			WithFieldIDInstance(egressVlanAttr).
			WithValue(binary.BigEndian.AppendUint16(nil, uint16(info.vid))),
	}
	outReq := fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), outputIfaceTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(info.rifID))),
			outActions...,
		).Build()
	if _, err := ri.dataplane.TableEntryAdd(ctx, outReq); err != nil {
		return err
	}

	var floodActions []fwdconfig.ActionDescBuilder
	switch len(members) {
	case 0:
		floodActions = append(floodActions, fwdconfig.DropAction())
	case 1:
		floodActions = append(floodActions,
			fwdconfig.TransmitAction(fmt.Sprint(members[0].PortID)),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TARGET_EGRESS_PORT).WithUint64Value(members[0].PortID),
		)
	default:
		for _, m := range members[:len(members)-1] {
			ma := fwdconfig.MirrorAction().WithPort(fmt.Sprint(m.PortID), fwdpb.PortAction_PORT_ACTION_WRITE)
			if m.Mode == saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
				ma.WithActions(
					fwdconfig.Action(fwdconfig.EncapAction(fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN)),
					fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).
						WithValue(binary.BigEndian.AppendUint16(nil, uint16(info.vid)))),
				)
			}
			floodActions = append(floodActions, ma)
		}
		last := members[len(members)-1]
		floodActions = append(floodActions,
			fwdconfig.TransmitAction(fmt.Sprint(last.PortID)),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TARGET_EGRESS_PORT).WithUint64Value(last.PortID),
		)
	}
	floodReq := fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), vlanFloodTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_16).
					WithBytes(binary.BigEndian.AppendUint16(nil, uint16(info.vid))),
			)),
			floodActions...,
		).Build()
	_, err := ri.dataplane.TableEntryAdd(ctx, floodReq)
	return err
}

func (ri *routerInterface) getVlanRIFInfos(vlanOID uint64) []*vlanRIFInfo {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	var infos []*vlanRIFInfo
	for rifID := range ri.vlanToRIFs[vlanOID] {
		if info, ok := ri.vlanRIFs[rifID]; ok {
			infos = append(infos, info)
		}
	}
	slices.SortFunc(infos, func(a, b *vlanRIFInfo) int {
		if a.rifID < b.rifID {
			return -1
		}
		if a.rifID > b.rifID {
			return 1
		}
		return 0
	})
	return infos
}

func (ri *routerInterface) onVlanMemberAdded(ctx context.Context, vlanOID uint64, m *vlanMember, members []*vlanMember) error {
	if ri == nil {
		return nil
	}
	for _, info := range ri.getVlanRIFInfos(vlanOID) {
		if err := ri.programVlanMemberInput(ctx, info, m); err != nil {
			return err
		}
		if m.Mode == saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
			if err := ri.programVlanMemberEgressTag(ctx, info.vid, m.PortID); err != nil {
				return err
			}
		}
		if err := ri.updateVlanOutputIface(ctx, info, members); err != nil {
			return err
		}
	}
	return nil
}

func (ri *routerInterface) onVlanMemberRemoved(ctx context.Context, vlanOID uint64, m *vlanMember, remainingMembers []*vlanMember) {
	if ri == nil {
		return
	}
	for _, info := range ri.getVlanRIFInfos(vlanOID) {
		if err := ri.removeVlanMemberInput(ctx, info.vid, m); err != nil {
			slog.WarnContext(ctx, "failed to remove inputIfaceTable entry for VLAN member", "err", err)
		}
		if m.Mode == saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
			if err := ri.removeVlanMemberEgressTag(ctx, info.vid, m.PortID); err != nil {
				slog.WarnContext(ctx, "failed to remove egressVlanTable entry for VLAN member", "err", err)
			}
		}
		if err := ri.updateVlanOutputIface(ctx, info, remainingMembers); err != nil {
			slog.WarnContext(ctx, "failed to update outputIfaceTable entry for VLAN RIF", "err", err)
		}
	}
}

func ifaceCounterID(oid uint64, input bool) string {
	if input {
		return fmt.Sprintf("%d-in-counter", oid)
	}
	return fmt.Sprintf("%d-out-counter", oid)
}

// CreateRouterInterfaces creates a new router interface.
func (ri *routerInterface) CreateRouterInterface(ctx context.Context, req *saipb.CreateRouterInterfaceRequest) (*saipb.CreateRouterInterfaceResponse, error) {
	id := ri.mgr.NextID()

	vlanID := uint16(0)
	switch req.GetType() {
	case saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_PORT:
	case saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_SUB_PORT:
		vlanID = uint16(req.GetOuterVlanId())
	case saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_LOOPBACK:
		if err := ri.macTracker.acquire(ctx, req.GetSrcMacAddress()); err != nil {
			return nil, err
		}
		return &saipb.CreateRouterInterfaceResponse{Oid: id}, nil
	case saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_VLAN:
		vlanOID := req.GetVlanId()
		vid, err := ri.resolveVlanID(vlanOID)
		if err != nil {
			return nil, err
		}
		inCounter := ifaceCounterID(id, true)
		outCounter := ifaceCounterID(id, false)
		if _, err := ri.dataplane.FlowCounterCreate(ctx, &fwdpb.FlowCounterCreateRequest{
			ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
			Id:        &fwdpb.FlowCounterId{ObjectId: &fwdpb.ObjectId{Id: inCounter}},
		}); err != nil {
			return nil, err
		}
		if _, err := ri.dataplane.FlowCounterCreate(ctx, &fwdpb.FlowCounterCreateRequest{
			ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
			Id:        &fwdpb.FlowCounterId{ObjectId: &fwdpb.ObjectId{Id: outCounter}},
		}); err != nil {
			return nil, err
		}

		info := &vlanRIFInfo{
			rifID:      id,
			vlanOID:    vlanOID,
			vid:        vid,
			inCounter:  inCounter,
			outCounter: outCounter,
		}
		// Register before snapshotting members so concurrent CreateVlanMember calls cannot be missed.
		ri.mu.Lock()
		ri.vlanRIFs[id] = info
		if ri.vlanToRIFs[vlanOID] == nil {
			ri.vlanToRIFs[vlanOID] = make(map[uint64]struct{})
		}
		ri.vlanToRIFs[vlanOID][id] = struct{}{}
		ri.mu.Unlock()

		rollbackVlanRIF := func() {
			ri.mu.Lock()
			delete(ri.vlanRIFs, id)
			if rifs := ri.vlanToRIFs[vlanOID]; rifs != nil {
				delete(rifs, id)
				if len(rifs) == 0 {
					delete(ri.vlanToRIFs, vlanOID)
				}
			}
			ri.mu.Unlock()
		}

		var members []*vlanMember
		if ri.vlan != nil {
			members = ri.vlan.membersForVlan(vlanOID)
		}
		for _, m := range members {
			if err := ri.programVlanMemberInput(ctx, info, m); err != nil {
				rollbackVlanRIF()
				return nil, err
			}
			if m.Mode == saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
				if err := ri.programVlanMemberEgressTag(ctx, info.vid, m.PortID); err != nil {
					rollbackVlanRIF()
					return nil, err
				}
			}
		}
		if err := ri.updateVlanOutputIface(ctx, info, members); err != nil {
			rollbackVlanRIF()
			return nil, err
		}
		if _, err := ri.dataplane.TableEntryAdd(ctx, fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), IngressVRFTable).
			AppendEntry(
				fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE).WithUint64(id))),
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(req.GetVirtualRouterId()),
			).Build()); err != nil {
			rollbackVlanRIF()
			return nil, err
		}
		if _, err := ri.dataplane.TableEntryAdd(ctx, fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), SRCMACTable).AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(id))),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_SRC).WithValue(req.GetSrcMacAddress()),
		).Build()); err != nil {
			rollbackVlanRIF()
			return nil, err
		}
		if err := ri.macTracker.acquire(ctx, req.GetSrcMacAddress()); err != nil {
			rollbackVlanRIF()
			return nil, err
		}
		return &saipb.CreateRouterInterfaceResponse{Oid: id}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown interface type: %v", req.GetType())
	}
	fwdCtx, err := ri.dataplane.FindContext(&fwdpb.ContextId{Id: ri.dataplane.ID()})
	if err != nil {
		return nil, err
	}
	obj, err := fwdCtx.Objects.FindID(&fwdpb.ObjectId{Id: fmt.Sprint(req.GetPortId())})
	if err != nil {
		return nil, err
	}

	inCounter := ifaceCounterID(id, true)
	outCounter := ifaceCounterID(id, false)

	_, err = ri.dataplane.FlowCounterCreate(ctx, &fwdpb.FlowCounterCreateRequest{
		ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
		Id:        &fwdpb.FlowCounterId{ObjectId: &fwdpb.ObjectId{Id: inCounter}},
	})
	if err != nil {
		return nil, err
	}
	_, err = ri.dataplane.FlowCounterCreate(ctx, &fwdpb.FlowCounterCreateRequest{
		ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
		Id:        &fwdpb.FlowCounterId{ObjectId: &fwdpb.ObjectId{Id: outCounter}},
	})
	if err != nil {
		return nil, err
	}

	inReq := fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), inputIfaceTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(uint64(obj.NID())),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithBytes(binary.BigEndian.AppendUint16(nil, vlanID)),
			)),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE).WithUint64Value(id),
			fwdconfig.FlowCounterAction(inCounter),
		).Build()

	if vlanID != 0 {
		inReq.Entries[0].Actions = append(inReq.Entries[0].Actions, &fwdpb.ActionDesc{
			ActionType: fwdpb.ActionType_ACTION_TYPE_DECAP,
			Action: &fwdpb.ActionDesc_Decap{
				Decap: &fwdpb.DecapActionDesc{
					HeaderId: fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN,
				},
			},
		})
	}

	// Link the port to the interface.
	_, err = ri.dataplane.TableEntryAdd(ctx, inReq)
	if err != nil {
		return nil, err
	}

	outReq := fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), outputIfaceTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(id))),
			fwdconfig.TransmitAction(fmt.Sprint(req.GetPortId())),
			fwdconfig.FlowCounterAction(outCounter),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TARGET_EGRESS_PORT).WithUint64Value(req.GetPortId()),
		).Build()

	if vlanID != 0 {
		outReq.Entries[0].Actions = append(outReq.Entries[0].Actions,
			fwdconfig.Action(fwdconfig.EncapAction(fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN)).Build(),
			fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithValue(binary.BigEndian.AppendUint16(nil, vlanID))).Build(),
		)
	}

	_, err = ri.dataplane.TableEntryAdd(ctx, outReq)
	if err != nil {
		return nil, err
	}

	// Link the interface to a VRF.
	_, err = ri.dataplane.TableEntryAdd(ctx, fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), IngressVRFTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE).WithUint64(id))),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_VRF).WithUint64Value(req.GetVirtualRouterId()),
		).Build())
	if err != nil {
		return nil, err
	}

	// Give the interface a SMAC.
	_, err = ri.dataplane.TableEntryAdd(ctx, fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), SRCMACTable).AppendEntry(
		fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(id))),
		fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_SRC).WithValue(req.GetSrcMacAddress()),
	).Build())
	if err != nil {
		return nil, err
	}

	if err := ri.macTracker.acquire(ctx, req.GetSrcMacAddress()); err != nil {
		return nil, err
	}

	return &saipb.CreateRouterInterfaceResponse{Oid: id}, nil
}

func (ri *routerInterface) RemoveRouterInterface(ctx context.Context, req *saipb.RemoveRouterInterfaceRequest) (*saipb.RemoveRouterInterfaceResponse, error) {
	resp := &saipb.GetRouterInterfaceAttributeResponse{}
	err := ri.mgr.PopulateAttributes(&saipb.GetRouterInterfaceAttributeRequest{
		Oid:      req.GetOid(),
		AttrType: []saipb.RouterInterfaceAttr{saipb.RouterInterfaceAttr_ROUTER_INTERFACE_ATTR_TYPE},
	}, resp)
	if err != nil {
		return nil, err
	}

	allAttr := &saipb.RouterInterfaceAttribute{}
	if err := ri.mgr.PopulateAllAttributes(fmt.Sprint(req.GetOid()), allAttr); err != nil {
		return nil, err
	}

	switch resp.GetAttr().GetType() {
	case saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_LOOPBACK:
		if err := ri.macTracker.release(ctx, allAttr.GetSrcMacAddress()); err != nil {
			slog.WarnContext(ctx, "failed to remove MyMacTable entry for RouterInterface", "err", err)
		}
		return &saipb.RemoveRouterInterfaceResponse{}, nil

	case saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_VLAN:
		ri.mu.Lock()
		info := ri.vlanRIFs[req.GetOid()]
		lastOnVlan := false
		if info != nil {
			delete(ri.vlanRIFs, req.GetOid())
			if rifs := ri.vlanToRIFs[info.vlanOID]; rifs != nil {
				delete(rifs, req.GetOid())
				if len(rifs) == 0 {
					delete(ri.vlanToRIFs, info.vlanOID)
					lastOnVlan = true
				}
			}
		}
		ri.mu.Unlock()

		vlanOID := allAttr.GetVlanId()
		var vid uint32
		if info != nil {
			vlanOID = info.vlanOID
			vid = info.vid
		} else {
			vid, _ = ri.resolveVlanID(vlanOID)
		}

		if ri.vlan != nil {
			for _, m := range ri.vlan.membersForVlan(vlanOID) {
				if err := ri.removeVlanMemberInput(ctx, vid, m); err != nil {
					slog.WarnContext(ctx, "failed to remove inputIfaceTable entry for VLAN RouterInterface", "err", err)
				}
				if m.Mode == saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
					if err := ri.removeVlanMemberEgressTag(ctx, vid, m.PortID); err != nil {
						slog.WarnContext(ctx, "failed to remove egressVlanTable entry for VLAN RouterInterface", "err", err)
					}
				}
			}
		}
		if lastOnVlan {
			if _, err := ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), vlanFloodTable).
				AppendEntry(
					fwdconfig.EntryDesc(fwdconfig.ExactEntry(
						fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_16).
							WithBytes(binary.BigEndian.AppendUint16(nil, uint16(vid))),
					)),
				).Build()); err != nil {
				slog.WarnContext(ctx, "failed to remove vlanFloodTable entry for RouterInterface", "err", err)
			}
		}

		if _, err := ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), outputIfaceTable).
			AppendEntry(
				fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetOid()))),
			).Build()); err != nil {
			slog.WarnContext(ctx, "failed to remove outputIfaceTable entry for RouterInterface", "err", err)
		}
		if _, err := ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), IngressVRFTable).
			AppendEntry(
				fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE).WithUint64(req.GetOid()))),
			).Build()); err != nil {
			slog.WarnContext(ctx, "failed to remove IngressVRFTable entry for RouterInterface", "err", err)
		}
		if _, err := ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), SRCMACTable).AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetOid()))),
		).Build()); err != nil {
			slog.WarnContext(ctx, "failed to remove SRCMACTable entry for RouterInterface", "err", err)
		}
		if err := ri.macTracker.release(ctx, allAttr.GetSrcMacAddress()); err != nil {
			slog.WarnContext(ctx, "failed to remove MyMacTable entry for RouterInterface", "err", err)
		}
		return &saipb.RemoveRouterInterfaceResponse{}, nil
	}

	portResp := &saipb.GetRouterInterfaceAttributeResponse{}
	if err := ri.mgr.PopulateAttributes(&saipb.GetRouterInterfaceAttributeRequest{
		Oid:      req.GetOid(),
		AttrType: []saipb.RouterInterfaceAttr{saipb.RouterInterfaceAttr_ROUTER_INTERFACE_ATTR_PORT_ID},
	}, portResp); err != nil {
		return nil, err
	}

	var vlanID uint16
	if resp.GetAttr().GetType() == saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_SUB_PORT {
		vlanResp := &saipb.GetRouterInterfaceAttributeResponse{}
		err := ri.mgr.PopulateAttributes(&saipb.GetRouterInterfaceAttributeRequest{
			Oid:      req.GetOid(),
			AttrType: []saipb.RouterInterfaceAttr{saipb.RouterInterfaceAttr_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID},
		}, vlanResp)
		if err != nil {
			return nil, err
		}
		vlanID = uint16(vlanResp.GetAttr().GetOuterVlanId())
	}

	nid, err := ri.dataplane.ObjectNID(ctx, &fwdpb.ObjectNIDRequest{
		ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
		ObjectId:  &fwdpb.ObjectId{Id: fmt.Sprint(portResp.GetAttr().GetPortId())},
	})
	if err != nil {
		return nil, err
	}

	_, err = ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), inputIfaceTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(nid.GetNid()),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithBytes(binary.BigEndian.AppendUint16(nil, vlanID)),
			)),
		).Build())
	if err != nil {
		slog.WarnContext(ctx, "failed to remove inputIfaceTable entry for RouterInterface", "err", err)
	}

	_, err = ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), outputIfaceTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetOid()))),
		).Build())
	if err != nil {
		slog.WarnContext(ctx, "failed to remove outputIfaceTable entry for RouterInterface", "err", err)
	}

	// Link the interface to a VRF.
	_, err = ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), IngressVRFTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_INPUT_IFACE).WithUint64(req.GetOid()))),
		).Build())
	if err != nil {
		slog.WarnContext(ctx, "failed to remove IngressVRFTable entry for RouterInterface", "err", err)
	}

	// Give the interface a SMAC.
	_, err = ri.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(ri.dataplane.ID(), SRCMACTable).AppendEntry(
		fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetOid()))),
	).Build())
	if err != nil {
		slog.WarnContext(ctx, "failed to remove SRCMACTable entry for RouterInterface", "err", err)
	}

	if err := ri.macTracker.release(ctx, allAttr.GetSrcMacAddress()); err != nil {
		slog.WarnContext(ctx, "failed to remove MyMacTable entry for RouterInterface", "err", err)
	}

	return &saipb.RemoveRouterInterfaceResponse{}, nil
}

func (ri *routerInterface) SetRouterInterfaceAttribute(ctx context.Context, req *saipb.SetRouterInterfaceAttributeRequest) (*saipb.SetRouterInterfaceAttributeResponse, error) {
	if req.SrcMacAddress != nil {
		ri.mu.Lock()
		defer ri.mu.Unlock()
		if !ri.mgr.Exists(fmt.Sprint(req.GetOid())) {
			return nil, status.Errorf(codes.NotFound, "router interface %d not found", req.GetOid())
		}
		oldAttr := &saipb.RouterInterfaceAttribute{}
		if err := ri.mgr.PopulateAllAttributes(fmt.Sprint(req.GetOid()), oldAttr); err != nil {
			return nil, err
		}
		if oldAttr.GetType() != saipb.RouterInterfaceType_ROUTER_INTERFACE_TYPE_LOOPBACK {
			if _, err := ri.dataplane.TableEntryAdd(ctx, fwdconfig.TableEntryAddRequest(ri.dataplane.ID(), SRCMACTable).AppendEntry(
				fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_OUTPUT_IFACE).WithUint64(req.GetOid()))),
				fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_SRC).WithValue(req.GetSrcMacAddress()),
			).Build()); err != nil {
				return nil, err
			}
		}
		if err := ri.macTracker.replace(ctx, oldAttr.GetSrcMacAddress(), req.GetSrcMacAddress()); err != nil {
			return nil, err
		}
		ri.mgr.StoreAttributes(req.GetOid(), &saipb.RouterInterfaceAttribute{
			SrcMacAddress: req.SrcMacAddress,
		})
	}
	return &saipb.SetRouterInterfaceAttributeResponse{}, nil
}

func (ri *routerInterface) GetRouterInterfaceStats(ctx context.Context, req *saipb.GetRouterInterfaceStatsRequest) (*saipb.GetRouterInterfaceStatsResponse, error) {
	counters, err := ri.dataplane.FlowCounterQuery(ctx, &fwdpb.FlowCounterQueryRequest{
		ContextId: &fwdpb.ContextId{Id: ri.dataplane.ID()},
		Ids: []*fwdpb.FlowCounterId{{
			ObjectId: &fwdpb.ObjectId{Id: ifaceCounterID(req.GetOid(), true)},
		}, {
			ObjectId: &fwdpb.ObjectId{Id: ifaceCounterID(req.GetOid(), false)},
		}},
	})
	if err != nil {
		return nil, err
	}

	vals := []uint64{}

	for _, counter := range req.GetCounterIds() {
		switch counter {
		case saipb.RouterInterfaceStat_ROUTER_INTERFACE_STAT_IN_OCTETS:
			vals = append(vals, counters.GetCounters()[0].Octets)
		case saipb.RouterInterfaceStat_ROUTER_INTERFACE_STAT_IN_PACKETS:
			vals = append(vals, counters.GetCounters()[0].Packets)
		case saipb.RouterInterfaceStat_ROUTER_INTERFACE_STAT_OUT_OCTETS:
			vals = append(vals, counters.GetCounters()[1].Octets)
		case saipb.RouterInterfaceStat_ROUTER_INTERFACE_STAT_OUT_PACKETS:
			vals = append(vals, counters.GetCounters()[1].Packets)
		default: // TODO: Support more stats.
			vals = append(vals, 0)
		}
	}

	return &saipb.GetRouterInterfaceStatsResponse{Values: vals}, nil
}

func (ri *routerInterface) CreateRouterInterfaces(ctx context.Context, req *saipb.CreateRouterInterfacesRequest) (*saipb.CreateRouterInterfacesResponse, error) {
	resp := &saipb.CreateRouterInterfacesResponse{}
	for _, r := range req.GetReqs() {
		id, err := attrmgr.InvokeAndSave(ctx, ri.mgr, ri.CreateRouterInterface, r)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, id)
	}
	return resp, nil
}

func (ri *routerInterface) RemoveRouterInterfaces(ctx context.Context, req *saipb.RemoveRouterInterfacesRequest) (*saipb.RemoveRouterInterfacesResponse, error) {
	resp := &saipb.RemoveRouterInterfacesResponse{}
	for _, r := range req.GetReqs() {
		id, err := attrmgr.InvokeAndSave(ctx, ri.mgr, ri.RemoveRouterInterface, r)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, id)
	}
	return resp, nil
}

// vlanMember contains the info of a VLAN member.
type vlanMember struct {
	Oid          uint64
	PortID       uint64
	Vid          uint32
	Mode         saipb.VlanTaggingMode
	BridgePortID uint64
}

type vlan struct {
	mu sync.Mutex
	saipb.UnimplementedVlanServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
	ri        *routerInterface
	oidByVId  map[uint32]uint64                 // VID -> VLAN_OID
	vlans     map[uint64]map[uint64]*vlanMember // VLAN_OID -> VLAN_Member_OID (port)
}

func newVlan(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *vlan {
	v := &vlan{
		mgr:       mgr,
		dataplane: dataplane,
		oidByVId:  map[uint32]uint64{},
		vlans:     map[uint64]map[uint64]*vlanMember{},
	}
	saipb.RegisterVlanServer(s, v)
	return v
}

func (vlan *vlan) vidByOid(oid uint64) (uint32, error) {
	vlan.mu.Lock()
	defer vlan.mu.Unlock()
	for v, o := range vlan.oidByVId {
		if o == oid {
			return v, nil
		}
	}
	return 0, fmt.Errorf("cannot find VLAN with OID %d", oid)
}

func (vlan *vlan) membersForVlanLocked(vlanOID uint64) []*vlanMember {
	membersMap := vlan.vlans[vlanOID]
	members := make([]*vlanMember, 0, len(membersMap))
	for _, m := range membersMap {
		cp := *m
		members = append(members, &cp)
	}
	slices.SortFunc(members, func(a, b *vlanMember) int {
		if a.Oid < b.Oid {
			return -1
		}
		if a.Oid > b.Oid {
			return 1
		}
		return 0
	})
	return members
}

func (vlan *vlan) membersForVlan(vlanOID uint64) []*vlanMember {
	vlan.mu.Lock()
	defer vlan.mu.Unlock()
	return vlan.membersForVlanLocked(vlanOID)
}

func (vlan *vlan) untaggedMemberByPortId(oid uint64) *vlanMember {
	vlan.mu.Lock()
	defer vlan.mu.Unlock()
	for _, v := range vlan.vlans {
		for _, member := range v {
			if member.PortID == oid && member.Mode != saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
				return member
			}
		}
	}
	return nil
}

func (vlan *vlan) hasMember(vlanOID, portID uint64) bool {
	vlan.mu.Lock()
	defer vlan.mu.Unlock()
	for _, m := range vlan.vlans[vlanOID] {
		if m.PortID == portID {
			return true
		}
	}
	return false
}

func (vlan *vlan) oidByVid(vid uint32) (uint64, bool) {
	vlan.mu.Lock()
	defer vlan.mu.Unlock()
	oid, ok := vlan.oidByVId[vid]
	return oid, ok
}

func (vlan *vlan) CreateVlan(ctx context.Context, r *saipb.CreateVlanRequest) (*saipb.CreateVlanResponse, error) {
	if _, ok := vlan.oidByVid(r.GetVlanId()); ok {
		return nil, fmt.Errorf("found existing VLAN %d", r.GetVlanId())
	}
	id := vlan.mgr.NextID()
	vlan.mgr.SetType(fmt.Sprint(id), saipb.ObjectType_OBJECT_TYPE_VLAN)
	req := &saipb.GetSwitchAttributeRequest{Oid: r.GetSwitch(), AttrType: []saipb.SwitchAttr{saipb.SwitchAttr_SWITCH_ATTR_DEFAULT_STP_INST_ID}}
	resp := &saipb.GetSwitchAttributeResponse{}

	if err := vlan.mgr.PopulateAttributes(req, resp); err != nil {
		return nil, err
	}

	attrs := &saipb.VlanAttribute{
		MemberList:                         []uint64{},
		StpInstance:                        resp.Attr.DefaultStpInstId,
		VlanId:                             r.VlanId,
		UnknownNonIpMcastOutputGroupId:     proto.Uint64(0),
		UnknownIpv4McastOutputGroupId:      proto.Uint64(0),
		UnknownIpv6McastOutputGroupId:      proto.Uint64(0),
		UnknownLinklocalMcastOutputGroupId: proto.Uint64(0),
		IngressAcl:                         proto.Uint64(0),
		EgressAcl:                          proto.Uint64(0),
		UnknownUnicastFloodGroup:           proto.Uint64(0),
		UnknownMulticastFloodGroup:         proto.Uint64(0),
		BroadcastFloodGroup:                proto.Uint64(0),
		TamObject:                          []uint64{},
	}
	vlan.mgr.StoreAttributes(id, attrs)
	vlan.mu.Lock()
	vlan.vlans[id] = map[uint64]*vlanMember{}
	vlan.oidByVId[r.GetVlanId()] = id
	vlan.mu.Unlock()
	return &saipb.CreateVlanResponse{
		Oid: id,
	}, nil
}

func (vlan *vlan) RemoveVlan(ctx context.Context, r *saipb.RemoveVlanRequest) (*saipb.RemoveVlanResponse, error) {
	vId, err := vlan.vidByOid(r.GetOid())
	if err != nil {
		return nil, fmt.Errorf("cannot find VLAN ID for OID %d", r.GetOid())
	}
	if vId == DefaultVlanId {
		return nil, fmt.Errorf("cannot remove default VLAN")
	}

	vlan.mu.Lock()
	var memberOids []uint64
	for mOid := range vlan.vlans[r.GetOid()] {
		memberOids = append(memberOids, mOid)
	}
	vlan.mu.Unlock()

	for _, mOid := range memberOids {
		_, err := attrmgr.InvokeAndSave(ctx, vlan.mgr, vlan.RemoveVlanMember, &saipb.RemoveVlanMemberRequest{
			Oid: mOid,
		})
		if err != nil {
			return nil, err
		}
	}
	// Update the internal map.
	vlan.mu.Lock()
	delete(vlan.vlans, r.GetOid())
	delete(vlan.oidByVId, vId)
	vlan.mu.Unlock()
	return &saipb.RemoveVlanResponse{}, nil
}

func (vlan *vlan) SetVlanAttribute(ctx context.Context, req *saipb.SetVlanAttributeRequest) (*saipb.SetVlanAttributeResponse, error) {
	return &saipb.SetVlanAttributeResponse{}, nil
}

func (vlan *vlan) GetVlanAttribute(ctx context.Context, req *saipb.GetVlanAttributeRequest) (*saipb.GetVlanAttributeResponse, error) {
	return &saipb.GetVlanAttributeResponse{}, nil
}

func (vlan *vlan) CreateVlanMember(ctx context.Context, r *saipb.CreateVlanMemberRequest) (*saipb.CreateVlanMemberResponse, error) {
	vOid := r.GetVlanId()
	vId, err := vlan.vidByOid(vOid)
	if err != nil {
		return nil, err
	}

	// Get the port ID from the bridge port.
	bpAttrReq := &saipb.GetBridgePortAttributeRequest{
		Oid:      r.GetBridgePortId(),
		AttrType: []saipb.BridgePortAttr{saipb.BridgePortAttr_BRIDGE_PORT_ATTR_PORT_ID},
	}
	bpAttrResp := &saipb.GetBridgePortAttributeResponse{}
	if err := vlan.mgr.PopulateAttributes(bpAttrReq, bpAttrResp); err != nil {
		return nil, err
	}

	portID := bpAttrResp.GetAttr().GetPortId()
	if vlan.hasMember(vOid, portID) {
		return nil, status.Errorf(codes.AlreadyExists, "port %d is already a member of vlan %d", portID, vOid)
	}

	// Only untagged ports have a single default/native VLAN and migrate between VLANs.
	var prevUntagged *vlanMember
	if r.GetVlanTaggingMode() != saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
		prevUntagged = vlan.untaggedMemberByPortId(portID)
	}

	mOid := vlan.mgr.NextID()
	nid, err := vlan.dataplane.ObjectNID(ctx, &fwdpb.ObjectNIDRequest{
		ContextId: &fwdpb.ContextId{Id: vlan.dataplane.ID()},
		ObjectId:  &fwdpb.ObjectId{Id: fmt.Sprint(portID)},
	})
	if err != nil {
		slog.InfoContext(ctx, "Failed to find NID for port", "port_id", portID, "err", err)
		return nil, err
	}

	vlanAttrReq := &saipb.GetVlanAttributeRequest{Oid: vOid, AttrType: []saipb.VlanAttr{saipb.VlanAttr_VLAN_ATTR_MEMBER_LIST}}
	vlanAttrResp := &saipb.GetVlanAttributeResponse{}
	if err := vlan.mgr.PopulateAttributes(vlanAttrReq, vlanAttrResp); err != nil {
		return nil, err
	}
	oldMemberList := slices.Clone(vlanAttrResp.GetAttr().GetMemberList())

	// Evict prior untagged membership BEFORE programming/adding the new VLAN member so
	// onVlanMemberRemoved on prevUntagged never removes the inputIfaceTable binding for the new VLAN's RIF.
	var preVlanOid uint64
	var oldPreMemberList []uint64
	if prevUntagged != nil {
		preVlanOid, _ = vlan.oidByVid(prevUntagged.Vid)
		preAttrReq := &saipb.GetVlanAttributeRequest{Oid: preVlanOid, AttrType: []saipb.VlanAttr{saipb.VlanAttr_VLAN_ATTR_MEMBER_LIST}}
		preAttrResp := &saipb.GetVlanAttributeResponse{}
		if err := vlan.mgr.PopulateAttributes(preAttrReq, preAttrResp); err != nil {
			return nil, err
		}
		oldPreMemberList = slices.Clone(preAttrResp.GetAttr().GetMemberList())
		newMemList := make([]uint64, 0, len(oldPreMemberList))
		for _, i := range oldPreMemberList {
			if i != prevUntagged.Oid {
				newMemList = append(newMemList, i)
			}
		}
		preAttrResp.GetAttr().MemberList = newMemList
		vlan.mgr.StoreAttributes(preVlanOid, preAttrResp.GetAttr())
		vlan.mu.Lock()
		delete(vlan.vlans[preVlanOid], prevUntagged.Oid)
		oldRemaining := vlan.membersForVlanLocked(preVlanOid)
		vlan.mu.Unlock()
		if vlan.ri != nil {
			vlan.ri.onVlanMemberRemoved(ctx, preVlanOid, prevUntagged, oldRemaining)
		}
	}

	restorePrevUntagged := func(restoreVlanTable bool) {
		if prevUntagged == nil {
			return
		}
		if restoreVlanTable {
			restoreReq := fwdconfig.TableEntryAddRequest(vlan.dataplane.ID(), VlanTable).AppendEntry(
				fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(nid.GetNid())))).Build()
			restoreReq.Entries[0].Actions = []*fwdpb.ActionDesc{
				fwdconfig.Action(fwdconfig.EncapAction(fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN)).Build(),
				fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithUint64Value(uint64(prevUntagged.Vid))).Build(),
			}
			_, _ = vlan.dataplane.TableEntryAdd(ctx, restoreReq)
		}
		vlan.mgr.StoreAttributes(preVlanOid, &saipb.VlanAttribute{MemberList: oldPreMemberList})
		vlan.mu.Lock()
		vlan.vlans[preVlanOid][prevUntagged.Oid] = prevUntagged
		restoredMembers := vlan.membersForVlanLocked(preVlanOid)
		vlan.mu.Unlock()
		if vlan.ri != nil {
			_ = vlan.ri.onVlanMemberAdded(ctx, preVlanOid, prevUntagged, restoredMembers)
		}
	}

	// Program VlanTable when adding an untagged member or the first tagged membership
	// (so an untagged native VLAN entry is not overwritten by subsequent tagged memberships).
	programVlanTable := r.GetVlanTaggingMode() != saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED || vlan.untaggedMemberByPortId(portID) == nil
	if programVlanTable {
		vlanReq := fwdconfig.TableEntryAddRequest(vlan.dataplane.ID(), VlanTable).AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(nid.GetNid())))).Build()
		if r.GetVlanTaggingMode() != saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
			vlanReq.Entries[0].Actions = []*fwdpb.ActionDesc{
				fwdconfig.Action(fwdconfig.EncapAction(fwdpb.PacketHeaderId_PACKET_HEADER_ID_ETHERNET_VLAN)).Build(),
				fwdconfig.Action(fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_VLAN_TAG).WithUint64Value(uint64(vId))).Build(),
			}
		}
		if _, err := vlan.dataplane.TableEntryAdd(ctx, vlanReq); err != nil {
			restorePrevUntagged(false)
			return nil, err
		}
	}
	// Update the attributes and internal data.
	vlanAttrResp.GetAttr().MemberList = append(vlanAttrResp.GetAttr().MemberList, mOid)
	vlan.mgr.StoreAttributes(vOid, vlanAttrResp.GetAttr())
	newMember := &vlanMember{
		Oid:          mOid,
		PortID:       portID,
		Vid:          vId,
		Mode:         r.GetVlanTaggingMode(),
		BridgePortID: r.GetBridgePortId(),
	}
	vlan.mu.Lock()
	vlan.vlans[vOid][mOid] = newMember
	newMembers := vlan.membersForVlanLocked(vOid)
	vlan.mu.Unlock()

	if vlan.ri != nil {
		if err := vlan.ri.onVlanMemberAdded(ctx, vOid, newMember, newMembers); err != nil {
			vlan.mu.Lock()
			delete(vlan.vlans[vOid], mOid)
			vlan.mu.Unlock()
			vlan.mgr.StoreAttributes(vOid, &saipb.VlanAttribute{MemberList: oldMemberList})
			if prevUntagged != nil {
				restorePrevUntagged(programVlanTable)
			} else if programVlanTable {
				_, _ = vlan.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(vlan.dataplane.ID(), VlanTable).AppendEntry(
					fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(nid.GetNid())))).Build())
			}
			return nil, err
		}
	}

	vlan.mgr.SetType(fmt.Sprint(mOid), saipb.ObjectType_OBJECT_TYPE_VLAN_MEMBER)
	return &saipb.CreateVlanMemberResponse{Oid: mOid}, nil
}

func (vlan *vlan) RemoveVlanMember(ctx context.Context, r *saipb.RemoveVlanMemberRequest) (*saipb.RemoveVlanMemberResponse, error) {
	vlan.mu.Lock()

	var member *vlanMember
	var targetVlanOid uint64
	found := false

	for vlanOid, members := range vlan.vlans {
		if m, ok := members[r.GetOid()]; ok {
			cp := *m
			member = &cp
			targetVlanOid = vlanOid
			found = true
			break
		}
	}

	if !found {
		vlan.mu.Unlock()
		return nil, fmt.Errorf("cannot find member with OID %d", r.GetOid())
	}
	vlan.mu.Unlock()

	if member.Mode != saipb.VlanTaggingMode_VLAN_TAGGING_MODE_TAGGED {
		nid, err := vlan.dataplane.ObjectNID(ctx, &fwdpb.ObjectNIDRequest{
			ContextId: &fwdpb.ContextId{Id: vlan.dataplane.ID()},
			ObjectId:  &fwdpb.ObjectId{Id: fmt.Sprint(member.PortID)},
		})
		if err != nil {
			slog.InfoContext(ctx, "Failed to find NID for port", "bridge_port", member.PortID, "err", err)
			return nil, err
		}
		if _, err := vlan.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(vlan.dataplane.ID(), VlanTable).AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_PORT_INPUT).WithUint64(nid.GetNid())))).Build()); err != nil {
			return nil, err
		}
	}

	vlan.mu.Lock()
	delete(vlan.vlans[targetVlanOid], r.GetOid())
	remaining := vlan.membersForVlanLocked(targetVlanOid)
	vlan.mu.Unlock()

	if vlan.ri != nil {
		vlan.ri.onVlanMemberRemoved(ctx, targetVlanOid, member, remaining)
	}

	return &saipb.RemoveVlanMemberResponse{}, nil
}

func (vlan *vlan) CreateVlanMembers(ctx context.Context, r *saipb.CreateVlanMembersRequest) (*saipb.CreateVlanMembersResponse, error) {
	resp := &saipb.CreateVlanMembersResponse{}
	for _, req := range r.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, vlan.mgr, vlan.CreateVlanMember, req)
		if err != nil {
			return nil, err
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, nil
}

func (vlan *vlan) Reset() {
	slog.Info("resetting vlan")
	vlan.oidByVId = map[uint32]uint64{}
	vlan.vlans = map[uint64]map[uint64]*vlanMember{}
}

type bridge struct {
	saipb.UnimplementedBridgeServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
}

func newBridge(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *bridge {
	b := &bridge{
		mgr:       mgr,
		dataplane: dataplane,
	}
	saipb.RegisterBridgeServer(s, b)
	return b
}

func (b *bridge) CreateBridge(ctx context.Context, req *saipb.CreateBridgeRequest) (*saipb.CreateBridgeResponse, error) {
	id := b.mgr.NextID()
	b.mgr.SetType(fmt.Sprint(id), saipb.ObjectType_OBJECT_TYPE_BRIDGE)
	attrs := &saipb.BridgeAttribute{
		PortList:                   []uint64{},
		UnknownUnicastFloodGroup:   proto.Uint64(0),
		UnknownMulticastFloodGroup: proto.Uint64(0),
		BroadcastFloodGroup:        proto.Uint64(0),
	}
	b.mgr.StoreAttributes(id, attrs)
	return &saipb.CreateBridgeResponse{
		Oid: id,
	}, nil
}

func (b *bridge) RemoveBridge(ctx context.Context, req *saipb.RemoveBridgeRequest) (*saipb.RemoveBridgeResponse, error) {
	return &saipb.RemoveBridgeResponse{}, nil
}

func (b *bridge) SetBridgeAttribute(ctx context.Context, req *saipb.SetBridgeAttributeRequest) (*saipb.SetBridgeAttributeResponse, error) {
	return &saipb.SetBridgeAttributeResponse{}, nil
}

func (b *bridge) GetBridgeAttribute(ctx context.Context, req *saipb.GetBridgeAttributeRequest) (*saipb.GetBridgeAttributeResponse, error) {
	return &saipb.GetBridgeAttributeResponse{}, nil
}

func (b *bridge) GetBridgeStats(ctx context.Context, req *saipb.GetBridgeStatsRequest) (*saipb.GetBridgeStatsResponse, error) {
	return &saipb.GetBridgeStatsResponse{}, nil
}

func (b *bridge) CreateBridgePort(ctx context.Context, req *saipb.CreateBridgePortRequest) (*saipb.CreateBridgePortResponse, error) {
	oid := b.mgr.NextID()
	b.mgr.SetType(fmt.Sprint(oid), saipb.ObjectType_OBJECT_TYPE_BRIDGE_PORT)
	adminState := req.GetAdminState()
	attrs := &saipb.BridgePortAttribute{
		AdminState: proto.Bool(adminState),
		PortId:     proto.Uint64(req.GetPortId()),
		Type:       req.Type,
	}
	b.mgr.StoreAttributes(oid, attrs)
	return &saipb.CreateBridgePortResponse{
		Oid: oid,
	}, nil
}

func (b *bridge) RemoveBridgePort(ctx context.Context, req *saipb.RemoveBridgePortRequest) (*saipb.RemoveBridgePortResponse, error) {
	return &saipb.RemoveBridgePortResponse{}, nil
}

func (b *bridge) SetBridgePortAttribute(ctx context.Context, req *saipb.SetBridgePortAttributeRequest) (*saipb.SetBridgePortAttributeResponse, error) {
	return &saipb.SetBridgePortAttributeResponse{}, nil
}

func (b *bridge) GetBridgePortAttribute(ctx context.Context, req *saipb.GetBridgePortAttributeRequest) (*saipb.GetBridgePortAttributeResponse, error) {
	return &saipb.GetBridgePortAttributeResponse{}, nil
}

func (b *bridge) GetBridgePortStats(ctx context.Context, req *saipb.GetBridgePortStatsRequest) (*saipb.GetBridgePortStatsResponse, error) {
	return &saipb.GetBridgePortStatsResponse{}, nil
}

type hash struct {
	saipb.UnimplementedHashServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
}

func newHash(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *hash {
	m := &hash{
		mgr:       mgr,
		dataplane: dataplane,
	}
	saipb.RegisterHashServer(s, m)
	return m
}

func convertHashFields(list []saipb.NativeHashField) ([]*fwdpb.PacketFieldId, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("got 0 hash fields")
	}

	fields := []*fwdpb.PacketFieldId{}
	for _, field := range list {
		switch field {
		case saipb.NativeHashField_NATIVE_HASH_FIELD_SRC_IP, saipb.NativeHashField_NATIVE_HASH_FIELD_SRC_IPV4, saipb.NativeHashField_NATIVE_HASH_FIELD_SRC_IPV6:
			fields = append(fields, &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_SRC}})
		case saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IP, saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IPV4, saipb.NativeHashField_NATIVE_HASH_FIELD_DST_IPV6:
			fields = append(fields, &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP_ADDR_DST}})
		case saipb.NativeHashField_NATIVE_HASH_FIELD_L4_SRC_PORT:
			fields = append(fields, &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_SRC}})
		case saipb.NativeHashField_NATIVE_HASH_FIELD_L4_DST_PORT:
			fields = append(fields, &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_L4_PORT_DST}})
		case saipb.NativeHashField_NATIVE_HASH_FIELD_IPV6_FLOW_LABEL:
			fields = append(fields, &fwdpb.PacketFieldId{Field: &fwdpb.PacketField{FieldNum: fwdpb.PacketFieldNum_PACKET_FIELD_NUM_IP6_FLOW}})
		default:
			return nil, fmt.Errorf("unsupported hash field: %v", field)
		}
	}
	return fields, nil
}

func (h *hash) CreateHash(_ context.Context, req *saipb.CreateHashRequest) (*saipb.CreateHashResponse, error) {
	id := h.mgr.NextID()

	// Creating a hash doesn't affect the forwarding pipeline, just validate the arguments.
	_, err := convertHashFields(req.GetNativeHashFieldList())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &saipb.CreateHashResponse{Oid: id}, nil
}

type virtualRouter struct {
	saipb.UnimplementedVirtualRouterServer
	mgr        *attrmgr.AttrMgr
	dataplane  switchDataplaneAPI
	macTracker *macTracker
	mu         sync.Mutex
}

func newVirtualRouter(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server, tracker *macTracker) *virtualRouter {
	vr := &virtualRouter{
		mgr:        mgr,
		dataplane:  dataplane,
		macTracker: tracker,
	}
	saipb.RegisterVirtualRouterServer(s, vr)
	return vr
}

func (vr *virtualRouter) CreateVirtualRouter(ctx context.Context, req *saipb.CreateVirtualRouterRequest) (*saipb.CreateVirtualRouterResponse, error) {
	id := vr.mgr.NextID()
	if err := vr.macTracker.acquire(ctx, req.GetSrcMacAddress()); err != nil {
		return nil, err
	}

	return &saipb.CreateVirtualRouterResponse{Oid: id}, nil
}

func (vr *virtualRouter) RemoveVirtualRouter(ctx context.Context, req *saipb.RemoveVirtualRouterRequest) (*saipb.RemoveVirtualRouterResponse, error) {
	attr := &saipb.VirtualRouterAttribute{}
	if err := vr.mgr.PopulateAllAttributes(fmt.Sprint(req.GetOid()), attr); err == nil {
		if err := vr.macTracker.release(ctx, attr.GetSrcMacAddress()); err != nil {
			slog.WarnContext(ctx, "failed to remove MyMacTable entry for VirtualRouter", "err", err)
		}
	}
	return &saipb.RemoveVirtualRouterResponse{}, nil
}

func (vr *virtualRouter) SetVirtualRouterAttribute(ctx context.Context, req *saipb.SetVirtualRouterAttributeRequest) (*saipb.SetVirtualRouterAttributeResponse, error) {
	if req.SrcMacAddress != nil {
		vr.mu.Lock()
		defer vr.mu.Unlock()
		if !vr.mgr.Exists(fmt.Sprint(req.GetOid())) {
			return nil, status.Errorf(codes.NotFound, "virtual router %d not found", req.GetOid())
		}
		oldAttr := &saipb.VirtualRouterAttribute{}
		if err := vr.mgr.PopulateAllAttributes(fmt.Sprint(req.GetOid()), oldAttr); err != nil {
			return nil, err
		}
		if err := vr.macTracker.replace(ctx, oldAttr.GetSrcMacAddress(), req.GetSrcMacAddress()); err != nil {
			return nil, err
		}
		vr.mgr.StoreAttributes(req.GetOid(), &saipb.VirtualRouterAttribute{
			SrcMacAddress: req.SrcMacAddress,
		})
	}
	return &saipb.SetVirtualRouterAttributeResponse{}, nil
}

type rpfGroup struct {
	saipb.UnimplementedRpfGroupServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
}

func newRpfGroup(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server) *rpfGroup {
	rpf := &rpfGroup{
		mgr:       mgr,
		dataplane: dataplane,
	}
	saipb.RegisterRpfGroupServer(s, rpf)
	return rpf
}

func (rpf *rpfGroup) CreateRpfGroup(context.Context, *saipb.CreateRpfGroupRequest) (*saipb.CreateRpfGroupResponse, error) {
	id := rpf.mgr.NextID()

	return &saipb.CreateRpfGroupResponse{Oid: id}, nil
}

func (rpf *rpfGroup) CreateRpfGroupMember(context.Context, *saipb.CreateRpfGroupMemberRequest) (*saipb.CreateRpfGroupMemberResponse, error) {
	id := rpf.mgr.NextID()

	return &saipb.CreateRpfGroupMemberResponse{Oid: id}, nil
}

func (rpf *rpfGroup) RemoveRpfGroup(context.Context, *saipb.RemoveRpfGroupRequest) (*saipb.RemoveRpfGroupResponse, error) {
	return &saipb.RemoveRpfGroupResponse{}, nil
}

func (rpf *rpfGroup) RemoveRpfGroupMember(context.Context, *saipb.RemoveRpfGroupMemberRequest) (*saipb.RemoveRpfGroupMemberResponse, error) {
	return &saipb.RemoveRpfGroupMemberResponse{}, nil
}
