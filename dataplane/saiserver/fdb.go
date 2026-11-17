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
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/openconfig/gnmi/errlist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/openconfig/lemming/dataplane/forwarding/fwdconfig"
	saipb "github.com/openconfig/lemming/dataplane/proto/sai"
	"github.com/openconfig/lemming/dataplane/saiserver/attrmgr"
	fwdpb "github.com/openconfig/lemming/proto/forwarding"
)

type fdbEntryKey struct {
	vid uint32
	mac [6]byte
}

type fdb struct {
	saipb.UnimplementedFdbServer
	mgr       *attrmgr.AttrMgr
	dataplane switchDataplaneAPI
	vlan      *vlan
	mu        sync.Mutex
	entries   map[fdbEntryKey]*saipb.CreateFdbEntryRequest
}

func newFdb(mgr *attrmgr.AttrMgr, dataplane switchDataplaneAPI, s *grpc.Server, v *vlan) (*fdb, error) {
	f := &fdb{
		mgr:       mgr,
		dataplane: dataplane,
		vlan:      v,
		entries:   make(map[fdbEntryKey]*saipb.CreateFdbEntryRequest),
	}
	saipb.RegisterFdbServer(s, f)
	return f, nil
}

func (f *fdb) resolveVlanID(bvID uint64) (uint32, error) {
	if f.vlan != nil {
		if vid, err := f.vlan.vidByOid(bvID); err == nil {
			return vid, nil
		}
	}
	vResp := &saipb.GetVlanAttributeResponse{}
	if err := f.mgr.PopulateAttributes(&saipb.GetVlanAttributeRequest{
		Oid:      bvID,
		AttrType: []saipb.VlanAttr{saipb.VlanAttr_VLAN_ATTR_VLAN_ID},
	}, vResp); err == nil && vResp.GetAttr().VlanId != nil {
		return vResp.GetAttr().GetVlanId(), nil
	}
	return 0, status.Errorf(codes.NotFound, "VLAN or bridge %d not found", bvID)
}

func (f *fdb) resolvePortID(bridgePortID uint64) (uint64, error) {
	if bridgePortID == 0 {
		return 0, status.Errorf(codes.InvalidArgument, "bridge_port_id is required")
	}
	bpResp := &saipb.GetBridgePortAttributeResponse{}
	if err := f.mgr.PopulateAttributes(&saipb.GetBridgePortAttributeRequest{
		Oid:      bridgePortID,
		AttrType: []saipb.BridgePortAttr{saipb.BridgePortAttr_BRIDGE_PORT_ATTR_PORT_ID},
	}, bpResp); err != nil {
		return 0, err
	}
	return bpResp.GetAttr().GetPortId(), nil
}

func (f *fdb) programFdbEntry(ctx context.Context, vid uint32, mac [6]byte, action saipb.PacketAction, bridgePortID uint64) error {
	var actions []fwdconfig.ActionDescBuilder
	switch action {
	case saipb.PacketAction_PACKET_ACTION_DROP:
		actions = append(actions, fwdconfig.DropAction())
	case saipb.PacketAction_PACKET_ACTION_UNSPECIFIED, saipb.PacketAction_PACKET_ACTION_FORWARD:
		portID, err := f.resolvePortID(bridgePortID)
		if err != nil {
			return err
		}
		actions = append(actions,
			fwdconfig.TransmitAction(fmt.Sprint(portID)),
			fwdconfig.UpdateAction(fwdpb.UpdateType_UPDATE_TYPE_SET, fwdpb.PacketFieldNum_PACKET_FIELD_NUM_TARGET_EGRESS_PORT).WithUint64Value(portID),
		)
	default:
		return status.Errorf(codes.InvalidArgument, "unsupported FDB packet action: %v", action)
	}
	req := fwdconfig.TableEntryAddRequest(f.dataplane.ID(), fdbTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_16).
					WithBytes(binary.BigEndian.AppendUint16(nil, uint16(vid))),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST).WithBytes(mac[:]),
			)),
			actions...,
		).Build()
	_, err := f.dataplane.TableEntryAdd(ctx, req)
	return err
}

func (f *fdb) removeFdbTableEntry(ctx context.Context, vid uint32, mac [6]byte) error {
	_, err := f.dataplane.TableEntryRemove(ctx, fwdconfig.TableEntryRemoveRequest(f.dataplane.ID(), fdbTable).
		AppendEntry(
			fwdconfig.EntryDesc(fwdconfig.ExactEntry(
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_PACKET_ATTRIBUTE_16).
					WithBytes(binary.BigEndian.AppendUint16(nil, uint16(vid))),
				fwdconfig.PacketFieldBytes(fwdpb.PacketFieldNum_PACKET_FIELD_NUM_ETHER_MAC_DST).WithBytes(mac[:]),
			)),
		).Build())
	return err
}

func parseFdbEntryKey(entry *saipb.FdbEntry) ([6]byte, error) {
	var mac [6]byte
	if entry == nil || len(entry.GetMacAddress()) != 6 {
		return mac, status.Errorf(codes.InvalidArgument, "fdb entry requires a 6-byte MAC address")
	}
	copy(mac[:], entry.GetMacAddress())
	return mac, nil
}

func (f *fdb) CreateFdbEntry(ctx context.Context, req *saipb.CreateFdbEntryRequest) (*saipb.CreateFdbEntryResponse, error) {
	mac, err := parseFdbEntryKey(req.GetEntry())
	if err != nil {
		return nil, err
	}
	vid, err := f.resolveVlanID(req.GetEntry().GetBvId())
	if err != nil {
		return nil, err
	}
	if err := f.programFdbEntry(ctx, vid, mac, req.GetPacketAction(), req.GetBridgePortId()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.entries[fdbEntryKey{vid: vid, mac: mac}] = proto.Clone(req).(*saipb.CreateFdbEntryRequest)
	f.mu.Unlock()
	return &saipb.CreateFdbEntryResponse{}, nil
}

func (f *fdb) RemoveFdbEntry(ctx context.Context, req *saipb.RemoveFdbEntryRequest) (*saipb.RemoveFdbEntryResponse, error) {
	mac, err := parseFdbEntryKey(req.GetEntry())
	if err != nil {
		return nil, err
	}
	vid, err := f.resolveVlanID(req.GetEntry().GetBvId())
	if err != nil {
		return nil, err
	}
	if err := f.removeFdbTableEntry(ctx, vid, mac); err != nil {
		return nil, err
	}
	f.mu.Lock()
	delete(f.entries, fdbEntryKey{vid: vid, mac: mac})
	f.mu.Unlock()
	return &saipb.RemoveFdbEntryResponse{}, nil
}

func (f *fdb) SetFdbEntryAttribute(ctx context.Context, req *saipb.SetFdbEntryAttributeRequest) (*saipb.SetFdbEntryAttributeResponse, error) {
	mac, err := parseFdbEntryKey(req.GetEntry())
	if err != nil {
		return nil, err
	}
	vid, err := f.resolveVlanID(req.GetEntry().GetBvId())
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	existing := f.entries[fdbEntryKey{vid: vid, mac: mac}]
	if existing == nil {
		f.mu.Unlock()
		return nil, status.Errorf(codes.NotFound, "fdb entry %x in vlan %d not found", mac, vid)
	}
	merged := proto.Clone(existing).(*saipb.CreateFdbEntryRequest)
	f.mu.Unlock()

	if req.Type != nil {
		merged.Type = req.Type
	}
	if req.PacketAction != nil {
		merged.PacketAction = req.PacketAction
	}
	if req.BridgePortId != nil {
		merged.BridgePortId = req.BridgePortId
	}
	if err := f.programFdbEntry(ctx, vid, mac, merged.GetPacketAction(), merged.GetBridgePortId()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.entries[fdbEntryKey{vid: vid, mac: mac}] = merged
	f.mu.Unlock()
	return &saipb.SetFdbEntryAttributeResponse{}, nil
}

func (f *fdb) CreateFdbEntries(ctx context.Context, req *saipb.CreateFdbEntriesRequest) (*saipb.CreateFdbEntriesResponse, error) {
	var errs errlist.List
	resp := &saipb.CreateFdbEntriesResponse{
		Resps: make([]*saipb.CreateFdbEntryResponse, 0, len(req.GetReqs())),
	}
	for _, r := range req.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, f.mgr, f.CreateFdbEntry, r)
		errs.Add(err)
		if res == nil {
			res = &saipb.CreateFdbEntryResponse{}
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, errs.Err()
}

func (f *fdb) RemoveFdbEntries(ctx context.Context, req *saipb.RemoveFdbEntriesRequest) (*saipb.RemoveFdbEntriesResponse, error) {
	var errs errlist.List
	resp := &saipb.RemoveFdbEntriesResponse{
		Resps: make([]*saipb.RemoveFdbEntryResponse, 0, len(req.GetReqs())),
	}
	for _, r := range req.GetReqs() {
		res, err := attrmgr.InvokeAndSave(ctx, f.mgr, f.RemoveFdbEntry, r)
		errs.Add(err)
		if res == nil {
			res = &saipb.RemoveFdbEntryResponse{}
		}
		resp.Resps = append(resp.Resps, res)
	}
	return resp, errs.Err()
}

func (f *fdb) FlushFdbEntries(ctx context.Context, req *saipb.FlushFdbEntriesRequest) (*saipb.FlushFdbEntriesResponse, error) {
	var targetVid uint32
	var filterBv bool
	if req.BvId != nil {
		vid, err := f.resolveVlanID(req.GetBvId())
		if err != nil {
			return nil, err
		}
		targetVid = vid
		filterBv = true
	}

	flushType := saipb.FdbFlushEntryType_FDB_FLUSH_ENTRY_TYPE_DYNAMIC
	if req.EntryType != nil {
		flushType = req.GetEntryType()
	}

	f.mu.Lock()
	var toRemove []fdbEntryKey
	for k, e := range f.entries {
		if filterBv && k.vid != targetVid {
			continue
		}
		if req.BridgePortId != nil && e.GetBridgePortId() != req.GetBridgePortId() {
			continue
		}
		switch flushType {
		case saipb.FdbFlushEntryType_FDB_FLUSH_ENTRY_TYPE_DYNAMIC:
			if e.GetType() != saipb.FdbEntryType_FDB_ENTRY_TYPE_DYNAMIC {
				continue
			}
		case saipb.FdbFlushEntryType_FDB_FLUSH_ENTRY_TYPE_STATIC:
			if e.GetType() != saipb.FdbEntryType_FDB_ENTRY_TYPE_STATIC {
				continue
			}
		}
		toRemove = append(toRemove, k)
	}
	f.mu.Unlock()

	var errs errlist.List
	for _, k := range toRemove {
		if err := f.removeFdbTableEntry(ctx, k.vid, k.mac); err != nil {
			errs.Add(err)
		}
		f.mu.Lock()
		delete(f.entries, k)
		f.mu.Unlock()
	}
	if err := errs.Err(); err != nil {
		return nil, err
	}
	return &saipb.FlushFdbEntriesResponse{}, nil
}

func (f *fdb) Reset() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = make(map[fdbEntryKey]*saipb.CreateFdbEntryRequest)
}
