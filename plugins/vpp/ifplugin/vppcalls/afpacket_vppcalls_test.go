// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vppcalls_test

import (
	"testing"

	"github.com/ligato/vpp-agent/plugins/vpp/binapi/af_packet"
	"github.com/ligato/vpp-agent/plugins/vpp/binapi/interfaces"
	"github.com/ligato/vpp-agent/plugins/vpp/ifplugin/vppcalls"
	if_api "github.com/ligato/vpp-agent/plugins/vpp/model/interfaces"
	"github.com/ligato/vpp-agent/tests/vppcallmock"
	. "github.com/onsi/gomega"
)

func TestAddAfPacketInterface(t *testing.T) {
	ctx := vppcallmock.SetupTestCtx(t)
	defer ctx.TeardownTestCtx()

	ctx.MockVpp.MockReply(&af_packet.AfPacketCreateReply{})
	ctx.MockVpp.MockReply(&interfaces.SwInterfaceTagAddDelReply{})

	ifIndex, err := vppcalls.AddAfPacketInterface("if1", &if_api.Interfaces_Interface_Afpacket{
		HostIfName: "host1",
	}, ctx.MockChannel, nil)

	Expect(err).To(BeNil())
	Expect(ifIndex).ToNot(BeNil())
	Expect(len(ctx.MockChannel.Msgs)).To(BeEquivalentTo(2))
	for i, msg := range ctx.MockChannel.Msgs {
		if i == 0 {
			vppMsg, ok := msg.(*af_packet.AfPacketCreate)
			Expect(ok).To(BeTrue())
			Expect(vppMsg).To(Equal(&af_packet.AfPacketCreate{
				HostIfName:      []byte("host1"),
				HwAddr:          nil,
				UseRandomHwAddr: 1,
			}))
		}
	}
}

func TestAddAfPacketInterfaceError(t *testing.T) {
	ctx := vppcallmock.SetupTestCtx(t)
	defer ctx.TeardownTestCtx()

	ctx.MockVpp.MockReply(&af_packet.AfPacketDeleteReply{})

	_, err := vppcalls.AddAfPacketInterface("if1", &if_api.Interfaces_Interface_Afpacket{
		HostIfName: "host1",
	}, ctx.MockChannel, nil)

	Expect(err).ToNot(BeNil())
}

func TestAddAfPacketInterfaceRetval(t *testing.T) {
	ctx := vppcallmock.SetupTestCtx(t)
	defer ctx.TeardownTestCtx()

	ctx.MockVpp.MockReply(&af_packet.AfPacketCreateReply{
		Retval: 1,
	})
	ctx.MockVpp.MockReply(&interfaces.SwInterfaceTagAddDelReply{})

	_, err := vppcalls.AddAfPacketInterface("if1", &if_api.Interfaces_Interface_Afpacket{
		HostIfName: "host1",
	}, ctx.MockChannel, nil)

	Expect(err).ToNot(BeNil())
}

func TestDeleteAfPacketInterface(t *testing.T) {
	ctx := vppcallmock.SetupTestCtx(t)
	defer ctx.TeardownTestCtx()

	ctx.MockVpp.MockReply(&af_packet.AfPacketDeleteReply{})
	ctx.MockVpp.MockReply(&interfaces.SwInterfaceTagAddDelReply{})

	err := vppcalls.DeleteAfPacketInterface("if1", 0, &if_api.Interfaces_Interface_Afpacket{
		HostIfName: "host1",
	}, ctx.MockChannel, nil)

	Expect(err).To(BeNil())
	Expect(len(ctx.MockChannel.Msgs)).To(BeEquivalentTo(2))
	for i, msg := range ctx.MockChannel.Msgs {
		if i == 0 {
			vppMsg, ok := msg.(*af_packet.AfPacketDelete)
			Expect(ok).To(BeTrue())
			Expect(vppMsg).To(Equal(&af_packet.AfPacketDelete{
				HostIfName: []byte("host1"),
			}))
		}
	}
}

func TestDeleteAfPacketInterfaceError(t *testing.T) {
	ctx := vppcallmock.SetupTestCtx(t)
	defer ctx.TeardownTestCtx()

	ctx.MockVpp.MockReply(&af_packet.AfPacketCreateReply{})

	err := vppcalls.DeleteAfPacketInterface("if1", 0, &if_api.Interfaces_Interface_Afpacket{
		HostIfName: "host1",
	}, ctx.MockChannel, nil)

	Expect(err).ToNot(BeNil())
}

func TestDeleteAfPacketInterfaceRetval(t *testing.T) {
	ctx := vppcallmock.SetupTestCtx(t)
	defer ctx.TeardownTestCtx()

	ctx.MockVpp.MockReply(&af_packet.AfPacketDeleteReply{
		Retval: 1,
	})
	ctx.MockVpp.MockReply(&interfaces.SwInterfaceTagAddDelReply{})

	err := vppcalls.DeleteAfPacketInterface("if1", 0, &if_api.Interfaces_Interface_Afpacket{
		HostIfName: "host1",
	}, ctx.MockChannel, nil)

	Expect(err).ToNot(BeNil())
}