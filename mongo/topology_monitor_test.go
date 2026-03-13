package mongo

import (
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/description"

	"testing"
)

func TestTopologyDescriptionEqual(t *testing.T) {
	d1 := description.Topology{}
	d2 := description.Topology{}
	assert.True(t, topologyDescriptionEqual(&d1, &d2))

	d1 = description.Topology{Kind: description.TopologyKindReplicaSet}
	d2 = description.Topology{Kind: description.TopologyKindReplicaSetNoPrimary}
	assert.False(t, topologyDescriptionEqual(&d1, &d2))

	d1 = description.Topology{Servers: []description.Server{{Addr: "addr1", Kind: description.ServerKindStandalone}}}
	d2 = description.Topology{Servers: []description.Server{{Addr: "addr2", Kind: description.ServerKindStandalone}}}
	assert.False(t, topologyDescriptionEqual(&d1, &d2))

	d1 = description.Topology{Servers: []description.Server{{Addr: "addr1", Kind: description.ServerKindStandalone}}}
	d2 = description.Topology{Servers: []description.Server{{Addr: "addr1", Kind: description.ServerKindMongos}}}
	assert.False(t, topologyDescriptionEqual(&d1, &d2))

	d1 = description.Topology{Servers: []description.Server{
		{Addr: "addr1", Kind: description.ServerKindStandalone},
		{Addr: "addr2", Kind: description.ServerKindMongos},
	}}
	d2 = description.Topology{Servers: []description.Server{
		{Addr: "addr2", Kind: description.ServerKindMongos},
		{Addr: "addr1", Kind: description.ServerKindStandalone},
	}}
	assert.True(t, topologyDescriptionEqual(&d1, &d2))
}
