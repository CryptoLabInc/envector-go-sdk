package envector

import (
	"context"
	"reflect"
	"testing"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
)

func TestGetIndexList_RoundTrip(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune", "vault"}

	got, err := c.GetIndexList(context.Background())
	if err != nil {
		t.Fatalf("GetIndexList: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"rune", "vault"}) {
		t.Errorf("got %v", got)
	}
}

func TestClient_Index_RequiresName(t *testing.T) {
	c, _ := newFakeClient(t)
	if _, err := c.Index(context.Background()); err == nil {
		t.Error("expected error when WithIndexName absent")
	}
}

func TestClient_Index_IdempotentWhenExisting(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}

	idx, err := c.Index(context.Background(), WithIndexName("rune"))
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if idx.Name() != "rune" {
		t.Errorf("Name = %q", idx.Name())
	}
	if fake.createIndexInfo != nil {
		t.Error("CreateIndex must not be called when index already exists")
	}
}

func TestClient_Index_CreatesWhenMissing(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = nil

	_, err := c.Index(context.Background(),
		WithIndexName("vault"),
		WithIndexKeys(openTestKeys(t)),
		WithIndexDim(1024),
		WithIndexType("FLAT"),
		WithIndexDescription("vault shard"),
	)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	info := fake.createIndexInfo
	if info == nil {
		t.Fatal("CreateIndex was not invoked")
	}
	if info.GetIndexName() != "vault" {
		t.Errorf("IndexName = %q", info.GetIndexName())
	}
	if info.GetDim() != 1024 {
		t.Errorf("Dim = %d", info.GetDim())
	}
	if info.GetIndexType() != es2pb.IndexType_FLAT {
		t.Errorf("IndexType = %v, want FLAT", info.GetIndexType())
	}
	if info.GetIndexEncryption() != "cipher" {
		t.Errorf("IndexEncryption = %q, want default cipher", info.GetIndexEncryption())
	}
	if info.GetQueryEncryption() != "plain" {
		t.Errorf("QueryEncryption = %q, want default plain", info.GetQueryEncryption())
	}
	if info.GetKeyId() != "test-key" {
		t.Errorf("KeyId = %q, want test-key", info.GetKeyId())
	}
}

func TestIndex_Drop(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}

	idx, _ := c.Index(context.Background(), WithIndexName("rune"))
	if err := idx.Drop(context.Background()); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if !reflect.DeepEqual(fake.deleteIndexCalls, []string{"rune"}) {
		t.Errorf("deleteIndexCalls = %v", fake.deleteIndexCalls)
	}
}

func TestIndex_GetMetadata(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.indexList = []string{"rune"}
	fake.metadataRows = []*es2pb.Metadata{
		{Id: 1, Data: `{"a":"first"}`},
		{Id: 2, Data: `{"a":"second"}`},
	}

	idx, _ := c.Index(context.Background(), WithIndexName("rune"))
	got, err := idx.GetMetadata(context.Background(),
		[]MetadataRef{{ShardIdx: 0, RowIdx: 1}, {ShardIdx: 0, RowIdx: 2}},
		[]string{"metadata"})
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	want := []Metadata{{ID: 1, Data: `{"a":"first"}`}, {ID: 2, Data: `{"a":"second"}`}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if fake.getMetadataReq.GetIndexName() != "rune" {
		t.Errorf("IndexName = %q", fake.getMetadataReq.GetIndexName())
	}
	if len(fake.getMetadataReq.GetIdx()) != 2 {
		t.Errorf("Idx len = %d", len(fake.getMetadataReq.GetIdx()))
	}
	if !reflect.DeepEqual(fake.getMetadataReq.GetOutputFields(), []string{"metadata"}) {
		t.Errorf("OutputFields = %v", fake.getMetadataReq.GetOutputFields())
	}
}

func TestCheckHeader_PropagatesServerError(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.headerErr = es2pb.ReturnCode_NoSuchIndex

	_, err := c.GetIndexList(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
