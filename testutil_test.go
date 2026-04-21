package envector

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	es2pb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2"
	es2epb "github.com/CryptoLabInc/envector-go-sdk/internal/transport/pb/es2e"
)

type fakeES2E struct {
	es2epb.UnimplementedES2EServiceServer

	mu sync.Mutex

	loadKeyCalls       []string
	unloadKeyCalls     []string
	deleteKeyCalls     []string
	getKeyListCalls    int
	getIndexListCalls  int
	registerKeyChunks  [][]byte
	registerKeyInfo    *es2pb.KeyInfo
	createIndexInfo    *es2pb.IndexInfo
	deleteIndexCalls   []string
	batchInsertPackets [][]*es2pb.PackedVectors
	batchInsertIndex   string
	getMetadataReq     *es2epb.GetMetadataRequest
	innerProductReq    *es2epb.InnerProductRequest

	indexList     []string
	keyList       []string
	itemIDs       []int64
	metadataRows  []*es2pb.Metadata
	ipResponses   []*es2epb.InnerProductResponse
	createIndexRC es2pb.ReturnCode
	headerErr     es2pb.ReturnCode

	// Per-RPC ReturnCode overrides. When non-zero, the specific handler
	// returns that ReturnCode instead of falling back to headerErr/Success.
	getKeyListRC  es2pb.ReturnCode
	registerKeyRC es2pb.ReturnCode
	unloadKeyRC   es2pb.ReturnCode
	loadKeyRC     es2pb.ReturnCode

	// lastIncomingMD captures the metadata of the most recent unary RPC
	// so tests can assert header injection.
	lastIncomingMD metadata.MD

	onInnerProduct func(req *es2epb.InnerProductRequest, send func(*es2epb.InnerProductResponse) error) error
}

func okHeader() *es2pb.ResponseHeader {
	return &es2pb.ResponseHeader{ReturnCode: es2pb.ReturnCode_Success}
}

func (f *fakeES2E) header() *es2pb.ResponseHeader {
	if f.headerErr != 0 {
		return &es2pb.ResponseHeader{ReturnCode: f.headerErr, ErrorMessage: "fake error"}
	}
	return okHeader()
}

func (f *fakeES2E) headerFor(rc es2pb.ReturnCode) *es2pb.ResponseHeader {
	if rc != 0 {
		return &es2pb.ResponseHeader{ReturnCode: rc, ErrorMessage: "fake error"}
	}
	return f.header()
}

func (f *fakeES2E) captureMD(ctx context.Context) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.lastIncomingMD = md
	}
}

func (f *fakeES2E) GetIndexList(ctx context.Context, req *es2epb.GetIndexListRequest) (*es2epb.GetIndexListResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getIndexListCalls++
	return &es2epb.GetIndexListResponse{Header: f.header(), IndexNames: append([]string{}, f.indexList...)}, nil
}

func (f *fakeES2E) GetKeyList(ctx context.Context, req *es2epb.GetKeyListRequest) (*es2epb.GetKeyListResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captureMD(ctx)
	f.getKeyListCalls++
	return &es2epb.GetKeyListResponse{Header: f.headerFor(f.getKeyListRC), KeyId: append([]string{}, f.keyList...)}, nil
}

func (f *fakeES2E) LoadKey(ctx context.Context, req *es2epb.LoadKeyRequest) (*es2epb.LoadKeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadKeyCalls = append(f.loadKeyCalls, req.GetKeyId())
	return &es2epb.LoadKeyResponse{Header: f.headerFor(f.loadKeyRC)}, nil
}

func (f *fakeES2E) UnloadKey(ctx context.Context, req *es2epb.UnloadKeyRequest) (*es2epb.UnloadKeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unloadKeyCalls = append(f.unloadKeyCalls, req.GetKeyId())
	return &es2epb.UnloadKeyResponse{Header: f.headerFor(f.unloadKeyRC)}, nil
}

func (f *fakeES2E) DeleteKey(ctx context.Context, req *es2epb.DeleteKeyRequest) (*es2epb.DeleteKeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteKeyCalls = append(f.deleteKeyCalls, req.GetKeyId())
	return &es2epb.DeleteKeyResponse{Header: f.header()}, nil
}

func (f *fakeES2E) DeleteIndex(ctx context.Context, req *es2epb.DeleteIndexRequest) (*es2epb.DeleteIndexResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteIndexCalls = append(f.deleteIndexCalls, req.GetIndexName())
	return &es2epb.DeleteIndexResponse{Header: f.header()}, nil
}

func (f *fakeES2E) GetMetadata(ctx context.Context, req *es2epb.GetMetadataRequest) (*es2epb.GetMetadataResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getMetadataReq = req
	return &es2epb.GetMetadataResponse{Header: f.header(), Metadata: append([]*es2pb.Metadata{}, f.metadataRows...)}, nil
}

func (f *fakeES2E) RegisterKey(stream grpc.ClientStreamingServer[es2epb.RegisterKeyRequest, es2epb.RegisterKeyResponse]) error {
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.registerKeyInfo = msg.GetKeyInfo()
		f.registerKeyChunks = append(f.registerKeyChunks, append([]byte(nil), msg.GetKey().GetValue()...))
		f.mu.Unlock()
	}
	return stream.SendAndClose(&es2epb.RegisterKeyResponse{Header: f.headerFor(f.registerKeyRC)})
}

func (f *fakeES2E) CreateIndex(stream grpc.ClientStreamingServer[es2epb.CreateIndexRequest, es2epb.CreateIndexResponse]) error {
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.createIndexInfo = msg.GetIndexInfo()
		f.mu.Unlock()
	}
	h := f.header()
	if f.createIndexRC != 0 {
		h = &es2pb.ResponseHeader{ReturnCode: f.createIndexRC, ErrorMessage: "create_index failed"}
	}
	return stream.SendAndClose(&es2epb.CreateIndexResponse{Header: h})
}

func (f *fakeES2E) BatchInsertData(stream grpc.ClientStreamingServer[es2epb.BatchInsertDataRequest, es2epb.BatchInsertDataResponse]) error {
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.batchInsertIndex = msg.GetIndexName()
		f.batchInsertPackets = append(f.batchInsertPackets, msg.GetPackedVectors())
		f.mu.Unlock()
	}
	return stream.SendAndClose(&es2epb.BatchInsertDataResponse{Header: f.header(), ItemIds: append([]int64{}, f.itemIDs...)})
}

func (f *fakeES2E) InnerProduct(req *es2epb.InnerProductRequest, stream grpc.ServerStreamingServer[es2epb.InnerProductResponse]) error {
	f.mu.Lock()
	f.innerProductReq = req
	hook := f.onInnerProduct
	responses := append([]*es2epb.InnerProductResponse(nil), f.ipResponses...)
	f.mu.Unlock()

	if hook != nil {
		return hook(req, stream.Send)
	}
	for _, r := range responses {
		if err := stream.Send(r); err != nil {
			return err
		}
	}
	return nil
}

func newFakeClient(t *testing.T) (*Client, *fakeES2E) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	fake := &fakeES2E{}
	srv := grpc.NewServer()
	es2epb.RegisterES2EServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &Client{
		conn: conn,
		stub: es2epb.NewES2EServiceClient(conn),
		opts: clientOptions{Address: "bufnet"},
	}, fake
}
