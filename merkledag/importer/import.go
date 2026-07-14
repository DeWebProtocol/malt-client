// Package merkledagimport imports local UnixFS data into an IPFS-style Merkle DAG.
package importer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	chunker "github.com/ipfs/boxo/chunker"
	merkledag "github.com/ipfs/boxo/ipld/merkledag"
	unixfs "github.com/ipfs/boxo/ipld/unixfs"
	balanced "github.com/ipfs/boxo/ipld/unixfs/importer/balanced"
	helpers "github.com/ipfs/boxo/ipld/unixfs/importer/helpers"
	trickle "github.com/ipfs/boxo/ipld/unixfs/importer/trickle"
	unixfsio "github.com/ipfs/boxo/ipld/unixfs/io"
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	mh "github.com/multiformats/go-multihash"
)

const (
	ModelUnixFS = "unixfs"

	FileLayoutBalanced = "balanced"
	FileLayoutTrickle  = "trickle"

	DirLayoutBasic    = "basic"
	DirLayoutHAMT     = "hamt"
	DirLayoutAdaptive = "adaptive"
)

const defaultChunkSize = 262144

// Options controls how local data is materialized as a Merkle DAG.
type Options struct {
	Model       string
	Layout      string
	FileLayout  string
	DirLayout   string
	ChunkSize   int
	HAMTFanout  int
	RawFileLeaf bool
	Ignore      PathFilter
}

// PathFilter lets callers apply local import policy without storing that policy
// in the resulting Merkle DAG.
type PathFilter interface {
	LoadDirectoryRules(localDir string) error
	Ignored(localPath string, isDir bool) (bool, error)
}

// RootedPathFilter can load per-directory rules through the same confined
// filesystem root used by the importer. Implementations should treat readFile
// names as relative to localDir.
type RootedPathFilter interface {
	PathFilter
	LoadDirectoryRulesRooted(localDir string, readFile func(name string) ([]byte, error)) error
}

// Result describes the imported Merkle DAG root and local input stats.
type Result struct {
	Root  string
	Files int
	Bytes int64
}

// File describes one virtual file to materialize into a UnixFS DAG.
type File struct {
	Path string
	Data []byte
	Mode fs.FileMode
}

// Store is the minimal CAS surface needed by the DAGService adapter.
type Store interface {
	PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error)
	Get(ctx context.Context, c cid.Cid) ([]byte, error)
}

// NewDAGService adapts a CAS store to the Boxo UnixFS DAGService interfaces.
func NewDAGService(store Store) ipld.DAGService {
	return &casDAGService{store: store}
}

// ImportPath imports localPath into the supplied CAS using Boxo's UnixFS DAG
// builders and returns the Merkle DAG root CID.
func ImportPath(ctx context.Context, store Store, localPath string, opts Options) (*Result, error) {
	if store == nil {
		return nil, fmt.Errorf("store is nil")
	}
	opts = normalizeOptions(opts)
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	abs, err := filepath.Abs(localPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path %q: %w", localPath, err)
	}
	inputInfo, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("lstat %s: %w", abs, err)
	}
	importer := &pathImporter{
		dag:   NewDAGService(store),
		opts:  opts,
		build: cid.Prefix{Version: 1, Codec: cid.DagProtobuf, MhType: mh.SHA2_256, MhLength: -1},
	}
	var root ipld.Node
	var files int
	var bytesUploaded int64
	if inputInfo.IsDir() {
		rootFS, openErr := os.OpenRoot(abs)
		if openErr != nil {
			return nil, fmt.Errorf("open import root %q: %w", abs, openErr)
		}
		defer rootFS.Close()
		openedInfo, statErr := rootFS.Stat(".")
		if statErr != nil {
			return nil, fmt.Errorf("stat import root %q: %w", abs, statErr)
		}
		if !sameEntry(inputInfo, openedInfo) {
			return nil, fmt.Errorf("directory changed while importing: %s", abs)
		}
		root, files, bytesUploaded, err = importer.importDirectory(ctx, rootFS, abs, openedInfo)
	} else {
		baseDir := filepath.Dir(abs)
		baseName := filepath.Base(abs)
		if abs == baseDir {
			baseName = "."
		}
		rootFS, openErr := os.OpenRoot(baseDir)
		if openErr != nil {
			return nil, fmt.Errorf("open import root %q: %w", baseDir, openErr)
		}
		defer rootFS.Close()
		root, files, bytesUploaded, err = importer.importPath(ctx, rootFS, baseName, abs, inputInfo)
	}
	if err != nil {
		return nil, err
	}
	return &Result{
		Root:  root.Cid().String(),
		Files: files,
		Bytes: bytesUploaded,
	}, nil
}

// ImportFiles imports a virtual repository snapshot into the supplied CAS using
// Boxo's UnixFS DAG builders and returns the directory root CID.
func ImportFiles(ctx context.Context, store Store, files []File, opts Options) (*Result, error) {
	if store == nil {
		return nil, fmt.Errorf("store is nil")
	}
	opts = normalizeOptions(opts)
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	importer := &pathImporter{
		dag:   NewDAGService(store),
		opts:  opts,
		build: cid.Prefix{Version: 1, Codec: cid.DagProtobuf, MhType: mh.SHA2_256, MhLength: -1},
	}
	root, fileCount, bytesUploaded, err := importer.importFiles(ctx, files)
	if err != nil {
		return nil, err
	}
	return &Result{
		Root:  root.Cid().String(),
		Files: fileCount,
		Bytes: bytesUploaded,
	}, nil
}

func normalizeOptions(opts Options) Options {
	if opts.Model == "" {
		opts.Model = ModelUnixFS
	}
	if opts.FileLayout == "" {
		opts.FileLayout = FileLayoutBalanced
	}
	if opts.DirLayout == "" {
		opts.DirLayout = DirLayoutAdaptive
	}
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = defaultChunkSize
	}
	if opts.HAMTFanout <= 0 {
		opts.HAMTFanout = unixfsio.DefaultShardWidth
	}
	return opts
}

func validateOptions(opts Options) error {
	if opts.Model != ModelUnixFS {
		return fmt.Errorf("unsupported merkle-dag model %q", opts.Model)
	}
	if opts.Layout != "" {
		return fmt.Errorf("merkle-dag uses file-layout and dir-layout, not top-level layout %q", opts.Layout)
	}
	if opts.FileLayout != FileLayoutBalanced && opts.FileLayout != FileLayoutTrickle {
		return fmt.Errorf("unsupported merkle-dag unixfs file layout %q", opts.FileLayout)
	}
	if opts.DirLayout != DirLayoutBasic && opts.DirLayout != DirLayoutHAMT && opts.DirLayout != DirLayoutAdaptive {
		return fmt.Errorf("unsupported merkle-dag unixfs directory layout %q", opts.DirLayout)
	}
	return nil
}

type pathImporter struct {
	dag   ipld.DAGService
	opts  Options
	build cid.Prefix
}

func (i *pathImporter) importPath(ctx context.Context, root *os.Root, rootPath, localPath string, expected fs.FileInfo) (ipld.Node, int, int64, error) {
	if root == nil {
		return nil, 0, 0, fmt.Errorf("filesystem root is nil")
	}
	info, err := root.Lstat(rootPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("lstat %s: %w", localPath, err)
	}
	if expected != nil && !sameEntry(expected, info) {
		return nil, 0, 0, fmt.Errorf("path changed while importing: %s", localPath)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		node, targetBytes, err := i.importSymlink(ctx, root, rootPath, localPath, info)
		if err != nil {
			return nil, 0, 0, err
		}
		return node, 1, targetBytes, nil
	}
	if info.IsDir() {
		directoryRoot, err := root.OpenRoot(rootPath)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("open directory root %s: %w", localPath, err)
		}
		defer directoryRoot.Close()
		openedInfo, err := directoryRoot.Stat(".")
		if err != nil {
			return nil, 0, 0, fmt.Errorf("stat opened directory %s: %w", localPath, err)
		}
		if !sameEntry(info, openedInfo) {
			return nil, 0, 0, fmt.Errorf("directory changed while importing: %s", localPath)
		}
		return i.importDirectory(ctx, directoryRoot, localPath, openedInfo)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, 0, fmt.Errorf("only regular files and directories are supported: %s", localPath)
	}
	node, err := i.importFile(ctx, root, rootPath, localPath, info)
	if err != nil {
		return nil, 0, 0, err
	}
	return node, 1, info.Size(), nil
}

func (i *pathImporter) importSymlink(ctx context.Context, root *os.Root, rootPath, localPath string, info fs.FileInfo) (ipld.Node, int64, error) {
	target, err := root.Readlink(rootPath)
	if err != nil {
		return nil, 0, fmt.Errorf("read symlink %s: %w", localPath, err)
	}
	after, err := root.Lstat(rootPath)
	if err != nil || !sameEntry(info, after) {
		return nil, 0, fmt.Errorf("symlink changed while importing: %s", localPath)
	}
	data, err := unixfs.SymlinkData(target)
	if err != nil {
		return nil, 0, fmt.Errorf("encode unixfs symlink %s: %w", localPath, err)
	}
	node := merkledag.NodeWithData(data)
	if err := node.SetCidBuilder(i.build); err != nil {
		return nil, 0, fmt.Errorf("configure unixfs symlink cid for %s: %w", localPath, err)
	}
	if err := i.dag.Add(ctx, node); err != nil {
		return nil, 0, fmt.Errorf("store unixfs symlink %s: %w", localPath, err)
	}
	return node, int64(len(target)), nil
}

func (i *pathImporter) importFile(ctx context.Context, root *os.Root, rootPath, localPath string, info fs.FileInfo) (ipld.Node, error) {
	f, err := root.Open(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened file %s: %w", localPath, err)
	}
	if !openedInfo.Mode().IsRegular() || !stableFileInfo(info, openedInfo) {
		return nil, fmt.Errorf("file changed while importing: %s", localPath)
	}

	node, err := i.importFileReader(ctx, localPath, f, openedInfo.Mode(), openedInfo.ModTime())
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat imported file %s: %w", localPath, err)
	}
	if !stableFileInfo(openedInfo, after) {
		return nil, fmt.Errorf("file changed while importing: %s", localPath)
	}
	return node, nil
}

func (i *pathImporter) importFileReader(_ context.Context, name string, r io.Reader, mode fs.FileMode, modTime time.Time) (ipld.Node, error) {
	dbp := helpers.DagBuilderParams{
		Dagserv:     i.dag,
		Maxlinks:    helpers.DefaultLinksPerBlock,
		RawLeaves:   i.opts.RawFileLeaf,
		CidBuilder:  i.build,
		FileMode:    mode,
		FileModTime: modTime,
	}
	db, err := dbp.New(chunker.NewSizeSplitter(r, int64(i.opts.ChunkSize)))
	if err != nil {
		return nil, fmt.Errorf("create unixfs dag builder for %s: %w", name, err)
	}
	var root ipld.Node
	switch i.opts.FileLayout {
	case FileLayoutBalanced:
		root, err = balanced.Layout(db)
	case FileLayoutTrickle:
		root, err = trickle.Layout(db)
	default:
		return nil, fmt.Errorf("unsupported merkle-dag unixfs file layout %q", i.opts.FileLayout)
	}
	if err != nil {
		return nil, fmt.Errorf("build unixfs file dag for %s: %w", name, err)
	}
	return root, nil
}

type virtualDir struct {
	dirs  map[string]*virtualDir
	files map[string]File
}

func newVirtualDir() *virtualDir {
	return &virtualDir{
		dirs:  make(map[string]*virtualDir),
		files: make(map[string]File),
	}
}

func (d *virtualDir) add(file File) error {
	clean, err := cleanVirtualPath(file.Path)
	if err != nil {
		return err
	}
	parts := strings.Split(clean, "/")
	dir := d
	for _, part := range parts[:len(parts)-1] {
		if _, exists := dir.files[part]; exists {
			return fmt.Errorf("virtual path %q traverses file %q", clean, part)
		}
		child := dir.dirs[part]
		if child == nil {
			child = newVirtualDir()
			dir.dirs[part] = child
		}
		dir = child
	}
	name := parts[len(parts)-1]
	if _, ok := dir.files[name]; ok {
		return fmt.Errorf("duplicate virtual file path %q", clean)
	}
	if _, ok := dir.dirs[name]; ok {
		return fmt.Errorf("virtual file path %q conflicts with a directory", clean)
	}
	file.Path = clean
	dir.files[name] = file
	return nil
}

func cleanVirtualPath(raw string) (string, error) {
	trimmed := strings.Trim(filepath.ToSlash(raw), "/")
	clean := path.Clean(trimmed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("invalid virtual file path %q", raw)
	}
	return clean, nil
}

func (i *pathImporter) importFiles(ctx context.Context, files []File) (ipld.Node, int, int64, error) {
	root := newVirtualDir()
	for _, file := range files {
		if err := root.add(file); err != nil {
			return nil, 0, 0, err
		}
	}
	return i.importVirtualDirectory(ctx, ".", root)
}

func (i *pathImporter) importVirtualDirectory(ctx context.Context, name string, node *virtualDir) (ipld.Node, int, int64, error) {
	dir, err := i.newDirectory()
	if err != nil {
		return nil, 0, 0, err
	}

	var files int
	var bytesUploaded int64
	for _, childName := range sortedKeys(node.dirs) {
		child, childFiles, childBytes, err := i.importVirtualDirectory(ctx, childName, node.dirs[childName])
		if err != nil {
			return nil, 0, 0, err
		}
		if err := dir.AddChild(ctx, childName, child); err != nil {
			return nil, 0, 0, fmt.Errorf("add %s to virtual unixfs directory %s: %w", childName, name, err)
		}
		files += childFiles
		bytesUploaded += childBytes
	}
	for _, fileName := range sortedKeys(node.files) {
		file := node.files[fileName]
		child, err := i.importFileReader(ctx, file.Path, bytes.NewReader(file.Data), virtualFileMode(file.Mode), time.Time{})
		if err != nil {
			return nil, 0, 0, err
		}
		if err := dir.AddChild(ctx, fileName, child); err != nil {
			return nil, 0, 0, fmt.Errorf("add %s to virtual unixfs directory %s: %w", fileName, name, err)
		}
		files++
		bytesUploaded += int64(len(file.Data))
	}

	root, err := dir.GetNode()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("materialize virtual unixfs directory %s: %w", name, err)
	}
	if err := i.dag.Add(ctx, root); err != nil {
		return nil, 0, 0, fmt.Errorf("store virtual unixfs directory %s: %w", name, err)
	}
	return root, files, bytesUploaded, nil
}

func virtualFileMode(mode fs.FileMode) fs.FileMode {
	if mode == 0 {
		return 0o644
	}
	return mode
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (i *pathImporter) importDirectory(ctx context.Context, root *os.Root, localPath string, info fs.FileInfo) (ipld.Node, int, int64, error) {
	directoryFile, err := root.Open(".")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open directory %s: %w", localPath, err)
	}
	defer directoryFile.Close()
	openedInfo, err := directoryFile.Stat()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("stat opened directory %s: %w", localPath, err)
	}
	if !openedInfo.IsDir() || !sameEntry(info, openedInfo) {
		return nil, 0, 0, fmt.Errorf("directory changed while importing: %s", localPath)
	}
	dir, err := i.newDirectory()
	if err != nil {
		return nil, 0, 0, err
	}
	entries, err := directoryFile.ReadDir(-1)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read directory %s: %w", localPath, err)
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].Name() < entries[b].Name() })
	type entrySnapshot struct {
		name string
		info fs.FileInfo
	}
	snapshots := make([]entrySnapshot, 0, len(entries))
	for _, entry := range entries {
		childPath := filepath.Join(localPath, entry.Name())
		childInfo, err := root.Lstat(entry.Name())
		if err != nil {
			return nil, 0, 0, fmt.Errorf("stat directory entry %s: %w", childPath, err)
		}
		snapshots = append(snapshots, entrySnapshot{name: entry.Name(), info: childInfo})
	}
	if i.opts.Ignore != nil {
		var err error
		if rooted, ok := i.opts.Ignore.(RootedPathFilter); ok {
			err = rooted.LoadDirectoryRulesRooted(localPath, func(name string) ([]byte, error) {
				return root.ReadFile(name)
			})
		} else {
			err = i.opts.Ignore.LoadDirectoryRules(localPath)
		}
		if err != nil {
			return nil, 0, 0, err
		}
	}

	var files int
	var bytesUploaded int64
	for _, entry := range snapshots {
		childPath := filepath.Join(localPath, entry.name)
		if i.opts.Ignore != nil {
			ignored, err := i.opts.Ignore.Ignored(childPath, entry.info.IsDir())
			if err != nil {
				return nil, 0, 0, err
			}
			if ignored {
				continue
			}
		}
		child, childFiles, childBytes, err := i.importPath(ctx, root, entry.name, childPath, entry.info)
		if err != nil {
			return nil, 0, 0, err
		}
		if err := dir.AddChild(ctx, entry.name, child); err != nil {
			return nil, 0, 0, fmt.Errorf("add %s to unixfs directory %s: %w", entry.name, localPath, err)
		}
		files += childFiles
		bytesUploaded += childBytes
	}

	node, err := dir.GetNode()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("materialize unixfs directory %s: %w", localPath, err)
	}
	if err := i.dag.Add(ctx, node); err != nil {
		return nil, 0, 0, fmt.Errorf("store unixfs directory %s: %w", localPath, err)
	}
	return node, files, bytesUploaded, nil
}

func sameEntry(expected, actual fs.FileInfo) bool {
	if expected == nil || actual == nil {
		return false
	}
	return expected.Mode().Type() == actual.Mode().Type() && os.SameFile(expected, actual)
}

func stableFileInfo(before, after fs.FileInfo) bool {
	if !sameEntry(before, after) {
		return false
	}
	return before.Size() == after.Size() && before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}

func (i *pathImporter) newDirectory() (unixfsio.Directory, error) {
	opts := []unixfsio.DirectoryOption{
		unixfsio.WithCidBuilder(i.build),
		unixfsio.WithMaxHAMTFanout(i.opts.HAMTFanout),
	}
	switch i.opts.DirLayout {
	case DirLayoutHAMT:
		return unixfsio.NewHAMTDirectory(i.dag, 0, opts...)
	case DirLayoutBasic:
		return unixfsio.NewBasicDirectory(i.dag, opts...)
	case DirLayoutAdaptive:
		return unixfsio.NewDirectory(i.dag, opts...)
	default:
		return nil, fmt.Errorf("unsupported merkle-dag unixfs directory layout %q", i.opts.DirLayout)
	}
}

type casDAGService struct {
	store Store
}

func (s *casDAGService) Add(ctx context.Context, node ipld.Node) error {
	if node == nil {
		return nil
	}
	got, err := s.store.PutWithCodec(ctx, node.RawData(), node.Cid().Type())
	if err != nil {
		return err
	}
	if !got.Equals(node.Cid()) {
		return fmt.Errorf("stored block CID %s does not match DAG node CID %s", got, node.Cid())
	}
	return nil
}

func (s *casDAGService) AddMany(ctx context.Context, nodes []ipld.Node) error {
	for _, node := range nodes {
		if err := s.Add(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

func (s *casDAGService) Get(ctx context.Context, c cid.Cid) (ipld.Node, error) {
	data, err := s.store.Get(ctx, c)
	if err != nil {
		return nil, ipld.ErrNotFound{Cid: c}
	}
	block, err := blocks.NewBlockWithCid(data, c)
	if err != nil {
		return nil, err
	}
	switch c.Type() {
	case cid.Raw:
		return merkledag.DecodeRawBlock(block)
	case cid.DagProtobuf:
		return merkledag.DecodeProtobufBlock(block)
	default:
		return nil, fmt.Errorf("unsupported merkledag codec %d for %s", c.Type(), c)
	}
}

func (s *casDAGService) GetMany(ctx context.Context, cids []cid.Cid) <-chan *ipld.NodeOption {
	out := make(chan *ipld.NodeOption)
	go func() {
		defer close(out)
		for _, c := range cids {
			node, err := s.Get(ctx, c)
			select {
			case out <- &ipld.NodeOption{Node: node, Err: err}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (s *casDAGService) Remove(context.Context, cid.Cid) error {
	return nil
}

func (s *casDAGService) RemoveMany(context.Context, []cid.Cid) error {
	return nil
}
