//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"

	"local/panel/internal/loadbalancestream"
)

// Fixed Linux UAPI prefixes, shared by supported little-endian amd64/arm64.
// These wrappers use GET_FD_BY_ID, OBJ_GET_INFO_BY_FD, GET_NEXT_KEY and LOOKUP
// only. They never load/attach/detach a filter, update a map, change a capability
// or select a cgroup from HTTP data.
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h
type streamFilterGetID struct{ ID, NextID, Flags uint32 }
type streamFilterInfoRequest struct {
	FD, Bytes uint32
	Info      uint64
}
type streamFilterProgramInfo struct {
	Type, ID                uint32
	Tag                     [8]byte
	JitedBytes, XlatedBytes uint32
	JitedCode, XlatedCode   uint64
	LoadTime                uint64
	UID, MapCount           uint32
	MapIDs                  uint64
	Name                    [16]byte
	IfIndex, Flags          uint32
}
type streamFilterMapInfo struct {
	Type, ID, KeyBytes, ValueBytes, MaxEntries, Flags uint32
	Name                                              [16]byte
	IfIndex, BTFVmlinuxValueID                        uint32
	NetnsDevice, NetnsInode                           uint64
	BTFID, BTFKeyID, BTFValueID, BTFVmlinuxID         uint32
	Extra                                             uint64
}
type streamFilterMapRequest struct {
	FD, Reserved uint32
	Key, Value   uint64
	Flags        uint64
}

func streamFilterNativeABI() bool {
	return (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") &&
		unsafe.Sizeof(streamFilterGetID{}) == 12 &&
		unsafe.Sizeof(streamFilterInfoRequest{}) == 16 &&
		unsafe.Offsetof(streamFilterInfoRequest{}.Info) == 8 &&
		unsafe.Sizeof(streamFilterProgramInfo{}) == 88 &&
		unsafe.Offsetof(streamFilterProgramInfo{}.MapIDs) == 56 &&
		unsafe.Offsetof(streamFilterProgramInfo{}.Name) == 64 &&
		unsafe.Sizeof(streamFilterMapInfo{}) == 88 &&
		unsafe.Offsetof(streamFilterMapInfo{}.Extra) == 80 &&
		unsafe.Sizeof(streamFilterMapRequest{}) == 32
}

func streamFilterObjectFD(id uint32, program bool) (int, error) {
	if !streamFilterNativeABI() || id == 0 {
		return -1, loadbalancestream.ErrService
	}
	command := uintptr(unix.BPF_MAP_GET_FD_BY_ID)
	if program {
		command = unix.BPF_PROG_GET_FD_BY_ID
	}
	query := streamFilterGetID{ID: id}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&query)), unsafe.Sizeof(query))
	if errno != 0 {
		return -1, loadbalancestream.ErrService
	}
	if fd > 1<<31-1 || query != (streamFilterGetID{ID: id}) {
		unix.Close(int(fd))
		return -1, loadbalancestream.ErrService
	}
	return int(fd), nil
}

func streamFilterInfoReply(before, after streamFilterInfoRequest, minimum uint32) bool {
	// Linux5.10 reports an80-byte map-info body; newer kernels add the
	// optional map_extra field. Both expose every required definition field.
	// Program-info needs its complete fixed88-byte prefix on either kernel.
	return (minimum == 80 || minimum == 88) && before.Bytes == 88 &&
		after.FD == before.FD && after.Info == before.Info &&
		after.Bytes >= minimum && after.Bytes <= before.Bytes && after.Bytes%8 == 0
}

func streamFilterObjectInfo(fd int, pointer unsafe.Pointer, size uintptr, minimum uint32) error {
	if !streamFilterNativeABI() || fd < 0 || fd > 1<<31-1 || pointer == nil || size != 88 || (minimum != 80 && minimum != 88) {
		return loadbalancestream.ErrService
	}
	query := streamFilterInfoRequest{FD: uint32(fd), Bytes: uint32(size), Info: uint64(uintptr(pointer))}
	expected := query
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&query)), unsafe.Sizeof(query))
	runtime.KeepAlive(pointer)
	if errno != 0 || !streamFilterInfoReply(expected, query, minimum) {
		return loadbalancestream.ErrService
	}
	return nil
}

func streamFilterObjectName(name [16]byte) (string, bool) {
	last := 0
	for last < len(name) && name[last] != 0 {
		c := name[last]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return "", false
		}
		last++
	}
	if last == 0 || last == len(name) || !slices.Equal(name[last:], make([]byte, len(name)-last)) {
		return "", false
	}
	return string(name[:last]), true
}

func streamFilterMapRead(fd int, command uintptr, key, value []byte) error {
	if !streamFilterNativeABI() || fd < 0 || len(value) == 0 ||
		(command != unix.BPF_MAP_GET_NEXT_KEY && command != unix.BPF_MAP_LOOKUP_ELEM) {
		return loadbalancestream.ErrService
	}
	query := streamFilterMapRequest{FD: uint32(fd), Value: uint64(uintptr(unsafe.Pointer(&value[0])))}
	if len(key) != 0 {
		query.Key = uint64(uintptr(unsafe.Pointer(&key[0])))
	}
	expected := query
	_, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&query)), unsafe.Sizeof(query))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if query != expected {
		return loadbalancestream.ErrService
	}
	if errno == unix.ENOENT {
		return unix.ENOENT
	}
	if errno != 0 {
		return loadbalancestream.ErrService
	}
	return nil
}

func streamFilterMapEntries(ctx context.Context, fd int, m streamFilterMap) ([]streamFilterEntry, error) {
	if ctx == nil || ctx.Err() != nil || m.Type != 11 || (m.KeyBytes != 8 && m.KeyBytes != 20) ||
		m.ValueBytes != 8 || m.MaxEntries == 0 || m.MaxEntries > streamFilterMaxMapEntries {
		return nil, loadbalancestream.ErrService
	}
	out := []streamFilterEntry{}
	var previous []byte
	seen := map[string]bool{}
	for n := uint32(0); n <= m.MaxEntries; n++ {
		if ctx.Err() != nil {
			return nil, loadbalancestream.ErrService
		}
		next := make([]byte, m.KeyBytes)
		err := streamFilterMapRead(fd, unix.BPF_MAP_GET_NEXT_KEY, previous, next)
		if errors.Is(err, unix.ENOENT) {
			return out, nil
		}
		if err != nil || n == m.MaxEntries || seen[string(next)] {
			return nil, loadbalancestream.ErrService
		}
		seen[string(next)] = true
		value := make([]byte, 8)
		if streamFilterMapRead(fd, unix.BPF_MAP_LOOKUP_ELEM, next, value) != nil {
			return nil, loadbalancestream.ErrService
		}
		out = append(out, streamFilterEntry{next, value})
		previous = next
	}
	return nil, loadbalancestream.ErrService
}

func streamFilterKernelMap(ctx context.Context, id uint32, ingress bool) (streamFilterMap, error) {
	var out streamFilterMap
	if ctx == nil || ctx.Err() != nil {
		return out, loadbalancestream.ErrService
	}
	fd, err := streamFilterObjectFD(id, false)
	if err != nil {
		return out, err
	}
	defer unix.Close(fd)
	var original streamFilterMapInfo
	if streamFilterObjectInfo(fd, unsafe.Pointer(&original), unsafe.Sizeof(original), 80) != nil ||
		original.ID != id || original.IfIndex != 0 || original.BTFVmlinuxValueID != 0 ||
		original.NetnsDevice != 0 || original.NetnsInode != 0 || original.BTFID != 0 ||
		original.BTFKeyID != 0 || original.BTFValueID != 0 || original.BTFVmlinuxID != 0 || original.Extra != 0 {
		return out, loadbalancestream.ErrService
	}
	name, valid := streamFilterObjectName(original.Name)
	if !valid {
		return out, loadbalancestream.ErrService
	}
	out = streamFilterMap{ID: id, Type: original.Type, Name: name, KeyBytes: original.KeyBytes,
		ValueBytes: original.ValueBytes, MaxEntries: original.MaxEntries, Flags: original.Flags}
	if out.Type == 11 {
		out.Entries, err = streamFilterMapEntries(ctx, fd, out)
		if err != nil {
			return out, err
		}
	}
	first, err := streamFilterMapCanonical(out, ingress)
	if err != nil {
		return out, err
	}
	var again streamFilterMapInfo
	if streamFilterObjectInfo(fd, unsafe.Pointer(&again), unsafe.Sizeof(again), 80) != nil || again != original {
		return out, loadbalancestream.ErrService
	}
	if out.Type == 11 {
		out.Entries, err = streamFilterMapEntries(ctx, fd, out)
		if err != nil {
			return out, err
		}
		second, err := streamFilterMapCanonical(out, ingress)
		if err != nil || !streamFilterMapsEqual(first, second) {
			return out, loadbalancestream.ErrService
		}
	}
	return out, nil
}

func streamFilterMapsEqual(a, b streamFilterCanonicalMap) bool {
	if a.Type != b.Type || a.Name != b.Name || a.KeyBytes != b.KeyBytes || a.ValueBytes != b.ValueBytes ||
		a.MaxEntries != b.MaxEntries || a.Flags != b.Flags || a.CounterOnly != b.CounterOnly {
		return false
	}
	return slices.Equal(a.Entries, b.Entries)
}

func streamFilterKernelProgram(ctx context.Context, id uint32, ingress bool) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", loadbalancestream.ErrService
	}
	fd, err := streamFilterObjectFD(id, true)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	var original streamFilterProgramInfo
	if streamFilterObjectInfo(fd, unsafe.Pointer(&original), unsafe.Sizeof(original), 88) != nil || original.ID != id ||
		original.Type != 8 || original.UID != 0 || original.Flags != 1 || original.IfIndex != 0 ||
		original.XlatedBytes < 8 || original.XlatedBytes > streamFilterMaxInstructions || original.XlatedBytes%8 != 0 ||
		original.MapCount < 1 || original.MapCount > streamFilterMaxMaps || original.LoadTime == 0 {
		return "", loadbalancestream.ErrService
	}
	name, valid := streamFilterObjectName(original.Name)
	if !valid {
		return "", loadbalancestream.ErrService
	}
	code := make([]byte, original.XlatedBytes)
	ids := make([]uint32, original.MapCount)
	// A fresh request avoids interpreting the kernel's returned JIT length as
	// permission to copy JIT bytes to a null pointer on the second info read.
	read := streamFilterProgramInfo{XlatedBytes: uint32(len(code)), XlatedCode: uint64(uintptr(unsafe.Pointer(&code[0]))),
		MapCount: uint32(len(ids)), MapIDs: uint64(uintptr(unsafe.Pointer(&ids[0])))}
	err = streamFilterObjectInfo(fd, unsafe.Pointer(&read), unsafe.Sizeof(read), 88)
	runtime.KeepAlive(code)
	runtime.KeepAlive(ids)
	if err != nil || read.ID != original.ID || read.Type != original.Type || read.Tag != original.Tag ||
		read.LoadTime != original.LoadTime || read.UID != original.UID || read.Flags != original.Flags ||
		read.Name != original.Name || read.IfIndex != original.IfIndex || read.JitedBytes != original.JitedBytes ||
		read.XlatedBytes != original.XlatedBytes || read.MapCount != original.MapCount {
		return "", loadbalancestream.ErrService
	}
	program := streamFilterProgram{ID: id, Type: read.Type, UID: read.UID, Flags: read.Flags, Name: name,
		Tag: read.Tag, Instructions: code, Maps: []streamFilterMap{}}
	for _, mapID := range ids {
		m, err := streamFilterKernelMap(ctx, mapID, ingress)
		if err != nil {
			return "", err
		}
		program.Maps = append(program.Maps, m)
	}
	var end streamFilterProgramInfo
	if streamFilterObjectInfo(fd, unsafe.Pointer(&end), unsafe.Sizeof(end), 88) != nil || end != original || ctx.Err() != nil {
		return "", loadbalancestream.ErrService
	}
	return streamFilterProgramSHA256(program, ingress)
}

func observeStreamFilterPolicySHA256(ctx context.Context, directory *os.File, ingressIDs, egressIDs []uint32) (string, error) {
	if ctx == nil || ctx.Err() != nil || directory == nil || !streamServiceBPFIDs(ingressIDs) || !streamServiceBPFIDs(egressIDs) {
		return "", loadbalancestream.ErrService
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(directory.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return "", loadbalancestream.ErrService
	}
	programs := make([][]string, 2)
	for direction, ids := range [][]uint32{ingressIDs, egressIDs} {
		for _, id := range ids {
			hash, err := streamFilterKernelProgram(ctx, id, direction == 0)
			if err != nil {
				return "", err
			}
			programs[direction] = append(programs[direction], hash)
		}
		attach := uint32(unix.BPF_CGROUP_INET_INGRESS)
		if direction != 0 {
			attach = unix.BPF_CGROUP_INET_EGRESS
		}
		direct, err := loadBalanceStreamCgroupBPFProgramsWithFlags(directory, attach, 0)
		effective, err2 := loadBalanceStreamCgroupBPFPrograms(directory, attach)
		if err != nil || err2 != nil || !slices.Equal(direct, ids) {
			return "", loadbalancestream.ErrService
		}
		// Preserve the existing attachment contract: inherited filters never
		// substitute for a direct unit filter, and all direct filters must be
		// effective. This does not claim an unrelated ancestor policy is ours.
		for _, id := range direct {
			if !slices.Contains(effective, id) {
				return "", loadbalancestream.ErrService
			}
		}
	}
	return streamFilterPolicySHA256(programs[0], programs[1])
}
