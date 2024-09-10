package carvers

import (
	"bytes"
	"context"
	"fmt"
	"github.com/Velocidex/ordereddict"
	"time"
	ntfs "www.velocidex.com/golang/go-ntfs/parser"
	"www.velocidex.com/golang/velociraptor/accessors"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/common"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
	"www.velocidex.com/golang/vfilter/types"
)

const i30YaraRule = `
rule i30rule
{
	strings:
		$i30regex = /[\x00-\xff]{4}\x00{2}[\x00-\xff]{2}([\x00-\xff]{6}[\xb4-\xe5]\x01){4}([\x00-\xff]{4}[\x00-\x50]\x00{3}){2}[\x00-\xff]{4}[\x00-\xff]{4}[\x01-\xff](\x00|\x01|\x02|\x03)/

    condition:
       $i30regex
}
`

type I30CarverPluginArgs struct {
	Filename []*accessors.OSPath `vfilter:"required,field=filename,doc=A list of log files to parse."`
	Accessor string              `vfilter:"optional,field=accessor,doc=The accessor to use."`
}

type I30CarverFileInfo = struct {
	MFTId          string
	SequenceNumber uint16
	Mtime          time.Time
	Atime          time.Time
	Ctime          time.Time
	Btime          time.Time
	Name           string
	NameType       string
	Size           int64
	AllocatedSize  int64
	Flags          []string
	OSFile         *accessors.OSPath
	OSFileOffset   uint64
}

func NewI30CarverFileInfo(entry *ntfs.INDEX_RECORD_ENTRY, osFile *accessors.OSPath, offset uint64) *I30CarverFileInfo {
	filename := entry.File()
	return &I30CarverFileInfo{
		MFTId:          fmt.Sprintf("%d", entry.MftReference()),
		SequenceNumber: filename.Seq_num(),
		Mtime:          filename.Mft_modified().Time,
		Atime:          filename.File_accessed().Time,
		Ctime:          filename.Created().Time,
		Btime:          filename.File_modified().Time,
		Name:           filename.Name(),
		NameType:       filename.NameType().Name,
		Size:           int64(filename.FilenameSize()),
		AllocatedSize:  int64(filename.Allocated_size()),
		Flags:          filename.Flags().Values(),
		OSFile:         osFile,
		OSFileOffset:   offset,
	}
}

type I30Carver struct {
}

func (self I30Carver) Call(ctx context.Context, scope types.Scope, args *ordereddict.Dict) <-chan types.Row {
	outputChan := make(chan vfilter.Row)
	go func() {
		defer close(outputChan)
		defer vql_subsystem.RegisterMonitor("carve_i30", args)()

		arg := &I30CarverPluginArgs{}
		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("carve_i30: %s", err)
			return
		}

		err = vql_subsystem.CheckFilesystemAccess(scope, arg.Accessor)
		if err != nil {
			scope.Log("carve_i30: %s", err)
			return
		}
		yaraArgs := ordereddict.NewDict().Set("accessor", arg.Accessor).Set("files", arg.Filename).Set("context", 1024).Set("number", 5000000).Set("rules", i30YaraRule)
		yaraFinder := common.YaraScanPlugin{}
		profile := ntfs.NewNTFSProfile()
		for row := range yaraFinder.Call(ctx, scope, yaraArgs) {
			yaraResult := row.(*common.YaraResult)
			data := yaraResult.String.Data
			if len(data) > 0 {
				reader := bytes.NewReader(data)
				testMatch := profile.INDEX_RECORD_ENTRY(reader, 0)
				if testMatch.IsValid(true) {
					outputChan <- NewI30CarverFileInfo(testMatch, yaraResult.FileName, yaraResult.String.Offset)
				}
			}
		}
	}()
	return outputChan
}

func (self I30Carver) Info(scope types.Scope, type_map *types.TypeMap) *types.PluginInfo {
	return &vfilter.PluginInfo{
		Name:    "carve_i30",
		Doc:     "Carve i30 entries using accessor",
		ArgType: type_map.AddType(scope, &I30CarverPluginArgs{}),
	}
}

func init() {
	vql_subsystem.RegisterPlugin(&I30Carver{})
}
