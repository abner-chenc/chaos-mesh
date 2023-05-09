// Copyright 2023 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package time

import (
	"debug/elf"
	"encoding/binary"

	"github.com/pkg/errors"
)

func AssetLD(rela elf.Rela64, imageOffset map[string]int, imageContent *[]byte, sym elf.Symbol, byteorder binary.ByteOrder) {
	imageOffset[sym.Name] = len(*imageContent)

	targetOffset := uint32(len(*imageContent)) - uint32(rela.Off) + uint32(rela.Addend)

	// gcc -c -fPIE -mcmodel=normal fake_gettimeofday.c fake_clock_gettime.c
	// The relocation of a loong64 image is like:
	// Offset        Info         Type                Sym. Value       Sym. Name + Addend
	// 000000000028  000900000042 R_LARCH_B26         0000000000000000 real_clock_gettime + 0
	// 000000000034  000a0000004b R_LARCH_GOT_PC_HI20 0000000000000000 TV_SEC_DELTA + 0
	// 000000000038  000a0000004c R_LARCH_GOT_PC_LO12 0000000000000000 TV_SEC_DELTA + 0

	instr := byteorder.Uint32((*imageContent)[rela.Off : rela.Off+4])
	switch elf.R_LARCH(rela.Info & 0xffffffff) {
	case elf.R_LARCH_B26:
		// bl off26
		targetOffset >>= 2
		bit25_16 := (targetOffset >> 16) & 0x3ff
		bit15_0 := targetOffset & 0xffff
		instr = uint32((instr & ^(uint32(0x3ffffff))) | (bit15_0 << 10) | bit25_16)

	case elf.R_LARCH_GOT_PC_HI20:
		// pcalau12i rd, si20
		bit31_12 := (targetOffset >> 12) & 0xfffff
		instr = uint32((instr & ^(uint32(0xfffff) << 5)) | (bit31_12 << 5))

	case elf.R_LARCH_GOT_PC_LO12:
		// ld.d rd,rj, si12
		bit11_0 := targetOffset & 0xfff
		instr = uint32((instr & ^(uint32(0xfff) << 10)) | (bit11_0 << 10))

	default:
		errors.Errorf("unsupport relocation: %v", elf.R_LARCH(rela.Info&0xffffffff))
		return
	}
	byteorder.PutUint32((*imageContent)[rela.Off:rela.Off+4], instr)

	// TODO: support other length besides uint64 (which is 8 bytes)
	*imageContent = append(*imageContent, make([]byte, varLength)...)
}
