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
//go:build cgo

package ptrace

import (
	"encoding/binary"
	"syscall"

	"github.com/pkg/errors"
)

var endian = binary.LittleEndian

const syscallInstrSize = 4

const nrProcessVMReadv = 270
const nrProcessVMWritev = 271

func getIp(regs *syscall.PtraceRegs) uintptr {
	return uintptr(regs.Era)
}

func getRegs(pid int, regsout *syscall.PtraceRegs) error {
	err := syscall.PtraceGetRegs(pid, regsout)
	if err != nil {
		return errors.Wrapf(err, "get registers of process %d", pid)
	}

	return nil
}

func setRegs(pid int, regs *syscall.PtraceRegs) error {
	err := syscall.PtraceSetRegs(pid, regs)
	if err != nil {
		return errors.Wrapf(err, "set registers of process %d", pid)
	}

	return nil
}

// Syscall runs a syscall at main thread of process
func (p *TracedProgram) Syscall(number uint64, args ...uint64) (uint64, error) {
	// save the original registers and the current instructions
	err := p.Protect()
	if err != nil {
		return 0, err
	}

	var regs syscall.PtraceRegs

	err = getRegs(p.pid, &regs)
	if err != nil {
		return 0, err
	}

	// set the registers according to the syscall convention. Learn more about
	// it in `man 2 syscall`. In loong64 the syscall nr is stored in R11, and
	// the arguments are stored in R4, R5, R6, R7, R8, R9, R10 in order
	regs.Regs[11] = number
	for index, arg := range args {
		if index > 7 {
			return 0, errors.New("too many arguments for a syscall")
		} else {
			regs.Regs[index+4] = arg
		}
	}
	err = setRegs(p.pid, &regs)
	if err != nil {
		return 0, err
	}

	instruction := make([]byte, syscallInstrSize)
	ip := getIp(p.backupRegs)

	// 0x002b0000 is `syscall 0` to call the system call
	endian.PutUint32(instruction, 0x002b0000)
	_, err = syscall.PtracePokeData(p.pid, ip, instruction)
	if err != nil {
		return 0, errors.Wrapf(err, "writing data %v to %x", instruction, ip)
	}

	// run one instruction, and stop
	err = p.Step()
	if err != nil {
		return 0, err
	}

	// read registers, the return value of syscall is stored inside x0 register
	err = getRegs(p.pid, &regs)
	if err != nil {
		return 0, err
	}

	return regs.Regs[0], p.Restore()
}

// JumpToFakeFunc writes jmp instruction to jump to fake function
func (p *TracedProgram) JumpToFakeFunc(originAddr uint64, targetAddr uint64) error {
	instructions := make([]byte, 24)

	// pcaddi r30, (12 >> 2)
	// ld.d r30, r30, 0
	// jirl r0, r30, 0
	// targetAddr
	// nop
	endian.PutUint32(instructions[0:], 0x1800007E)
	endian.PutUint32(instructions[4:], 0x28C003DE)
	endian.PutUint32(instructions[8:], 0x4C0003C0)
	endian.PutUint64(instructions[12:], targetAddr)
	endian.PutUint32(instructions[20:], 0x03400000)

	return p.PtraceWriteSlice(originAddr, instructions)
}
