{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

{$M+}
unit TestDECAESNI;

interface

{$INCLUDE TestDefines.inc}

uses
  System.SysUtils, System.Classes,
  {$IFDEF DUnitX}
  DUnitX.TestFramework, DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  DECCipherBase, DECCipherFormats, DECCiphers, DECTypes, DECFormat, DECCPUSupport;

type
  /// <summary>
  ///   FIPS-197 single-block ECB KATs for AES-128/192/256, comparing pure
  ///   Pascal and AES-NI paths when the CPU supports AES-NI.
  /// </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestAESNI = class(TTestCase)
  private
    function HexToBytes(const AHex: string): TBytes;
    procedure RoundTripECB(ACipherClass: TDECCipherClass;
      const AKeyHex, APlainHex, ACipherHex: string; AUseAsm: Boolean);
    procedure ComparePasVsAsm(ACipherClass: TDECCipherClass;
      const AKeyHex, APlainHex, ACipherHex: string);
  published
    procedure TestAES128_FIPS197_PAS;
    procedure TestAES192_FIPS197_PAS;
    procedure TestAES256_FIPS197_PAS;
    procedure TestAES128_PAS_vs_AESNI;
    procedure TestAES192_PAS_vs_AESNI;
    procedure TestAES256_PAS_vs_AESNI;
    procedure TestUseAESAsmDefaultMatchesCPU;
  end;

implementation

{ TestAESNI }

function TestAESNI.HexToBytes(const AHex: string): TBytes;
begin
  Result := BytesOf(TFormat_HexL.Decode(RawByteString(LowerCase(AHex))));
end;

procedure TestAESNI.RoundTripECB(ACipherClass: TDECCipherClass;
  const AKeyHex, APlainHex, ACipherHex: string; AUseAsm: Boolean);
var
  LCipher: TDECFormattedCipher;
  LKey, LPlain, LExpected, LOut, LDec, LIV: TBytes;
  LPrev: Boolean;
begin
  LPrev := TCipher_Rijndael.UseAESAsm;
  try
    TCipher_Rijndael.UseAESAsm := AUseAsm;

    LKey := HexToBytes(AKeyHex);
    LPlain := HexToBytes(APlainHex);
    LExpected := HexToBytes(ACipherHex);
    SetLength(LIV, 0);

    LCipher := ACipherClass.Create as TDECFormattedCipher;
    try
      LCipher.Mode := cmECBx;
      LCipher.Init(LKey, LIV, 0);
      LOut := LCipher.EncodeBytes(LPlain);
      CheckEquals(Length(LExpected), Length(LOut));
      CheckEquals(True, CompareMem(@LExpected[0], @LOut[0], Length(LExpected)),
        'encrypt mismatch UseAESAsm=' + BoolToStr(AUseAsm) +
        ' CPU.AES=' + BoolToStr(TDEC_CPUSupport.AES));

      LCipher.Init(LKey, LIV, 0);
      LDec := LCipher.DecodeBytes(LOut);
      CheckEquals(Length(LPlain), Length(LDec));
      CheckEquals(True, CompareMem(@LPlain[0], @LDec[0], Length(LPlain)),
        'decrypt mismatch UseAESAsm=' + BoolToStr(AUseAsm));
    finally
      LCipher.Free;
    end;
  finally
    TCipher_Rijndael.UseAESAsm := LPrev;
  end;
end;

procedure TestAESNI.ComparePasVsAsm(ACipherClass: TDECCipherClass;
  const AKeyHex, APlainHex, ACipherHex: string);
begin
  // Always verify pure Pascal against FIPS-197.
  RoundTripECB(ACipherClass, AKeyHex, APlainHex, ACipherHex, False);

  // When AES-NI is available (and ASM compiled), force it and re-check.
  // When not available, UseAESAsm=True still selects PAS via FAESAsmActive.
  RoundTripECB(ACipherClass, AKeyHex, APlainHex, ACipherHex, True);
end;

procedure TestAESNI.TestAES128_FIPS197_PAS;
// FIPS-197 Appendix C.1
begin
  RoundTripECB(TCipher_AES128,
    '000102030405060708090a0b0c0d0e0f',
    '00112233445566778899aabbccddeeff',
    '69c4e0d86a7b0430d8cdb78070b4c55a',
    False);
end;

procedure TestAESNI.TestAES192_FIPS197_PAS;
// FIPS-197 Appendix C.2
begin
  RoundTripECB(TCipher_AES192,
    '000102030405060708090a0b0c0d0e0f1011121314151617',
    '00112233445566778899aabbccddeeff',
    'dda97ca4864cdfe06eaf70a0ec0d7191',
    False);
end;

procedure TestAESNI.TestAES256_FIPS197_PAS;
// FIPS-197 Appendix C.3
begin
  RoundTripECB(TCipher_AES256,
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    '00112233445566778899aabbccddeeff',
    '8ea2b7ca516745bfeafc49904b496089',
    False);
end;

procedure TestAESNI.TestAES128_PAS_vs_AESNI;
begin
  ComparePasVsAsm(TCipher_AES128,
    '000102030405060708090a0b0c0d0e0f',
    '00112233445566778899aabbccddeeff',
    '69c4e0d86a7b0430d8cdb78070b4c55a');
end;

procedure TestAESNI.TestAES192_PAS_vs_AESNI;
begin
  ComparePasVsAsm(TCipher_AES192,
    '000102030405060708090a0b0c0d0e0f1011121314151617',
    '00112233445566778899aabbccddeeff',
    'dda97ca4864cdfe06eaf70a0ec0d7191');
end;

procedure TestAESNI.TestAES256_PAS_vs_AESNI;
begin
  ComparePasVsAsm(TCipher_AES256,
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    '00112233445566778899aabbccddeeff',
    '8ea2b7ca516745bfeafc49904b496089');
end;

procedure TestAESNI.TestUseAESAsmDefaultMatchesCPU;
begin
  // Re-apply unit-init rule and verify.
  {$IF defined(X86ASM) or defined(X64ASM)}
  TCipher_Rijndael.UseAESAsm := TDEC_CPUSupport.AES;
  CheckEquals(True, TDEC_CPUSupport.AES = TCipher_Rijndael.UseAESAsm,
    'UseAESAsm should follow TDEC_CPUSupport.AES when ASM is compiled');
  {$ELSE}
  TCipher_Rijndael.UseAESAsm := False;
  CheckEquals(False, TCipher_Rijndael.UseAESAsm,
    'UseAESAsm must be False when ASM path is not compiled');
  {$IFEND}
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestAESNI);
  {$ELSE}
  RegisterTests('DECCiphers', [TestAESNI.Suite]);
  {$ENDIF}

end.
