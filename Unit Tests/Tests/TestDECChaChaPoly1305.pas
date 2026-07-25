{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory
  of this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}
unit TestDECChaChaPoly1305;

interface

uses
  {$IFDEF DUnitX}
  DUnitX.TestFramework, DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  System.SysUtils, Generics.Collections, System.Math,
  DECBaseClass, System.JSON,
  DECCipherBase, DECCipherModes, DECCipherFormats, DECCiphers;

type
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestChaCha20Poly1305 = class(TTestCase)
  private
    type
      TJsonTestCase = record
        key: TBytes;
        iv: TBytes;
        msg: TBytes;
        aad: TBytes;
        tag: TBytes;
        enc: TBytes;
        isValid: Boolean;
      end;
      TTestEnumerator = class(TEnumerable<TJsonTestCase>)
      private
        FTests: TList<TJsonTestCase>;
      protected
        function DoGetEnumerator: TEnumerator<TJsonTestCase>; override;
      public
        constructor Create(const ATestFile: string);
        destructor Destroy; override;
      end;
  private
    FTests: TTestEnumerator;
    function IterTests: TTestEnumerator;
  public
    destructor Destroy; override;
  published
    procedure TestPoly1305;
    procedure TestChaCha20_Poly1305_KeySetup;
    procedure TestChaCha20_Poly1305_AEAD;
    procedure TestXChaCha_Poly1305_AEAD;
    procedure TestEncode;
    procedure TestDecode;
    procedure TestMultiChunkAEAD_7_25;
    procedure TestMultiChunkAEAD_16_16;
    procedure TestEmptyPlaintextWithAAD;
    procedure TestEmptyAAD;
    procedure TestWrongTagRaisesOnDone;
    procedure TestEncodeAfterDoneRejected;
  end;

implementation

uses
  DECCipherModesPoly1305, Classes, DECFormat, DECTypes;

type
  THackChaChaCipher = class(TCipher_ChaCha20);
  THackPoly1305 = class(TPoly1305);

{ TestChaCha20Poly1305 }

procedure TestChaCha20Poly1305.TestChaCha20_Poly1305_KeySetup;
// RFC 7539 section 2.6.2
const
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$00, $00, $00, $00, $00, $01, $02, $03, $04, $05, $06, $07];
  cChaChaMtx: TChaChaMtx = ($8ba0d58a, $cc815f90, $27405081, $7194b24a,
                            $37b633a8, $a50dfde3, $e2b8db08, $46a6d1fd,
                            $7da03782, $9183a233, $148ad271, $b46773d1,
                            $3cc1875a, $8607def1, $ca5c3086, $7085eb87);
var
  ChaCha: TCipher_ChaCha20;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.Init(cKey, cNonce);
    Check(THackChaChaCipher(ChaCha).TestChaChaMtx(cChaChaMtx), 'Initialization failed');
  finally
    ChaCha.Free;
  end;
end;

procedure TestChaCha20Poly1305.TestDecode;
var
  ATest: TJsonTestCase;
  ChaCha: TCipher_ChaCha20;
  Decode: TBytes;
  IsValid: Boolean;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  IsValid := False;
  for ATest in IterTests do
  begin
    try
      ChaCha := TCipher_ChaCha20.Create;
      try
        ChaCha.Mode := cmPoly1305;
        ChaCha.DataToAuthenticate := ATest.aad;
        ChaCha.ExpectedAuthenticationResult := ATest.tag;
        ChaCha.Init(ATest.key, ATest.iv);
        Decode := ChaCha.DecodeBytes(ATest.enc);
        ChaCha.Done;
        IsValid := True;
      finally
        ChaCha.Free;
      end;

      Check(Length(Decode) = Length(ATest.msg), 'Decoding length test failed');
      if Length(Decode) <> 0 then
        Check(CompareMem(@Decode[0], @ATest.msg[0], Length(Decode)), 'Decoding failed');
    except
      on E: EDECException do
        IsValid := False;
    else
      raise;
    end;

    Check(not (IsValid xor ATest.isValid), 'Test failed');
  end;
end;

procedure TestChaCha20Poly1305.TestEncode;
var
  ATest: TJsonTestCase;
  ChaCha: TCipher_ChaCha20;
  Encode: TBytes;
  IsValid: Boolean;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  IsValid := False;
  for ATest in IterTests do
  begin
    try
      ChaCha := TCipher_ChaCha20.Create;
      try
        ChaCha.Mode := cmPoly1305;
        ChaCha.DataToAuthenticate := ATest.aad;
        ChaCha.ExpectedAuthenticationResult := ATest.tag;
        ChaCha.Init(ATest.key, ATest.iv);
        Encode := ChaCha.EncodeBytes(ATest.msg);
        ChaCha.Done;
        IsValid := True;
      finally
        ChaCha.Free;
      end;

      Check(Length(Encode) = Length(ATest.enc), 'Encoding length test failed');
      if Length(Encode) <> 0 then
        Check(CompareMem(@Encode[0], @ATest.enc[0], Length(Encode)), 'Encoding failed');
    except
      on E: EDECException do
        IsValid := False;
    else
      raise;
    end;

    Check(not (IsValid xor ATest.isValid), 'Test failed');
  end;
end;

procedure TestChaCha20Poly1305.TestPoly1305;
// Pure Poly1305 MAC vectors from RFC 7539 (not AEAD framing)
const
  cMsg: AnsiString = 'Cryptographic Forum Research Group';
  cS: array of Byte = [$01, $03, $80, $8a, $fb, $0d, $b2, $fd, $4a, $bf, $f6, $af, $41, $49, $f5, $1b];
  cR: array of Byte = [$85, $d6, $be, $78, $57, $55, $6d, $33, $7f, $44, $52, $fe, $42, $d5, $06, $a8];
  cTag: array of Byte = [$a8, $06, $1d, $c1, $30, $51, $36, $c6, $c2, $2b, $8b, $af, $0c, $01, $27, $a9];
  cR1: array of Byte = [$85, $1f, $c4, $0c, $34, $67, $ac, $0b, $e0, $5c, $c2, $04, $04, $f3, $f7, $00];
  cS1: array of Byte = [$ec, $07, $4c, $83, $55, $80, $74, $17, $01, $42, $5b, $62, $32, $35, $ad, $d6];
  cMsg1: array of Byte = [$f3, $f6];
  cTag1: array of Byte = [$88, $C3, $44, $37, $C6, $87, $7A, $3E, $90, $C1, $F8, $08, $58, $C3, $92, $F8];
var
  Poly: TPoly1305;
  IV: T32ByteArray;
  Msg: TBytes;
  CalcTag: TBytes;
begin
  FillChar(IV[0], Length(IV), 0);
  Move(cR1[0], IV[0], Length(cR1));
  Move(cS1[0], IV[16], Length(cS1));
  SetLength(Msg, Length(cMsg1));
  Move(cMsg1[0], Msg[0], Length(Msg));

  TPoly1305.CpuMode := pmPas;
  Poly := TPoly1305.Create;
  try
    THackPoly1305(Poly).InitInternal(IV);
    THackPoly1305(Poly).UpdatePoly(@Msg[0], Length(Msg));
    THackPoly1305(Poly).Finalize;
    CalcTag := Poly.CalculatedAuthenticationTag;
  finally
    Poly.Free;
  end;

  Check(Length(cTag1) = Length(CalcTag), 'MAC length is wrong');
  Check(CompareMem(@cTag1[0], @CalcTag[0], Length(CalcTag)), 'Polynom calculated tag does not match');

  FillChar(IV[0], Length(IV), 0);
  Move(cR[0], IV[0], Length(cR));
  Move(cS[0], IV[16], Length(cS));
  SetLength(Msg, Length(cMsg));
  Move(cMsg[1], Msg[0], Length(Msg));

  Poly := TPoly1305.Create;
  try
    THackPoly1305(Poly).InitInternal(IV);
    THackPoly1305(Poly).UpdatePoly(@Msg[0], Length(Msg));
    THackPoly1305(Poly).Finalize;
    CalcTag := Poly.CalculatedAuthenticationTag;
  finally
    Poly.Free;
  end;

  Check(Length(cTag) = Length(CalcTag), 'MAC length is wrong');
  Check(CompareMem(@cTag[0], @CalcTag[0], Length(CalcTag)), 'Polynom calculated tag does not match');
end;

function TestChaCha20Poly1305.IterTests: TTestEnumerator;
begin
  if not Assigned(FTests) then
    FTests := TTestEnumerator.Create('..\..\Unit Tests\Data\chacha20_poly1305_test.json');
  Result := FTests;
end;

procedure TestChaCha20Poly1305.TestXChaCha_Poly1305_AEAD;
const
  cMsg: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  cAAD: TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $4a, $4b, $4c, $4d, $4e, $4f,
                    $50, $51, $52, $53, $54, $55, $56, $57];
  cTag: TBytes = [$c0, $87, $59, $24, $c1, $c7, $98, $79, $47, $de, $af, $d8, $78, $0a, $cf, $49];
  cCipherText: TBytes = [
    $bd, $6d, $17, $9d, $3e, $83, $d4, $3b, $95, $76, $57, $94, $93, $c0, $e9, $39,
    $57, $2a, $17, $00, $25, $2b, $fa, $cc, $be, $d2, $90, $2c, $21, $39, $6c, $bb,
    $73, $1c, $7f, $1b, $0b, $4a, $a6, $44, $0b, $f3, $a8, $2f, $4e, $da, $7e, $39,
    $ae, $64, $c6, $70, $8c, $54, $c2, $16, $cb, $96, $b7, $2e, $12, $13, $b4, $52,
    $2f, $8c, $9b, $a4, $0d, $b5, $d9, $45, $b1, $1b, $69, $b9, $82, $c1, $bb, $9e,
    $3f, $3f, $ac, $2b, $c3, $69, $48, $8f, $76, $b2, $38, $35, $65, $d3, $ff, $f9,
    $21, $f9, $66, $4c, $97, $63, $7d, $a9, $76, $88, $12, $f6, $15, $c6, $8b, $13,
    $b5, $2e];
var
  ChaCha: TCipher_XChaCha20;
  Msg, Encr, EncrTag, Decr, DecodeTag: TBytes;
begin
  TCipher_XChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;

  SetLength(Msg, Length(cMsg));
  Move(cMsg[1], Msg[0], Length(Msg));

  ChaCha := TCipher_XChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    Encr := ChaCha.EncodeBytes(Msg);
    ChaCha.Done;
    EncrTag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  Check(Length(cCipherText) = Length(Encr), 'Encryption length is wrong');
  Check(CompareMem(@cCipherText[0], @Encr[0], Length(Encr)), 'Encryption failed');
  Check(Length(cTag) = Length(EncrTag), 'Tag length is wrong');
  Check(CompareMem(@EncrTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');

  ChaCha := TCipher_XChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.ExpectedAuthenticationResult := EncrTag;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    Decr := ChaCha.DecodeBytes(Encr);
    ChaCha.Done;
    DecodeTag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  Check(Length(cTag) = Length(DecodeTag), 'Tag length is wrong');
  Check(CompareMem(@DecodeTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');
  Check(Length(Decr) = Length(Msg), 'Decrypt length wrong');
  Check(CompareMem(@Decr[0], @Msg[0], Length(Msg)), 'Decrypt mismatch');
end;

destructor TestChaCha20Poly1305.Destroy;
begin
  FTests.Free;
  inherited;
end;

procedure TestChaCha20Poly1305.TestChaCha20_Poly1305_AEAD;
const
  cMsg: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  cAAD: TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];
  cTag: TBytes = [$1a, $e1, $0b, $59, $4f, $09, $e2, $6a, $7e, $90, $2e, $cb, $d0, $60, $06, $91];
  cCipherText: TBytes = [
    $d3, $1a, $8d, $34, $64, $8e, $60, $db, $7b, $86, $af, $bc, $53, $ef, $7e, $c2,
    $a4, $ad, $ed, $51, $29, $6e, $08, $fe, $a9, $e2, $b5, $a7, $36, $ee, $62, $d6,
    $3d, $be, $a4, $5e, $8c, $a9, $67, $12, $82, $fa, $fb, $69, $da, $92, $72, $8b,
    $1a, $71, $de, $0a, $9e, $06, $0b, $29, $05, $d6, $a5, $b6, $7e, $cd, $3b, $36,
    $92, $dd, $bd, $7f, $2d, $77, $8b, $8c, $98, $03, $ae, $e3, $28, $09, $1b, $58,
    $fa, $b3, $24, $e4, $fa, $d6, $75, $94, $55, $85, $80, $8b, $48, $31, $d7, $bc,
    $3f, $f4, $de, $f0, $8e, $4b, $7a, $9d, $e5, $76, $d2, $65, $86, $ce, $c6, $4b,
    $61, $16];
var
  ChaCha: TCipher_ChaCha20;
  Msg, Encr, EncrTag, Decr, DecodeTag: TBytes;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;

  SetLength(Msg, Length(cMsg));
  Move(cMsg[1], Msg[0], Length(Msg));

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    Encr := ChaCha.EncodeBytes(Msg);
    ChaCha.Done;
    EncrTag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  Check(Length(cCipherText) = Length(Encr), 'Encryption length is wrong');
  Check(CompareMem(@cCipherText[0], @Encr[0], Length(Encr)), 'Encryption failed');
  Check(Length(cTag) = Length(EncrTag), 'Tag length is wrong');
  Check(CompareMem(@EncrTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.ExpectedAuthenticationResult := EncrTag;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    Decr := ChaCha.DecodeBytes(Encr);
    ChaCha.Done;
    DecodeTag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  Check(Length(cTag) = Length(DecodeTag), 'Tag length is wrong');
  Check(CompareMem(@DecodeTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');
  Check(Length(Decr) = Length(Msg), 'Decrypt length wrong');
  Check(CompareMem(@Decr[0], @Msg[0], Length(Msg)), 'Decrypt mismatch');
end;

procedure TestChaCha20Poly1305.TestMultiChunkAEAD_7_25;
// Multi-call AEAD must match one-shot (7 + rest split of the RFC 7539 sample PT)
const
  cMsg: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  cAAD: TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];
  cTag: TBytes = [$1a, $e1, $0b, $59, $4f, $09, $e2, $6a, $7e, $90, $2e, $cb, $d0, $60, $06, $91];
var
  ChaCha: TCipher_ChaCha20;
  Msg, OneShot, Multi, Tag: TBytes;
  N, Rest: Integer;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  SetLength(Msg, Length(cMsg));
  Move(cMsg[1], Msg[0], Length(Msg));
  N := Length(Msg);
  Check(N > 7, 'Fixture message length');
  Rest := N - 7;

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    OneShot := ChaCha.EncodeBytes(Msg);
    ChaCha.Done;
    Tag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    SetLength(Multi, N);
    ChaCha.Encode(Msg[0], Multi[0], 7);
    ChaCha.Encode(Msg[7], Multi[7], Rest);
    ChaCha.Done;
    Check(CompareMem(@OneShot[0], @Multi[0], N), 'Multi-chunk 7+rest CT differs from one-shot');
    Check(CompareMem(@Tag[0], @ChaCha.CalculatedAuthenticationResult[0], Length(cTag)),
      'Multi-chunk 7+rest tag differs');
    Check(CompareMem(@Tag[0], @cTag[0], Length(cTag)), 'Tag mismatch vs RFC');
  finally
    ChaCha.Free;
  end;
end;

procedure TestChaCha20Poly1305.TestMultiChunkAEAD_16_16;
const
  cMsg: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  cAAD: TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];
var
  ChaCha: TCipher_ChaCha20;
  Msg, OneShot, Multi, Tag: TBytes;
  N, Rest: Integer;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  SetLength(Msg, Length(cMsg));
  Move(cMsg[1], Msg[0], Length(Msg));
  N := Length(Msg);
  Rest := N - 16;

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    OneShot := ChaCha.EncodeBytes(Msg);
    ChaCha.Done;
    Tag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    SetLength(Multi, N);
    ChaCha.Encode(Msg[0], Multi[0], 16);
    ChaCha.Encode(Msg[16], Multi[16], Rest);
    ChaCha.Done;
    Check(CompareMem(@OneShot[0], @Multi[0], N), 'Multi-chunk 16+rest CT differs');
    Check(CompareMem(@Tag[0], @ChaCha.CalculatedAuthenticationResult[0], Length(Tag)),
      'Multi-chunk 16+rest tag differs');
  finally
    ChaCha.Free;
  end;
end;

procedure TestChaCha20Poly1305.TestEmptyPlaintextWithAAD;
const
  cAAD: TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];
var
  ChaCha: TCipher_ChaCha20;
  Empty, Encr, Tag: TBytes;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  SetLength(Empty, 0);

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.Init(cKey, cNonce);
    Encr := ChaCha.EncodeBytes(Empty);
    ChaCha.Done;
    Tag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  Check(Length(Encr) = 0, 'Empty PT must yield empty CT');
  Check(Length(Tag) = 16, 'Tag must still be produced for AAD-only');
end;

procedure TestChaCha20Poly1305.TestEmptyAAD;
const
  cMsg: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];
var
  ChaCha: TCipher_ChaCha20;
  Msg, Encr, Tag: TBytes;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  SetLength(Msg, Length(cMsg));
  Move(cMsg[1], Msg[0], Length(Msg));

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    // no AAD
    ChaCha.Init(cKey, cNonce);
    Encr := ChaCha.EncodeBytes(Msg);
    ChaCha.Done;
    Tag := ChaCha.CalculatedAuthenticationResult;
  finally
    ChaCha.Free;
  end;

  Check(Length(Encr) = Length(Msg), 'CT length');
  Check(Length(Tag) = 16, 'Tag length with empty AAD');
end;

procedure TestChaCha20Poly1305.TestWrongTagRaisesOnDone;
const
  cMsg: AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
  cAAD: TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];
  cCipherText: TBytes = [
    $d3, $1a, $8d, $34, $64, $8e, $60, $db, $7b, $86, $af, $bc, $53, $ef, $7e, $c2,
    $a4, $ad, $ed, $51, $29, $6e, $08, $fe, $a9, $e2, $b5, $a7, $36, $ee, $62, $d6,
    $3d, $be, $a4, $5e, $8c, $a9, $67, $12, $82, $fa, $fb, $69, $da, $92, $72, $8b,
    $1a, $71, $de, $0a, $9e, $06, $0b, $29, $05, $d6, $a5, $b6, $7e, $cd, $3b, $36,
    $92, $dd, $bd, $7f, $2d, $77, $8b, $8c, $98, $03, $ae, $e3, $28, $09, $1b, $58,
    $fa, $b3, $24, $e4, $fa, $d6, $75, $94, $55, $85, $80, $8b, $48, $31, $d7, $bc,
    $3f, $f4, $de, $f0, $8e, $4b, $7a, $9d, $e5, $76, $d2, $65, $86, $ce, $c6, $4b,
    $61, $16];
var
  ChaCha: TCipher_ChaCha20;
  BadTag: TBytes;
  RaisedAuth: Boolean;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  SetLength(BadTag, 16);
  FillChar(BadTag[0], 16, $AA);
  RaisedAuth := False;

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.DataToAuthenticate := cAAD;
    ChaCha.ExpectedAuthenticationResult := BadTag;
    ChaCha.Init(cKey, cNonce);
    ChaCha.DecodeBytes(cCipherText);
    try
      ChaCha.Done;
    except
      on E: EDECCipherAuthenticationException do
        RaisedAuth := True;
    end;
  finally
    ChaCha.Free;
  end;

  Check(RaisedAuth, 'Wrong tag must raise EDECCipherAuthenticationException on Done');
end;

procedure TestChaCha20Poly1305.TestEncodeAfterDoneRejected;
const
  cKey: TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                  $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
  cNonce: TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];
var
  ChaCha: TCipher_ChaCha20;
  Empty, Scratch: TBytes;
  Raised: Boolean;
begin
  TCipher_ChaCha20.CpuMode := cmPas;
  TPoly1305.CpuMode := pmPas;
  SetLength(Empty, 0);
  SetLength(Scratch, 4);
  Raised := False;

  ChaCha := TCipher_ChaCha20.Create;
  try
    ChaCha.Mode := cmPoly1305;
    ChaCha.Init(cKey, cNonce);
    ChaCha.EncodeBytes(Empty);
    ChaCha.Done;
    try
      ChaCha.Encode(Scratch[0], Scratch[0], Length(Scratch));
    except
      on E: EDECCipherException do
        Raised := True;
    end;
  finally
    ChaCha.Free;
  end;

  Check(Raised, 'Encode after Done must raise EDECCipherException');
end;

{ TestChaCha20Poly1305.TTestEnumerator }

constructor TestChaCha20Poly1305.TTestEnumerator.Create(const ATestFile: string);
var
  Groups: TJSONArray;
  Tests: TJSONValue;
  ATest: TJSONValue;
  TestFile: TJSONObject;
  TestRec: TJsonTestCase;
begin
  inherited Create;

  FTests := TList<TJsonTestCase>.Create;
  with TStringList.Create do
  try
    LoadFromFile('..\..\Unit Tests\Data\chacha20_poly1305_test.json');
    TestFile := TJSONObject.ParseJSONValue(Text) as TJSONObject;
  finally
    Free;
  end;

  try
    Groups := TestFile.GetValue('testGroups') as TJSONArray;
    for Tests in Groups do
    begin
      for ATest in ((Tests as TJSONObject).GetValue('tests') as TJSONArray) do
      begin
        TestRec.aad := BytesOf(TFormat_HexL.Decode(RawByteString(ATest.GetValue<string>('aad'))));
        TestRec.iv := BytesOf(TFormat_HexL.Decode(RawByteString(ATest.GetValue<string>('iv'))));
        TestRec.key := BytesOf(TFormat_HexL.Decode(RawByteString(ATest.GetValue<string>('key'))));
        TestRec.msg := BytesOf(TFormat_HexL.Decode(RawByteString(ATest.GetValue<string>('msg'))));
        TestRec.tag := BytesOf(TFormat_HexL.Decode(RawByteString(ATest.GetValue<string>('tag'))));
        TestRec.enc := BytesOf(TFormat_HexL.Decode(RawByteString(ATest.GetValue<string>('ct'))));
        TestRec.isValid := SameText(ATest.GetValue<string>('result'), 'Valid');
        FTests.Add(TestRec);
      end;
    end;
  finally
    TestFile.Free;
  end;
end;

destructor TestChaCha20Poly1305.TTestEnumerator.Destroy;
begin
  FTests.Free;
  inherited;
end;

function TestChaCha20Poly1305.TTestEnumerator.DoGetEnumerator: TEnumerator<TJsonTestCase>;
begin
  Result := FTests.GetEnumerator;
end;

initialization
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestChaCha20Poly1305);
  {$ELSE}
  RegisterTest(TestChaCha20Poly1305.Suite);
  {$ENDIF}
end.
