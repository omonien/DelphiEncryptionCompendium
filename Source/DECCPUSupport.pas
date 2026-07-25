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

/// <summary>
///   x86 / x64 CPU feature detection (CPUID).
///   On non-x86 platforms all feature flags remain False.
/// </summary>
unit DECCPUSupport;

interface

type
  /// <summary>
  ///   Result of a CPUID leaf query (EAX/EBX/ECX/EDX register values)
  /// </summary>
  TCPUIDRec = record
    EAX: Cardinal;
    EBX: Cardinal;
    ECX: Cardinal;
    EDX: Cardinal;
  end;

  /// <summary>
  ///   Static CPU feature flags, filled once at unit initialization.
  /// </summary>
  TDEC_CPUSupport = class(TObject)
  public
    class var AES: Boolean;
    class var AVX: Boolean;
    class var AVX2: Boolean;

    class var SSE: Boolean;
    class var SSE2: Boolean;
    class var SSE3: Boolean;
    class var SSE41: Boolean;
    class var SSE42: Boolean;

    class var RDRand: Boolean;
    class var RDSeed: Boolean;
  end;

/// <summary>
///   Execute CPUID with the given leaf / sub-leaf. Non-x86 stubs return zeros.
/// </summary>
function GetCPUID(ALeaf: Cardinal; ASubLeaf: Cardinal = 0): TCPUIDRec;

implementation

{$IFDEF CPUX64}
{$DEFINE x64}
{$ENDIF}
{$IFDEF cpux86_64}
{$DEFINE x64}
{$ENDIF}

{$IFDEF CPU86}
{$DEFINE x86}
{$ENDIF}
{$IFDEF CPUX86}
{$DEFINE x86}
{$ENDIF}
{$IFDEF CPU386}
{$DEFINE x86}
{$ENDIF}

{$IF Defined(x64) or Defined(x86)}

/// <summary>
///   Low-level CPUID. Uses a procedure so calling conventions stay simple:
///   x86 register: EAX=Leaf, EDX=SubLeaf, ECX=@Out
///   x64 Win:      RCX=Leaf, RDX=SubLeaf, R8=@Out
/// </summary>
procedure CPUIDQuery(ALeaf, ASubLeaf: Cardinal; var AOut: TCPUIDRec);
{$IFDEF x64}
asm
  // RCX = ALeaf, RDX = ASubLeaf, R8 = @AOut
  push rbx
  mov r10, r8
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r10 + 0], eax
  mov dword ptr [r10 + 4], ebx
  mov dword ptr [r10 + 8], ecx
  mov dword ptr [r10 + 12], edx
  pop rbx
end;
{$ELSE}
asm
  // EAX = ALeaf, EDX = ASubLeaf, ECX = @AOut
  push ebx
  push edi
  mov edi, ecx
  mov ecx, edx
  // EAX already holds ALeaf
  cpuid
  mov [edi + 0], eax
  mov [edi + 4], ebx
  mov [edi + 8], ecx
  mov [edi + 12], edx
  pop edi
  pop ebx
end;
{$ENDIF}

function GetCPUID(ALeaf: Cardinal; ASubLeaf: Cardinal = 0): TCPUIDRec;
begin
  CPUIDQuery(ALeaf, ASubLeaf, Result);
end;

procedure InitFlags;
var
  Reg: TCPUIDRec;
  NIds: Cardinal;
begin
  Reg := GetCPUID(0, 0);
  NIds := Reg.EAX;

  if NIds >= 1 then
  begin
    Reg := GetCPUID(1, 0);
    TDEC_CPUSupport.SSE := (Reg.EDX and (1 shl 25)) <> 0;
    TDEC_CPUSupport.SSE2 := (Reg.EDX and (1 shl 26)) <> 0;
    // SSE3 is ECX bit 0 (bit 9 is SSSE3)
    TDEC_CPUSupport.SSE3 := (Reg.ECX and (1 shl 0)) <> 0;
    TDEC_CPUSupport.SSE41 := (Reg.ECX and (1 shl 19)) <> 0;
    TDEC_CPUSupport.SSE42 := (Reg.ECX and (1 shl 20)) <> 0;
    TDEC_CPUSupport.AES := (Reg.ECX and (1 shl 25)) <> 0;
    TDEC_CPUSupport.AVX := (Reg.ECX and (1 shl 28)) <> 0;
    TDEC_CPUSupport.RDRand := (Reg.ECX and (1 shl 30)) <> 0;
  end;

  if NIds >= 7 then
  begin
    Reg := GetCPUID(7, 0);
    TDEC_CPUSupport.AVX2 := (Reg.EBX and (1 shl 5)) <> 0;
    TDEC_CPUSupport.RDSeed := (Reg.EBX and (1 shl 18)) <> 0;
  end;
end;

{$ELSE}

function GetCPUID(ALeaf: Cardinal; ASubLeaf: Cardinal = 0): TCPUIDRec;
begin
  Result.EAX := 0;
  Result.EBX := 0;
  Result.ECX := 0;
  Result.EDX := 0;
end;

{$IFEND}

initialization
  TDEC_CPUSupport.AES := False;
  TDEC_CPUSupport.AVX := False;
  TDEC_CPUSupport.AVX2 := False;
  TDEC_CPUSupport.SSE := False;
  TDEC_CPUSupport.SSE2 := False;
  TDEC_CPUSupport.SSE3 := False;
  TDEC_CPUSupport.SSE41 := False;
  TDEC_CPUSupport.SSE42 := False;
  TDEC_CPUSupport.RDRand := False;
  TDEC_CPUSupport.RDSeed := False;
{$IF Defined(x64) or Defined(x86)}
  InitFlags;
{$IFEND}
end.
