;
;
; Copyright (c) 2015-2018 by blindtiger ( blindtiger@foxmail.com )
;
; The contents of this file are subject to the Mozilla Public License Version
; 2.0 (the "License"); you may not use this file except in compliance with
; the License. You may obtain a copy of the License at
; http://www.mozilla.org/MPL/
;
; Software distributed under the License is distributed on an "AS IS" basis,
; WITHOUT WARRANTY OF ANY KIND, either express or implied. SEe the License
; for the specific language governing rights and limitations under the
; License.
;
; The Initial Developer of the Original e is blindtiger.
;
;

    .XLIST
INCLUDE KSAMD64.INC
    .LIST

OPTION CASEMAP:NONE

IoGetInitialStack PROTO
PgDecodeClear PROTO

_DATA$00 SEGMENT PAGE 'DATA'

_DATA$00 ENDS

_TEXT$00 SEGMENT PAGE 'CODE'

_btc64 :
    
    btc rcx, rdx
    mov rax, rcx
    ret

PUBLIC _btc64

align 40h

_PgEncodeClear :
    
extern PgEncodeClear : PROTO

    sub rsp, 28h
    
    call PgEncodeClear
    
    add rsp, 28h
    
    add rsp, 30h
    ret

PUBLIC _PgEncodeClear

align 40h

_RevertWorkerThreadToSelf :
    
extern NtosKiStartSystemThread : PTR
extern NtosPspSystemThreadStartup : PTR
extern NtosExpWorkerThread : PTR
extern NtosExpWorkerContext : PTR

    call PgDecodeClear

    call IoGetInitialStack

    mov rsp, rax
    sub rsp, KSTART_FRAME_LENGTH

    mov rax, NtosExpWorkerContext 
    mov SfP1Home [rsp], rax

    mov rax, NtosExpWorkerThread
    mov SfP2Home [rsp], rax

    mov rax, NtosPspSystemThreadStartup
    mov SfP3Home [rsp], rax
    
    xor rax, rax
    mov SfReturn [rsp], rax

    mov rax, NtosKiStartSystemThread
    jmp rax

PUBLIC _RevertWorkerThreadToSelf

align 40h

MakePgFire :

    sub rsp, 20h

    lea rcx, [rsp + 2]

    sidt fword ptr [rcx]

    mov ax, 0ffffh
    mov [rcx], ax

    lidt fword ptr [rcx]
    sidt fword ptr [rcx]

    add rsp, 20h

    ret

PUBLIC MakePgFire

align 40h

_TEXT$00 ENDS

END
