.586
.model flat,stdcall
option casemap:none

   include windows.inc
   include user32.inc
   include kernel32.inc 
   include msvcrt.inc
   includelib user32.lib
   includelib kernel32.lib
   includelib msvcrt.LIB


;IMAGE_SIZE equ 00020000h
.data
   g_szExeName db "dll.dll",0
   g_szFuncName db "MsgBox",0
   g_szLoadError db "加载dll失",0

.data?
   hInstance HINSTANCE ?
   CommandLine LPSTR ?

.code
;	db IMAGE_SIZE dup(0)
;	org IMAGE_SIZE
MyGetProcAddress proc hDll:HINSTANCE,pName:LPCTSTR
	LOCAL @dwAddressOfNames:DWORD
	LOCAL @dwCnt:DWORD

	mov esi,hDll
	assume esi:ptr IMAGE_DOS_HEADER
	mov esi,[esi].e_lfanew
	add esi,hDll
	
	assume esi:ptr IMAGE_NT_HEADERS
	;得到导出表位置
	mov esi,[esi].OptionalHeader.DataDirectory[0].VirtualAddress
	add esi,hDll
	
	assume esi:ptr IMAGE_EXPORT_DIRECTORY
	
	.if pName > 0ffffh ;名称
		;导出名称表地址
		mov eax,[esi].AddressOfNames
		add eax,hDll
		mov @dwAddressOfNames,eax
	
		;遍历导出名称表，查找对应函数
		mov eax,[esi].NumberOfNames
		mov @dwCnt,eax
		dec @dwCnt
 		.while @dwCnt> 0
			;数组首地址
			mov ebx,@dwAddressOfNames
			mov eax,@dwCnt
			mov eax,[ebx+ eax * sizeof DWORD]
			add eax,hDll 

			;对比字符串
			invoke crt_strcmp,pName,eax
			.if eax == 0
				
				mov eax,@dwCnt
				mov ebx,[esi].AddressOfNameOrdinals
				add ebx,hDll
				movzx eax,word ptr [ebx+eax*sizeof WORD]
				
				;获取地址
				mov ebx,[esi].AddressOfFunctions
				add ebx,hDll
				mov eax,[ebx+eax*sizeof DWORD]
				
				add eax,hDll
				ret
			.endif
		
			dec @dwCnt
		.endw
	
	.else
		;获取导出地址表中的下标索引
		mov eax,pName
		sub eax,[esi].nBase
		
		;获取地址
		mov ebx,[esi].AddressOfFunctions
		add ebx,hDll
		mov eax,[ebx+eax*sizeof DWORD]
				
		add eax,hDll
		ret	
	.endif
	

	xor eax,eax	
	ret

MyGetProcAddress endp 
; ---------------------------------------------------------------------------
LoadDll proc uses esi edi ebx ecx pPath:LPSTR
	LOCAL @hFile:HANDLE
	LOCAL @hFileMap:HANDLE
	LOCAL @lpMapAddr:LPVOID
	LOCAL @dwFileSize:DWORD
	LOCAL @dwNumberOfsection:DWORD
	LOCAL @dwNumOfHeaders:DWORD
	LOCAL @pSecHdr:ptr IMAGE_SECTION_HEADER
	LOCAL @hInst:HANDLE
	LOCAL @dwOldProc:DWORD
	LOCAL @pImpHdr:ptr IMAGE_IMPORT_DESCRIPTOR
	LOCAL @zeroImp:IMAGE_IMPORT_DESCRIPTOR
	LOCAL @hDll:HANDLE
	LOCAL @pTempThunk: ptr IMAGE_DATA_THUNK
	LOCAL @dwPFNAddr:dword
	LOCAL @dwIAT:DWORD
	LOCAL @dwOep:DWORD
	LOCAL @dwSizeOfImag:DWORD
	LOCAL @pBaseReloc:ptr IMAGE_BASE_RELOCATION
	LOCAL @dwSizeOfReloc:DWORD
	LOCAL @dwOffReloc:DWORD
	LOCAL @dwCntOfReloc:DWORD
	
	
	invoke GetModuleHandle,NULL
	mov @hInst,eax
	
	
	invoke RtlZeroMemory,addr @zeroImp,sizeof IMAGE_IMPORT_DESCRIPTOR
	
	
	;映射文件
	invoke CreateFile,offset g_szExeName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if eax ==INVALID_HANDLE_VALUE
		xor eax,eax
		ret	
	.endif
	
	;存储文件
	mov @hFile,eax
	
	;创建映射
	invoke CreateFileMapping,@hFile,NULL,PAGE_READONLY,0,0,NULL
	.if eax==NULL
		invoke CloseHandle,@hFile
		ret
	.endif
	
	mov @hFileMap,eax
	;执行映射
	invoke MapViewOfFile,@hFileMap,FILE_MAP_READ,0,0,0
	
	.if eax==NULL
		invoke CloseHandle,@hFileMap
		invoke CloseHandle,@hFile
		xor eax,eax
		ret
	.endif 
	
	;保存映射得到的地址
	mov @lpMapAddr,eax
	assume esi:nothing
	
	;拷贝PE
	mov esi,@lpMapAddr
	assume esi:ptr IMAGE_DOS_HEADER
	;指向新的NT头地址
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	
	
	mov eax,[esi].OptionalHeader.SizeOfHeaders
	mov @dwNumOfHeaders,eax
	
	;节表数量
	movzx eax,[esi].FileHeader.NumberOfSections
	mov @dwNumberOfsection,eax
	
	;存储的是节表头地址
	movzx eax,[esi].FileHeader.SizeOfOptionalHeader
	lea ebx,[esi].OptionalHeader
	add eax,ebx
	mov @pSecHdr,eax
	
	mov eax,[esi].OptionalHeader.SizeOfImage
	mov @dwSizeOfImag,eax
	 
	;申请dll内存
	invoke  VirtualAlloc,NULL,@dwSizeOfImag,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	.if eax==NULL
		mov @hInst,NULL
		jmp EXIT 
	.endif
	;存储的是dll申请的内存
	mov @hInst,eax
	
	;@dwOffReloc存储的是首选基地址和实际加载地址的偏差
	sub eax,[esi].OptionalHeader.ImageBase
	mov @dwOffReloc,eax
	
	;存储的是dll 的dllmain
	push [esi].OptionalHeader.AddressOfEntryPoint
	pop @dwOep
	mov eax,@hInst
	add @dwOep,eax
	
	;得到导入表的地址
	lea eax,[esi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof IMAGE_DATA_DIRECTORY ]
	assume eax:ptr IMAGE_DATA_DIRECTORY
	mov eax,[eax].VirtualAddress 
	add eax,@hInst
	mov @pImpHdr,eax
	assume eax:nothing	
	

	;得到重定位表
	lea ebx,[esi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC * sizeof IMAGE_DATA_DIRECTORY ]
	assume ebx:ptr IMAGE_DATA_DIRECTORY
	mov eax,[ebx].VirtualAddress
	add eax,@hInst
	;存储的重定位表地址
	mov @pBaseReloc,eax
	;存储的重定位表大小
	mov eax,[ebx].isize
	;保存重定位表大小
	mov @dwSizeOfReloc,eax
	
	assume ebx:nothing
	
	assume esi:nothing
	
	assume eax:ptr IMAGE_DATA_DIRECTORY
	
	
	;拷贝dll节头到内存中
	invoke crt_memcpy,@hInst,@lpMapAddr,@dwNumOfHeaders
	
	
	xor ebx,ebx
	
	 ;拷贝节
	.while ebx < @dwNumberOfsection
		mov ecx,@pSecHdr
		assume ecx:ptr IMAGE_SECTION_HEADER
		;源
		mov esi,[ecx].PointerToRawData
		add esi,@lpMapAddr
		
		;目的
		mov edi,[ecx].VirtualAddress
		add edi,@hInst
		
		
		invoke crt_memcpy,edi,esi,[ecx].SizeOfRawData
		assume ecx:nothing
		
		
		add @pSecHdr,sizeof IMAGE_SECTION_HEADER
		inc ebx
	.endw
	
	
	;处理导入表
	.while TRUE
	;遇到全0项目，遍历结束
	 	invoke crt_memcmp,@pImpHdr,addr @zeroImp,sizeof IMAGE_IMPORT_DESCRIPTOR
	 	.if eax == 0
	  		.break
	  	.endif
	  
	 	mov esi,@pImpHdr
	 	assume esi:ptr IMAGE_IMPORT_DESCRIPTOR
		
		;获取dll的名称
		
		mov eax,[esi].Name1
		add eax,@hInst
		
		invoke LoadLibrary,eax
		.if eax==NULL
		 	;
		 	invoke MessageBox,NULL,offset g_szLoadError,offset g_szLoadError,MB_OK
			.break
		.endif
		
		mov @hDll,eax
		
		
		.if [esi].FirstThunk ==NULL
			.break
		.endif
		mov eax,[esi].FirstThunk
		add eax,@hInst
		mov @dwIAT,eax
		
		
		
		mov eax,[esi].OriginalFirstThunk
		mov @pTempThunk,eax
		
		.if @pTempThunk ==NULL
			mov eax,[esi].FirstThunk
			mov @pTempThunk,eax	
		.endif
		
		mov eax,@hInst
		add @pTempThunk,eax
		
		
		
		
		mov ebx,@pTempThunk
		.while dword ptr [ebx]!=NULL
			.if dword ptr[ebx] >= 8000000h
				;序号导入
				movzx eax,word ptr [ebx] ;低字为序号
				invoke GetProcAddress,@hDll,eax
				;check
				mov @dwPFNAddr,eax
			
			.else
				;名称导入
				mov eax,[ebx]
				add eax,@hInst ;ptr IMAGE_IMPORT_BY_NAME 前面有一个word
				add eax,sizeof word;导入函数地址
				invoke GetProcAddress,@hDll,eax
				mov @dwPFNAddr,eax
				
			.endif  
			
			
			;填充IAT
			mov eax,@dwIAT
			push @dwPFNAddr
			pop dword ptr [eax]
			
			
			add ebx,4
			add @dwIAT,4
		.endw
		
		 
		
		
		
	 	assume esi:nothing
	 	add @pImpHdr,sizeof IMAGE_IMPORT_DESCRIPTOR;下一项
	.endw
	
	;int 3;
	;处理重定位
	.while TRUE
		;@pBaseReloc存储的是重定位表初始化地址
		mov esi,@pBaseReloc
		assume esi:ptr IMAGE_BASE_RELOCATION
		
		
		;获取页内偏移数组地址,IMAGE_BASE_RELOCATION结构不包偏移数组含
		lea ebx,[esi+sizeof IMAGE_BASE_RELOCATION]
		
		;这里的得到是是偏移数组和IMAGE_BASE_RELOCATION总大小
		mov ecx,[esi].SizeOfBlock
		;减去结构体可以偏移数组的大小
		sub ecx,sizeof IMAGE_BASE_RELOCATION
		;右移动除以2，可以得到数组个数（因为每个item大小为2）
		shr ecx,1
		;存储数组的大小
		mov @dwCntOfReloc,ecx
		
		
		xor ecx,ecx
		;遍历偏移数组每一项
		.while ecx < @dwCntOfReloc
			;ecx表示正在遍历第几个
			movzx eax,word ptr[ebx + ecx*sizeof word]
			;只处理30类别 
			.if eax  & 0f000h
				;需要重定位
				and eax,0fffh
				add eax,[esi].VirtualAddress
				;获取需要重定位的地址
				add eax,@hInst
			
				;重定位
				mov edi,@dwOffReloc
				add dword ptr [eax],edi 
					
			.endif
			
			inc ecx

		.endw
		
		;;处理下一个分页 重定位表的下一个item
		add esi,[esi].SizeOfBlock
		;判断是否处理完所有重定位
		mov edi,esi
		;如果下一项的地址减去初始地址大于重定位初始地址证明遍历完成
		sub edi,@pBaseReloc
		.if edi >= @dwSizeOfReloc
			.break
		.endif
	.endw
	
	;调用dllmain
	push NULL
	push DLL_PROCESS_ATTACH
	push @hInst
	call @dwOep
	
	
	;清理
EXIT:	
	invoke UnmapViewOfFile,@lpMapAddr
	invoke CloseHandle,@hFileMap
	invoke CloseHandle,@hFile
	
	;返回模块的  句柄
	mov eax,@hInst
	ret

LoadDll endp

start:
	invoke LoadDll, offset g_szExeName
	invoke MyGetProcAddress, eax,offset g_szFuncName
	call eax
	
 	invoke ExitProcess,0


end start
