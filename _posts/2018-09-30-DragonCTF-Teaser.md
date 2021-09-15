---
author: zero
comments: true
date: 2018-09-30 00:00:00 
layout: post
slug: DragonCTF-Teaser 
title: DragonCTF-Teaser-Brutal Oldskull 
---

**Description**:
The '90s called and wanted their crackme back. It's basically a walk in a park.

## File

```
~/Desktop                                                         
▶ file oldskull.exe
oldskull.exe: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows
```

It's PE32 exectuable....time to spin up the vm...

## Protections

Not relevant for this challenge...

## Program

{% highlight c %}
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  int result; // eax
  struct tagMSG Msg; // [esp+30h] [ebp-58h]
  WNDCLASSEXA v6; // [esp+4Ch] [ebp-3Ch]
  HWND hWnd; // [esp+7Ch] [ebp-Ch]

  ::hInstance = hInstance;
  v6.cbSize = 48;
  v6.style = 0;
  v6.lpfnWndProc = sub_401D77;
  v6.cbClsExtra = 0;
  v6.cbWndExtra = 0;
  v6.hInstance = hInstance;
  v6.hIcon = LoadIconA(0, (LPCSTR)0x7F00);
  v6.hCursor = LoadCursorA(0, (LPCSTR)0x7F00);
  v6.hbrBackground = (HBRUSH)5;
  v6.lpszMenuName = 0;
  v6.lpszClassName = "PrettyBrutalWindowClass";
  v6.hIconSm = LoadIconA(0, (LPCSTR)0x7F00);
  if ( RegisterClassExA(&v6) == 0 )
  {
    MessageBoxA(0, "Window Registration Failed!", "Error!", 0x30u);
    result = 0;
  }
  else
  {
    hWnd = CreateWindowExA(
             0,
             "PrettyBrutalWindowClass",
             "Brutal Oldskull",
             0xCF0000u,
             150,
             150,
             320,
             260,
             0,
             0,
             hInstance,
             0);
    if ( hWnd )
    {
      ShowWindow(hWnd, nShowCmd);
      UpdateWindow(hWnd);
      while ( GetMessageA(&Msg, 0, 0, 0) != 0 )
      {
        TranslateMessage(&Msg);
        DispatchMessageA(&Msg);
      }
      result = Msg.wParam;
    }
    else
    {
      MessageBoxA(0, "Window Creation Failed!", "Error!", 0x30u);
      result = 0;
    }
  }
  return result;
}
{% endhighlight %}

**WinMain** function does not do much other than creating a window with some registered functions.  

## Analysis 

![score]({{ site.url }}/images/2018/oldskull1.bmp)


This program expects five inputs: code1~code4 and the final flag. It seems the user input goes through some functions that determine whether it is correct or not.

**Code Checker**

{% highlight c %}

void code_checker()
{
  char *v0; // eax
  CHAR v1; // [esp+30h] [ebp-498h]
  unsigned int v2; // [esp+130h] [ebp-398h]
  CHAR String[4]; // [esp+134h] [ebp-394h]
  int v4; // [esp+138h] [ebp-390h]
  int v5; // [esp+13Ch] [ebp-38Ch]
  int v6; // [esp+140h] [ebp-388h]
  DWORD ExitCode; // [esp+144h] [ebp-384h]
  CHAR v8; // [esp+148h] [ebp-380h]
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+248h] [ebp-280h]
  struct _STARTUPINFOA StartupInfo; // [esp+258h] [ebp-270h]
  char Buffer[512]; // [esp+29Ch] [ebp-22Ch]
  unsigned __int16 v12; // [esp+49Ch] [ebp-2Ch]
  unsigned __int16 v13; // [esp+49Eh] [ebp-2Ah]
  unsigned __int16 v14; // [esp+4A0h] [ebp-28h]
  unsigned __int16 v15; // [esp+4A2h] [ebp-26h]
  BOOL v16; // [esp+4A4h] [ebp-24h]
  FILE *fd; // [esp+4A8h] [ebp-20h]
  void *data; // [esp+4ACh] [ebp-1Ch]
  void *v19; // [esp+4B0h] [ebp-18h]
  void *v20; // [esp+4B4h] [ebp-14h]
  void *v21; // [esp+4B8h] [ebp-10h]
  int i; // [esp+4BCh] [ebp-Ch]

  sub_4016C2("Processing...");
  for ( i = 0; i <= 3; ++i )
  {
    *(_DWORD *)String = 0;
    v4 = 0;
    v5 = 0;
    v6 = 0;
    GetWindowTextA(*(&dword_40C034 + i), String, 8);
    if ( sscanf(String, "%x", &v2) != 1 )
    {
      sprintf(&v1, "Incorrect Code %i format (16-bit HEX)", i + 1);
      sub_4016C2(&v1);
      return;
    }
    if ( v2 > 0xFFFF )
    {
      sub_4016C2("Incorrect Code.");
      return;
    }
    *(&v12 + i) = v2;
  }
  v21 = checker((int)&unk_405020, 0x4C8Eu, v12);
  if ( v21 )
  {
    v20 = checker((int)v21, 0x4C6Eu, v13);
    if ( v20 )
    {
      v19 = checker((int)v20, 0x4C4Eu, v14);
      if ( v19 )
      {
        data = checker((int)v19, 0x4C2Eu, v15);
        if ( data )
        {
          free(v21);
          free(v20);
          free(v19);
          memset(Buffer, 0, sizeof(Buffer));
          GetTempPathA(256u, Buffer);
          v0 = &Buffer[strlen(Buffer)];
          *(_DWORD *)v0 = 0x646C6F5C;
          *((_DWORD *)v0 + 1) = 0x6C756B73;
          *((_DWORD *)v0 + 2) = 'hc_l';
          *((_DWORD *)v0 + 3) = 'ekce';
          *((_DWORD *)v0 + 4) = 'xe.r';
          *((_WORD *)v0 + 10) = 101;
          fd = fopen(Buffer, "wb");
          if ( fd )
          {
            fwrite(data, 1u, 0x4C0Eu, fd);
            fclose(fd);
            free(data);
            memset(&StartupInfo, 0, sizeof(StartupInfo));
            StartupInfo.cb = 68;
            ProcessInformation.hProcess = 0;
            ProcessInformation.hThread = 0;
            ProcessInformation.dwProcessId = 0;
            ProcessInformation.dwThreadId = 0;
            memset(&v8, 0, 0x100u);
            GetWindowTextA(dword_40C044, &v8, 64);
            *(_WORD *)&Buffer[strlen(Buffer)] = 32;
            strcat(Buffer, &v8);
            v16 = CreateProcessA(0, Buffer, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation);
            if ( v16 )
            {
              if ( WaitForSingleObject(ProcessInformation.hProcess, 0x7D0u) != 0 )
              {
                TerminateProcess(ProcessInformation.hProcess, 9u);
                CloseHandle(ProcessInformation.hProcess);
                CloseHandle(ProcessInformation.hThread);
                sub_4016C2("Checker crashed. Sorry.");
              }
              else
              {
                ExitCode = -1;
                v16 = GetExitCodeProcess(ProcessInformation.hProcess, &ExitCode);
                if ( v16 )
                {
                  if ( ExitCode )
                    sub_4016C2("Wrong Flag.");
                  else
                    sub_4016C2("Well Done! But you know that :)");
                  CloseHandle(ProcessInformation.hProcess);
                  CloseHandle(ProcessInformation.hThread);
                }
                else
                {
                  CloseHandle(ProcessInformation.hProcess);
                  CloseHandle(ProcessInformation.hThread);
                  sub_4016C2("Checker failed. Sorry.");
                }
              }
            }
            else
            {
              sub_4016C2("Couldn't spawn checker");
            }
          }
          else
          {
            sub_4016C2("Couldn't write the checker file.");
            free(data);
          }
        }
        else
        {
          sub_4016C2("Wrong Code 4.");
          free(v21);
          free(v20);
          free(v19);
        }
      }
      else
      {
        sub_4016C2("Wrong Code 3.");
        free(v21);
        free(v20);
      }
    }
    else
    {
      sub_4016C2("Wrong Code 2.");
      free(v21);
    }
  }
  else
  {
    sub_4016C2("Wrong Code 1.");
  }
}
{% endhighlight %}

In order to pass the check, the user input must be between 0 - 0xFFFF (16 bit) and it has to return NON-ZERO value after going through the **checker**.

Looking at the checker function, this function calls out even more and more functions... 

For your sanity, this is the pseudo code for the checker function:

{% highlight c %}

char payload[0x4cd0] = some large character set

int checker(char*data,size_t size,int user_input)
{
	local_buffer = malloc(size);
		
	memset(local_buffer, 0, size);
	
	for ( i = 0; i < size; ++i )
    		local_buffer[i] = (payload[i] ^ input) - HIBYTE(input);
    	
	input *= 0x62F3;
	
	memset(&, 0, 0x28u);
	
	some_crazy_operation(local_buffer, size - 32, (int)&result);
  	
	if ( !memcmp(&result, (char *)local_buffer + size - 32, 32u) )
    		return result;
  	
	free(local_buffer);
  	
	return 0;	
	
}
 
{% endhighlight %}

The key point here is that it checks if the last 32 bytes from the local buffer are equal to the result (after going through that **some_crazy_function**).     

## Solution 

As my first attempt, I wrote the following script to brute force each code since it could be solved without taking too much time. 

{% highlight python %}
import lief

pe = lief.parse("oldskull.exe")

sz1 = 0x4C8E 
sz2 = 0x4C6E
sz3 = 0x4C4E
sz4 = 0x4C2E

data = pe.get_secton(".data")
array = data.content[:32]
result = [0]*sz1
end_value = [*]*0x28

for i in range(0xFFFF):
    temp = i
    for j in range(len(array)):
        result[i] = (array[i] ^ temp) - temp
	temp  *= 0x62F3
    check = crazy_function(result,sz1-32,end_value)
    if check == result[-32:]:
	print "Code1: %x" % (i)
        break	 

    #reset
    result = [0]*sz1
    end_value = [*]*0x28	

{% endhighlight %}

But then again, it did not help me as much since I did not fully reverse the **crazy_fucntion**. 

As my second attempt I wrote an autohotkey script that fed the number and clicked the button to see if it was correct or not:

{% highlight autohotkey	 %}
F1::Reload
F2::

Loop, 0XFFFF
{

SetFormat, IntegerFast, Hex

temp := A_INDEX

StringTrimLeft, temp, temp, 2 ;strip 0x

ControlSetText, ,%temp%, macroworld 

Loop, 3
{
	MouseClick, left, 147, 195
}	

Sleep, 50

ImageSearch, vx, vy, 0, 0, A_ScreenWidth, A_ScreenHeight, *100 %A_ScriptDir%\Images\wrong.bmp	

if (Errorlevel != 0)
{
	MsgBox, %temp%.
	return 
}
	
}
F3::Pause

F10::winsettitle,Brutal Oldskull,, macroworld

{% endhighlight %} 

This was more promising since there was a guarantee that it would tell me the correct number...

![score]({{ site.url }}/images/2018/autohotkey.gif)

But it was taking forever (at least not up to the speed that I was expected. Perhaps, it was due to ImageSearch...)

As my final attempt, I decided to patch the program so that the program itself reveals the answer. 

{% highlight nasm %}


004018E6 | 0FB7C0                   | movzx eax,ax                               | //target1
004018E9 | 894424 08                | mov dword ptr ss:[esp+8],eax               |
004018ED | C74424 04 8E4C0000       | mov dword ptr ss:[esp+4],4C8E              |
004018F5 | C70424 20504000          | mov dword ptr ss:[esp],oldskull.405020    |
004018FC | E8 E3FDFFFF              | call oldskull.4016E4                       | //v21 = checker((int)&unk_405020, 0x4C8Eu, v12)
00401901 | 8945 F0                  | mov dword ptr ss:[ebp-10],eax              |
00401904 | 837D F0 00               | cmp dword ptr ss:[ebp-10],0                |
00401908 | 75 11                    | jne oldskull.40191B                        | //target2
0040190A | C70424 B2A04000          | mov dword ptr ss:[esp],oldskull.40A0B2    | 40A0B2:"Wrong Code 1."
00401911 | E8 ACFDFFFF              | call oldskull.4016C2                       |

{% endhighlight %}

I made the following patch to get the code:

{% highlight nasm %}

Instruction: movzx eax --> inc ebx,mov eax,ebx
Opcode: 0FB7C0 --> 4389d8

Instruction: jne --> je
Opcdoe: 7511 -->  74 DD 

{% endhighlight %}

By doing so, the program will jump back to `inc ebx` until the return value from the checker function is non-zero.  

Once I got all the correct numbers, the program reaches the following code:


{% highlight c %}
...

free(v21);
free(v20);
free(v19);

memset(Buffer, 0, sizeof(Buffer));

GetTempPathA(256u, Buffer);

v0 = &Buffer[strlen(Buffer)];
*(_DWORD *)v0 = 0x646C6F5C;
*((_DWORD *)v0 + 1) = 0x6C756B73;
*((_DWORD *)v0 + 2) = 'hc_l';
*((_DWORD *)v0 + 3) = 'ekce';
*((_DWORD *)v0 + 4) = 'xe.r';
*((_WORD *)v0 + 10) = 101;

fd = fopen(Buffer, "wb");

if ( fd )
{
	fwrite(data, 1u, 0x4C0Eu, fd);
	fclose(fd);
	free(data);
	memset(&StartupInfo, 0, sizeof(StartupInfo));
	StartupInfo.cb = 68;
	ProcessInformation.hProcess = 0;
	ProcessInformation.hThread = 0;
	ProcessInformation.dwProcessId = 0;
	ProcessInformation.dwThreadId = 0;
	memset(&v8, 0, 0x100u);
	GetWindowTextA(dword_40C044, &v8, 64);
	*(_WORD *)&Buffer[strlen(Buffer)] = 32;
	strcat(Buffer, &v8);
	v16 = CreateProcessA(0, Buffer, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation);
	if ( v16 )
	{
		if ( WaitForSingleObject(ProcessInformation.hProcess, 0x7D0u) != 0 )
		{
			TerminateProcess(ProcessInformation.hProcess, 9u);
			CloseHandle(ProcessInformation.hProcess);
	
	...

{% endhighlight %}
 
This just writes some data return from the last checker function to `C:\HOME\AppData\Local\Temp\oldskull_checker.exe`. (To be more exact, data from a decrypted blob gets written to the file called **oldskull_checker.exe**). 

Then, it runs the program and sends the user input (final flag). Based on the return status, it prints `Wrong Flag` or `Well Done! But you know that :)`.

Looking at `oldskull_checker.exe` in ida, it does the following check on the user input:

{% highlight c %}
for ( i = 0; i <= 19; ++i )
{
	if ( user_input[i] != (data[i] ^ 0x8F) )
		return 3;
}
{% endhighlight %}

At this point, all I had to do was to write a simple python script that prints out the flag.

```
~/Desktop/DRAGONSECTOR2018
▶ python oldskull.py
[*]FLAG:DrgnS(WaaayTooEZ!!1}

```

Verifying with the program:

![score]({{ site.url }}/images/2018/oldskull2.bmp)


