-- NullSec PECheck - PE File Analyzer
-- Ada security tool demonstrating:
--   - Strong static typing
--   - Design by contract (pre/postconditions)
--   - Tagged types for OOP
--   - Safe memory management
--   - Exception handling
--
-- Author: bad-antics
-- License: MIT

with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Integer_Text_IO;   use Ada.Integer_Text_IO;
with Ada.Command_Line;      use Ada.Command_Line;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Calendar;          use Ada.Calendar;
with Ada.Directories;       use Ada.Directories;

procedure PECheck is
   
   Version : constant String := "1.0.0";
   
   -- ANSI Colors
   Red    : constant String := ASCII.ESC & "[31m";
   Green  : constant String := ASCII.ESC & "[32m";
   Yellow : constant String := ASCII.ESC & "[33m";
   Cyan   : constant String := ASCII.ESC & "[36m";
   Gray   : constant String := ASCII.ESC & "[90m";
   Reset  : constant String := ASCII.ESC & "[0m";
   
   -- Severity levels
   type Severity is (Critical, High, Medium, Low, Info);
   
   function Severity_Color (S : Severity) return String is
   begin
      case S is
         when Critical | High => return Red;
         when Medium          => return Yellow;
         when Low             => return Cyan;
         when Info            => return Gray;
      end case;
   end Severity_Color;
   
   -- PE Magic numbers
   MZ_Magic : constant := 16#5A4D#;  -- "MZ"
   PE_Magic : constant := 16#4550#;  -- "PE\0\0"
   
   -- Machine types
   type Machine_Type is (Unknown, I386, AMD64, ARM, ARM64, IA64);
   
   function Machine_Name (M : Machine_Type) return String is
   begin
      case M is
         when Unknown => return "Unknown";
         when I386    => return "x86 (32-bit)";
         when AMD64   => return "x64 (64-bit)";
         when ARM     => return "ARM";
         when ARM64   => return "ARM64";
         when IA64    => return "IA-64";
      end case;
   end Machine_Name;
   
   -- PE Characteristics flags
   type PE_Characteristics is record
      Is_Executable   : Boolean := False;
      Is_DLL          : Boolean := False;
      Is_Large_Address: Boolean := False;
      Is_Relocatable  : Boolean := False;
      Is_Debug_Strip  : Boolean := False;
      Is_System       : Boolean := False;
      ASLR_Enabled    : Boolean := False;
      DEP_Enabled     : Boolean := False;
      SEH_Enabled     : Boolean := False;
      CFG_Enabled     : Boolean := False;
   end record;
   
   -- Section info
   type Section_Info is record
      Name           : Unbounded_String;
      Virtual_Size   : Natural := 0;
      Virtual_Addr   : Natural := 0;
      Raw_Size       : Natural := 0;
      Entropy        : Float := 0.0;
      Is_Executable  : Boolean := False;
      Is_Writable    : Boolean := False;
      Is_Readable    : Boolean := False;
   end record;
   
   type Section_Array is array (1 .. 16) of Section_Info;
   
   -- PE Header info
   type PE_Header is tagged record
      File_Path       : Unbounded_String;
      Machine         : Machine_Type := Unknown;
      Num_Sections    : Natural := 0;
      Timestamp       : Time;
      Entry_Point     : Natural := 0;
      Image_Base      : Natural := 0;
      Characteristics : PE_Characteristics;
      Sections        : Section_Array;
      Is_64bit        : Boolean := False;
      Subsystem       : Natural := 0;
   end record;
   
   -- Finding record
   type Finding is record
      Sev         : Severity;
      Category    : Unbounded_String;
      Message     : Unbounded_String;
      Detail      : Unbounded_String;
   end record;
   
   type Finding_Array is array (1 .. 50) of Finding;
   
   -- Analyzer state
   type PE_Analyzer is tagged record
      Header       : PE_Header;
      Findings     : Finding_Array;
      Finding_Count: Natural := 0;
   end record;
   
   -- Add finding with precondition
   procedure Add_Finding (Analyzer : in out PE_Analyzer;
                         S : Severity;
                         Cat : String;
                         Msg : String;
                         Det : String := "")
     with Pre => Analyzer.Finding_Count < 50
   is
   begin
      Analyzer.Finding_Count := Analyzer.Finding_Count + 1;
      Analyzer.Findings (Analyzer.Finding_Count) := 
        (Sev      => S,
         Category => To_Unbounded_String (Cat),
         Message  => To_Unbounded_String (Msg),
         Detail   => To_Unbounded_String (Det));
   end Add_Finding;
   
   -- Simulate PE parsing
   procedure Parse_PE (Analyzer : in out PE_Analyzer;
                      Path : String) is
   begin
      Analyzer.Header.File_Path := To_Unbounded_String (Path);
      Analyzer.Header.Machine := AMD64;
      Analyzer.Header.Is_64bit := True;
      Analyzer.Header.Num_Sections := 5;
      Analyzer.Header.Entry_Point := 16#1000#;
      Analyzer.Header.Image_Base := 16#140000000#;
      Analyzer.Header.Timestamp := Clock;
      
      -- Simulated characteristics
      Analyzer.Header.Characteristics := (
         Is_Executable    => True,
         Is_DLL           => False,
         Is_Large_Address => True,
         Is_Relocatable   => True,
         Is_Debug_Strip   => True,
         Is_System        => False,
         ASLR_Enabled     => True,
         DEP_Enabled      => True,
         SEH_Enabled      => True,
         CFG_Enabled      => False  -- Missing CFG for demo
      );
      
      -- Simulated sections
      Analyzer.Header.Sections (1) := (
         Name          => To_Unbounded_String (".text"),
         Virtual_Size  => 16#5000#,
         Virtual_Addr  => 16#1000#,
         Raw_Size      => 16#5000#,
         Entropy       => 6.2,
         Is_Executable => True,
         Is_Writable   => False,
         Is_Readable   => True
      );
      
      Analyzer.Header.Sections (2) := (
         Name          => To_Unbounded_String (".rdata"),
         Virtual_Size  => 16#2000#,
         Virtual_Addr  => 16#6000#,
         Raw_Size      => 16#2000#,
         Entropy       => 4.8,
         Is_Executable => False,
         Is_Writable   => False,
         Is_Readable   => True
      );
      
      Analyzer.Header.Sections (3) := (
         Name          => To_Unbounded_String (".data"),
         Virtual_Size  => 16#1000#,
         Virtual_Addr  => 16#8000#,
         Raw_Size      => 16#800#,
         Entropy       => 3.5,
         Is_Executable => False,
         Is_Writable   => True,
         Is_Readable   => True
      );
      
      Analyzer.Header.Sections (4) := (
         Name          => To_Unbounded_String ("UPX0"),
         Virtual_Size  => 16#10000#,
         Virtual_Addr  => 16#9000#,
         Raw_Size      => 16#100#,
         Entropy       => 7.9,  -- High entropy = packed
         Is_Executable => True,
         Is_Writable   => True,
         Is_Readable   => True
      );
      
      Analyzer.Header.Sections (5) := (
         Name          => To_Unbounded_String (".rsrc"),
         Virtual_Size  => 16#500#,
         Virtual_Addr  => 16#19000#,
         Raw_Size      => 16#500#,
         Entropy       => 5.1,
         Is_Executable => False,
         Is_Writable   => False,
         Is_Readable   => True
      );
   end Parse_PE;
   
   -- Analyze security features
   procedure Analyze_Security (Analyzer : in Out PE_Analyzer) is
      C : PE_Characteristics renames Analyzer.Header.Characteristics;
   begin
      -- Check ASLR
      if not C.ASLR_Enabled then
         Add_Finding (Analyzer, High, "Security", 
                     "ASLR not enabled",
                     "Enable /DYNAMICBASE linker flag");
      end if;
      
      -- Check DEP
      if not C.DEP_Enabled then
         Add_Finding (Analyzer, High, "Security",
                     "DEP/NX not enabled",
                     "Enable /NXCOMPAT linker flag");
      end if;
      
      -- Check CFG
      if not C.CFG_Enabled then
         Add_Finding (Analyzer, Medium, "Security",
                     "Control Flow Guard not enabled",
                     "Enable /guard:cf linker flag");
      end if;
   end Analyze_Security;
   
   -- Analyze sections
   procedure Analyze_Sections (Analyzer : in out PE_Analyzer) is
   begin
      for I in 1 .. Analyzer.Header.Num_Sections loop
         declare
            S : Section_Info renames Analyzer.Header.Sections (I);
         begin
            -- Check for high entropy (packed/encrypted)
            if S.Entropy > 7.0 then
               Add_Finding (Analyzer, High, "Packing",
                           "High entropy section: " & To_String (S.Name),
                           "Entropy: " & Float'Image (S.Entropy));
            end if;
            
            -- Check for executable + writable
            if S.Is_Executable and S.Is_Writable then
               Add_Finding (Analyzer, Critical, "Memory",
                           "Section is both executable and writable: " & To_String (S.Name),
                           "Potential shellcode injection target");
            end if;
            
            -- Check for suspicious names
            if To_String (S.Name) = "UPX0" or 
               To_String (S.Name) = "UPX1" then
               Add_Finding (Analyzer, Medium, "Packing",
                           "UPX packer signature found",
                           "Section: " & To_String (S.Name));
            end if;
         end;
      end loop;
   end Analyze_Sections;
   
   -- Print banner
   procedure Print_Banner is
   begin
      New_Line;
      Put_Line ("╔══════════════════════════════════════════════════════════════════╗");
      Put_Line ("║            NullSec PECheck - PE File Analyzer                    ║");
      Put_Line ("╚══════════════════════════════════════════════════════════════════╝");
      New_Line;
   end Print_Banner;
   
   -- Print usage
   procedure Print_Usage is
   begin
      Print_Banner;
      Put_Line ("USAGE:");
      Put_Line ("    pecheck [OPTIONS] <file.exe>");
      New_Line;
      Put_Line ("OPTIONS:");
      Put_Line ("    -h, --help       Show this help");
      Put_Line ("    -j, --json       JSON output");
      Put_Line ("    -v, --verbose    Verbose output");
      Put_Line ("    --sections       Show section details");
      Put_Line ("    --imports        Show import table");
      New_Line;
      Put_Line ("EXAMPLES:");
      Put_Line ("    pecheck malware.exe");
      Put_Line ("    pecheck --sections sample.dll");
      Put_Line ("    pecheck -j suspicious.exe > report.json");
      New_Line;
      Put_Line ("CHECKS:");
      Put_Line ("    - ASLR/DEP/CFG protection");
      Put_Line ("    - Section entropy analysis");
      Put_Line ("    - Packer detection (UPX, etc.)");
      Put_Line ("    - Executable/writable sections");
   end Print_Usage;
   
   -- Print PE info
   procedure Print_PE_Info (Analyzer : PE_Analyzer) is
      H : PE_Header renames Analyzer.Header;
   begin
      Put_Line (Cyan & "File: " & Reset & To_String (H.File_Path));
      Put_Line ("  Machine:     " & Machine_Name (H.Machine));
      Put_Line ("  Sections:    " & Natural'Image (H.Num_Sections));
      Put ("  Entry Point: 0x");
      Put (H.Entry_Point, Base => 16);
      New_Line;
      New_Line;
      
      Put_Line (Cyan & "Security Features:" & Reset);
      Put ("  ASLR:  ");
      if H.Characteristics.ASLR_Enabled then
         Put_Line (Green & "Enabled" & Reset);
      else
         Put_Line (Red & "Disabled" & Reset);
      end if;
      
      Put ("  DEP:   ");
      if H.Characteristics.DEP_Enabled then
         Put_Line (Green & "Enabled" & Reset);
      else
         Put_Line (Red & "Disabled" & Reset);
      end if;
      
      Put ("  CFG:   ");
      if H.Characteristics.CFG_Enabled then
         Put_Line (Green & "Enabled" & Reset);
      else
         Put_Line (Yellow & "Disabled" & Reset);
      end if;
      New_Line;
      
      Put_Line (Cyan & "Sections:" & Reset);
      for I in 1 .. H.Num_Sections loop
         declare
            S : Section_Info renames H.Sections (I);
            Perms : String (1 .. 3) := "---";
         begin
            if S.Is_Readable then Perms (1) := 'R'; end if;
            if S.Is_Writable then Perms (2) := 'W'; end if;
            if S.Is_Executable then Perms (3) := 'X'; end if;
            
            Put ("  " & To_String (S.Name));
            for J in Length (S.Name) .. 10 loop
               Put (" ");
            end loop;
            Put ("[" & Perms & "]  Entropy: ");
            Put (S.Entropy, Fore => 1, Aft => 2, Exp => 0);
            New_Line;
         end;
      end loop;
      New_Line;
   end Print_PE_Info;
   
   -- Print findings
   procedure Print_Findings (Analyzer : PE_Analyzer) is
   begin
      if Analyzer.Finding_Count = 0 then
         Put_Line (Green & "✓ No security issues found" & Reset);
         return;
      end if;
      
      Put_Line (Yellow & "Findings:" & Reset);
      New_Line;
      
      for I in 1 .. Analyzer.Finding_Count loop
         declare
            F : Finding renames Analyzer.Findings (I);
            Sev_Str : String (1 .. 10);
         begin
            case F.Sev is
               when Critical => Sev_Str := "[CRITICAL]";
               when High     => Sev_Str := "[HIGH]    ";
               when Medium   => Sev_Str := "[MEDIUM]  ";
               when Low      => Sev_Str := "[LOW]     ";
               when Info     => Sev_Str := "[INFO]    ";
            end case;
            
            Put_Line ("  " & Severity_Color (F.Sev) & Sev_Str & Reset & 
                     " " & To_String (F.Category) & ": " & To_String (F.Message));
         end;
      end loop;
   end Print_Findings;
   
   -- Print summary
   procedure Print_Summary (Analyzer : PE_Analyzer) is
      Critical_Count : Natural := 0;
      High_Count     : Natural := 0;
      Medium_Count   : Natural := 0;
   begin
      for I in 1 .. Analyzer.Finding_Count loop
         case Analyzer.Findings (I).Sev is
            when Critical => Critical_Count := Critical_Count + 1;
            when High     => High_Count := High_Count + 1;
            when Medium   => Medium_Count := Medium_Count + 1;
            when others   => null;
         end case;
      end loop;
      
      New_Line;
      Put_Line (Gray & "═══════════════════════════════════════════" & Reset);
      New_Line;
      Put_Line ("Summary:");
      Put_Line ("  " & Red & "Critical:" & Reset & Natural'Image (Critical_Count));
      Put_Line ("  " & Red & "High:" & Reset & "    " & Natural'Image (High_Count));
      Put_Line ("  " & Yellow & "Medium:" & Reset & "  " & Natural'Image (Medium_Count));
   end Print_Summary;
   
   -- Main execution
   Analyzer : PE_Analyzer;
   File_Path : Unbounded_String := To_Unbounded_String ("sample.exe");
   
begin
   if Argument_Count > 0 then
      if Argument (1) = "-h" or Argument (1) = "--help" then
         Print_Usage;
         return;
      end if;
      File_Path := To_Unbounded_String (Argument (1));
   end if;
   
   Print_Banner;
   
   Put_Line (Yellow & "[Demo Mode]" & Reset);
   New_Line;
   
   Parse_PE (Analyzer, To_String (File_Path));
   Analyze_Security (Analyzer);
   Analyze_Sections (Analyzer);
   
   Print_PE_Info (Analyzer);
   Print_Findings (Analyzer);
   Print_Summary (Analyzer);
   
end PECheck;
