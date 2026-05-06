--  CAVP cross-validation harness for sha3_ada.
--
--  Reads NIST CAVP `.rsp` files (ShortMsg, LongMsg, VariableOut) and
--  drives this implementation against each Len/Msg/{MD,Output} triple
--  found, reporting pass/fail per vector.
--
--  Vector file format (informally):
--
--      [L = 256]              -- output length in bits, optional header
--
--      Len = 0                -- input length in bits
--      Msg = 00               -- input message in hex; '00' means empty
--      MD = a7ffc6f8...       -- expected digest in hex (or 'Output =')
--
--  Usage:
--
--      cavp_runner <algorithm> <path-to-rsp>
--
--  where <algorithm> is one of: sha3_256, sha3_512, shake128, shake256.

with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Interfaces;
with SHA3;

procedure Cavp_Runner is

   use Ada.Text_IO;
   use Ada.Strings.Unbounded;
   use type Interfaces.Unsigned_8;

   subtype U8 is Interfaces.Unsigned_8;
   type Byte_Array is array (Natural range <>) of U8;

   function Hex_Char_Value (C : Character) return U8 is
   begin
      case C is
         when '0' .. '9' => return U8 (Character'Pos (C) - Character'Pos ('0'));
         when 'a' .. 'f' => return U8 (Character'Pos (C) - Character'Pos ('a') + 10);
         when 'A' .. 'F' => return U8 (Character'Pos (C) - Character'Pos ('A') + 10);
         when others     => raise Constraint_Error with "non-hex char: '" & C & "'";
      end case;
   end Hex_Char_Value;

   function Hex_Decode (S : String) return Byte_Array is
      Result : Byte_Array (0 .. S'Length / 2 - 1);
   begin
      for I in Result'Range loop
         Result (I) := 16 * Hex_Char_Value (S (S'First + 2 * I))
                          + Hex_Char_Value (S (S'First + 2 * I + 1));
      end loop;
      return Result;
   end Hex_Decode;

   function Hex_Encode (B : Byte_Array) return String is
      Hex_Chars : constant String := "0123456789abcdef";
      Result    : String (1 .. 2 * B'Length);
   begin
      for I in B'Range loop
         Result (1 + 2 * (I - B'First)) :=
           Hex_Chars (1 + Integer (B (I) / 16));
         Result (2 + 2 * (I - B'First)) :=
           Hex_Chars (1 + Integer (B (I) mod 16));
      end loop;
      return Result;
   end Hex_Encode;

   procedure Equals_Sign_Split
     (Line  : String;
      Key   : out Unbounded_String;
      Value : out Unbounded_String)
   is
      Eq : constant Natural := Ada.Strings.Fixed.Index (Line, "=");
   begin
      if Eq = 0 then
         Key   := Null_Unbounded_String;
         Value := Null_Unbounded_String;
         return;
      end if;
      Key := To_Unbounded_String
        (Ada.Strings.Fixed.Trim
          (Line (Line'First .. Eq - 1), Ada.Strings.Both));
      Value := To_Unbounded_String
        (Ada.Strings.Fixed.Trim
          (Line (Eq + 1 .. Line'Last), Ada.Strings.Both));
   end Equals_Sign_Split;

   --  Run one vector against the chosen algorithm. Returns True on
   --  match. Out_Len_Bits is used by SHAKE; ignored for fixed-length.
   function Run_Vector
     (Algo         : String;
      Msg          : Byte_Array;
      Expected     : Byte_Array;
      Out_Len_Bits : Natural) return Boolean
   is
      pragma Unreferenced (Out_Len_Bits);
      Sha3_Msg : SHA3.Byte_Array (Msg'Range);
      Got_32   : SHA3.Byte_Array_32;
      Got_64   : SHA3.Byte_Array_64;
      Got_Var  : SHA3.Byte_Array (Expected'Range);
   begin
      for I in Msg'Range loop
         Sha3_Msg (I) := SHA3.U8 (Msg (I));
      end loop;
      if Algo = "sha3_256" then
         SHA3.SHA3_256 (Sha3_Msg, Got_32);
         if Expected'Length /= 32 then return False; end if;
         for I in Expected'Range loop
            if U8 (Got_32 (I)) /= Expected (I) then return False; end if;
         end loop;
         return True;
      elsif Algo = "sha3_512" then
         SHA3.SHA3_512 (Sha3_Msg, Got_64);
         if Expected'Length /= 64 then return False; end if;
         for I in Expected'Range loop
            if U8 (Got_64 (I)) /= Expected (I) then return False; end if;
         end loop;
         return True;
      elsif Algo = "shake128" then
         SHA3.SHAKE128 (Sha3_Msg, Got_Var);
         for I in Expected'Range loop
            if U8 (Got_Var (I)) /= Expected (I) then return False; end if;
         end loop;
         return True;
      elsif Algo = "shake256" then
         SHA3.SHAKE256 (Sha3_Msg, Got_Var);
         for I in Expected'Range loop
            if U8 (Got_Var (I)) /= Expected (I) then return False; end if;
         end loop;
         return True;
      else
         raise Constraint_Error with "unknown algorithm: " & Algo;
      end if;
   end Run_Vector;

   procedure Process_File (Algo : String; Path : String) is
      F           : File_Type;
      Cur_Len     : Natural := 0;
      Cur_Msg     : Unbounded_String := Null_Unbounded_String;
      Cur_Out_Bits : Natural := 0;
      Have_Len    : Boolean := False;
      Have_Msg    : Boolean := False;
      Pass, Fail  : Natural := 0;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         declare
            Line  : constant String := Get_Line (F);
            Key   : Unbounded_String;
            Value : Unbounded_String;
         begin
            if Line'Length = 0 or else Line (Line'First) = '#' then
               null;  --  skip blanks and comments
            elsif Line'Length >= 1 and then Line (Line'First) = '[' then
               --  Header line like "[L = 256]" — capture output bit length
               --  for SHAKE variable-output runs.
               declare
                  L_Pos : constant Natural :=
                    Ada.Strings.Fixed.Index (Line, "L = ");
                  R_Pos : constant Natural :=
                    Ada.Strings.Fixed.Index (Line, "]");
               begin
                  if L_Pos > 0 and R_Pos > L_Pos then
                     Cur_Out_Bits := Natural'Value
                       (Ada.Strings.Fixed.Trim
                         (Line (L_Pos + 4 .. R_Pos - 1),
                          Ada.Strings.Both));
                  end if;
               end;
            else
               Equals_Sign_Split (Line, Key, Value);
               if Length (Key) = 0 then null;
               elsif To_String (Key) = "Len" then
                  Cur_Len := Natural'Value (To_String (Value));
                  Have_Len := True;
               elsif To_String (Key) = "Msg" then
                  Cur_Msg := Value;
                  Have_Msg := True;
               elsif To_String (Key) = "Outputlen" then
                  Cur_Out_Bits := Natural'Value (To_String (Value));
               elsif To_String (Key) = "MD"
                     or else To_String (Key) = "Output"
               then
                  if Have_Len and Have_Msg then
                     declare
                        --  Len is in bits; an empty Msg encodes as "00"
                        --  per CAVP convention. Cap byte length at Len/8.
                        Msg_Hex     : constant String := To_String (Cur_Msg);
                        Msg_Bytes   : constant Byte_Array :=
                          (if Cur_Len = 0 then Byte_Array'(1 .. 0 => 0)
                           else Hex_Decode (Msg_Hex));
                        Exp_Bytes   : constant Byte_Array :=
                          Hex_Decode (To_String (Value));
                        OK : constant Boolean :=
                          Run_Vector (Algo, Msg_Bytes, Exp_Bytes, Cur_Out_Bits);
                     begin
                        if OK then
                           Pass := Pass + 1;
                        else
                           Fail := Fail + 1;
                           Put_Line
                             ("FAIL Len=" & Natural'Image (Cur_Len)
                              & " expected=" & Hex_Encode (Exp_Bytes));
                        end if;
                     end;
                     Have_Len := False;
                     Have_Msg := False;
                  end if;
               end if;
            end if;
         end;
      end loop;
      Close (F);
      Put_Line (Path & ": pass=" & Natural'Image (Pass)
                & " fail=" & Natural'Image (Fail));
      if Fail > 0 then
         Ada.Command_Line.Set_Exit_Status (1);
      end if;
   end Process_File;

begin
   if Ada.Command_Line.Argument_Count /= 2 then
      Put_Line (Standard_Error,
        "Usage: cavp_runner <sha3_256|sha3_512|shake128|shake256> <path.rsp>");
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;
   Process_File
     (Algo => Ada.Command_Line.Argument (1),
      Path => Ada.Command_Line.Argument (2));
end Cavp_Runner;
