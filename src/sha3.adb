with SHA3.Keccak;

package body SHA3 is

   pragma SPARK_Mode;

   procedure XOR_Byte_Into_State
     (S   : in out State_Array;
      Pos : Natural;
      B   : U8)
   with Pre => Pos < State_Bytes
   is
      Lane  : constant Natural := Pos / 8;
      Shift : constant Natural := (Pos mod 8) * 8;
   begin
      S (Lane) := S (Lane) xor Interfaces.Shift_Left (U64 (B), Shift);
   end XOR_Byte_Into_State;

   procedure XOR_Into_State
     (S      : in out State_Array;
      Offset : Natural;
      Data   : Byte_Array)
   with Pre => Data'First >= 0
               and then Data'Length <= State_Bytes
               and then Offset <= State_Bytes - Data'Length
   is
      Pos : Natural := Offset;
   begin
      for I in Data'Range loop
         pragma Loop_Invariant (Pos = Offset + (I - Data'First));
         pragma Loop_Invariant (Pos < State_Bytes);
         declare
            Lane  : constant Natural := Pos / 8;
            Shift : constant Natural := (Pos mod 8) * 8;
         begin
            S (Lane) := S (Lane)
                        xor Interfaces.Shift_Left (U64 (Data (I)), Shift);
         end;
         Pos := Pos + 1;
      end loop;
   end XOR_Into_State;

   procedure Extract_From_State
     (S      : State_Array;
      Offset : Natural;
      Data   : out Byte_Array)
   with Pre => Data'Length <= State_Bytes
               and then Offset <= State_Bytes - Data'Length
   is
      Pos : Natural := Offset;
   begin
      for I in Data'Range loop
         pragma Loop_Invariant (Pos = Offset + (I - Data'First));
         pragma Loop_Invariant (Pos < State_Bytes);
         declare
            Lane  : constant Natural := Pos / 8;
            Shift : constant Natural := (Pos mod 8) * 8;
         begin
            Data (I) := U8
              (Interfaces.Shift_Right (S (Lane), Shift) and 16#FF#);
         end;
         Pos := Pos + 1;
      end loop;
   end Extract_From_State;

   procedure Init
     (S : out Sponge_State; Rate : Sponge_Rate; Domain : U8)
   is
   begin
      S.State     := [others => 0];
      S.Rate      := Rate;
      S.Byte_Pos  := 0;
      S.Squeezing := False;
      S.Domain    := Domain;
   end Init;

   procedure Absorb (S : in out Sponge_State; Data : Byte_Array) is
      Pos : Natural := Data'First;
   begin
      while Pos <= Data'Last loop
         pragma Loop_Invariant (Pos >= Data'First);
         pragma Loop_Invariant (Pos <= Data'Last);
         pragma Loop_Invariant (S.Byte_Pos < S.Rate);
         pragma Loop_Invariant (S.Rate < State_Bytes);
         pragma Loop_Invariant (not S.Squeezing);

         declare
            Want : constant Natural := S.Rate - S.Byte_Pos;
            Take : constant Natural :=
              Natural'Min (Data'Last - Pos + 1, Want);
         begin
            pragma Assert (Take >= 1);
            pragma Assert (Take <= Want);
            pragma Assert (Take <= S.Rate - S.Byte_Pos);
            pragma Assert (S.Byte_Pos + Take <= S.Rate);
            pragma Assert (S.Byte_Pos + Take <= State_Bytes);
            XOR_Into_State
              (S.State, S.Byte_Pos, Data (Pos .. Pos + Take - 1));
            S.Byte_Pos := S.Byte_Pos + Take;
            Pos := Pos + Take;
         end;

         if S.Byte_Pos = S.Rate then
            Keccak.Permute (S.State);
            S.Byte_Pos := 0;
         end if;

         pragma Assert (S.Byte_Pos < S.Rate);
      end loop;
   end Absorb;

   procedure Squeeze
     (S : in out Sponge_State; Result : out Byte_Array)
   is
      Pos : Natural := Result'First;
   begin
      Result := [others => 0];

      pragma Assert (S.Rate >= 1);
      pragma Assert (S.Rate < State_Bytes);

      if not S.Squeezing then
         pragma Assert (S.Byte_Pos < S.Rate);
         pragma Assert (S.Byte_Pos < State_Bytes);
         pragma Assert (S.Rate - 1 < State_Bytes);
         XOR_Byte_Into_State (S.State, S.Byte_Pos, S.Domain);
         XOR_Byte_Into_State (S.State, S.Rate - 1, 16#80#);
         Keccak.Permute (S.State);
         S.Byte_Pos  := 0;
         S.Squeezing := True;
      end if;

      while Pos <= Result'Last loop
         pragma Loop_Invariant (Pos >= Result'First);
         pragma Loop_Invariant (Pos <= Result'Last + 1);
         pragma Loop_Invariant (S.Byte_Pos < S.Rate);
         pragma Loop_Invariant (S.Rate < State_Bytes);
         pragma Loop_Invariant (S.Squeezing);

         declare
            Available : constant Natural := S.Rate - S.Byte_Pos;
            Remaining : constant Natural := Result'Last - Pos + 1;
            Take      : constant Natural :=
              Natural'Min (Available, Remaining);
         begin
            pragma Assert (Take >= 1);
            pragma Assert (S.Byte_Pos + Take <= S.Rate);
            pragma Assert (S.Byte_Pos + Take <= State_Bytes);
            Extract_From_State
              (S.State, S.Byte_Pos, Result (Pos .. Pos + Take - 1));
            S.Byte_Pos := S.Byte_Pos + Take;
            Pos := Pos + Take;
         end;

         if S.Byte_Pos = S.Rate then
            Keccak.Permute (S.State);
            S.Byte_Pos := 0;
         end if;

         pragma Assert (S.Byte_Pos < S.Rate);
      end loop;
   end Squeeze;

   procedure SHA3_256 (Data : Byte_Array; Result : out Byte_Array_32) is
      S : Sponge_State;
   begin
      Init (S, SHA3_256_Rate, SHA3_Domain);
      Absorb (S, Data);
      Squeeze (S, Result);
      pragma Assert (S.Squeezing);
   end SHA3_256;

   procedure SHA3_512 (Data : Byte_Array; Result : out Byte_Array_64) is
      S : Sponge_State;
   begin
      Init (S, SHA3_512_Rate, SHA3_Domain);
      Absorb (S, Data);
      Squeeze (S, Result);
      pragma Assert (S.Squeezing);
   end SHA3_512;

   procedure SHAKE128 (Data : Byte_Array; Result : out Byte_Array) is
      S : Sponge_State;
   begin
      Init (S, SHAKE128_Rate, SHAKE_Domain);
      Absorb (S, Data);
      Squeeze (S, Result);
      pragma Assert (S.Squeezing);
   end SHAKE128;

   procedure SHAKE256 (Data : Byte_Array; Result : out Byte_Array) is
      S : Sponge_State;
   begin
      Init (S, SHAKE256_Rate, SHAKE_Domain);
      Absorb (S, Data);
      Squeeze (S, Result);
      pragma Assert (S.Squeezing);
   end SHAKE256;

end SHA3;
