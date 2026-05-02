with Interfaces;

package SHA3 is

   pragma Pure;
   pragma SPARK_Mode;

   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_64;

   subtype U8  is Interfaces.Unsigned_8;
   subtype U64 is Interfaces.Unsigned_64;

   type Byte_Array is array (Natural range <>) of U8;
   subtype Byte_Array_32 is Byte_Array (0 .. 31);
   subtype Byte_Array_64 is Byte_Array (0 .. 63);

   type State_Array is array (0 .. 24) of U64;

   State_Bytes : constant := 200;
   subtype Sponge_Rate is Positive range 1 .. State_Bytes - 1;

   SHA3_256_Rate : constant := 136;
   SHA3_512_Rate : constant := 72;
   SHAKE128_Rate : constant := 168;
   SHAKE256_Rate : constant := 136;

   SHA3_Domain  : constant U8 := 16#06#;
   SHAKE_Domain : constant U8 := 16#1F#;

   type Sponge_State is limited record
      State     : State_Array;
      Rate      : Sponge_Rate;
      Byte_Pos  : Natural;
      Squeezing : Boolean;
      Domain    : U8;
   end record;

   procedure SHA3_256 (Data : Byte_Array; Result : out Byte_Array_32)
     with Pre => Data'First >= 0
                 and then Data'Last < Natural'Last;

   procedure SHA3_512 (Data : Byte_Array; Result : out Byte_Array_64)
     with Pre => Data'First >= 0
                 and then Data'Last < Natural'Last;

   procedure SHAKE128 (Data : Byte_Array; Result : out Byte_Array)
     with Pre => Result'First >= 0
                 and then Result'Last < Natural'Last
                 and then Data'First >= 0
                 and then Data'Last < Natural'Last;

   procedure SHAKE256 (Data : Byte_Array; Result : out Byte_Array)
     with Pre => Result'First >= 0
                 and then Result'Last < Natural'Last
                 and then Data'First >= 0
                 and then Data'Last < Natural'Last;

   procedure Init (S : out Sponge_State; Rate : Sponge_Rate; Domain : U8)
     with Post => S.Rate = Rate
                  and then S.Domain = Domain
                  and then S.Byte_Pos = 0
                  and then not S.Squeezing
                  and then (for all I in 0 .. 24 => S.State (I) = 0);

   procedure Absorb (S : in out Sponge_State; Data : Byte_Array)
     with Pre => not S.Squeezing
                 and then S.Byte_Pos < S.Rate
                 and then S.Rate < State_Bytes
                 and then Data'First >= 0
                 and then Data'Last < Natural'Last,
          Post => not S.Squeezing
                  and then S.Byte_Pos < S.Rate
                  and then S.Rate < State_Bytes
                  and then S.Rate = S.Rate'Old
                  and then S.Domain = S.Domain'Old;

   procedure Squeeze (S : in out Sponge_State; Result : out Byte_Array)
     with Pre => Result'First >= 0
                 and then Result'Last < Natural'Last
                 and then S.Byte_Pos < S.Rate
                 and then S.Rate < State_Bytes,
          Post => S.Squeezing
                  and then S.Byte_Pos < S.Rate
                  and then S.Rate = S.Rate'Old
                  and then S.Domain = S.Domain'Old;

end SHA3;
